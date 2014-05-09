#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "util.h"
#inlcude "list.h"
#include "hash.h"
#include "log.h"
#include "service.h"
#include "checksum.h"
#include "ip-options.h"
#include "ip-packet.h"

#define MAX_IP_PACKET_SIZE 65535
/* Default expire timeout of ipQueue is 30 seconds */
#define DEFAULT_IPQUEUE_EXPIRE_TIMEOUT 30
/* Default ipQueue hash table size */
#define DEFAULT_IPQUEUE_HASH_TABLE_SIZE 65535
/* ipQueue hash key format string */
#define IPQUEUE_HASH_KEY_FORMAT "%s:%s:%u"

/* ipQueue expire timeout list */
static LIST_HEAD (ipQueueExpireTimeoutList);
/* Ip host fragment hash table */
static hashTablePtr ipQueueHashTable = NULL;

static ipFragPtr
newIpFrag (struct ip *iph) {
    u_short iphLen, ipLen;
    u_char *skbuf;
    ipFragPtr ipf;

    iphLen = iph->ip_hl * 4;
    ipLen = ntohs (iph->ip_len);
    ipf = (ipFragPtr) malloc (sizeof (ipFrag));
    if (ipf == NULL)
        return NULL;

    ipf->offset = ntohs (iph->ip_off);
    ipf->end = ipf->offset + ipLen - iphLen;
    ipf->len = ipf->end - ipf->offset;
    skbuf = (u_char *) malloc (ipLen);
    if (skbuf == NULL) {
        free (ipf);
        return NULL;
    }
    memcpy (skbuf, iph, ipLen);
    ipf->dataPtr = skbuf + iphLen;
    ipf->skbuf = skbuf;
    initListHead (&ipf->node);
    return ipf;
}

static void
freeIpFrag (ipFragPtr ipf) {
    if (ipf == NULL)
        return;

    free (ipf->skbuf);
    free (ipf);
}

static void
addIpQueueToExpireTimeoutList (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr new;

    new = (ipQueueTimeoutPtr) malloc (sizeof (ipQueueTimeout));
    if (new == NULL) {
        LOGE ("Alloc ipQueue expire timeout error: %s.\n", strerror (errno));
        return;
    }

    new->queue = ipq;
    new->timeout = tm->tvSec + DEFAULT_IPQUEUE_EXPIRE_TIMEOUT;
    listAddTail (&new->node, &ipQueueExpireTimeoutList);
}

static void
delIpQueueFromExpireTimeoutList (ipQueuePtr ipq) {
    ipQueueTimeoutPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &ipQueueExpireTimeoutList, node) {
        if (pos->queue == ipq) {
            listDel (&pos->node);
            free (pos);
        }
    }
}

static void
updateIpQueueExpireTimeout (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &ipQueueExpireTimeoutList, node) {
        if (pos->queue == ipq) {
            listDel (&pos->node);
            pos->timeout = tm->tvSec + DEFAULT_IPQUEUE_EXPIRE_TIMEOUT;
            listAddTail (&pos->node, &ipQueueExpireTimeoutList);
        }
    }
}

static int
addIpQueueToHash (ipQueuePtr ipq, hashFreeCB freeFun) {
    int ret;
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->sourcIp), inet_ntoa (ipq->destIp), ipq->id);
    ret = hashInsert (ipQueueHashTable, key, ipq, freeFun);
    if (ret < 0)
        return -1;
    else
        return 0;
}

static void
delIpQueueFromHash (ipQueuePtr ipq) {
    int ret;
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->sourcIp), inet_ntoa (ipq->destIp), ipq->id);
    ret = hashDel (ipQueueHashTable, key);
    if (ret < 0)
        LOGE ("Delete ipQueue from hash table error.\n");
}

static ipQueuePtr
findIpQueue (struct ip *iph) {
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (iph->ip_src), inet_ntoa (iph->ip_dst), ntohs (iph->ip_id));
    return (ipQueuePtr) hashLookup (ipQueueHashTable, key);
}

static ipQueuePtr
newIpQueue (struct ip * iph) {
    ipQueuePtr ipq;

    ipq = (ipQueuePtr) malloc (sizeof (ipQueue));
    if (ipq == NULL)
        return NULL;

    ipq->sourcIp = iph->ip_src;
    ipq->destIp = iph->ip_dst;
    ipq->id = ntohs (iph->ip_id);
    ipq->iph = (struct ip *) malloc (64 + 8);
    if (ipq->iph == NULL) {
        free (ipq);
        return NULL;
    }
    ipq->iphLen = 0;
    ipq->dataLen = 0;
    initListHead (&ipq->fragments);
    return ipq;
}

static void
freeIpQueue (void *data) {
    ipFragPtr pos, tmp;
    ipQueuePtr ipq = (ipQueuePtr) data;

    delIpQueueFromExpireTimeoutList (ipq);
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        listDel (pos->node);
        free (pos->skbuf);
        free (pos);
    }
    free (ipq->iph);
    free (data);
}

static void
checkIpQueueExpireTimeoutList (timeValPtr tm) {
    ipFragTimeoutQueuePtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &ipQueueExpireTimeoutList, node) {
        if (pos->timeout > tm->tvSec)
            return;
        else
            delIpQueueFromHash (pos->ipq);
    }
}

static BOOL
ipQueueDone (ipQueuePtr ipq) {
    ipFragPtr pos, tmp;
    u_short offset = 0;

    if (!ipq->dataLen)
        return FALSE;

    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        if (pos->offset != offset)
            return FALSE;
        offset = pos->end;
    }

    return TRUE;
}

static struct ip *
ipQueueGlue (ipQueuePtr ipq) {
    u_int ipLen;
    u_char *buf;
    struct ip *iph;
    ipFragPtr pos, tmp;

    ipLen = ipq->iphLen + ipq->dataLen;
    if (ipLen > MAX_IP_PACKET_SIZE) {
        LOGE ("Oversized ip packet from %s.\n", inet_ntoa (ipq->sourcIp));
        return NULL;
    }

    buf = (u_char *) malloc (ipLen);
    if (buf == NULL) {
        LOGE ("Alloc ipQueue buffer error: %s.\n", strerror (errno));
        return NULL;
    }

    /* Glue data of all fragments to new ip packet buffer . */
    memcpy (buf, ((u_char *) ipq->iph), ipq->iphLen);
    buf += ipq->iphLen;
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node)
            memcpy (buf + pos->offset, pos->dataPtr, pos->len);

    iph = (struct ip *) buf;
    iph->ip_off = 0;
    iph->ip_len = htons (ipq->iphLen + ipq->dataLen);

    return iph
            }

static int
checkIpHeader (struct ip *iph, u_int capLen) {
    u_char ipVer = iph->ip_v;
    u_short iphLen = iph->ip_hl * 4;
    u_short ipLen = ntohs (iph->ip_len);

    if ((ipVer != 4) || (capLen < iphLen) || (capLen < ipLen) ||
        (iphLen < sizeof (struct ip)) || (ipLen < iphLen)) {
        LOGE ("IpVer: %d, iphLen: %d, ipLen: %d, capLen: %d.\n", ipVer, iphLen, ipLen, capLen);
        return -1;
    }

#if DO_STRICT_CHECKSUM
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((const u_char *) iph, iph->ip_hl)) {
        LOGD ("ipFastCheckSum error.\n");
        return -1;
    }
#endif

    if ((iphLen > sizeof (struct ip)) && ipOptionsCompile ((u_char *) iph)) {
        LOGD ("IpOptionsCompile error.\n");
        return -1;
    }

    return 0;
}


int
ipDefragProcess (struct ip *iph, u_int capLen, timeValPtr tm, struct ip **newIph) {
    int ret;
    u_short iphLen, ipLen, offset, flags;
    ipFragPtr ipf;
    ipQueuePtr ipq;

    /* Check ipQueue expire timeout list */
    checkIpQueueExpireTimeoutList (tm);
    ret = checkIpHeader (iph, capLen);
    if (ret < 0)
        return IPF_ERROR;

    iphLen = iph->ip_hl * 4;
    ipLen = ntohs (iph->ip_len);
    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    offset <<= 3;

    /* Get ipQueue */
    ipq = findIpQueue (iph);
    /* Not a ip fragment */
    if (((flags & IP_MF) == 0) && (offset == 0)) {
        if (ipq)
            delIpQueueFromHash (ipq);
        return IPF_NOTF;
    }

    /* Alloc new ipFrag */
    ipf = newIpFrag (iph);
    if (ipf == NULL) {
        LOGE ("Create ip fragment error.\n");
        return IPF_ERROR ;
    }

    if (ipq == NULL) {
        ipq = newIpQueue (iph);
        if (ipq == NULL) {
            LOGE ("Alloc new ipQueue error.\n");
            freeIpFrag (ipf);
            return IPF_ERROR;
        }

        ret = addIpQueueToHash (ipq, freeIpQueue);
        if (ret < 0) {
            LOGE ("Add ipQueue to hash table error.\n");
            freeIpFrag (ipf);
            return IPF_ERROR;
        }
        addIpQueueToExpireTimeoutList (ipq, tm);
    }

    /* Update ipQueue expire timeout */
    updateIpQueueExpireTimeout (ipq, tm);
    /* First packet of fragments */
    if (offset == 0) {
        ipq->iphLen = iphLen;
        memcpy (ipq->iph, iph, iphLen + 8);
    }
    
}

/* Init ip context */
int
initIp (void) {
    ipQueueHashTable = hashNew (DEFAULT_IPQUEUE_HASH_TABLE_SIZE);
    if (ipQueueHashTable == NULL)
        return -1;
    else
        return 0;
}

/* Destroy ip context */
void
destroyIp (void) {
    hashDestroy (ipQueueHashTable);
    ipQueueHashTable = NULL;
}
