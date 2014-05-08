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
/* Default expire timeout of ip queue is 30 seconds */
#define DEFAULT_IP_QUEUE_EXPIRE_TIMEOUT 30
/* Default ip queue hash table size */
#define DEFAULT_IP_QUEUE_HASH_TABLE_SIZE 65535
/* Ip queue hash key format string */
#define IP_QUEUE_HASH_KEY_FORMAT "%s:%s:%u"

/* Ip queue expire timeout list */
static LIST_HEAD (ipQueueExpireTimeoutList);
/* Ip host fragment hash table */
static hashTablePtr ipQueueHashTable = NULL;

static void
addIpQueueToExpireTimeoutList (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr new;

    new = (ipQueueTimeoutPtr) malloc (sizeof (ipQueueTimeout));
    if (new == NULL) {
        LOGE ("Alloc ip queue expire timeout error: %s.\n", strerror (errno));
        return;
    }

    new->queue = ipq;
    new->timeout = tm->tvSec + DEFAULT_IP_QUEUE_EXPIRE_TIMEOUT;
    listAddTail (&new->node, &ipQueueExpireTimeoutList);
}

static void
updateIpQueueToExpireTimeoutList (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &ipQueueExpireTimeoutList, node) {
        if (pos->queue == ipq) {
            listDel (&pos->node);
            pos->timeout = tm->tvSec + DEFAULT_IP_QUEUE_EXPIRE_TIMEOUT;
            listAddTail (&pos->node, &ipQueueExpireTimeoutList);
        }
    }
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

static int
addIpQueueToHash (ipQueuePtr ipq, hashFreeCB freeFun) {
    int ret;
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IP_QUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->sourcIp), inet_ntoa (ipq->destIp), ipq->id);
    ret = hashInsert (ipQueueHashTable, key, ipq, freeFun);
    if (ret < 0) {
        LOGE ("Insert ip queue to hash table error.\n");
        return -1;
    } else
        return 0;
}

static void
delIpQueueFromHash (ipQueuePtr ipq) {
    int ret;
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IP_QUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->sourcIp), inet_ntoa (ipq->destIp), ipq->id);
    ret = hashDel (ipQueueHashTable, key);
    if (ret < 0)
        LOGE ("Delete ip queue from hash table error.\n");
}

static ipQueuePtr
findIpQueue (struct ip *iph) {
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IP_QUEUE_HASH_KEY_FORMAT,
              inet_ntoa (iph->ip_src), inet_ntoa (iph->ip_dst), ntohs (iph->ip_id));
    return (ipQueuePtr) hashLookup (ipQueueHashTable, key);
}

static ipQueuePtr
createIpQueue (struct ip * iph) {
    ipQueuePtr ipq;
    u_short iphLen;

    ipq = (ipQueuePtr) malloc (sizeof (ipQueue));
    if (ipq) {
        ipq->sourcIp = iph->ip_src;
        ipq->destIp = iph->ip_dst;
        ipq->id = ntohs (iph->ip_id);
        ipq->iph = (struct ip *) malloc (64 + 8);
        if (ipq->iph == NULL) {
            LOGE ("Alloc ip header buffer error: %s\n", strerror (errno));
            free (ipq);
            return NULL;
        }
        ipq->iphLen = iph->ip_hl * 4;
        memcpy (ipq->iph, iph, iphLen);
        ipq->dataLen = 0;
        initListHead (&ipq->fragments);
    } else
        LOGE ("Alloc ip queue");

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
        LOGE ("Alloc ip queue buffer error: %s.\n", strerror (errno));
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
checkIphdr (struct ip *iphdr, u_int len) {
    u_char ipVer = iphdr->ip_v;
    u_short iphLen = iphdr->ip_hl * 4;
    u_short ipLen = ntohs (iphdr->ip_len);

    if ((ipVer != 4) || (len < iphLen) || (len < ipLen) ||
        (iphLen < sizeof (struct ip)) || (ipLen < iphLen)) {
        LOGE ("IpVer: %d, iphLen: %d, ipLen: %d, capLen: %d.\n", ipVer, iphLen, ipLen, len);
        return -1;
    }

#if DO_STRICT_CHECKSUM
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((const u_char *) iphdr, iphdr->ip_hl)) {
        LOGD ("ipFastCheckSum error.\n");
        return -1;
    }
#endif

    if ((iphLen > sizeof (struct ip)) && ipOptionsCompile ((u_char *) iphdr)) {
        LOGD ("IpOptionsCompile error.\n");
        return -1;
    }

    return 0;
}


int
ipDefragProcess (struct ip *iph, u_int capLen, timeValPtr tm, struct ip **newIphdr) {
    int ret;
    u_short offset, flags, ipLen;
    ipQueuePtr ipq;

    /* Check ip queue expire timeout list */
    checkIpQueueExpireTimeoutList (tm);
    ret = checkIphdr (iphdr, capLen);
    if (ret < 0)
        return IPF_ERROR;

    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    offset <<= 3;

    /* Not a fragment ip packet */
    if (((flags & IP_MF) == 0) && (offset == 0)) {
        ipq = findIpQueue (iph);
        if (ipq)
            delIpQueueFromHash (ipq);
        return IPF_NOTF;
    }

    

    
    
    ret = ipDefragStub (iphdr, newIphdr);
    switch (ret) {
        /* Not fragment packet */
        case IPF_NOTF:
            return IPF_NOTF;

            /* New defragment complete ip packet */
        case IPF_NEW:
            /* If not been filtered */
            if (!ipFilter (*newIphdr)) {
                iphdrShow (*newIphdr);
                return IPF_NEW;
            } else {
                free (*newIphdr);
                *newIphdr = NULL;
                return IPF_ERROR;
            }

            /* Fragment packet */
        case IPF_ISF:
            return IPF_ISF;

        default:
            return IPF_ERROR;
    }
}

/* Init ip context */
int
initIp (void) {
    ipQueueHashTable = hashNew (DEFAULT_IP_QUEUE_HASH_TABLE_SIZE);
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
