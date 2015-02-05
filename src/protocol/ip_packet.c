#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "config.h"
#include "util.h"
#include "list.h"
#include "hash.h"
#include "checksum.h"
#include "log.h"
#include "app_service_manager.h"
#include "ip.h"
#include "tcp.h"
#include "ip_options.h"
#include "ip_packet.h"

/* Ip packet maximum size */
#define MAX_IP_PACKET_SIZE 65535
/* Default expire timeout of ipQueue */
#define DEFAULT_IPQUEUE_EXPIRE_TIMEOUT 30
/* Default ipQueue hash table size */
#define DEFAULT_IPQUEUE_HASH_TABLE_SIZE 65535
/* ipQueue hash key format string */
#define IPQUEUE_HASH_KEY_FORMAT "%s:%s:%u"

/* IpQueue expire timeout list */
static LIST_HEAD (ipQueueExpireTimeoutList);
/* Ip host fragment hash table */
static hashTablePtr ipQueueHashTable = NULL;

static void
displayIphdr (iphdrPtr iph) {
    u_short offset, flags;

    offset = ntohs (iph->ipOff);
    flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;

    if ((flags & IP_MF) || offset) {
        LOGD ("Ip fragment src: %s ------------>", inet_ntoa (iph->ipSrc));
        LOGD (" dst: %s\n", inet_ntoa (iph->ipDest));
        LOGD ("Ip header len: %d , ip packet len: %u, offset: %u, IP_MF: %u.\n",
              (iph->iphLen * 4), ntohs (iph->ipLen), offset, ((flags & IP_MF) ? 1 : 0));
    }
}

static ipFragPtr
newIpFrag (iphdrPtr iph) {
    u_short iphLen, ipLen, offset, end;
    u_char *skbuf;
    ipFragPtr ipFragment;

    iphLen = iph->iphLen * 4;
    ipLen = ntohs (iph->ipLen);
    offset = (ntohs (iph->ipOff) & IP_OFFMASK) << 3;
    end = offset + ipLen - iphLen;

    ipFragment = (ipFragPtr) malloc (sizeof (ipFrag));
    if (ipFragment == NULL)
        return NULL;

    ipFragment->offset = offset;
    ipFragment->end = end;
    ipFragment->dataLen = end - offset;
    skbuf = (u_char *) malloc (ipLen);
    if (skbuf == NULL) {
        free (ipFragment);
        return NULL;
    }
    memcpy (skbuf, iph, ipLen);
    ipFragment->dataPtr = skbuf + iphLen;
    ipFragment->skbuf = skbuf;
    initListHead (&ipFragment->node);
    return ipFragment;
}

static void
freeIpFrag (ipFragPtr ipf) {
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
            return;
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
            return;
        }
    }
}

static int
addIpQueueToHash (ipQueuePtr ipq, hashItemFreeCB fun) {
    int ret;
    char key [64];

    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->ipSrc), inet_ntoa (ipq->ipDest), ipq->id);
    ret = hashInsert (ipQueueHashTable, key, ipq, fun);
    if (ret < 0)
        return -1;
    else
        return 0;
}

static void
delIpQueueFromHash (ipQueuePtr ipq) {
    int ret;
    char key [64];

    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->ipSrc), inet_ntoa (ipq->ipDest), ipq->id);
    ret = hashDel (ipQueueHashTable, key);
    if (ret < 0)
        LOGE ("Delete ipQueue from hash table error.\n");
}

static ipQueuePtr
findIpQueue (iphdrPtr iph) {
    char key [64];

    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (iph->ipSrc), inet_ntoa (iph->ipDest), ntohs (iph->ipId));
    return (ipQueuePtr) hashLookup (ipQueueHashTable, key);
}

static ipQueuePtr
newIpQueue (iphdrPtr iph) {
    ipQueuePtr ipq;

    ipq = (ipQueuePtr) malloc (sizeof (ipQueue));
    if (ipq == NULL)
        return NULL;

    ipq->ipSrc = iph->ipSrc;
    ipq->ipDest = iph->ipDest;
    ipq->id = ntohs (iph->ipId);
    /* Allocate memory for the IP header (plus 8 octets for ICMP). */
    ipq->iph = (iphdrPtr) malloc (64 + 8);
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
        listDel (&pos->node);
        freeIpFrag (pos);
    }
    free (ipq->iph);
    free (ipq);
}

static void
checkIpQueueExpireTimeoutList (timeValPtr tm) {
    ipQueueTimeoutPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &ipQueueExpireTimeoutList, node) {
        if (tm->tvSec < pos->timeout)
            return;
        else
            delIpQueueFromHash (pos->queue);
    }
}

static boolean
ipQueueDone (ipQueuePtr ipq) {
    ipFragPtr pos, tmp;
    u_short offset;

    if (!ipq->dataLen)
        return false;

    offset = 0;
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        if (pos->offset != offset)
            return false;
        offset = pos->end;
    }

    return true;
}

/*
 * @brief Glue ip fragments of ipQueue
 *
 * @param ipq ipQueue to glue
 *
 * @return new ip packet if success else NULL
 */
static iphdrPtr
glueIpQueue (ipQueuePtr ipq) {
    u_int ipLen;
    u_char *buf;
    iphdrPtr iph;
    ipFragPtr pos, tmp;

    ipLen = ipq->iphLen + ipq->dataLen;
    if (ipLen > MAX_IP_PACKET_SIZE) {
        LOGE ("Oversized ip packet from %s.\n", inet_ntoa (ipq->ipSrc));
        delIpQueueFromHash (ipq);
        return NULL;
    }

    buf = (u_char *) malloc (ipLen);
    if (buf == NULL) {
        LOGE ("Alloc ipQueue buffer error: %s.\n", strerror (errno));
        delIpQueueFromHash (ipq);
        return NULL;
    }

    /* Glue data of all fragments to new ip packet buffer . */
    memcpy (buf, ((u_char *) ipq->iph), ipq->iphLen);
    buf += ipq->iphLen;
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        memcpy (buf + pos->offset, pos->dataPtr, pos->dataLen);
    }

    iph = (iphdrPtr) buf;
    iph->ipOff = 0;
    iph->ipLen = htons (ipLen);
    delIpQueueFromHash (ipq);

    return iph;
}

static int
checkIpHeader (iphdrPtr iph) {
    u_char ipVer = iph->ipVer;
    u_short iphLen = iph->iphLen * 4;
    u_short ipLen = ntohs (iph->ipLen);

    if ((ipVer != 4) || (iphLen < sizeof (iphdr)) || (ipLen < iphLen)) {
        LOGE ("IpVer: %d, iphLen: %d, ipLen: %d.\n", ipVer, iphLen, ipLen);
        return -1;
    }

#ifdef DO_STRICT_CHECK
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((u_char *) iph, iph->iphl)) {
        LOGE ("ipFastCheckSum error.\n");
        return -1;
    }

    /* Check ip options */
    if ((iphLen > sizeof (iphdr)) && ipOptionsCompile ((u_char *) iph)) {
        LOGE ("IpOptionsCompile error.\n");
        return -1;
    }
#endif

    return 0;
}

/* Check whether ip packet should be dropped */
static boolean
ipPktShouldDrop (iphdrPtr iph) {
    tcphdrPtr tcph;
    char key1 [32];
    char key2 [32];

    if (iph->ipProto == IPPROTO_TCP) {
        tcph = (tcphdrPtr) ((u_char *) iph + (iph->iphLen * 4));

        snprintf (key1, sizeof (key1), "%s:%d", inet_ntoa (iph->ipSrc), ntohs (tcph->source));
        snprintf (key2, sizeof (key2), "%s:%d", inet_ntoa (iph->ipDest), ntohs (tcph->dest));
        if (getAppServiceProtoAnalyzer (key1) || getAppServiceProtoAnalyzer (key2))
            return false;
        else
            return true;
    } else
        return true;
}

/*
 * @brief Ip packet defragment
 *
 * @param iph ip packet header
 * @param tm packet capture timestamp
 * @param newIph pointer to return ip defragment packet
 *
 * @return 0 if success else -1
 */
int
ipDefrag (iphdrPtr iph, timeValPtr tm, iphdrPtr *newIph) {
    int ret;
    u_short iphLen, ipLen, offset, end, flags, gap;
    ipFragPtr ipf, prev, pos, tmp;
    ipQueuePtr ipq;
    iphdrPtr tmpIph;

    /* Check ipQueue expire timeout list */
    checkIpQueueExpireTimeoutList (tm);
    ret = checkIpHeader (iph);
    if (ret < 0) {
        *newIph = NULL;
        return -1;
    }

    iphLen = iph->iphLen * 4;
    ipLen = ntohs (iph->ipLen);
    offset = ntohs (iph->ipOff);
    flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;
    end = offset + ipLen - iphLen;

    /* Get ipQueue */
    ipq = findIpQueue (iph);

    /* Not a ip fragment */
    if (((flags & IP_MF) == 0) && (offset == 0)) {
        if (ipq)
            delIpQueueFromHash (ipq);
        *newIph = iph;
        return 0;
    }

    displayIphdr (iph);

    if (ipq == NULL) {
        ipq = newIpQueue (iph);
        if (ipq == NULL) {
            LOGE ("Alloc new ipQueue error.\n");
            *newIph = NULL;
            return -1;
        }

        /* Add ipQueue to hash */
        ret = addIpQueueToHash (ipq, freeIpQueue);
        if (ret < 0) {
            LOGE ("Add ipQueue to hash table error.\n");
            *newIph = NULL;
            return -1;
        }

        /* Add ipQueue to expire timeout list */
        addIpQueueToExpireTimeoutList (ipq, tm);
    } else {
        /* Update ipQueue expire timeout */
        updateIpQueueExpireTimeout (ipq, tm);
    }

    /* Alloc new ipFrag */
    ipf = newIpFrag (iph);
    if (ipf == NULL) {
        LOGE ("Create ip fragment error.\n");
        *newIph = NULL;
        return -1;
    }

    /* First packet of fragments */
    if (offset == 0) {
        ipq->iphLen = iphLen;
        memcpy (ipq->iph, iph, iphLen + 8);
    }

    /* Last packet of fragments */
    if ((flags & IP_MF) == 0)
        ipq->dataLen = end;

    /* Find the proper position to insert fragment */
    listForEachEntrySafeKeepPrev (prev, pos, tmp, &ipq->fragments, node) {
        if (ipf->offset <= pos->offset)
            break;
    }

    /* Check for overlap with preceding fragment */
    if ((prev != NULL) && (ipf->offset < prev->end)) {
        gap = prev->end - ipf->offset;
        ipf->offset += gap;
        ipf->dataLen -= gap;
        ipf->dataPtr += gap;
    }

    /* Check for overlap with succeeding fragments */
    listForEachEntryFromSafe (pos, tmp, &ipq->fragments, node) {
        if (ipf->end <= pos->offset)
            break;

        gap = ipf->end - pos->offset;
        /* If ipf overlap pos completely, remove pos */
        if (gap >= pos->dataLen) {
            listDel (&pos->node);
            freeIpFrag (pos);
        } else {
            pos->offset += gap;
            pos->dataLen -= gap;
            pos->dataPtr += gap;
        }
    }

    /* The proper position to insert ip fragment */
    if (prev == NULL)
        listAdd (&ipf->node, &ipq->fragments);
    else
        listAdd (&ipf->node, &prev->node);

    if (ipQueueDone (ipq)) {
        tmpIph = (iphdrPtr) glueIpQueue (ipq);
        if (tmpIph == NULL) {
            LOGE ("glueIpQueue error.\n");
            *newIph = NULL;
            return -1;
        } else {
            if (ipPktShouldDrop (tmpIph)) {
                free (tmpIph);
                *newIph = NULL;
                return -1;
            } else {
                *newIph = tmpIph;
                return 0;
            }
        }
    } else {
        *newIph = NULL;
        return 0;
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
