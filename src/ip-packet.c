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
#include "list.h"
#include "hash.h"
#include "logger.h"
#include "checksum.h"
#include "service-manager.h"
#include "ip-options.h"
#include "ip-packet.h"

#define MAX_IP_PACKET_SIZE 65535
/* Default expire timeout of ipQueue is 30 seconds */
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
displayIphdr (const struct ip *iph) {
    u_short offset, flags;

    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset = offset & IP_OFFMASK;
    offset <<= 3;

    if ((flags & IP_MF) || offset) {
        LOGD ("Ip fragment src: %s ------------>", inet_ntoa (iph->ip_src));
        LOGD (" dst: %s\n", inet_ntoa (iph->ip_dst));
        LOGD ("Ip header len: %d , ip packet len: %u, offset: %u, IP_MF: %u.\n",
              (iph->ip_hl * 4), ntohs (iph->ip_len), offset, ((flags & IP_MF) ? 1 : 0));
    }
}

static ipFragPtr
newIpFrag (struct ip *iph) {
    u_short iphLen, ipLen, offset, end;
    u_char *skbuf;
    ipFragPtr ipf;

    iphLen = iph->ip_hl * 4;
    ipLen = ntohs (iph->ip_len);
    offset = ntohs (iph->ip_off);
    offset &= IP_OFFMASK;
    offset <<= 3;
    end = offset + ipLen - iphLen;

    ipf = (ipFragPtr) malloc (sizeof (ipFrag));
    if (ipf == NULL)
        return NULL;
    ipf->offset = offset;
    ipf->end = end;
    ipf->dataLen = end - offset;
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
addIpQueueToHash (ipQueuePtr ipq, hashFreeCB fun) {
    int ret;
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IPQUEUE_HASH_KEY_FORMAT,
              inet_ntoa (ipq->sourcIp), inet_ntoa (ipq->destIp), ipq->id);
    ret = hashInsert (ipQueueHashTable, key, ipq, fun);
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
    /* Allocate memory for the IP header (plus 8 octets for ICMP). */
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
        listDel (&pos->node);
        freeIpFrag (pos);
    }
    free (ipq->iph);
    free (ipq);
}

/* Search ipQueue expire timeout list and remove expired ipQueue */
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

/* Check ipQueue done state */
static boolean
ipQueueDone (ipQueuePtr ipq) {
    ipFragPtr pos, tmp;
    u_short offset;

    if (!ipq->dataLen)
        return false;

    /* Init offset */
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
static struct ip *
ipQueueGlue (ipQueuePtr ipq) {
    u_int ipLen;
    u_char *buf;
    struct ip *iph;
    ipFragPtr pos, tmp;

    ipLen = ipq->iphLen + ipq->dataLen;
    if (ipLen > MAX_IP_PACKET_SIZE) {
        LOGE ("Oversized ip packet from %s.\n", inet_ntoa (ipq->sourcIp));
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
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node)
            memcpy (buf + pos->offset, pos->dataPtr, pos->dataLen);

    iph = (struct ip *) buf;
    iph->ip_off = 0;
    iph->ip_len = htons (ipLen);
    delIpQueueFromHash (ipq);

    return iph;
}

static int
checkIpHeader (struct ip *iph) {
    u_char ipVer = iph->ip_v;
    u_short iphLen = iph->ip_hl * 4;
    u_short ipLen = ntohs (iph->ip_len);

    if ((ipVer != 4) || (iphLen < sizeof (struct ip)) || (ipLen < iphLen)) {
        LOGE ("IpVer: %d, iphLen: %d, ipLen: %d.\n", ipVer, iphLen, ipLen);
        return -1;
    }

#if DO_STRICT_CHECK
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((const u_char *) iph, iph->ip_hl)) {
        LOGD ("ipFastCheckSum error.\n");
        return -1;
    }
    /* Check ip options */
    if ((iphLen > sizeof (struct ip)) && ipOptionsCompile ((u_char *) iph)) {
        LOGD ("IpOptionsCompile error.\n");
        return -1;
    }
#endif
    return 0;
}

/* Check whether ip packet should be filter */
static boolean
pktShouldBeFilter (struct ip *iphdr) {
    struct tcphdr *tcph;
    char key1 [32] = {0};
    char key2 [32] = {0};

    if (iphdr->ip_p == IPPROTO_TCP) {
        tcph = (struct tcphdr *) ((u_char *) iphdr + (iphdr->ip_hl * 4));

        snprintf (key1, sizeof (key1) - 1, "%s:%d", inet_ntoa (iphdr->ip_src), ntohs (tcph->source));
        snprintf (key2, sizeof (key2) - 1, "%s:%d", inet_ntoa (iphdr->ip_dst), ntohs (tcph->dest));
        if (lookupServiceProtoType (key1) != PROTO_UNKNOWN || lookupServiceProtoType (key2) != PROTO_UNKNOWN)
            return true;
        else
            return false;
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
ipDefrag (struct ip *iph, timeValPtr tm, struct ip **newIph) {
    int ret;
    u_short iphLen, ipLen, offset, end, flags, gap;
    ipFragPtr ipf, prev, pos, tmp;
    ipQueuePtr ipq;
    struct ip *newIphdr;

    /* Check ipQueue expire timeout list */
    checkIpQueueExpireTimeoutList (tm);
    ret = checkIpHeader (iph);
    if (ret < 0) {
        *newIph = NULL;
        return -1;
    }

    iphLen = iph->ip_hl * 4;
    ipLen = ntohs (iph->ip_len);
    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    offset <<= 3;
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

#ifndef NDEBUG
    /* Display ip fragment header information */
    displayIphdr (iph);
#endif

    if (ipq == NULL) {
        ipq = newIpQueue (iph);
        if (ipq == NULL) {
            LOGE ("Alloc new ipQueue error.\n");
            *newIph = NULL;
            return -1;
        }

        ret = addIpQueueToHash (ipq, freeIpQueue);
        if (ret < 0) {
            LOGE ("Add ipQueue to hash table error.\n");
            *newIph = NULL;
            return -1;
        }
        /* Add ipQueue to expire timeout list */
        addIpQueueToExpireTimeoutList (ipq, tm);
    }

    /* Update ipQueue expire timeout */
    updateIpQueueExpireTimeout (ipq, tm);

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
        newIphdr = (struct ip *) ipQueueGlue (ipq);
        if (newIphdr == NULL) {
            LOGE ("IpQueueGlue error.\n");
            *newIph = NULL;
            return -1;
        } else {
            if (pktShouldBeFilter (newIphdr)) {
                free (newIphdr);
                *newIph = NULL;
                return -1;
            } else {
                *newIph = newIphdr;
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
