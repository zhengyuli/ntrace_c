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
#include "hash.h"
#include "log.h"
#include "service.h"
#include "checksum.h"
#include "ip-options.h"
#include "ip-packet.h"
#include "config.h"

/* Ip fragment expire time 30 seconds */
#define IP_FRAGMENT_EXPIRE_TIME (30 * 1000)

/*
 * Fragment cache limits. We will commit 256K at one time. Should we
 * cross that limit we will prune down to 192K. This should cope with
 * even the most extreme cases without allowing an attacker to
 * measurably harm machine performance.
 */
#define IPFRAG_HIGH_THRESH (256 * 1024)
#define IPFRAG_LOW_THRESH (192 * 1024)

#define IP_HOSTFRAG_HASH_SIZE 65535

/* Ip fragment expire init time */
static unsigned int initTime;
/* Ip fragment expire timer list */
static LIST_HEAD (ipFragExpireTimerList);
/* Ip host fragment hash table */
static hashTablePtr hostFragsHashTable;

static void
iphdrShow (struct ip *iph) {
    u_short offset, flags;

    LOGD ("Ip src: %s ------------>", inet_ntoa (iph->ip_src));
    LOGD (" dst: %s\n", inet_ntoa (iph->ip_dst));
    LOGD ("Ip header len: %d  ip total len: %u.\n", (iph->ip_hl * 4), ntohs (iph->ip_len));

    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset <<= 3;
    if (((flags & IP_MF) == 0) && (offset == 0))
        LOGD ("IP packet doesn't fragment.\n");
    else {
        if (flags & IP_MF)
            LOGD ("Ip packet has more fragment.\n");
        else
            LOGD ("Ip packet last fragment.\n");
    }
}

static int
jiffies (void) {
    unsigned int timenow;
    struct timeval tv;

    gettimeofday (&tv, 0);
    timenow = (tv.tv_sec - initTime) * 1000 + (tv.tv_usec / 1000);

    return timenow;
}

/* Add expire timer to the tail of ipFragExpireTimerList */
static inline void
addTimer (expireTimerPtr timer) {
    listAddTail (&timer->node, &ipFragExpireTimerList);
}

static inline void
delTimer (expireTimerPtr timer) {
    listDel (&timer->node);
}

static inline void
freeSkb (skbBufPtr skb) {
    free (skb);
}

static inline void
fragFreeSkb (hostFragPtr hf, skbBufPtr skb) {
    freeSkb (skb);
    hf->ipFragMem -= skb->truesize;
}

static inline void
fragFree (hostFragPtr hf, void *ptr, int len) {
    free (ptr);
    hf->ipFragMem -= len;
}

static inline void *
fragAlloc (hostFragPtr hf, int size) {
    void *addr;

    addr = (void *) malloc (size);
    if (addr) {
        hf->ipFragMem += size;
        return addr;
    } else
        return NULL;
}

/*
 * @brief Create a new fragment entry.
 *
 * @param hf current hostFragPtr
 * @param offset fragment offset
 * @param end fragment end position
 * @param ptr point to data position
 * @param skb skbBuf of fragment
 *
 * @return IpFrag pointer if success else NULL
 */
static ipFragPtr
ipFragNew (hostFragPtr hf, int offset, int end, u_char *ptr, skbBufPtr skb) {
    ipFragPtr fp;

    fp = (ipFragPtr) fragAlloc (hf, sizeof (ipFrag));
    if (fp) {
        memset (fp, 0, sizeof (ipFrag));
        fp->offset = offset;
        fp->end = end;
        fp->len = end - offset;
        fp->ptr = ptr;
        fp->skb = skb;
        hf->ipFragMem += skb->truesize;
    } else
        LOGE ("ipFragNew error:%s.\n", strerror (errno));

    return fp;
}

/*
 * Remove an entry from the "incomplete datagrams" queue, either
 * because we completed, reassembled and processed it, or because it
 * timed out.
 */
static void
ipqFree (ipqPtr qp) {
    ipFragPtr fp, tmp;

    /* Remove qp from hostFrag ipqueue list */
    listDel (&qp->node);
    /* Stop the timer for this entry */
    delTimer (&qp->timer);
    /* Release all fragment data */
    listForEachEntrySafe (fp, tmp, &qp->fragments, node) {
        listDel (&fp->node);
        fragFreeSkb (qp->hf, fp->skb);
        fragFree (qp->hf, fp, sizeof (ipFrag));
    }
    /* Release the IP header */
    fragFree (qp->hf, qp->iph, 64 + 8);
    /* Finally, release the queue descriptor itself */
    fragFree (qp->hf, qp, sizeof (ipq));
}

/*
 * @brief Find ip queue from ipqueue
 *
 * @param hf current hostFragPtr
 * @param iph ip packet
 *
 * @return IpqPtr if success else NULL
 */
static ipqPtr
ipqFind (hostFragPtr hf, struct ip *iph) {
    ipqPtr qp;

    if (hf == NULL)
        return NULL;

    listForEachEntry (qp, &hf->ipqueue, node) {
        if (iph->ip_id == qp->iph->ip_id &&
            iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
            iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
            iph->ip_p == qp->iph->ip_p) {
            delTimer (&qp->timer);
            return qp;
        }
    }
    return NULL;
}

/* A fragment queue timed out, then kill it */
static void
ipExpire (void *arg) {
    ipqPtr qp = (ipqPtr) arg;
    ipqFree (qp);
}

/*
 * Memory limiting on fragments. Evictor trashes the oldest fragment
 * queue until we are back under the low threshold.
 */
static void
ipEvictor (hostFragPtr hf) {
    ipqPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &hf->ipqueue, node) {
        if (hf->ipFragMem > IPFRAG_LOW_THRESH)
            ipqFree (pos);
        else
            break;
    }

    if ((hf->ipFragMem > IPFRAG_LOW_THRESH) && listIsEmpty (&hf->ipqueue))
        LOGE ("ipEvictor: memcount error.\n");
}

/*
 * Add an entry to the 'ipq' queue for a newly received IP datagram.
 * We will receive all other fragments of this datagram in time, so
 * we just create a queue for this datagram, in which we will insert
 * the received fragments at their respective positions.
 */
static ipqPtr
ipqCreate (hostFragPtr hf, struct ip * iph) {
    ipqPtr qp;
    int ihlen;

    qp = (ipqPtr) fragAlloc (hf, sizeof (ipq));
    if (qp == NULL) {
        LOGE ("fragAlloc error: %s.\n", strerror (errno));
        return NULL;
    }
    memset (qp, 0, sizeof (ipq));
    /* Allocate memory for the IP header (plus 8 octets for ICMP). */
    ihlen = iph->ip_hl * 4;
    qp->iph = (struct ip *) fragAlloc (hf, 64 + 8);
    if (qp->iph == NULL) {
        LOGE ("fragAlloc error: %s.\n", strerror (errno));
        fragFree (qp->hf, qp, sizeof (ipq));
        return NULL;
    }
    memcpy (qp->iph, iph, ihlen + 8);
    qp->len = 0;
    qp->ihlen = ihlen;
    initListHead (&qp->fragments);
    qp->hf = hf;

    /* Start a timer for this ip queue. */
    qp->timer.expires = jiffies () + IP_FRAGMENT_EXPIRE_TIME;
    qp->timer.data = (void *) qp;
    qp->timer.fun = ipExpire;
    addTimer (&qp->timer);
    /* Add to hostFrag ipqueue list */
    listAdd (&qp->node, &hf->ipqueue);

    return qp;
}

static hostFragPtr
hostFragFind (struct ip *iph) {
    hostFragPtr hf;

    hf = (hostFragPtr) hashLookup (hostFragsHashTable, inet_ntoa (iph->ip_dst));

    return hf;
}

static void
hostFragFree (void *data);

static int
hostFragNeedFree (void *data, void *args) {
    hostFragPtr hf = (hostFragPtr) data;

    if (listIsEmpty (&hf->ipqueue))
        return 1;
    else
        return 0;
}

static hostFragPtr
hostFragNew (struct ip *iph) {
    int ret;
    hostFragPtr hf;

    hf = (hostFragPtr) malloc (sizeof (hostFrag));
    if (hf) {
        hf->ip.s_addr = iph->ip_dst.s_addr;
        initListHead (&hf->ipqueue);
        hf->ipFragMem = 0;
        /* If current hostFragsHashTable size exceeds eighty percent of hostFragsHashTable limit
         * then remove host frag items that will not be used.
         */
        if (hashSize (hostFragsHashTable) >= (hashLimit (hostFragsHashTable) * 0.8))
            hashForEachItemDelIf (hostFragsHashTable, hostFragNeedFree, NULL);
        ret = hashInsert (hostFragsHashTable, inet_ntoa (iph->ip_dst), (void *) hf, hostFragFree);
        if (ret < 0) {
            LOGE ("Insert hostFrag item error.\n");
            return NULL;
        }
        return hf;
    } else {
        LOGE ("Malloc hostFrag error: %s.\n", strerror (errno));
        return NULL;
    }
}

static void
hostFragFree (void *data) {
    ipqPtr pos, tmp;
    hostFragPtr hf = (hostFragPtr) data;

    listForEachEntrySafe (pos, tmp, &hf->ipqueue, node) {
        ipqFree (pos);
    }
    free (data);
}

/* Check if a fragment queue is complete. */
static int
ipDone (ipqPtr qp) {
    ipFragPtr fp;
    int offset;

    offset = 0;

    /* Only possible if we received the final fragment. */
    if (qp->len == 0)
        return 0;

    listForEachEntry (fp, &qp->fragments, node) {
        if (fp->offset != offset)
            return 0;
        offset = fp->end;
    }

    return 1;
}


/* Build a new IP datagram from fragments. */
static u_char *
ipGlue (ipqPtr qp) {
    int count, len;
    u_char *skb, *ptr;
    struct ip *iph;
    ipFragPtr fp;

    /* Allocate a new buffer for the datagram. */
    len = qp->ihlen + qp->len;
    if (len > 65535) {
        LOGE ("Oversized IP packet from %s.\n", inet_ntoa (qp->iph->ip_src));
        ipqFree (qp);
        return NULL;
    }

    skb = (u_char *) malloc (len);
    if (skb == NULL) {
        LOGE ("ipGlue malloc error: %s.\n", strerror (errno));
        ipqFree (qp);
        return NULL;
    }

    /* Fill in the basic details. */
    ptr = (u_char *) skb;
    memcpy (ptr, ((u_char *) qp->iph), qp->ihlen);
    ptr += qp->ihlen;

    /* Copy the data portions of all fragments into the new buffer. */
    count = 0;
    listForEachEntry (fp, &qp->fragments, node) {
        if (fp->len < 0 || (qp->ihlen + fp->offset + fp->len) > len) {
            LOGE ("Invalid fragment list: Fragment over size.\n");
            ipqFree (qp);
            free (skb);
            return NULL;
        }
        memcpy (ptr + fp->offset, fp->ptr, fp->len);
        count += fp->len;
    }
    /* Free ip queue */
    ipqFree (qp);

    /* Done with all fragments. Fixup the new IP header. */
    iph = (struct ip *) skb;
    /* Reset ip_off to 0 */
    iph->ip_off = 0;
    iph->ip_len = htons ((iph->ip_hl * 4) + count);

    return skb;
}

/*
 * @brief Process an incoming IP datagram fragment.
 *
 * @param iph ip packet
 * @param skb skbBuf
 * @param newIphdr pointer to receive new ip packet
 *
 * @return 0 if success else -1
 */
static int
ipDefrag (struct ip *iph, skbBufPtr skb, struct ip **newIphdr) {
    int i, ihl, end;
    u_short flags, offset;
    u_char *ptr;
    hostFragPtr currHost;
    ipqPtr qp;
    ipFragPtr prev, next, tmp, new;

    /* Preset *newIphdr to NULL  */
    *newIphdr = NULL;

    ihl = iph->ip_hl * 4;
    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    /* offset is in 8-byte chunks */
    offset <<= 3;

    currHost = hostFragFind (iph);
    if (skb && !currHost) {
        currHost = hostFragNew (iph);
        if (currHost == NULL) {
            LOGE ("Create hostFrag error.\n");
            return -1;
        }
    }

    /* Start by cleaning up the memory. */
    if (currHost && currHost->ipFragMem > IPFRAG_HIGH_THRESH)
        ipEvictor (currHost);

    /* Find the entry of this IP datagram in the "incomplete datagrams" queue. */
    qp = ipqFind (currHost, iph);
    /* If this is a non-fragmented ip packet */
    if (((flags & IP_MF) == 0) && (offset == 0)) {
        if (qp) {
            /* Fragmented frame replaced by full unfragmented copy */
            ipqFree (qp);
        }
        return 0;
    }

    /* If the queue already existed, keep restarting its timer as long as
     * we still are receiving fragments.  Otherwise, create a fresh queue
     * entry.
     */
    if (qp) {
        /* If the first fragment is received, we should remember the correct
           IP header (with options) */
        if (offset == 0) {
            qp->ihlen = ihl;
            memcpy (qp->iph, iph, ihl + 8);
        }
        /* Update expire timer */
        delTimer (&qp->timer);
        qp->timer.expires = jiffies () + IP_FRAGMENT_EXPIRE_TIME;
        qp->timer.data = (void *) qp;
        qp->timer.fun = ipExpire;
        addTimer (&qp->timer);
    } else {
        qp = ipqCreate (currHost, iph);
        /* If we failed to create it, then discard the frame. */
        if (qp == NULL) {
            LOGE ("Create ipq error.\n");
            freeSkb (skb);
            return -1;
        }
    }

    /* Attempt to construct an oversize packet. */
    if (ntohs (iph->ip_len) + (int) offset > 65535) {
        LOGE ("Oversized packet received from %s\n", inet_ntoa (iph->ip_src));
        freeSkb (skb);
        return -1;
    }

    /* Determine the position of this fragment. */
    end = offset + ntohs (iph->ip_len) - ihl;
    /* Point into the IP datagram 'data' part. */
    ptr = (u_char *) (skb->data + ihl);
    /* The final fragment */
    if ((flags & IP_MF) == 0)
        qp->len = end;
    /* Find the position to insert fragment */
    listForEachEntryKeepPrev (prev, next, &qp->fragments, node) {
        if (next->offset >= offset)
            break;
    }
    /* We found where to put this one.  Check for overlap with preceding
     * fragment, and, if needed, align things so that any overlaps are
     * eliminated.
     */
    if (&prev->node != &qp->fragments && offset < prev->end) {
        i = prev->end - offset;
        offset += i;
        ptr += i;
    }
    /* Look for overlap with succeeding segments.
     * If we can merge fragments, do it.
     */
    listForEachEntrySafeFrom (next, tmp, &qp->fragments, node) {
        if (next->offset >= end)
            break;

        i = end - next->offset;
        next->len -= i;
        next->offset += i;
        next->ptr += i;
        /* Remove overlapped fragment */
        if (next->len < 0) {
            listDel (&next->node);
            fragFreeSkb (currHost, next->skb);
            fragFree (currHost, next, sizeof (ipFrag));
        }
    }

    /* Insert this fragment in the chain of fragments. */
    new = ipFragNew (currHost, offset, end, ptr, skb);
    if (new == NULL) {
        freeSkb (skb);
        return -1;
    }
    /* Add to fragments list */
    listAdd (&new->node, &prev->node);

    if (ipDone (qp)) {
        /* glue together the fragments */
        *newIphdr = (struct ip *) ipGlue (qp);
        if (*newIphdr == NULL)
            return -1;
        else
            return 0;
    }

    return 0;
}

/*
 * @brief Ip defragment entry
 *
 * @param iph ip packet
 * @param newIphdr pointer to receive new ip packet
 *
 * @return Ip defragment flag (IPF_NOTF, IPF_ISF, IPF_NEW and IPF_ERROR)
 */
static int
ipDefragStub (struct ip *iph, struct ip **newIphdr) {
    int ret;
    int totalLen;
    u_short offset, flags;
    expireTimerPtr timer, tmp;
    skbBufPtr skb;

    /* Check ip fragment expire list */
    listForEachEntrySafe (timer, tmp, &ipFragExpireTimerList, node) {
        if (timer->expires > jiffies ())
            break;
        else
            timer->fun (timer->data);
    }

    offset = ntohs (iph->ip_off);
    flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    /* Current ip packet is not fragment */
    if (((flags & IP_MF) == 0) && (offset == 0)) {
        ret = ipDefrag (iph, NULL, newIphdr);
        if (ret < 0)
            return IPF_ERROR;
        else
            return IPF_NOTF;
    }

    totalLen = ntohs (iph->ip_len);
    skb = (skbBufPtr) malloc (totalLen + sizeof (skbBuf));
    if (!skb) {
        LOGE ("ipDefragStub no memory: %s.\n", strerror (errno));
        return IPF_ERROR;
    }
    skb->data = (u_char *) (skb + 1);
    memcpy (skb->data, iph, totalLen);
    skb->truesize = totalLen + sizeof (skbBuf);

    ret = ipDefrag (iph, skb, newIphdr);
    if (ret < 0)
        return IPF_ERROR;
    else {
        if (*newIphdr)
            return IPF_NEW;
        else
            return IPF_ISF;
    }
}

/*
 * @brief Do basic check, including checksum and options
 *        compile
 *
 * @param iphdr ip header
 * @param len ip packet len
 *
 * @return 0 if success else -1
 */
static int
ipCheck (struct ip *iphdr, int len) {
    int ipVer = iphdr->ip_v;
    int ihl = iphdr->ip_hl * 4;
    int ipLen = ntohs (iphdr->ip_len);

    if (ipVer != 4 || len < ihl || len < ipLen ||
        ihl < (int) sizeof (struct ip) || ipLen < ihl) {
        LOGD ("ipVer: %d, ihl: %d, ipLen: %d, capLen: %d.\n", ipVer, ihl, ipLen, len);
        return -1;
    }

#if DO_STRICT_CHECKSUM
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((u_char *) iphdr, iphdr->ip_hl) != 0) {
        LOGD ("ipFastCheckSum error.\n");
        return -1;
    }
#endif

    if (ihl > (int) sizeof (struct ip) &&
        ipOptionsCompile ((u_char *) iphdr)) {
        LOGD ("ipOptionsCompile error.\n");
        return -1;
    }

    return 0;
}

/*
 * @brief Filter new defragment complete packet
 *        For new defragment complete packet, especially for tcp fragment packet,
 *        if this packet belongs to none of existing service, then filter out this
 *        packet.
 *
 * @param iphdr ip header of ip packet to filter
 *
 * @return 1 if been filtered else 0
 */
static int
ipFilter (struct ip *iphdr) {
    struct tcphdr *tcph;
    char key1 [32] = {0};
    char key2 [32] = {0};

    if (iphdr->ip_p == IPPROTO_TCP) {
        tcph = (struct tcphdr *) ((u_char *) iphdr + (iphdr->ip_hl * 4));

        snprintf (key1, sizeof (key1) - 1, "%s:%d", inet_ntoa (iphdr->ip_src), ntohs (tcph->source));
        snprintf (key2, sizeof (key2) - 1, "%s:%d", inet_ntoa (iphdr->ip_dst), ntohs (tcph->dest));
        if (lookupServiceProtoType (key1) != PROTO_UNKNOWN ||
            lookupServiceProtoType (key2) != PROTO_UNKNOWN)
            return 0;
        else
            return 1;
    } else
        return 0;
}

/*
 * @brief Ip defragment process, it will do basic ip check and
 *        then send defragment complete ip packet to routerDispatch
 *        for next step processing.
 *
 * @param frame ip frame to process
 * @param ipCaptureLen ip packet capture length
 * @param newIphdr new ip header if available
 *
 * @return Ip defrag flag and new ip header if available
 */
int
ipDefragProcess (void *frame, int ipCaptureLen, struct ip **newIphdr) {
    int ret;
    struct ip *iphdr = (struct ip *) frame;

    /* Preset newIphdr to NULL */
    *newIphdr = NULL;

    ret = ipCheck (iphdr, ipCaptureLen);
    if (ret < 0) {
        LOGD ("ipCheck error.\n");
        return IPF_ERROR;
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
    struct timeval tv;

    gettimeofday (&tv, 0);
    initTime = tv.tv_sec;
    hostFragsHashTable = hashNew (IP_HOSTFRAG_HASH_SIZE);
    if (hostFragsHashTable == NULL)
        return -1;
    else
        return 0;
}

/* Destroy ip context */
void
destroyIp (void) {
    if (hostFragsHashTable)
        hashDestroy (&hostFragsHashTable);
}
