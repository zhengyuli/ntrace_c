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

/* Ip fragment queue expire timeout list */
static LIST_HEAD (ipQueueExpireTimeoutList);
/* Ip host fragment hash table */
static hashTablePtr ipQueueHashTable = NULL;

static void
addIpQueueToExpireTimeoutList (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr new;

    new = (ipQueueTimeoutPtr) malloc (sizeof (ipQueueTimeout));
    if (new == NULL) {
        LOGE ("Alloc ip fragment queue timeout error: %s.\n", strerror (errno));
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
        LOGE ("Insert ip fragment queue to hash table error.\n");
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
        LOGE ("Delete ip fragment queue from hash table error.\n");
}

static ipQueuePtr
findIpQueue (struct ip *iph) {
    char key [64] = {0};

    snprintf (key, sizeof (key) - 1, IP_QUEUE_HASH_KEY_FORMAT,
              inet_ntoa (iph->ip_src), inet_ntoa (iph->ip_dst), ntohs (iph->ip_id));
    return (ipQueuePtr) hashLookup (ipQueueHashTable, key);
}

static ipQueuePtr
newIpQueue (void) {
    ipQueuePtr ipq;

    ipq = (ipQueuePtr) malloc (sizeof (ipQueue));
    if (ipq) {
        ipq->sourcIp.s_addr = 0;
        ipq->destIp.s_addr = 0;
        ipq->id = 0;
        ipq->iph = NULL;
        ipq->iphLen = 0;
        ipq->dataLen = 0;
        initListHead (&ipq->fragments);
    }

    return ipq;
}

static void
freeIpQueue (void *data) {
    ipFragPtr pos, tmp;
    ipQueuePtr ipq = (ipQueuePtr) data;

    delIpQueueFromExpireTimeoutList (ipq);
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        listDel (pos->node);
        free (pos->ipFrag);
        free (pos);
    }
    free (ipq->iph);
    free (data);
}

static void
checkIpQueueExpireTimeout (timeValPtr tm) {
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

static u_char *
ipQueueGlue (ipQueuePtr ipq) {
    u_int ipLen;
    u_int count;
    struct ip *iph;
    u_char *ptr;
    ipFragPtr pos, tmp;

    ipLen = ipq->iphLen + ipq->dataLen;
    if (ipLen > MAX_IP_PACKET_SIZE) {
        LOGE ("Oversized ip packet from %s.\n", inet_ntoa (ipq->sourcIp));
        return NULL;
    }

    iph = (struct ip *) malloc (ipLen);
    if (iph == NULL) {
        LOGE ("Alloc ip queue buffer error: %s.\n", strerror (errno));
        return NULL;
    }

    ptr = (u_char *) iph;
    memcpy (ptr, ((u_char *) ipq->iph), ipq->iphLen);
    ptr += ipq->iphLen;

    /* Glue data of all fragments to new ip packet buffer . */
    count = 0;
    listForEachEntrySafe (pos, tmp, &ipq->fragments, node) {
        memcpy (ptr + pos->offset, pos->data, pos->len);
        count += pos->len;
    }

    /* Done with all fragments. Fixup the new IP header. */
    iph = (struct ip *) skb;
    /* Reset ip_off to 0 */
    iph->ip_off = 0;
    iph->ip_len = htons ((iph->ip_hl * 4) + count);

    return skb;
}

