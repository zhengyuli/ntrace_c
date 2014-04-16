#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <json/json.h>
#include "checksum.h"
#include "util.h"
#include "list.h"
#include "hash.h"
#include "log.h"
#include "service.h"
#include "redis-client.h"
#include "byte-order.h"
#include "protocol.h"
#include "tcp-options.h"
#include "tcp-packet.h"
#include "atomic.h"
#include "config.h"

/* Default tcp stream closing timeout 10 seconds */
#define DEFAULT_TCP_STREAM_CLOSING_TIMEOUT 15
/* Default tcp stream hash table size */
#define DEFAULT_TCP_STREAM_HASH_SIZE 65535
/* Tcp expect sequence */
#define EXP_SEQ (snd->firstDataSeq + rcv->count + rcv->urgCount)
/* Tcp stream hash key format string */
#define TCP_STREAM_HASH_FORMAT "%s:%d:%s:%d"

/* Debug statistic data */
static uint32_t tcpStreamsAlloc = 0;
static uint32_t tcpStreamsFree = 0;

/* Tcp stream list */
static __thread listHead tcpStreamList;
/* Tcp stream timeout list */
static __thread listHead tcpStreamTimoutList;
/* Tcp stream hash table */
static __thread hashTablePtr tcpStreamHashTable;

/* Tcp session breakdown callback */
static __thread publishTcpBreakdownCB publishTcpBreakdownFunc;
static __thread void *publishTcpBreakdownArgs;

static inline int
before (u_int seq1, u_int seq2) {
    if ((int) (seq1 - seq2) < 0)
        return 1;
    else
        return 0;
}

static inline int
after (u_int seq1, u_int seq2) {
    if ((int) (seq1 - seq2) > 0)
        return 1;
    else
        return 0;
}

/* Free halfStream skbuff list */
static void
purgeSkbuff (halfStreamPtr hs) {
    skbuffPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &hs->head, node) {
        listDel (&pos->node);
        free (pos->data);
        free (pos);
    }
    hs->rmemAlloc = 0;
}

/*
 * @brief Add tcp stream to global tcp stream timeout list
 *
 * @param stream tcp stream to add
 * @param tm tcp stream closing time
 */
static void
addTcpStreamToClosingTimeoutList (tcpStreamPtr stream, timeValPtr tm) {
    tcpTimeoutPtr new, pos;

    /* If already added, return directly */
    if (stream->inClosingTimeout)
        return;

    new = (tcpTimeoutPtr) malloc (sizeof (tcpTimeout));
    if (new == NULL) {
        LOGE ("Add tcp closing timeout error: %s.\n", strerror (errno));
        return;
    }

    stream->inClosingTimeout = 1;
    new->stream = stream;
    new->timeout = tm->tv_sec + DEFAULT_TCP_STREAM_CLOSING_TIMEOUT;
    /* Add new before pos */
    listAddTail (&new->node, &tcpStreamTimoutList);
}

/* Delete tcp stream from global tcp stream timeout list */
static void
delTcpStreamFromClosingTimeoutList (tcpStreamPtr stream) {
    tcpTimeoutPtr pos;

    if (!stream->inClosingTimeout)
        return;

    listForEachEntry (pos, &tcpStreamTimoutList, node) {
        if (pos->stream == stream) {
            listDel (&pos->node);
            free (pos);
            return;
        }
    }
}

/*
 * @brief Lookup tcp stream from global tcp stream hash
 *        table
 * @param addr tcp stream 4 tuple address
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
lookupTcpStreamFromHash (tuple4Ptr addr) {
    char key [64] = {0};

    snprintf(key, sizeof (key) - 1, TCP_STREAM_HASH_FORMAT,
             inet_ntoa (addr->saddr), addr->source,
             inet_ntoa (addr->daddr), addr->dest);
    return (tcpStreamPtr) hashLookup (tcpStreamHashTable, key);
}

/*
 * @brief Add tcp stream to global hash table
 *
 * @param stream tcp stream to add
 * @param freeFun tcp stream free function
 *
 * @return 0 if success else -1
 */
static int
addTcpStreamToHash (tcpStreamPtr stream, hashFreeFun freeFun) {
    int ret;
    tuple4Ptr addr;
    char key [64] = {0};

    addr = &stream->addr;
    snprintf(key, sizeof (key) - 1, TCP_STREAM_HASH_FORMAT,
             inet_ntoa (addr->saddr), addr->source,
             inet_ntoa (addr->daddr), addr->dest);
    ret = hashInsert (tcpStreamHashTable, key, stream, freeFun);
    if (ret < 0) {
        LOGE ("Insert stream to hash map error.\n");
        return -1;
    } else
        return 0;
}

/*
 * @brief Remove tcp stream from hash table
 *
 * @param stream tcp stream to remove
 */
static void
delTcpStreamFromHash (tcpStreamPtr stream) {
    tuple4Ptr addr;
    char key [64] = {0};

    addr = &stream->addr;
    snprintf(key, sizeof (key) - 1, TCP_STREAM_HASH_FORMAT,
             inet_ntoa (addr->saddr), addr->source,
             inet_ntoa (addr->daddr), addr->dest);
    if (hashDel (tcpStreamHashTable, key) < 0)
        LOGE ("Delete stream from hash map error.\n");
    else
        LOGD ("tcpStreamsAlloc: %u<------->tcpStreamsFree: %u\n", ATOMIC_ADD_AND_FETCH (&tcpStreamsAlloc, 0),
              ATOMIC_INC (&tcpStreamsFree));
}

/*
 * @brief Check tcp stream timeout list and remove timeout
 *        tcp stream.
 *
 * @param tm timestamp for current packet
 */
static void
tcpCheckTimeout (timeValPtr tm) {
    tcpTimeoutPtr pos, tmp;

    listForEachEntrySafe (pos, tmp, &tcpStreamTimoutList, node) {
        if (pos->timeout > tm->tv_sec)
            return;
        else {
            pos->stream->state = STREAM_TIMED_OUT;
            delTcpStreamFromHash (pos->stream);
        }
    }
}

/*
 * @brief Find tcp stream from global hash table
 *
 * @param tcph tcp header
 * @param iph ip header
 * @param fromClient return data flow direction
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
findTcpStream (struct tcphdr *tcph, struct ip * iph, int *fromClient) {
    tuple4 addr, reversed;
    tcpStreamPtr stream;

    addr.saddr = iph->ip_src;
    addr.source = ntohs (tcph->source);
    addr.daddr = iph->ip_dst;
    addr.dest = ntohs (tcph->dest);
    stream = lookupTcpStreamFromHash (&addr);
    if (stream) {
        *fromClient = 1;
        return stream;
    }

    reversed.saddr = iph->ip_dst;
    reversed.source = ntohs (tcph->dest);
    reversed.daddr = iph->ip_src;
    reversed.dest = ntohs (tcph->source);
    stream = lookupTcpStreamFromHash (&reversed);
    if (stream) {
        *fromClient = 0;
        return stream;
    }

    return NULL;
}

/* Create a new tcpStream and init */
static tcpStreamPtr
newTcpStream (protoType proto) {
    tcpStreamPtr stream;

    stream = (tcpStreamPtr) malloc (sizeof (tcpStream));
    if (stream == NULL) {
        LOGE ("Alloc tcp stream error: %s.\n", strerror (errno));
        return NULL;
    }

    stream->proto = proto;
    stream->parser = getProtoParser (proto);
    if (stream->parser == NULL) {
        LOGD ("Error: unsupported service proto type.\n");
        free (stream);
        return NULL;
    }
    /* Init 4-tuple address */
    stream->addr.saddr.s_addr = 0;
    stream->addr.source = 0;
    stream->addr.daddr.s_addr = 0;
    stream->addr.dest = 0;
    stream->state = STREAM_INIT;
    /* Init client halfStream */
    stream->client.state = TCP_CLOSE;
    stream->client.rcvBuf = NULL;
    stream->client.bufSize = 0;
    stream->client.offset = 0;
    stream->client.count = 0;
    stream->client.countNew = 0;
    stream->client.seq = 0;
    stream->client.ackSeq = 0;
    stream->client.firstDataSeq = 0;
    stream->client.urgData = 0;
    stream->client.urgCount = 0;
    stream->client.urgCountNew = 0;
    stream->client.urgSeen = 0;
    stream->client.urgPtr = 0;
    stream->client.window = 0;
    stream->client.tsOn = 0;
    stream->client.wscaleOn = 0;
    stream->client.currTs = 0;
    stream->client.wscale = 0;
    initListHead (&stream->client.head);
    stream->client.rmemAlloc = 0;
    /* Init client halfStream end */
    /* Init server halfStream */
    stream->server.state = TCP_CLOSE;
    stream->server.rcvBuf = NULL;
    stream->server.bufSize = 0;
    stream->server.offset = 0;
    stream->server.count = 0;
    stream->server.countNew = 0;
    stream->server.seq = 0;
    stream->server.ackSeq = 0;
    stream->server.firstDataSeq = 0;
    stream->server.urgData = 0;
    stream->server.urgCount = 0;
    stream->server.urgCountNew = 0;
    stream->server.urgSeen = 0;
    stream->server.urgPtr = 0;
    stream->server.window = 0;
    stream->server.tsOn = 0;
    stream->server.wscaleOn = 0;
    stream->server.currTs = 0;
    stream->server.wscale = 0;
    initListHead (&stream->server.head);
    stream->server.rmemAlloc = 0;
    /* Init server halfStream end */
    /* Init tcp session detail */
    stream->firstReq = 1;
    stream->synTime = 0;
    stream->retryTime = 0;
    stream->retryNum = 0;
    stream->synAckTime = 0;
    stream->estbTime = 0;
    stream->connectSuccess = 0;
    stream->pktsRetransmit = 0;
    stream->pktsOutOfOrder = 0;
    stream->sessionDetail = (*stream->parser->newSessionDetail) ();
    if (stream->sessionDetail == NULL) {
        LOGE (" newSessionDetail error.\n");
        free (stream);
        return NULL;
    }
    stream->closeTime = 0;
    stream->inClosingTimeout = 0;
    initListHead (&stream->node);

    return stream;
}

/* Tcp stream free function */
static void
freeTcpStream (void *data) {
    skbuffPtr pos, tmp;
    tcpStreamPtr stream = (tcpStreamPtr) data;

    /* Delete stream from global tcp stream list */
    listDel (&stream->node);
    /* Delete stream from closing timeout list */
    delTcpStreamFromClosingTimeoutList (stream);
    /* Free client halfStream */
    listForEachEntrySafe (pos, tmp, &stream->client.head, node) {
        listDel (&pos->node);
        free (pos->data);
        free (pos);
    }
    stream->client.rmemAlloc = 0;
    if (stream->client.rcvBuf) {
        free (stream->client.rcvBuf);
        stream->client.rcvBuf =  NULL;
    }
    /* Free client halfStream end */
    /* Free server halfStream */
    listForEachEntrySafe (pos, tmp, &stream->server.head, node) {
        listDel (&pos->node);
        free (pos->data);
        free (pos);
    }
    stream->server.rmemAlloc = 0;
    if (stream->server.rcvBuf) {
        free (stream->server.rcvBuf);
        stream->server.rcvBuf =  NULL;
    }
    /* Free server halfStream end */
    /* Free session detail */
    (*stream->parser->freeSessionDetail) (stream->sessionDetail);
    /* Free memory */
    free (data);
}

/*
 * @brief Alloc new tcp stream and add it to global hash table
 *
 * @param tcph tcp header for current packet
 * @param iph ip header for current packet
 * @param tm timestamp for current packet
 *
 * @return TcpStream if success else NULL
 */
static tcpStreamPtr
addNewTcpStream (struct tcphdr *tcph, struct ip *iph, timeValPtr tm) {
    int ret;
    protoType proto;
    char key [64] = {0};
    tcpStreamPtr stream, tmp;

    snprintf (key, sizeof (key) - 1, "%s:%d", inet_ntoa (iph->ip_dst), ntohs (tcph->dest));
    proto = lookupServiceProtoType (key);
    if (proto == PROTO_UNKNOWN) {
        LOGE ("Service (%s:%d) has not been registered.\n",
              inet_ntoa (iph->ip_dst), ntohs (tcph->dest));
        return NULL;
    }

    stream = newTcpStream (proto);
    if (stream == NULL) {
        LOGE ("Create new tcpStream error.\n");
        return NULL;
    }
    /* Set stream 4-tuple address */
    stream->addr.saddr = iph->ip_src;
    stream->addr.source = ntohs (tcph->source);
    stream->addr.daddr = iph->ip_dst;
    stream->addr.dest = ntohs (tcph->dest);
    /* Set client halfStream */
    stream->client.state = TCP_SYN_SENT;
    stream->client.seq = ntohl (tcph->seq) + 1;
    stream->client.firstDataSeq = stream->client.seq;
    stream->client.window = ntohs (tcph->window);
    stream->client.tsOn = getTimeStampOption (tcph, &stream->client.currTs);
    stream->client.wscaleOn = getTcpWindowScaleOption (tcph, &stream->client.wscale);
    if (!stream->client.wscaleOn)
        stream->client.wscale = 1;
    /* Set server halfStream */
    stream->server.state = TCP_CLOSE;
    /* Set sessionDetail */
    stream->synTime = timeVal2MilliSecond (tm);
    stream->retryTime = stream->synTime;
    /* Check the number of tcp streams. If the number of tcp streams exceed eighty
     * percent of tcpStreamHashTable size limit then remove the oldest tcp stream
     * from global tcp stream list head.
     */
    if (hashSize (tcpStreamHashTable) >= (hashLimit (tcpStreamHashTable) * 0.8)) {
        listFirstEntry (tmp, &tcpStreamList, node);
        delTcpStreamFromHash (stream);
    }
    /* Add to global tcp stream list */
    listAddTail (&stream->node, &tcpStreamList);
    /* Add to global tcp stream hash table */
    ret = addTcpStreamToHash (stream, freeTcpStream);
    if (ret < 0)
        return NULL;
    else {
        ATOMIC_INC (&tcpStreamsAlloc);
        return stream;
    }
}

static char *
tcpBreakdown2Json (tcpStreamPtr stream, tcpBreakdownPtr tbd) {
    char *out;
    const char *protoName;
    char buf [64];
    struct json_object *root;

    protoName = getProtoName (tbd->proto);
    if (protoName == NULL) {
        LOGE ("Unknown service proto type.\n");
        return NULL;
    }

    root = json_object_new_object ();
    if (is_error (root)) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    UINT64_TO_STRING (buf, tbd->timestamp);
    json_object_object_add (root, COMMON_SKBD_TIMESTAMP, json_object_new_string (buf));

    json_object_object_add (root, COMMON_SKBD_SERVICE_TYPE, json_object_new_string (protoName));

    json_object_object_add (root, COMMON_SKBD_SERVICE_IP, json_object_new_string (inet_ntoa (tbd->svcIp)));

    UINT16_TO_STRING (buf, tbd->svcPort);
    json_object_object_add (root, COMMON_SKBD_SERVICE_PORT, json_object_new_string (buf));

    json_object_object_add (root, COMMON_SKBD_SOURCE_IP, json_object_new_string (inet_ntoa (tbd->srcIp)));

    UINT16_TO_STRING (buf, tbd->srcPort);
    json_object_object_add (root, COMMON_SKBD_SOURCE_PORT, json_object_new_string (buf));

    UINT64_TO_STRING (buf, tbd->retryTime);
    json_object_object_add (root, COMMON_SKBD_TCP_RETRY_TIME, json_object_new_string (buf));

    UINT64_TO_STRING (buf, tbd->retryNum);
    json_object_object_add (root, COMMON_SKBD_TCP_RETRY_NUMBER, json_object_new_string (buf));

    UINT8_TO_STRING (buf, tbd->connectSuccess);
    json_object_object_add (root, COMMON_SKBD_CONNECT_SUCCESS, json_object_new_string (buf));

    UINT64_TO_STRING (buf, tbd->connectTime);
    json_object_object_add (root, COMMON_SKBD_CONNECT_TIME, json_object_new_string (buf));

    UINT64_TO_STRING (buf, tbd->pktsRetransmit);
    json_object_object_add (root, COMMON_SKBD_PACKETS_RETRANSMIT, json_object_new_string (buf));

    UINT64_TO_STRING (buf, tbd->pktsOutOfOrder);
    json_object_object_add (root, COMMON_SKBD_PACKETS_OUT_OF_ORDER, json_object_new_string (buf));

    if (tbd->connectSuccess)
        (*stream->parser->sessionBreakdown2Json) (root, stream->sessionDetail, tbd->sessionBreakdown);

    out = strdup (json_object_to_json_string (root));
    json_object_put (root);

    return out;
}

static void publishTcpBreakdown (tcpStreamPtr stream, timeValPtr tm) {
    int ret;
    tcpBreakdown tbd;
    char *jsonStr = NULL;

    tbd.sessionBreakdown = (*stream->parser->newSessionBreakdown) ();
    if (tbd.sessionBreakdown == NULL) {
        LOGE ("New sessionBreakdown error.\n");
        return;
    }

    tbd.timestamp = tm->tv_sec;
    tbd.proto = stream->proto;
    tbd.svcIp = stream->addr.daddr;
    tbd.svcPort = stream->addr.dest;
    tbd.srcIp = stream->addr.saddr;
    tbd.srcPort = stream->addr.source;
    tbd.connectSuccess = stream->connectSuccess;
    tbd.pktsRetransmit = stream->pktsRetransmit;
    tbd.pktsOutOfOrder = stream->pktsOutOfOrder;
    /* Reset stream packets retransmit and out of order */
    stream->pktsRetransmit = 0;
    stream->pktsOutOfOrder = 0;
    if (tbd.connectSuccess) {
        if (stream->firstReq) {
            stream->firstReq = 0;
            tbd.retryTime = stream->retryTime - stream->synTime;
            tbd.retryNum = stream->retryNum;
            tbd.connectTime = stream->estbTime - stream->retryTime;
        } else {
            tbd.retryTime = 0;
            tbd.retryNum = 0;
            tbd.connectTime = 0;
        }

        ret = (*stream->parser->generateSessionBreakdown) (stream->sessionDetail, tbd.sessionBreakdown);
        if (ret < 0) {
            LOGE ("GenerateSessionBreakdown error.\n");
            (*stream->parser->freeSessionBreakdown) (tbd.sessionBreakdown);
            return;
        }
    } else {
        tbd.retryTime = 0;
        tbd.retryNum = 0;
        tbd.connectTime = 0;
    }

    jsonStr = tcpBreakdown2Json (stream, &tbd);
    if (jsonStr == NULL) {
        LOGE ("SessionBreakdown2Json error.\n");
        (*stream->parser->freeSessionBreakdown) (tbd.sessionBreakdown);
        return;
    }

    /* Push session breakdown to redis server */
    publishTcpBreakdownFunc (jsonStr, publishTcpBreakdownArgs);

    free (jsonStr);
    (*stream->parser->freeSessionBreakdown) (tbd.sessionBreakdown);
}

static void
handleUrgData (tcpStreamPtr stream, halfStreamPtr snd, char urgData, timeValPtr tm) {
    int fromClient;

    if (snd == &stream->client)
        fromClient = 1;
    else
        fromClient = 0;

    if (stream->parser->sessionProcessUrgData)
        (*stream->parser->sessionProcessUrgData) (fromClient, urgData, stream->sessionDetail, tm);
}

/* Tcp data handler callback */
static int
handleData (tcpStreamPtr stream, halfStreamPtr snd, u_char *data, int dataLen, timeValPtr tm) {
    int fromClient;
    int parseCount;
    int sessionDone = 0;

    if (snd == &stream->client)
        fromClient = 1;
    else
        fromClient = 0;

    if (stream->parser->sessionProcessData) {
        parseCount = (*stream->parser->sessionProcessData) (fromClient, data, dataLen, stream->sessionDetail, tm, &sessionDone);
        if (sessionDone)
            publishTcpBreakdown (stream, tm);
    } else
        parseCount = dataLen;

    return parseCount;
}

/* Tcp reset handler callback */
static void
handleReset (tcpStreamPtr stream, halfStreamPtr snd, timeValPtr tm) {
    int fromClient;
    int sessionDone = 0;

    if (stream->connectSuccess) {
        if (snd == &stream->client)
            fromClient = 1;
        else
            fromClient = 0;

        if (stream->parser->sessionProcessReset) {
            (*stream->parser->sessionProcessReset) (fromClient, stream->sessionDetail, tm, &sessionDone);
            if (sessionDone)
                publishTcpBreakdown (stream, tm);
        }
    } else
        publishTcpBreakdown (stream, tm);

    stream->state = STREAM_RESET;
    /* Remove stream from tcpStream hash map */
    delTcpStreamFromHash (stream);
}

/* Tcp fin handler callback */
static void
handleFin (tcpStreamPtr stream, halfStreamPtr snd, timeValPtr tm) {
    int fromClient;
    halfStreamPtr rcv;
    int sessionDone = 0;

    if (snd == &stream->client) {
        fromClient = 1;
        rcv = &stream->server;
    } else {
        fromClient = 0;
        rcv = &stream->client;
    }

    stream->closeTime = timeVal2MilliSecond (tm);

    if (stream->parser->sessionProcessFin) {
        (*stream->parser->sessionProcessFin) (fromClient, stream->sessionDetail, tm, &sessionDone);
        if (sessionDone)
            publishTcpBreakdown (stream, tm);
    }

    snd->state = TCP_FIN_SENT;
    stream->state = STREAM_CLOSING;
    addTcpStreamToClosingTimeoutList (stream, tm);
}

/*
 * @brief Add data to halfStream receive buffer
 *
 * @param rcv halfStream to receive
 * @param data data to add
 * @param dataLen data length to add
 */
static void
add2buf (halfStreamPtr rcv, u_char *data, int dataLen) {
    int toalloc;

    if (rcv->count - rcv->offset + dataLen > rcv->bufSize) {
        if (rcv->rcvBuf == NULL) {
            if (dataLen < 2048)
                toalloc = 4096;
            else
                toalloc = dataLen * 2;
            rcv->rcvBuf = (u_char *) malloc (toalloc);
            if (rcv->rcvBuf == NULL) {
                LOGE ("Alloc memory for halfStream rcvBuf error: %s.\n", strerror (errno));
                rcv->bufSize = 0;
                return;
            }
            rcv->bufSize = toalloc;
        } else {
            if (dataLen < rcv->bufSize)
                toalloc = 2 * rcv->bufSize;
            else
                toalloc = rcv->bufSize + 2 * dataLen;
            rcv->rcvBuf = (u_char *) realloc (rcv->rcvBuf, toalloc);
            if (rcv->rcvBuf == NULL) {
                LOGE ("Alloc memory for halfStream rcvBuf error: %s.\n", strerror (errno));
                rcv->bufSize = 0;
                return;
            }
            rcv->bufSize = toalloc;
        }
    }
    memcpy (rcv->rcvBuf + rcv->count - rcv->offset, data, dataLen);
    rcv->countNew = dataLen;
    rcv->count += dataLen;
}

/*
 * @brief Tcp data defragment, merge data from skbuff to receiver's receive
 *        buffer. If data contains urgData, it needs to update receiver's urg
 *        data and pointer first else merge data directly.
 *
 * @param stream current tcp stream
 * @param snd tcp sender
 * @param rcv tcp receiver
 * @param data data to merge
 * @param dataLen data length
 * @param curSeq current send sequence
 * @param fin fin flag
 * @param urg urg flag
 * @param urgPtr urgPointer
 * @param push push flag
 * @param tm current timestamp
 */
static void
addFromSkb (tcpStreamPtr stream, halfStreamPtr snd, halfStreamPtr rcv, u_char *data,
            int dataLen, u_int curSeq, char fin, char urg, u_int urgPtr, char push, timeValPtr tm) {
    int parseCount;
    int toCopy1, toCopy2;
    u_int lost = EXP_SEQ - curSeq;

    if (urg && after (urgPtr, EXP_SEQ - 1) &&
        (!rcv->urgSeen || after (urgPtr, rcv->urgPtr))) {
        rcv->urgPtr = urgPtr;
        rcv->urgSeen = 1;
    }

    if (rcv->urgSeen && after (rcv->urgPtr + 1, curSeq + lost) &&
        before (rcv->urgPtr, curSeq + dataLen)) {
        toCopy1 = rcv->urgPtr - (curSeq + lost);
        if (toCopy1 > 0) {
            add2buf (rcv, data + lost, toCopy1);
            parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset, tm);
            memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset - parseCount);
            rcv->offset += parseCount;
            rcv->countNew = 0;
        }
        rcv->urgData = data [rcv->urgPtr - curSeq];
        rcv->urgCountNew = 1;
        handleUrgData (stream, snd, rcv->urgData, tm);
        rcv->urgCountNew = 0;
        rcv->urgSeen = 0;
        rcv->urgCount++;
        toCopy2 = curSeq + dataLen - rcv->urgPtr - 1;
        if (toCopy2 > 0) {
            add2buf (rcv, data + lost + toCopy1 + 1, toCopy2);
            parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset, tm);
            memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset - parseCount);
            rcv->offset += parseCount;
            rcv->countNew = 0;
        }
    } else {
        if (dataLen - lost > 0) {
            add2buf (rcv, data + lost, dataLen - lost);
            parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset, tm);
            memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset - parseCount);
            rcv->offset += parseCount;
            rcv->countNew = 0;
        }
    }

    if (fin)
        handleFin (stream, snd, tm);
}

/*
 * @brief Tcp queue process, for expected data merge it to receiver's
 *        receive buffer directly else store it to skbuff and link it
 *        to receiver's skbuff list.
 *
 * @param stream current tcp stream
 * @param tcph tcp header
 * @param snd tcp sender
 * @param rcv tcp receiver
 * @param data data to merge
 * @param dataLen data length
 * @param skbLen data capture length
 * @param tm current timestamp
 */
static void
tcpQueue (tcpStreamPtr stream, struct tcphdr *tcph, halfStreamPtr snd, halfStreamPtr rcv,
          u_char *data, int dataLen, int skbLen, timeValPtr tm) {
    u_int curSeq;
    skbuffPtr skbuf, tmp;

    curSeq = ntohl (tcph->seq);
    if (!after (curSeq, EXP_SEQ)) {
        /* Accumulate out of order packets */
        if (before (curSeq, EXP_SEQ))
            stream->pktsOutOfOrder++;

        if (after (curSeq + dataLen + tcph->fin, EXP_SEQ)) {
            /* The packet straddles our window end */
            getTimeStampOption (tcph, &snd->currTs);
            addFromSkb (stream, snd, rcv, (u_char *) data, dataLen, curSeq, tcph->fin,
                        tcph->urg, curSeq + ntohs (tcph->urg_ptr) - 1, tcph->psh, tm);

            listForEachEntrySafe (skbuf, tmp, &rcv->head, node) {
                if (after (skbuf->seq, EXP_SEQ))
                    break;
                listDel (&skbuf->node);
                if (after (skbuf->seq + skbuf->len + skbuf->fin, EXP_SEQ)) {
                    addFromSkb (stream, snd, rcv, skbuf->data, skbuf->len, skbuf->seq,
                                skbuf->fin, skbuf->urg, skbuf->seq + skbuf->urgPtr - 1, skbuf->psh, tm);
                }
                rcv->rmemAlloc -= skbuf->truesize;
                free (skbuf->data);
                free (skbuf);
            }
        } else
            return;
    } else {
        /* Accumulate out of order packets */
        stream->pktsOutOfOrder++;
        /* Alloc new skbuff */
        skbuf = (skbuffPtr) malloc (sizeof (skbuff));
        if (skbuf == NULL) {
            LOGE ("Alloc memory for skbuff error: %s.\n", strerror (errno));
            return;
        }
        memset(skbuf, 0, sizeof (skbuff));
        skbuf->truesize = skbLen;
        rcv->rmemAlloc += skbuf->truesize;
        skbuf->len = dataLen;
        skbuf->data = (u_char *) malloc (dataLen);
        if (skbuf->data == NULL) {
            LOGE ("Alloc memory for skbuff data error: %s.\n", strerror (errno));
            free (skbuf);
            return;
        }
        memcpy (skbuf->data, data, dataLen);
        skbuf->fin = tcph->fin;
        if (skbuf->fin) {
            snd->state = TCP_CLOSING;
            addTcpStreamToClosingTimeoutList (stream, tm);
        }
        skbuf->seq = curSeq;
        skbuf->urg = tcph->urg;
        skbuf->urgPtr = ntohs (tcph->urg_ptr);
        skbuf->psh = tcph->psh;

        listForEachEntryReverse (tmp, &rcv->head, node) {
            if (before (tmp->seq, curSeq)) {
                listAdd (&skbuf->node, &tmp->node);
                return;
            }
        }
        listAdd (&skbuf->node, &rcv->head);
    }
}

/*
 * @brief Tcp process portal, it will process tcp connection, tcp data
 *        defragment and tcp stream context destroy.
 *
 * @param data ip packet to process
 * @param skbLen packet capture length
 * @param tm current timestamp
 */
void
tcpProcess (u_char *data, int skbLen, timeValPtr tm) {
    int ipLen;
    int tcpLen;
    int tcpDataLen;
    int fromClient;
    u_int tmpTs;
    tcpStreamPtr stream;
    halfStreamPtr snd, rcv;
    struct ip *iph;
    struct tcphdr *tcph;
    int withData;

    iph = (struct ip *) data;
    tcph = (struct tcphdr *) (data + iph->ip_hl * 4);
    ipLen = ntohs (iph->ip_len);
    tcpLen = ipLen - iph->ip_hl * 4;
    tcpDataLen = ipLen - (iph->ip_hl * 4) - (tcph->doff * 4);
    withData = tcpDataLen ? 1 : 0;

    tm->tv_sec = ntoh64 (tm->tv_sec);
    tm->tv_usec = ntoh64 (tm->tv_usec);

    /* Check timeout tcp stream */
    tcpCheckTimeout (tm);
    /* Ip packet Check */
    if ((u_int) ipLen < (iph->ip_hl * 4 + sizeof (struct tcphdr))) {
        LOGE ("Invalid tcp packet.\n");
        return;
    }

    if (tcpDataLen < 0) {
        LOGE ("Invalid tcp data length.\n");
        return;
    }

    if (iph->ip_src.s_addr == 0 || iph->ip_dst.s_addr == 0) {
        LOGE ("Invalid ip address.\n");
        return;
    }

#if DO_STRICT_CHECKSUM
    /* Tcp checksum validation */
    if (tcpFastCheckSum (tcph, tcpLen, iph->ip_src.s_addr, iph->ip_dst.s_addr) != 0) {
        LOGE ("Tcp fast checksum error.\n");
        return;
    }
#endif

    stream = findTcpStream (tcph, iph, &fromClient);
    if (stream == NULL) {
        if (tcph->syn && !tcph->ack && !tcph->rst) {
            stream = addNewTcpStream (tcph, iph, tm);
            if (stream == NULL) {
                LOGE ("Add new tcp stream error.\n");
                return;
            }
        }
        return;
    }

    if (fromClient) {
        snd = &stream->client;
        rcv = &stream->server;
    } else {
        rcv = &stream->client;
        snd = &stream->server;
    }

    if (tcph->syn) {
        if (fromClient || stream->client.state != TCP_SYN_SENT ||
            stream->server.state != TCP_CLOSE || !tcph->ack) {
            /* Tcp connect retry */
            if (fromClient && stream->client.state == TCP_SYN_SENT) {
                stream->retryNum += 1;
                stream->retryTime = timeVal2MilliSecond (tm);
            }

            return;
        }

        /* Tcp connect syn/ack */
        if (stream->client.seq != ntohl (tcph->ack_seq))
            return;

        stream->server.state = TCP_SYN_RECV;
        stream->server.seq = ntohl (tcph->seq) + 1;
        stream->server.firstDataSeq = stream->server.seq;
        stream->server.ackSeq = ntohl (tcph->ack_seq);
        stream->server.window = ntohs (tcph->window);

        if (stream->client.tsOn) {
            stream->server.tsOn = getTimeStampOption (tcph, &stream->server.currTs);
            if (!stream->server.tsOn)
                stream->client.tsOn = 0;
        } else
            stream->server.tsOn = 0;

        if (stream->client.wscaleOn) {
            stream->server.wscaleOn = getTcpWindowScaleOption (tcph, &stream->server.wscale);
            if (!stream->server.wscaleOn) {
                stream->client.wscaleOn = 0;
                stream->client.wscale  = 1;
                stream->server.wscale = 1;
            }
        } else {
            stream->server.wscaleOn = 0;
            stream->server.wscale = 1;
        }
        stream->synAckTime = timeVal2MilliSecond (tm);
        return;
    }

    if (tcph->rst) {
        handleReset (stream, snd, tm);
        return;
    }

    /* Filter retransmitted or out of window range packet */
    if (!(!tcpDataLen && (ntohl (tcph->seq) == rcv->ackSeq)) &&
        (before (ntohl (tcph->seq) + tcpDataLen, rcv->ackSeq) ||
         !before (ntohl (tcph->seq), (rcv->ackSeq + rcv->window * rcv->wscale)))) {
        /* Accumulate retransmitted packets */
        if (before (ntohl (tcph->seq) + tcpDataLen, rcv->ackSeq))
            stream->pktsRetransmit++;
        return;
    }

    /* PAWS (Protect Against Wrapped Sequence numbers) check */
    if (rcv->tsOn && getTimeStampOption (tcph, &tmpTs) &&
        before (tmpTs, snd->currTs))
        return;

    if (tcph->ack) {
        if (fromClient && stream->client.state == TCP_SYN_SENT &&
            stream->server.state == TCP_SYN_RECV) {
            if (ntohl (tcph->ack_seq) == stream->server.seq) {
                stream->client.state = TCP_ESTABLISHED;
                stream->client.ackSeq = ntohl (tcph->ack_seq);
                stream->server.state = TCP_ESTABLISHED;
                stream->state = STREAM_JUST_EST;
                stream->connectSuccess = 1;
                stream->estbTime = timeVal2MilliSecond (tm);
                stream->state = STREAM_DATA;
            }
        }

        if (ntohl (tcph->ack_seq) > snd->ackSeq)
            snd->ackSeq = ntohl (tcph->ack_seq);

        if (rcv->state == TCP_FIN_SENT)
            rcv->state = TCP_FIN_CONFIRMED;
        if (rcv->state == TCP_FIN_CONFIRMED && snd->state == TCP_FIN_CONFIRMED) {
            stream->state = STREAM_CLOSE;
            delTcpStreamFromHash (stream);
            return;
        }
    }

    if (tcpDataLen + tcph->fin > 0) {
        tcpQueue (stream, tcph, snd, rcv, (u_char *) tcph + 4 * tcph->doff,
                  tcpDataLen, skbLen, tm);
    }
    snd->window = ntohs (tcph->window);
}

/* Init tcp process context */
int
initTcp (publishTcpBreakdownCB publishTcpBreakdown, void *args) {
    publishTcpBreakdownFunc = publishTcpBreakdown;
    publishTcpBreakdownArgs = args;

    initListHead (&tcpStreamList);
    initListHead (&tcpStreamTimoutList);
    tcpStreamHashTable = hashNew (DEFAULT_TCP_STREAM_HASH_SIZE);
    if (tcpStreamHashTable == NULL)
        return -1;
    else
        return 0;
}

/* Destroy tcp process context */
void
destroyTcp (void) {
    hashDestroy (&tcpStreamHashTable);
}
