#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <czmq.h>
#include "config.h"
#include "util.h"
#include "list.h"
#include "hash.h"
#include "log.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_packet.h"

/* Default tcp stream hash table size */
#define DEFAULT_TCP_STREAM_HASH_TABLE_SIZE (2 << 17)
/* Tcp stream hash key format string */
#define TCP_STREAM_HASH_KEY_FORMAT "%s:%u:%s:%u"

/* Tcp expect sequence */
#define EXP_SEQ (snd->firstDataSeq + rcv->count + rcv->urgCount)

/* Tcp stream list */
static listHead tcpStreamList;
/* Tcp stream hash table */
static hashTablePtr tcpStreamHashTable;

static inline boolean
before (u_int seq1, u_int seq2) {
    int ret;

    ret = (int) (seq1 - seq2);
    if (ret < 0)
        return True;
    else
        return False;
}

static inline boolean
after (u_int seq1, u_int seq2) {
    int ret;

    ret = (int) (seq1 - seq2);
    if (ret > 0)
        return True;
    else
        return False;
}

static inline boolean
tuple4IsEqual (tuple4Ptr addr1, tuple4Ptr addr2) {
    if (addr1->saddr.s_addr == addr2->saddr.s_addr &&
        addr1->source == addr2->source &&
        addr1->daddr.s_addr == addr2->daddr.s_addr &&
        addr1->dest == addr2->dest)
        return True;

    return False;
}

/**
 * @brief Lookup tcp stream from global tcp stream hash table
 *
 * @param addr tcp stream 4 tuple address
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
lookupTcpStreamFromHash (tuple4Ptr addr) {
    char key [64];

    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              inet_ntoa (addr->saddr), addr->source,
              inet_ntoa (addr->daddr), addr->dest);
    return (tcpStreamPtr) hashLookup (tcpStreamHashTable, key);
}

/**
 * @brief Add tcp stream to global hash table
 *
 * @param stream tcp stream to add
 * @param freeFun tcp stream free function
 *
 * @return 0 if success else -1
 */
static int
addTcpStreamToHash (tcpStreamPtr stream, hashItemFreeCB freeFun) {
    int ret;
    tuple4Ptr addr;
    char key [64];

    addr = &stream->addr;
    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              inet_ntoa (addr->saddr), addr->source,
              inet_ntoa (addr->daddr), addr->dest);
    ret = hashInsert (tcpStreamHashTable, key, stream, freeFun);
    if (ret < 0) {
        LOGE ("Insert stream to hash table error.\n");
        return -1;
    } else
        return 0;
}

/**
 * @brief Remove tcp stream from hash table
 *
 * @param stream tcp stream to remove
 */
static void
delTcpStreamFromHash (tcpStreamPtr stream) {
    int ret;
    tuple4Ptr addr;
    char key [64];

    addr = &stream->addr;
    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              inet_ntoa (addr->saddr), addr->source,
              inet_ntoa (addr->daddr), addr->dest);
    ret = hashRemove (tcpStreamHashTable, key);
    if (ret < 0)
        LOGE ("Delete stream from hash table error.\n");
}

/**
 * @brief Find tcp stream from global hash table
 *
 * @param tcph tcp header
 * @param iph ip header
 * @param direction return stream direction
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
findTcpStream (tcphdrPtr tcph, iphdrPtr iph, streamDirection *direction) {
    tuple4 addr, revAddr;
    tcpStreamPtr stream;

    addr.saddr = iph->ipSrc;
    addr.source = ntohs (tcph->source);
    addr.daddr = iph->ipDest;
    addr.dest = ntohs (tcph->dest);

    revAddr.saddr = iph->ipDest;
    revAddr.source = ntohs (tcph->dest);
    revAddr.daddr = iph->ipSrc;
    revAddr.dest = ntohs (tcph->source);

    stream = lookupTcpStreamFromHash (&addr);
    if (stream) {
        *direction = STREAM_FROM_CLIENT;
        return stream;
    }

    stream = lookupTcpStreamFromHash (&revAddr);
    if (stream) {
        *direction = STREAM_FROM_SERVER;
        return stream;
    }

    return NULL;
}

static tcpStreamPtr
newTcpStream (void) {
    tcpStreamPtr stream;

    stream = (tcpStreamPtr) malloc (sizeof (tcpStream));
    if (stream == NULL)
        return NULL;

    /* Init 4-tuple address */
    stream->addr.saddr.s_addr = 0;
    stream->addr.source = 0;
    stream->addr.daddr.s_addr = 0;
    stream->addr.dest = 0;

    /* Init client halfStream */
    stream->client.state = TCP_CONN_CLOSED;
    stream->client.rcvBuf = NULL;
    stream->client.bufSize = 0;
    stream->client.offset = 0;
    stream->client.count = 0;
    stream->client.seq = 0;
    stream->client.ackSeq = 0;
    stream->client.firstDataSeq = 0;
    stream->client.urgCount = 0;
    stream->client.urgSeen = 0;
    stream->client.urgPtr = 0;
    initListHead (&stream->client.head);
    /* Init client halfStream end */

    /* Init server halfStream */
    stream->server.state = TCP_CONN_CLOSED;
    stream->server.rcvBuf = NULL;
    stream->server.bufSize = 0;
    stream->server.offset = 0;
    stream->server.count = 0;
    stream->server.seq = 0;
    stream->server.ackSeq = 0;
    stream->server.firstDataSeq = 0;
    stream->server.urgCount = 0;
    stream->server.urgSeen = 0;
    stream->server.urgPtr = 0;
    initListHead (&stream->server.head);
    /* Init server halfStream end */

    initListHead (&stream->node);

    return stream;
}

static void
freeTcpStream (tcpStreamPtr stream) {
    skbuffPtr entry;
    listHeadPtr pos, npos;

    /* Delete stream from global tcp stream list */
    listDel (&stream->node);

    /* Free client halfStream */
    listForEachEntrySafe (entry, pos, npos, &stream->client.head, node) {
        listDel (&entry->node);
        free (entry->data);
        free (entry);
    }
    free (stream->client.rcvBuf);

    /* Free server halfStream */
    listForEachEntrySafe (entry, pos, npos, &stream->server.head, node) {
        listDel (&entry->node);
        free (entry->data);
        free (entry);
    }
    free (stream->server.rcvBuf);

    free (stream);
}

static void
freeTcpStreamForHash (void *data) {
    tcpStreamPtr stream = (tcpStreamPtr) data;

    freeTcpStream (stream);
}

/**
 * @brief Alloc new tcp stream and add it to tcp stream hash table
 *
 * @param tcph tcp header for current packet
 * @param iph ip header for current packet
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
addNewTcpStream (tcphdrPtr tcph, iphdrPtr iph) {
    int ret;
    char key [64];
    tcpStreamPtr stream, tmp;

    snprintf (key, sizeof (key), "%s:%d", inet_ntoa (iph->ipDest), ntohs (tcph->dest));
    stream = newTcpStream ();
    if (stream == NULL) {
        LOGE ("Create new tcpStream error.\n");
        return NULL;
    }

    /* Set stream 4-tuple address */
    stream->addr.saddr = iph->ipSrc;
    stream->addr.source = ntohs (tcph->source);
    stream->addr.daddr = iph->ipDest;
    stream->addr.dest = ntohs (tcph->dest);

    /* Set client halfStream */
    stream->client.state = TCP_SYN_PKT_SENT;
    stream->client.seq = ntohl (tcph->seq) + 1;
    stream->client.firstDataSeq = stream->client.seq;

    /* Check the count of tcp streams. If the count of tcp streams exceed eighty
     * percent of tcpStreamHashTable limit size then remove the oldest tcp stream
     * from global tcp stream list.
     */
    if (hashSize (tcpStreamHashTable) >= (hashLimit (tcpStreamHashTable) * 0.8)) {
        tmp = listHeadEntry (&tcpStreamList, tcpStream, node);
        tmp->client.state = TCP_CONN_CLOSED;
        tmp->server.state = TCP_CONN_CLOSED;
        tmp->state = STREAM_CLOSED;
        delTcpStreamFromHash (tmp);
    }

    /* Add to global tcp stream list */
    listAddTail (&stream->node, &tcpStreamList);

    /* Add to global tcp stream hash table */
    ret = addTcpStreamToHash (stream, freeTcpStreamForHash);
    if (ret < 0) {
        LOGE ("Add tcp stream to stream hash table error.\n");
        return NULL;
    }

    return stream;
}

/* Tcp data handler callback */
static u_int
handleData (tcpStreamPtr stream, halfStreamPtr snd, u_char *data, u_int dataLen) {
    streamDirection direction;

    if (snd == &stream->client)
        direction = STREAM_FROM_CLIENT;
    else
        direction = STREAM_FROM_SERVER;

    return dataLen;
}

/**
 * @brief Add data to halfStream receive buffer
 *
 * @param rcv halfStream to receive
 * @param data data to add
 * @param dataLen data length to add
 *
 * @return 0 if success else -1
 */
static int
add2buf (halfStreamPtr rcv, u_char *data, u_int dataLen) {
    int ret = 0;
    u_int toAlloc;

    if ((rcv->count - rcv->offset + dataLen) > rcv->bufSize) {
        if (rcv->rcvBuf == NULL) {
            if (dataLen < 2048)
                toAlloc = 4096;
            else
                toAlloc = dataLen * 2;

            rcv->rcvBuf = (u_char *) malloc (toAlloc);
            if (rcv->rcvBuf == NULL) {
                LOGE ("Alloc memory for halfStream rcvBuf error: %s.\n", strerror (errno));
                ret = -1;
            }
        } else {
            /*
             * If receive buffer size exceed TCP_RECEIVE_BUFFER_MAX_SIZE then
             * free it in case exhausting too much memory.
             */
            if (rcv->bufSize >= TCP_RECEIVE_BUFFER_MAX_SIZE) {
                LOGW ("Exceed maxium tcp stream receive buffer size.\n");
                free (rcv->rcvBuf);
                rcv->rcvBuf = NULL;
                ret = -1;
            } else {
                if (dataLen < rcv->bufSize)
                    toAlloc = rcv->bufSize * 2;
                else
                    toAlloc = rcv->bufSize + dataLen * 2;

                rcv->rcvBuf = (u_char *) realloc (rcv->rcvBuf, toAlloc);
                if (rcv->rcvBuf == NULL) {
                    LOGE ("Alloc memory for halfStream rcvBuf error: %s.\n", strerror (errno));
                    ret = -1;
                }
            }
        }

        if (ret < 0)
            rcv->bufSize = 0;
        else
            rcv->bufSize = toAlloc;
    }

    if (!ret)
        memcpy (rcv->rcvBuf + rcv->count - rcv->offset, data, dataLen);
    rcv->count += dataLen;
    return ret;
}

/**
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
 */
static void
addFromSkb (tcpStreamPtr stream,
            halfStreamPtr snd, halfStreamPtr rcv,
            u_char *data, u_int dataLen, u_int curSeq,
            u_char fin, u_char urg, u_short urgPtr) {
    int ret;
    u_int parseCount;
    u_int toCopy1, toCopy2;
    u_int lost = EXP_SEQ - curSeq;

    if (urg && !before (urgPtr, EXP_SEQ) && (!rcv->urgSeen || after (urgPtr, rcv->urgPtr))) {
        rcv->urgPtr = urgPtr;
        rcv->urgSeen = 1;
    }

    if (rcv->urgSeen && !before (rcv->urgPtr, EXP_SEQ) && before (rcv->urgPtr, curSeq + dataLen)) {
        /* Hanlde data before urgData */
        toCopy1 = rcv->urgPtr - EXP_SEQ;
        if (toCopy1 > 0) {
            ret = add2buf (rcv, data + lost, toCopy1);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset);
            }
        }

        rcv->urgSeen = 0;
        rcv->urgCount++;

        /* Handle data after urgData */
        toCopy2 = curSeq + dataLen - rcv->urgPtr - 1;
        if (toCopy2 > 0) {
            ret = add2buf (rcv, data + lost + toCopy1 + 1, toCopy2);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset);
            }
        }
    } else {
        if (dataLen - lost > 0) {
            ret = add2buf (rcv, data + lost, dataLen - lost);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf, rcv->count - rcv->offset);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,  rcv->count - rcv->offset);
            }
        }
    }
}

/**
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
 */
static void
tcpQueue (tcpStreamPtr stream,
          tcphdrPtr tcph,
          halfStreamPtr snd, halfStreamPtr rcv,
          u_char *data, u_int dataLen, timeValPtr tm) {
    u_int curSeq;
    skbuffPtr skbuf, entry;
    listHeadPtr pos, ppos, npos;

    curSeq = ntohl (tcph->seq);
    if (!after (curSeq, EXP_SEQ)) {
        if (after (curSeq + dataLen + tcph->fin, EXP_SEQ)) {
            addFromSkb (stream, snd, rcv,
                        (u_char *) data, dataLen, curSeq,
                        tcph->fin, tcph->urg, curSeq + ntohs (tcph->urgPtr) - 1);

            listForEachEntrySafe (entry, pos, npos, &rcv->head, node) {
                if (after (entry->seq, EXP_SEQ))
                    break;
                listDel (&entry->node);
                if (after (entry->seq + entry->len + entry->fin, EXP_SEQ)) {
                    addFromSkb (stream, snd, rcv,
                                entry->data, entry->len, entry->seq,
                                entry->fin, entry->urg, entry->seq + entry->urgPtr - 1);
                }
                free (entry->data);
                free (entry);
            }
        } else
            return;
    } else {
        /* Alloc new skbuff */
        skbuf = (skbuffPtr) malloc (sizeof (skbuff));
        if (skbuf == NULL) {
            LOGE ("Alloc memory for skbuff error: %s.\n", strerror (errno));
            return;
        }
        memset (skbuf, 0, sizeof (skbuff));
        skbuf->data = (u_char *) malloc (dataLen);
        if (skbuf->data == NULL) {
            LOGE ("Alloc memory for skbuff data error: %s.\n", strerror (errno));
            free (skbuf);
            return;
        }
        skbuf->len = dataLen;
        memcpy (skbuf->data, data, dataLen);
        skbuf->fin = tcph->fin;
        skbuf->seq = curSeq;
        skbuf->urg = tcph->urg;
        skbuf->urgPtr = ntohs (tcph->urgPtr);

        listForEachEntryReverseSafe (entry, pos, ppos, &rcv->head, node) {
            if (before (entry->seq, curSeq)) {
                listAdd (&skbuf->node, &entry->node);
                return;
            }
        }
        listAdd (&skbuf->node, &rcv->head);
    }
}

/**
 * @brief Tcp packet processor
 *
 * @param iph ip packet header
 */
void
tcpProcess (iphdrPtr iph) {
    u_int ipLen;
    tcphdrPtr tcph;
    u_int tcpLen;
    u_char *tcpData;
    u_int tcpDataLen;
    tcpStreamPtr stream;
    halfStreamPtr snd, rcv;
    streamDirection direction;

    ipLen = ntohs (iph->ipLen);
    tcph = (tcphdrPtr) ((u_char *) iph + iph->iphLen * 4);
    tcpLen = ipLen - iph->iphLen * 4;
    tcpData = (u_char *) tcph + tcph->doff * 4;
    tcpDataLen = ipLen - (iph->iphLen * 4) - (tcph->doff * 4);

    if (ipLen < (iph->iphLen * 4 + sizeof (tcphdr))) {
        LOGE ("Invalid tcp packet.\n");
        return;
    }

    if (tcpDataLen < 0) {
        LOGE ("Invalid tcp data length, ipLen: %u, tcpLen: %u, tcpHeaderLen: %u, tcpDataLen: %u.\n",
              ipLen, tcpLen, (tcph->doff * 4), tcpDataLen);
        return;
    }

    if (iph->ipSrc.s_addr == 0 || iph->ipDest.s_addr == 0) {
        LOGE ("Invalid ip address.\n");
        return;
    }

    stream = findTcpStream (tcph, iph, &direction);
    if (stream == NULL) {
        /* The first sync packet of tcp three handshakes */
        if (tcph->syn && !tcph->ack && !tcph->rst) {
            stream = addNewTcpStream (tcph, iph);
            if (stream == NULL) {
                LOGE ("Add new tcp stream error.\n");
                return;
            }
        }
        return;
    }

    if (direction == STREAM_FROM_CLIENT) {
        snd = &stream->client;
        rcv = &stream->server;
    } else {
        rcv = &stream->client;
        snd = &stream->server;
    }

    if (tcph->syn && tcph->ack &&
        direction == STREAM_FROM_SERVER &&
        stream->client.state == TCP_SYN_PKT_SENT &&
        stream->server.state == TCP_CONN_CLOSED) {
        /* The second packet of tcp three handshakes */
        if (stream->client.seq != ntohl (tcph->ackSeq)) {
            LOGW ("Wrong ack sequence number of syn/ack packet.\n");
            return;
        }

        stream->server.state = TCP_SYN_PKT_RECV;
        stream->server.seq = ntohl (tcph->seq) + 1;
        stream->server.firstDataSeq = stream->server.seq;
        stream->server.ackSeq = ntohl (tcph->ackSeq);
        return;
    }

    if (tcph->rst) {
        stream->client.state = TCP_CONN_CLOSED;
        stream->server.state = TCP_CONN_CLOSED;
        stream->state = STREAM_RESET;
        delTcpStreamFromHash (stream);
        return;
    }

    /* Filter retransmitted or out of window range packet */
    if (!(!tcpDataLen && ntohl (tcph->seq) == rcv->ackSeq) &&
        (before (ntohl (tcph->seq) + tcpDataLen, rcv->ackSeq) ||
         !before (ntohl (tcph->seq), (rcv->ackSeq + rcv->window * rcv->wscale)))) {
        return;
    }

    if (tcph->ack) {
        if (direction == STREAM_FROM_CLIENT &&
            stream->client.state == TCP_SYN_PKT_SENT &&
            stream->server.state == TCP_SYN_PKT_RECV &&
            ntohl (tcph->ackSeq) == stream->server.seq) {
            /* The last packet of tcp three handshakes */
            stream->client.state = TCP_CONN_ESTABLISHED;
            stream->server.state = TCP_CONN_ESTABLISHED;
            stream->state = STREAM_CONNECTED;
        }

        if (ntohl (tcph->ackSeq) > snd->ackSeq)
            snd->ackSeq = ntohl (tcph->ackSeq);
    }

    if (tcpDataLen + tcph->fin > 0) {
        if (tcpDataLen == 1)
            stream->tinyPkts++;
        tcpQueue (stream, tcph, snd, rcv, tcpData, tcpDataLen);
    }

    if (tcph->fin) {
        stream->client.state = TCP_CONN_CLOSED;
        stream->server.state = TCP_CONN_CLOSED;
        stream->state = STREAM_CLOSED;
        delTcpStreamFromHash (stream);
    }
}

/* Init tcp context */
int
initTcp (void *sock) {
    initListHead (&tcpStreamList);

    tcpStreamHashTable = hashNew (DEFAULT_TCP_STREAM_HASH_TABLE_SIZE);
    if (tcpStreamHashTable == NULL)
        return -1;

    return 0;
}

/* Destroy tcp context */
void
destroyTcp (void) {
    hashDestroy (tcpStreamHashTable);
    tcpStreamHashTable = NULL;
}
