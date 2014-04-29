#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <zlib.h>
#include <jansson.h>
#include "util.h"
#include "log.h"
#include "byte-order.h"
#include "mysql-analyzer.h"

#define PKT_WRONG_TYPE    0
#define PKT_HANDLED       1

/* Current timestamp */
static __thread timeValPtr currTime;
/* Current session done indicator */
static __thread int currSessionDone;
/* Current mysql session detail */
static __thread mysqlSessionDetailPtr currSessionDetail;

/* Mysql parser state map */
static mysqlStateEvents mysqlStateMap [MYSQL_STATES_NUM];

static uint64_t
lenencInt (const u_char *pkt, int *len) {
    unsigned int prefix;
    int encLen;

    prefix = (unsigned int) *pkt;
    if (prefix < 0xFB) {
        *len = 1;
        return (uint64_t) prefix;
    } else if (prefix == 0xFC) {
        *len = 3;
        return (uint64_t) G2 (pkt + 1);
    } else if (prefix == 0xFD) {
        *len = 4;
        return (uint64_t) G3 (pkt + 1);
    } else if (prefix == 0xFE) {
        *len = 9;
        return (uint64_t) G8 (pkt + 1);
    } else {
        *len = 0;
        return 0;
    }
}

static int
pktHandshakeServer (mysqlParserStatePtr parser, const u_char *payload,
                    int payloadLen, int fromClient) {
    int caps;
    int srvVer;
    short status;
    const u_char *salt1;
    const u_char *salt2;
    const u_char *pkt = payload;

    if (fromClient || parser->seqId != 0)
        return PKT_WRONG_TYPE;

    /* Only support v10 protocol */
    if (*pkt != 0x0A)
        return PKT_WRONG_TYPE;

    /* Proto version */
    parser->protoVer = (int) *pkt;
    pkt += 1;
    /* Server version, example: 4.1.1 ........ */
    parser->serverVer = strdup (pkt);
    pkt += strlen (pkt) + 1;
    srvVer = (parser->serverVer [0] - '0') * 10 + (parser->serverVer [2] - '0');
    if (srvVer >= 41)
        parser->cliProtoV41 = 1;
    else
        parser->cliProtoV41 = 0;
    /* Connection id */
    parser->conId = G4 (pkt);
    pkt += 4;
    /* 8 bytes auth plugin data part 1 + 1 byte 0 padding */
    salt1 = pkt;
    pkt += 9;
    /* Capability flags */
    caps = *pkt;
    pkt += 2;
    /* Character set */
    pkt += 1;
    /* Status flags */
    status = G2 (pkt);
    /* 2  bytes for status, 13 bytes for zero-byte padding */
    pkt += 15;
    salt2 = pkt;

    LOGD ("Cli<------Server: init handshake packet, server version:%s, connection id:%d.\n",
          parser->serverVer, parser->conId);
    return PKT_HANDLED;
}

static int
pktHandshakeClient (mysqlParserStatePtr parser, const u_char *payload,
                    int payloadLen, int fromClient) {
    int caps;
    u_char cs;
    const u_char *db;
    int passLen;
    u_char pass [128] = {0};
    const u_char *pkt = payload;

    if (!fromClient || parser->seqId != 1)
        return PKT_WRONG_TYPE;

    /* Protocol version before 4.1 */
    if (parser->cliProtoV41) {
        /* Capability flags */
        caps = G4 (pkt);
        pkt += 4;
        /* Max packet size */
        parser->maxPktSize = G4(pkt);
        pkt += 4;
        /* Character set */
        cs = *pkt;
        /* Character set byte + reserved 23 bytes */
        pkt += 24;
        /* User name */
        parser->userName = strdup (pkt);
        pkt += strlen (pkt) + 1;
        /* Password */
        passLen = ((caps & CLIENT_SECURE_CONNECTION) ? *pkt++ : strlen (pkt));
        if (passLen >= sizeof (pass))
            memcpy (pass, pkt, sizeof (pass) - 1);
        else
            memcpy (pass, pkt, passLen);
        pkt += passLen;
        db = ((caps & CLIENT_CONNECT_WITH_DB) ? pkt : NULL);
    } else {
        /* Capability flags */
        caps = G2 (pkt);
        pkt += 2;
        /* Max packet size */
        parser->maxPktSize = G3 (pkt);
        pkt += 3;
        /* User name */
        parser->userName = strdup (pkt);
        pkt += strlen (pkt) + 1;
        /* DB name */
        db = NULL;
    }

    parser->cliCaps = caps;
    parser->doSSL = ((caps & CLIENT_SSL) ? 1 : 0);
    parser->doCompress = ((caps & CLIENT_COMPRESS) ? 1 : 0);

    LOGD ("Cli------>Server: client handshake packet, user name: %s, doCompress: %s.\n",
          parser->userName, parser->doCompress ? "Yes" : "No");
    return PKT_HANDLED;
}

static int
pktSecureAuth (mysqlParserStatePtr parser, const u_char *payload,
               int payloadLen, int fromClient) {
    if (fromClient)
        LOGD ("Cli------>Server: Secure authentication.\n");
    else
        LOGD ("Cli<------Server: Secure authentication.\n");

    return PKT_HANDLED;
}

static void
resetMysqlSessionDetail (mysqlSessionDetailPtr msd);

static int
pktOkOrError (mysqlParserStatePtr parser, const u_char *payload,
              int payloadLen, int fromClient) {
    int len;
    uint64_t rows;
    uint64_t insertId;
    int status;
    int warn;
    const u_char *msg;
    uint16_t errCode;
    u_char sqlState [6] = {0};
    u_char errMsg [512] = {0};
    const u_char *pkt = payload;

    if ((*pkt == 0x00)) {
        /* Mysql ok packet */
        if ((!parser->cliProtoV41 && (payloadLen < 5)) ||
            (parser->cliProtoV41 && (payloadLen < 7)))
            return PKT_WRONG_TYPE;

        /* Affected rows */
        rows = lenencInt (pkt, &len);
        pkt += len;
        /* Last insert id */
        insertId = lenencInt (pkt, &len);
        pkt += len;

        if (parser->cliProtoV41) {
            status = G2 (pkt);
            pkt += 2;
            warn = G2 (pkt);
            pkt += 2;
        } else if (parser->cliCaps & CLIENT_TRANSACTIONS) {
            status = G2 (pkt);
            pkt += 2;
            warn = 0;
        } else {
            status = 0;
            warn = 0;
        }

        /* Message */
        if ((pkt - payload) < payloadLen)
            msg = pkt;

        /*
         * For mysql handshake, COM_QUIT and COM_PING, there is no request
         * statement and session breakdown.
         */
        if (currSessionDetail->reqStmt) {
            currSessionDetail->state = MYSQL_RESPONSE_OK;
            currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
            currSessionDone = 1;
        } else
            LOGD ("Cli<------Server: OK packet.\n");

        return PKT_HANDLED;
    } else if (*pkt == 0xFF) {
        /* Mysql error packet */
        pkt++;
        errCode = G2 (pkt);
        pkt += 2;
        if (parser->cliProtoV41) {
            /* |#-1 byte|sql state 5 bytes| */
            pkt++;
            memcpy (sqlState, pkt, 5);
            pkt += 5;

            /* V41 error message format: |0xFF-1|errno-2|#-1|sqlState-5|errMsg-EOF| */
            if ((payloadLen - 9) >= sizeof (errMsg))
                memcpy (errMsg, pkt, sizeof (errMsg) - 1);
            else
                memcpy (errMsg, pkt, (payloadLen - 9));
        } else {
            /* V40 error message format: |0xFF-1|errno-2|errMsg-EOF| */
            if ((payloadLen - 3) >= sizeof (errMsg))
                memcpy (errMsg, pkt, sizeof (errMsg) - 1);
            else
                memcpy (errMsg, pkt, (payloadLen - 3));
        }

        /*
         * For mysql handshake, COM_QUIT and COM_PING, there is no request
         * statement and session breakdown.
         */
        if (currSessionDetail->reqStmt) {
            currSessionDetail->state = MYSQL_RESPONSE_ERROR;
            currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
            currSessionDetail->errCode = errCode;
            if (*sqlState)
                currSessionDetail->sqlState = atoi (sqlState);
            currSessionDetail->errMsg = strdup (errMsg);
            currSessionDone = 1;
        } else {
            resetMysqlSessionDetail (currSessionDetail);
            LOGD ("Cli<------Server: ERROR packet, error code: %d, error msg: %s.\n", errCode, errMsg);
        }

        return PKT_HANDLED;
    } else
        return PKT_WRONG_TYPE;
}

static int
pktEnd (mysqlParserStatePtr parser, const u_char *payload,
        int payloadLen, int fromClient) {
    uint16_t warn = 0;
    uint16_t status = 0;
    const u_char *pkt = payload;

    if (*pkt != 0xFE ||
        (parser->cliProtoV41 && (payloadLen != 5)) ||
        (!parser->cliProtoV41 && (payloadLen != 1)))
        return PKT_WRONG_TYPE;

    if (parser->cliProtoV41) {
        pkt++;
        warn = G2(pkt);
        pkt += 2;
        status = G2(pkt);

        if (((parser->state == STATE_TXT_ROW) || (parser->state == STATE_BIN_ROW)) &&
            (status & SERVER_MORE_RESULTS_EXISTS) &&
            parser->event != EVENT_END_MULTI_RESULT)
            return PKT_WRONG_TYPE;
    }

    if ((parser->state == STATE_FIELD_LIST) ||
        (parser->state == STATE_TXT_ROW) ||
        (parser->state == STATE_BIN_ROW) ||
        (parser->state == STATE_END)) {
        currSessionDetail->state = MYSQL_RESPONSE_OK;
        currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
        currSessionDone = 1;
    }

    if (parser->state == STATE_SECURE_AUTH && fromClient)
        LOGD ("Cli------>Server: END packet.\n");

    return PKT_HANDLED;
}

static int
pktComX (mysqlParserStatePtr parser, const u_char *payload,
         int payloadLen, int fromClient) {
    int pktEventMatch;
    const u_char *pkt = payload;

    if (payloadLen > 1 || *pkt >= COM_UNKNOWN)
        return PKT_WRONG_TYPE;

    // Does pkt match event?
    switch (parser->event) {
        case COM_QUIT:
            pktEventMatch = MATCH (*pkt, COM_QUIT);
            break;

        case COM_PING:
            pktEventMatch = MATCH (*pkt, COM_PING);
            break;

        case COM_STATISTICS:
            pktEventMatch = MATCH (*pkt, COM_STATISTICS);
            break;

        case COM_DEBUG:
            pktEventMatch = MATCH (*pkt, COM_DEBUG);
            break;

        case COM_DAEMON:
            pktEventMatch = MATCH (*pkt, COM_DAEMON);
            break;

        case COM_RESET_CONNECTION:
            pktEventMatch = MATCH (*pkt, COM_RESET_CONNECTION);
            break;

        default:
            pktEventMatch = 0;
            break;
    }

    if (pktEventMatch == 0)
        return PKT_WRONG_TYPE;

    /* For COM_QUIT and COM_PING, doesn't do statistics */
    if (MATCH (*pkt, COM_QUIT) || MATCH (*pkt, COM_PING))
        LOGD ("Cli------>Server: %s\n", mysqlCommandName [*pkt]);
    else {
        currSessionDetail->reqStmt = strdup (mysqlCommandName [*pkt]);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;
    }

    return PKT_HANDLED;
}

static int
pktComXString (mysqlParserStatePtr parser, const u_char *payload,
               int payloadLen, int fromClient) {
    int pktEventMatch;
    int argsLen;
    u_char com [4096] = {0};
    const u_char *pkt = payload;

    if (payloadLen == 1 || *pkt >= COM_UNKNOWN)
        return PKT_WRONG_TYPE;

    switch (parser->event) {
        case COM_QUERY:
            pktEventMatch = MATCH (*pkt, COM_QUERY);
            break;

        case COM_FIELD_LIST:
            pktEventMatch = MATCH (*pkt, COM_FIELD_LIST);
            break;

        case COM_INIT_DB:
            pktEventMatch = MATCH (*pkt, COM_INIT_DB);
            break;

        case COM_CREATE_DB:
            pktEventMatch = MATCH (*pkt, COM_CREATE_DB);
            break;

        case COM_DROP_DB:
            pktEventMatch = MATCH (*pkt, COM_DROP_DB);
            break;

        case COM_STMT_PREPARE:
            pktEventMatch = MATCH (*pkt, COM_STMT_PREPARE);
            break;

        default:
            pktEventMatch = 0;
            break;
    }

    if (pktEventMatch == 0)
        return PKT_WRONG_TYPE;

    snprintf (com, sizeof (com) - 1, "%s:", mysqlCommandName [*pkt]);
    argsLen = payloadLen - 1;
    if (argsLen >= sizeof (com) - strlen (com))
        argsLen = sizeof (com) - strlen (com) - 1;
    memcpy (com + strlen (com), (pkt + 1), argsLen);

    currSessionDetail->reqStmt = strdup (com);
    currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

    return PKT_HANDLED;
}

static int
pktComXInt (mysqlParserStatePtr parser, const u_char *payload,
            int payloadLen, int fromClient) {
    int pktEventMatch;
    u_char com [64] = {0};
    const u_char *pkt = payload;

    if (payloadLen == 1 || payloadLen > 5)
        return PKT_WRONG_TYPE;

    switch(parser->event) {
        case COM_PROCESS_KILL:
            pktEventMatch = MATCH (*pkt, COM_PROCESS_KILL);
            break;

        case COM_REFRESH:
            pktEventMatch = MATCH (*pkt, COM_REFRESH);
            break;

        case COM_STMT_CLOSE:
            pktEventMatch = MATCH (*pkt, COM_STMT_CLOSE);
            break;

        default:
            pktEventMatch = 0;
            break;
    }

    if (pktEventMatch == 0)
        return PKT_WRONG_TYPE;

    snprintf (com, sizeof (com) - 1, "%s:%d", mysqlCommandName [*pkt], G4 (pkt + 1));

    currSessionDetail->reqStmt = strdup (com);
    currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

    return PKT_HANDLED;
}

static int
pktStatistics (mysqlParserStatePtr parser, const u_char *payload,
               int payloadLen, int fromClient) {
    u_char stats [4096];
    const u_char *pkt = payload;

    if (payloadLen == 1)
        return PKT_WRONG_TYPE;

    if (payloadLen >= sizeof (stats))
        payloadLen = sizeof (stats) - 1;
    memcpy (stats, pkt, payloadLen);

    currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
    currSessionDetail->state = MYSQL_RESPONSE_OK;
    currSessionDone = 1;

    return PKT_HANDLED;
}

static int
pktNFields (mysqlParserStatePtr parser, const u_char *payload,
            int payloadLen, int fromClient) {
    int len;
    uint64_t count;
    const u_char *pkt = payload;

    count = lenencInt (pkt, &len);
    if ((len != payloadLen) || (count == 0))
        return PKT_WRONG_TYPE;

    return PKT_HANDLED;
}

static int
pktField (mysqlParserStatePtr parser, const u_char *payload,
          int payloadLen, int fromClient) {
    const u_char *pkt = payload;

    if (*pkt == 0xFE)
        return PKT_WRONG_TYPE;

    return PKT_HANDLED;
}

static int
pktRow (mysqlParserStatePtr parser, const u_char *payload,
        int payloadLen, int fromClient) {
    const u_char *pkt = payload;

    /* EOF packet */
    if ((*pkt == 0xFE) && ((payloadLen == 1) || (payloadLen == 5)))
        return PKT_WRONG_TYPE;

    return PKT_HANDLED;
}

static int
pktBinaryRow (mysqlParserStatePtr parser, const u_char *payload,
              int payloadLen, int fromClient) {
    const u_char *pkt = payload;

    if (*pkt != 0x00)
        return PKT_WRONG_TYPE;

    return PKT_HANDLED;
}

static int
pktStmtMeta (mysqlParserStatePtr parser, const u_char *payload,
             int payloadLen, int fromClient) {
    const u_char *pkt = payload;

    if (payloadLen != 12)
        return PKT_WRONG_TYPE;

    return PKT_HANDLED;
}

static int
pktStmtExecute (mysqlParserStatePtr parser, const u_char *payload,
                int payloadLen, int fromClient) {
    u_int   stmtId;
    u_int   iterationCount;
    u_char com [128] = {0};
    const u_char *pkt = payload;

    if (!MATCH (*pkt, COM_STMT_EXECUTE))
        return PKT_WRONG_TYPE;

    pkt++;
    stmtId = G4 (pkt);
    pkt += 5;
    iterationCount = G4 (pkt);

    snprintf(com, sizeof (com) - 1, "%s: id-%d, iterationCount-%d",
             mysqlCommandName [*pkt], stmtId, iterationCount);

    currSessionDetail->reqStmt = strdup (com);
    currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

    return PKT_HANDLED;
}

static int
sqlParse (mysqlParserStatePtr parser, const u_char *data, int dataLen, int fromClient) {
    int ret;
    int parseCount = 0;
    int parseLeft = dataLen;
    const char *pkt;
    int pktLen;
    mysqlHeaderPtr hdr;
    int payloadLen;
    const char *payload;
    int event;
    int numEvents;
    mysqlHandler handler;

    while (1) {
        if (parseLeft < MYSQL_HEADER_SIZE)
            break;

        /* Next mysql packet begin */
        pkt = data + parseCount;
        hdr = (mysqlHeaderPtr) pkt;
        payloadLen = hdr->payloadLen;
        parser->seqId = hdr->pktId;
        payload = pkt + MYSQL_HEADER_SIZE;
        pktLen = MYSQL_HEADER_SIZE + payloadLen;

        /* If packet is not complete, return and wait for further processing */
        if (parseLeft < pktLen)
            break;

        if (payloadLen) {
            for (event = 0; event < mysqlStateMap [parser->state].numEvents; event++) {
                handler = mysqlStateMap [parser->state].handler [event];
                parser->event = mysqlStateMap [parser->state].event [event];

                if ((*handler) (parser, payload, payloadLen, fromClient) == PKT_HANDLED) {
                    parser->state = mysqlStateMap [parser->state].nextState [event];
                    break;
                } else
                    handler = NULL;
            }
            if (handler == NULL)
                LOGD ("has no proper handler.\n");
        }

        parseCount += pktLen;
        parseLeft -= pktLen;
    }

    return parseCount;
}

static int
mysqlParserExecute (mysqlParserStatePtr parser, const u_char *data, int dataLen, int fromClient) {
    int parseCount = 0;
    int parseLeft = dataLen;
    const char *compPkt;
    char *uncompPkt;
    int pktLen;
    int compPktLen;
    mysqlCompHeaderPtr compHdr;
    int payloadLen;
    int compPayloadLen;
    uLong uncompPayloadLen;
    const char *compPayload;

    if (parser->doSSL) {
        LOGD ("Doesn't support mysql with ssl");
        return dataLen;
    }

    /* Mysql packet after handshake  */
    if ((parser->state != STATE_NOT_CONNECTED) &&
        (parser->state != STATE_CLIENT_HANDSHAKE) &&
        (parser->state != STATE_SECURE_AUTH)) {
        /* For incomplete mysql packet, return directly */
        if ((parser->doCompress && (parseLeft < MYSQL_COMPRESSED_HEADER_SIZE)) ||
            (parseLeft < MYSQL_COMPRESSED_HEADER_SIZE))
            return 0;

        /* New mysql request */
        if (fromClient) {
            /*
             * For every mysql request has only one packet, so, every packet from client
             * thought as a new mysql request. To make sure mysql parser's state is correct
             * (some conditions like packets dropping or parsing error can cause parser's
             * state uncorrect), we need to set parser's state to STATE_SLEhEP explicitly for
             * every new client request and reset currSessionDetail.
             */
            parser->state = STATE_SLEEP;
            resetMysqlSessionDetail (currSessionDetail);
            currSessionDetail->state = MYSQL_REQUEST_BEGIN;
            currSessionDetail->reqTime = timeVal2MilliSecond (currTime);
        } else if (!fromClient && (currSessionDetail->state == MYSQL_REQUEST_COMPLETE)) {
            currSessionDetail->state = MYSQL_RESPONSE_BEGIN;
            currSessionDetail->respTimeBegin = timeVal2MilliSecond (currTime);
        }

        /* Compressed mysql packets */
        if (parser->doCompress) {
            while (1) {
                /* Incomplete header of compressed packet */
                if (parseLeft < MYSQL_COMPRESSED_HEADER_SIZE)
                    break;

                compPkt = (u_char *) data + parseCount;
                compHdr = (mysqlCompHeaderPtr) compPkt;
                payloadLen = compHdr->payloadLen;
                compPayloadLen = compHdr->compPayloadLen;
                compPayload = (u_char *) (compPkt + MYSQL_COMPRESSED_HEADER_SIZE);
                compPktLen = MYSQL_COMPRESSED_HEADER_SIZE + compPayloadLen;

                /* Incomplete compressed packet */
                if (parseLeft < compPktLen)
                    break;

                if (payloadLen) {
                    /* Compressed pkt */
                    uncompPkt = malloc (payloadLen);
                    if (uncompPkt == NULL) {
                        LOGE ("Alloc memory for uncompPkt error: %s.\n", strerror (errno));
                        break;
                    }

                    uncompPayloadLen = payloadLen;
                    if (uncompress (uncompPkt, &uncompPayloadLen, compPayload, compPayloadLen) != Z_OK) {
                        LOGE ("Uncompress packet error.\n");
                        free (uncompPkt);
                        uncompPkt = NULL;
                        parseCount += compPktLen;
                        parseLeft -= compPktLen;
                        continue;
                    }
                } else {
                    uncompPkt = (u_char *) compPayload;
                    uncompPayloadLen = compPayloadLen;
                }

                /* Real sql parse */
                sqlParse (parser, uncompPkt, uncompPayloadLen, fromClient);
                /* Free uncompressed packet buffer if any */
                if (payloadLen) {
                    free (uncompPkt);
                    uncompPkt = NULL;
                }

                parseCount += compPktLen;
                parseLeft -= compPktLen;
            }
        } else  /* Non Compressed mysql packets */
            parseCount = sqlParse (parser, data, dataLen, fromClient);

        if (fromClient)
            currSessionDetail->reqSize += parseCount;
        else
            currSessionDetail->respSize += parseCount;
    } else  /* Mysql handshake packets */
        parseCount = sqlParse (parser, data, dataLen, fromClient);

    return parseCount;
}

static int
initMysqlProto (void) {
    /* Init mysql state map */
    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_NOT_CONNECTED].numEvents = 1;
    mysqlStateMap [STATE_NOT_CONNECTED].event [0] = EVENT_SERVER_HANDSHAKE;
    mysqlStateMap [STATE_NOT_CONNECTED].nextState [0] = STATE_CLIENT_HANDSHAKE;
    mysqlStateMap [STATE_NOT_CONNECTED].handler [0] = &pktHandshakeServer;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_CLIENT_HANDSHAKE].numEvents = 1;
    mysqlStateMap [STATE_CLIENT_HANDSHAKE].event [0] = EVENT_CLIENT_HANDSHAKE;
    mysqlStateMap [STATE_CLIENT_HANDSHAKE].nextState [0] = STATE_SECURE_AUTH;
    mysqlStateMap [STATE_CLIENT_HANDSHAKE].handler [0] = &pktHandshakeClient;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_SECURE_AUTH].numEvents = 2;
    mysqlStateMap [STATE_SECURE_AUTH].event [0] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_SECURE_AUTH].nextState [0] = STATE_SLEEP;
    mysqlStateMap [STATE_SECURE_AUTH].handler [0] = &pktOkOrError;

    mysqlStateMap [STATE_SECURE_AUTH].event [1] = EVENT_SECURE_AUTH;
    mysqlStateMap [STATE_SECURE_AUTH].nextState [1] = STATE_SECURE_AUTH;
    mysqlStateMap [STATE_SECURE_AUTH].handler [1] = &pktSecureAuth;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_SLEEP].numEvents = 15;
    mysqlStateMap [STATE_SLEEP].event [0] = COM_QUERY;
    mysqlStateMap [STATE_SLEEP].nextState [0] = STATE_TXT_RS;
    mysqlStateMap [STATE_SLEEP].handler [0] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [1] = COM_INIT_DB;
    mysqlStateMap [STATE_SLEEP].nextState [1] = STATE_OK_OR_ERROR;
    mysqlStateMap [STATE_SLEEP].handler [1] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [2] = COM_FIELD_LIST;
    mysqlStateMap [STATE_SLEEP].nextState [2] = STATE_FIELD_LIST;
    mysqlStateMap [STATE_SLEEP].handler [2] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [3] = COM_CREATE_DB;
    mysqlStateMap [STATE_SLEEP].nextState [3] = STATE_OK_OR_ERROR;
    mysqlStateMap [STATE_SLEEP].handler [3] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [4] = COM_DROP_DB;
    mysqlStateMap [STATE_SLEEP].nextState [4] = STATE_OK_OR_ERROR;
    mysqlStateMap [STATE_SLEEP].handler [4] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [5] = COM_PROCESS_KILL;
    mysqlStateMap [STATE_SLEEP].nextState [5] = STATE_OK_OR_ERROR;
    mysqlStateMap [STATE_SLEEP].handler [5] = &pktComXInt;

    mysqlStateMap [STATE_SLEEP].event [6] = COM_REFRESH;
    mysqlStateMap [STATE_SLEEP].nextState [6] = STATE_OK_OR_ERROR;
    mysqlStateMap [STATE_SLEEP].handler [6] = &pktComXInt;

    mysqlStateMap [STATE_SLEEP].event [7] = COM_SHUTDOWN;
    mysqlStateMap [STATE_SLEEP].nextState [7] = STATE_END;
    mysqlStateMap [STATE_SLEEP].handler [7] = &pktEnd;

    mysqlStateMap [STATE_SLEEP].event [8] = COM_DEBUG;
    mysqlStateMap [STATE_SLEEP].nextState [8] = STATE_END;
    mysqlStateMap [STATE_SLEEP].handler [8] = &pktComX;

    mysqlStateMap [STATE_SLEEP].event [9] = COM_STATISTICS;
    mysqlStateMap [STATE_SLEEP].nextState [9] = STATE_STATISTICS;
    mysqlStateMap [STATE_SLEEP].handler [9] = &pktComX;

    mysqlStateMap [STATE_SLEEP].event [10] = COM_PING;
    mysqlStateMap [STATE_SLEEP].nextState [10] = STATE_PONG;
    mysqlStateMap [STATE_SLEEP].handler [10] = &pktComX;

    mysqlStateMap [STATE_SLEEP].event [11] = COM_QUIT;
    mysqlStateMap [STATE_SLEEP].nextState [11] = STATE_NOT_CONNECTED;
    mysqlStateMap [STATE_SLEEP].handler [11] = &pktComX;

    mysqlStateMap [STATE_SLEEP].event [12] = COM_STMT_PREPARE;
    mysqlStateMap [STATE_SLEEP].nextState [12] = STATE_STMT_META;
    mysqlStateMap [STATE_SLEEP].handler [12] = &pktComXString;

    mysqlStateMap [STATE_SLEEP].event [13] = COM_STMT_EXECUTE;
    mysqlStateMap [STATE_SLEEP].nextState [13] = STATE_BIN_RS;
    mysqlStateMap [STATE_SLEEP].handler [13] = &pktStmtExecute;

    mysqlStateMap [STATE_SLEEP].event [14] = COM_STMT_CLOSE;
    mysqlStateMap [STATE_SLEEP].nextState [14] = STATE_SLEEP;
    mysqlStateMap [STATE_SLEEP].handler [14] = &pktComXInt;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_PONG].numEvents = 1;
    mysqlStateMap [STATE_PONG].event [0] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_PONG].nextState [0] = STATE_SLEEP;
    mysqlStateMap [STATE_PONG].handler [0] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_OK_OR_ERROR].numEvents = 1;
    mysqlStateMap [STATE_OK_OR_ERROR].event [0] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_OK_OR_ERROR].nextState [0] = STATE_SLEEP;
    mysqlStateMap [STATE_OK_OR_ERROR].handler [0] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_STATISTICS].numEvents = 1;
    mysqlStateMap [STATE_STATISTICS].event [0] = EVENT_STATISTICS;
    mysqlStateMap [STATE_STATISTICS].nextState [0] = STATE_SLEEP;
    mysqlStateMap [STATE_STATISTICS].handler [0] = &pktStatistics;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_FIELD_LIST].numEvents = 2;
    mysqlStateMap [STATE_FIELD_LIST].event [0] = EVENT_FL_FIELD;
    mysqlStateMap [STATE_FIELD_LIST].nextState [0] = STATE_FIELD_LIST;
    mysqlStateMap [STATE_FIELD_LIST].handler [0] = &pktField;

    mysqlStateMap [STATE_FIELD_LIST].event [1] = EVENT_END;
    mysqlStateMap [STATE_FIELD_LIST].nextState [1] = STATE_SLEEP;
    mysqlStateMap [STATE_FIELD_LIST].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_FIELD].numEvents = 2;
    mysqlStateMap [STATE_FIELD].event [0] = EVENT_FIELD ;
    mysqlStateMap [STATE_FIELD].nextState [0] = STATE_FIELD;
    mysqlStateMap [STATE_FIELD].handler [0] = &pktField;

    mysqlStateMap [STATE_FIELD].event [1] = EVENT_END;
    mysqlStateMap [STATE_FIELD].nextState [1] = STATE_TXT_ROW;
    mysqlStateMap [STATE_FIELD].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_FIELD_BIN].numEvents = 2;
    mysqlStateMap [STATE_FIELD_BIN].event [0] = EVENT_FIELD_BIN;
    mysqlStateMap [STATE_FIELD_BIN].nextState [0] = STATE_FIELD_BIN;
    mysqlStateMap [STATE_FIELD_BIN].handler [0] = &pktField;

    mysqlStateMap [STATE_FIELD_BIN].event [1] = EVENT_END;
    mysqlStateMap [STATE_FIELD_BIN].nextState [1] = STATE_BIN_ROW;
    mysqlStateMap [STATE_FIELD_BIN].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_TXT_RS].numEvents = 2;
    mysqlStateMap [STATE_TXT_RS].event [0] = EVENT_NUM_FIELDS;
    mysqlStateMap [STATE_TXT_RS].nextState [0] = STATE_FIELD;
    mysqlStateMap [STATE_TXT_RS].handler [0] = &pktNFields;

    mysqlStateMap [STATE_TXT_RS].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_TXT_RS].nextState [1] = STATE_SLEEP;
    mysqlStateMap [STATE_TXT_RS].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_BIN_RS].numEvents = 2;
    mysqlStateMap [STATE_BIN_RS].event [0] = EVENT_NUM_FIELDS_BIN;
    mysqlStateMap [STATE_BIN_RS].nextState [0] = STATE_FIELD_BIN;
    mysqlStateMap [STATE_BIN_RS].handler [0] = &pktNFields;

    mysqlStateMap [STATE_BIN_RS].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_BIN_RS].nextState [1] = STATE_SLEEP;
    mysqlStateMap [STATE_BIN_RS].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_END].numEvents = 1;
    mysqlStateMap [STATE_END].event [0] = EVENT_END;
    mysqlStateMap [STATE_END].nextState [0] = STATE_SLEEP;
    mysqlStateMap [STATE_END].handler [0] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_TXT_ROW].numEvents = 4;
    mysqlStateMap [STATE_TXT_ROW].event [0] = EVENT_ROW;
    mysqlStateMap [STATE_TXT_ROW].nextState [0] = STATE_TXT_ROW;
    mysqlStateMap [STATE_TXT_ROW].handler [0] = &pktRow;

    mysqlStateMap [STATE_TXT_ROW].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_TXT_ROW].nextState [1] = STATE_SLEEP;
    mysqlStateMap [STATE_TXT_ROW].handler [1] = &pktOkOrError;

    mysqlStateMap [STATE_TXT_ROW].event [2] = EVENT_END;
    mysqlStateMap [STATE_TXT_ROW].nextState [2] = STATE_SLEEP;
    mysqlStateMap [STATE_TXT_ROW].handler [2] = &pktEnd;

    mysqlStateMap [STATE_TXT_ROW].event [3] = EVENT_END_MULTI_RESULT;
    mysqlStateMap [STATE_TXT_ROW].nextState [3] = STATE_TXT_RS;
    mysqlStateMap [STATE_TXT_ROW].handler [3] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_BIN_ROW].numEvents = 3;
    mysqlStateMap [STATE_BIN_ROW].event [0] = EVENT_ROW;
    mysqlStateMap [STATE_BIN_ROW].nextState [0] = STATE_BIN_ROW;
    mysqlStateMap [STATE_BIN_ROW].handler [0] = &pktBinaryRow;

    mysqlStateMap [STATE_BIN_ROW].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateMap [STATE_BIN_ROW].nextState [1] = STATE_SLEEP;
    mysqlStateMap [STATE_BIN_ROW].handler [1] = &pktOkOrError;

    mysqlStateMap [STATE_BIN_ROW].event [2] = EVENT_END;
    mysqlStateMap [STATE_BIN_ROW].nextState [2] = STATE_SLEEP;
    mysqlStateMap [STATE_BIN_ROW].handler [2] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_STMT_META].numEvents = 1;
    mysqlStateMap [STATE_STMT_META].event [0] = EVENT_STMT_META;
    mysqlStateMap [STATE_STMT_META].nextState [0] = STATE_STMT_PARAM;
    mysqlStateMap [STATE_STMT_META].handler [0] = &pktStmtMeta;

    /* -------------------------------------------------------------- */
    mysqlStateMap [STATE_STMT_PARAM].numEvents = 2;
    mysqlStateMap [STATE_STMT_PARAM].event [0] = EVENT_STMT_PARAM;
    mysqlStateMap [STATE_STMT_PARAM].nextState [0] = STATE_STMT_PARAM;
    mysqlStateMap [STATE_STMT_PARAM].handler [0] = &pktField;

    mysqlStateMap [STATE_STMT_PARAM].event [1] = EVENT_END;
    mysqlStateMap [STATE_STMT_PARAM].nextState [1] = STATE_FIELD_LIST;
    mysqlStateMap [STATE_STMT_PARAM].handler [1] = &pktEnd;

    return 0;
}

static void
destroyMysqlProto (void) {
    return;
}

static int
initMysqlParser (mysqlParserStatePtr parser) {
    parser->protoVer = 0;
    parser->serverVer = NULL;
    parser->cliCaps = 0;
    parser->cliProtoV41 = 0;
    parser->conId = 0;
    parser->maxPktSize = 0;
    parser->doCompress = 0;
    parser->doSSL = 0;
    parser->userName = NULL;
    parser->seqId = 0;
    parser->state = STATE_NOT_CONNECTED;
    parser->event = EVENT_UNKNOWN;

    return 0;
}

static void
destroyMysqlParser (mysqlParserStatePtr parser) {
    if (parser == NULL)
        return;

    if (parser->serverVer)
        free (parser->serverVer);
    if (parser->userName)
        free (parser->userName);
}

static void *
newMysqlSessionDetail (void) {
    int ret;
    mysqlSessionDetailPtr msd;

    msd = (mysqlSessionDetailPtr) malloc (sizeof (mysqlSessionDetail));
    if (msd) {
        ret = initMysqlParser (&msd->parser);
        if (ret < 0) {
            free (msd);
            return NULL;
        }
        msd->reqStmt = NULL;
        msd->state = MYSQL_INIT;
        msd->errCode = 0;
        msd->sqlState = 0;
        msd->errMsg = NULL;
        msd->reqSize = 0;
        msd->respSize = 0;
        msd->reqTime = 0;
        msd->respTimeBegin = 0;
        msd->respTimeEnd = 0;
        return msd;
    } else
        return NULL;
}

/* Reset mysql session detail */
static void
resetMysqlSessionDetail (mysqlSessionDetailPtr msd) {
    free (msd->reqStmt);
    msd->reqStmt = NULL;
    msd->state = MYSQL_INIT;
    msd->errCode = 0;
    msd->sqlState = 0;
    free (msd->errMsg);
    msd->errMsg = NULL;
    msd->reqSize = 0;
    msd->respSize = 0;
    msd->reqTime = 0;
    msd->respTimeBegin = 0;
    msd->respTimeEnd = 0;
}

static void
freeMysqlSessionDetail (void *sd) {
    mysqlSessionDetailPtr msd;

    if (sd == NULL)
        return;

    msd = (mysqlSessionDetailPtr) sd;
    /* Clean mysql parser context */
    destroyMysqlParser (&msd->parser);
    free (msd->reqStmt);
    free (msd->errMsg);

    free (msd);
}

static void *
newMysqlSessionBreakdown (void) {
    mysqlSessionBreakdownPtr msbd;

    msbd = (mysqlSessionBreakdownPtr) malloc (sizeof (mysqlSessionBreakdown));
    if (msbd) {
        msbd->serverVer = NULL;
        msbd->userName = NULL;
        msbd->conId = 0;
        msbd->reqStmt = NULL;
        msbd->state = MYSQL_BREAKDOWN_ERROR;
        msbd->errCode = 0;
        msbd->sqlState = 0;
        msbd->errMsg = NULL;
        msbd->reqSize = 0;
        msbd->respSize = 0;
        msbd->respLatency = 0;
        msbd->downloadLatency = 0;
        return msbd;
    } else
        return NULL;
}

static void
freeMysqlSessionBreakdown (void *sbd) {
    mysqlSessionBreakdownPtr msbd;

    if (sbd == NULL)
        return;

    msbd = (mysqlSessionBreakdownPtr) sbd;
    free (msbd->serverVer);
    free (msbd->userName);
    free (msbd->reqStmt);
    free (msbd->errMsg);

    free (msbd);
}

static int
generateMysqlSessionBreakdown (void *sd, void *sbd) {
    int ret = 0;
    mysqlSessionDetailPtr msd = (mysqlSessionDetailPtr) sd;
    mysqlSessionBreakdownPtr msbd = (mysqlSessionBreakdownPtr) sbd;
    mysqlParserStatePtr parser = &msd->parser;

    if (parser->serverVer) {
        msbd->serverVer = strdup (parser->serverVer);
        if (msbd->serverVer == NULL) {
            LOGE ("Strdup mysql server version error: %s.\n", strerror (errno));
            ret = -1;
            goto exit;
        }
    } else {
        LOGE ("Mysql server version is NULL.\n");
        ret = -1;
        goto exit;
    }

    if (parser->userName) {
        msbd->userName = strdup (parser->userName);
        if (msbd->userName == NULL) {
            LOGE ("Strdup mysql userName error: %s.\n", strerror (errno));
            ret = -1;
            goto exit;
        }
    } else {
        LOGE ("Mysql user name is NULL.\n");
        ret = -1;
        goto exit;
    }

    msbd->conId = parser->conId;

    /* For MYSQL_BREAKDOWN_RESET_TYPE4 case, reqStmt is NULL */
    if (msd->reqStmt && (msbd->state != MYSQL_BREAKDOWN_RESET_TYPE4)) {
        msbd->reqStmt = strdup (msd->reqStmt);
        if (msbd->reqStmt == NULL) {
            LOGE ("Strdup mysql request error: %s.\n", strerror (errno));
            ret = -1;
            goto exit;
        }
    }

    switch (msd->state) {
        case MYSQL_RESPONSE_OK:
        case MYSQL_RESPONSE_ERROR:
            if (msd->state == MYSQL_RESPONSE_OK) {
                msbd->state = MYSQL_BREAKDOWN_OK;
                msbd->errCode = 0;
                msbd->sqlState = 0;
                msbd->errMsg = NULL;
            } else {
                msbd->state = MYSQL_BREAKDOWN_ERROR;
                msbd->errCode = msd->errCode;
                msbd->sqlState = msd->sqlState;
                if (msd->errMsg) {
                    msbd->errMsg = strdup (msd->errMsg);
                    if (msbd->errMsg == NULL) {
                        LOGE ("Strdup mysql error message error: %s.\n", strerror (errno));
                        ret = -1;
                        goto exit;
                    }
                } else {
                    LOGE ("Mysql errMsg is NULL.\n");
                    ret = -1;
                    goto exit;
                }
            }
            msbd->reqSize = msd->reqSize;
            msbd->respSize = msd->respSize;
            msbd->respLatency = msd->respTimeBegin - msd->reqTime;
            msbd->downloadLatency = msd->respTimeEnd - msd->respTimeBegin;
            break;

        case MYSQL_RESET_TYPE1:
        case MYSQL_RESET_TYPE2:
            if (msd->state == MYSQL_RESET_TYPE1)
                msbd->state = MYSQL_BREAKDOWN_RESET_TYPE1;
            else
                msbd->state = MYSQL_BREAKDOWN_RESET_TYPE2;
            msbd->errCode = 0;
            msbd->sqlState = 0;
            msbd->errMsg = NULL;
            msbd->reqSize = msd->reqSize;
            msbd->respSize = 0;
            msbd->respLatency = 0;
            msbd->downloadLatency = 0;
            break;

        case MYSQL_RESET_TYPE3:
            msbd->state = MYSQL_BREAKDOWN_RESET_TYPE3;
            msbd->errCode = 0;
            msbd->sqlState = 0;
            msbd->errMsg = NULL;
            msbd->reqSize = msd->reqSize;
            msbd->respSize = msd->respSize;
            msbd->respLatency = msd->respTimeBegin - msd->reqTime;
            msbd->downloadLatency = 0;
            break;

        case MYSQL_RESET_TYPE4:
            msbd->state = MYSQL_BREAKDOWN_RESET_TYPE4;
            msbd->errCode = 0;
            msbd->sqlState = 0;
            msbd->errMsg = NULL;
            msbd->reqSize = 0;
            msbd->respSize = 0;
            msbd->respLatency = 0;
            msbd->downloadLatency = 0;
            break;

        default:
            LOGE ("Wrong mysql state for breakdown.\n");
            ret = -1;
            goto exit;
    }

exit:
    /* Reset mysqlSessionDetail for next request */
    resetMysqlSessionDetail (msd);
    return ret;
}

static void
mysqlSessionBreakdown2Json (json_t *root, void *sd, void *sbd) {
    mysqlSessionBreakdownPtr msbd = (mysqlSessionBreakdownPtr) sbd;

    /* Mysql server version */
    json_object_set_new (root, MYSQL_SBKD_SERVER_VERSION, json_string (msbd->serverVer));
    /* Mysql user name */
    json_object_set_new (root, MYSQL_SBKD_USER_NAME, json_string (msbd->userName));
    /* Mysql connection id */
    json_object_set_new (root, MYSQL_SBKD_CONNECTION_ID, json_integer (msbd->conId));
    /* Mysql request statement */
    if (msbd->reqStmt)
        json_object_set_new (root, MYSQL_SBKD_REQUEST_STATEMENT, json_string (msbd->reqStmt));
    else
        json_object_set_new (root, MYSQL_SBKD_REQUEST_STATEMENT, json_string (""));
    /* Mysql state */
    json_object_set_new (root, MYSQL_SBKD_STATE, json_integer (msbd->state));
    /* Mysql error code */
    json_object_set_new (root, MYSQL_SBKD_ERROR_CODE, json_integer (msbd->errCode));
    /* Mysql sql state */
    json_object_set_new (root, MYSQL_SBKD_SQL_STATE, json_integer (msbd->sqlState));
    /* Mysql error message */
    if (msbd->errMsg)
        json_object_set_new (root, MYSQL_SBKD_ERROR_MESSAGE, json_string (msbd->errMsg));
    else
        json_object_set_new (root, MYSQL_SBKD_ERROR_MESSAGE, json_string (""));
    /* Mysql request size */
    json_object_set_new (root, MYSQL_SBKD_REQUEST_SIZE, json_integer (msbd->reqSize));
    /* Mysql response size */
    json_object_set_new (root, MYSQL_SBKD_RESPONSE_SIZE, json_integer (msbd->respSize));
    /* Mysql response latency */
    json_object_set_new (root, MYSQL_SBKD_RESPONSE_LATENCY, json_integer (msbd->respLatency));
    /* Mysql download latency */
    json_object_set_new (root, MYSQL_SBKD_DOWNLOAD_LATENCY, json_integer (msbd->downloadLatency));
}

static void
mysqlSessionProcessEstb (void *sd, timeValPtr tm) {
    return;
}

static void
mysqlSessionProcessUrgData (int fromClient, char urgData, void *sd, timeValPtr tm) {
    return;
}

static int
mysqlSessionProcessData (int fromClient, const u_char *data, int dataLen, void *sd, timeValPtr tm, int *sessionDone) {
    int parseCount;

    currTime = tm;
    currSessionDone = 0;
    currSessionDetail = (mysqlSessionDetailPtr) sd;

    parseCount = mysqlParserExecute (&currSessionDetail->parser, data, dataLen, fromClient);
    *sessionDone = currSessionDone;

    return parseCount;
}

static void
mysqlSessionProcessReset (int fromClient, void *sd, timeValPtr tm) {
    mysqlSessionDetailPtr msd = (mysqlSessionDetailPtr) sd;

    if (msd->state == MYSQL_REQUEST_BEGIN)
        msd->state = MYSQL_RESET_TYPE1;
    else if (msd->state == MYSQL_REQUEST_COMPLETE)
        msd->state = MYSQL_RESET_TYPE2;
    else if (msd->state == MYSQL_RESPONSE_BEGIN)
        msd->state = MYSQL_RESET_TYPE3;
    else if (msd->state == MYSQL_INIT)
        msd->state = MYSQL_RESET_TYPE4;

    return;
}

static void
mysqlSessionProcessFin (int fromClient, void *sd, timeValPtr tm, int *sessionDone) {
    return;
}

protoParser mysqlParser = {
    .initProto = initMysqlProto,
    .destroyProto = destroyMysqlProto,
    .newSessionDetail = newMysqlSessionDetail,
    .freeSessionDetail = freeMysqlSessionDetail,
    .newSessionBreakdown = newMysqlSessionBreakdown,
    .freeSessionBreakdown = freeMysqlSessionBreakdown,
    .generateSessionBreakdown = generateMysqlSessionBreakdown,
    .sessionBreakdown2Json = mysqlSessionBreakdown2Json,
    .sessionProcessEstb = mysqlSessionProcessEstb,
    .sessionProcessUrgData = mysqlSessionProcessUrgData,
    .sessionProcessData = mysqlSessionProcessData,
    .sessionProcessReset = mysqlSessionProcessReset,
    .sessionProcessFin = mysqlSessionProcessFin
};
