#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <zlib.h>
#include <pthread.h>
#include <jansson.h>
#include "util.h"
#include "log.h"
#include "mysql_analyzer.h"

#define PKT_HANDLE_OK       0
#define PKT_HANDLE_ERROR    1

#define MATCH(a, b) ((a) == (b) ? true : false)

/* Current timestamp */
static __thread timeValPtr currTime;
/* Current session state */
static __thread sessionState currSessionState;
/* Current mysql shared info */
static __thread mysqlSharedInfoPtr currSharedInfo;
/* Current mysql session detail */
static __thread mysqlSessionDetailPtr currSessionDetail;

/* Mysql state event matrix */
static mysqlEventHandleMap mysqlStateEventMatrix [MYSQL_STATE_SIZE];
/* Mysql proto init once control */
static pthread_once_t mysqlProtoInitOnceControl = PTHREAD_ONCE_INIT;
/* Mysql proto destroy once control */
static pthread_once_t mysqlProtoDestroyOnceControl = PTHREAD_ONCE_INIT;

/* =============================Mysql integer type============================ */

/* Fixed-Length Integer Types */
#define FLI1(A) ((u_char) (A) [0])

#define FLI2(A) ((u_short) (((u_short) ((u_char) (A) [0])) +        \
                            ((u_short) ((u_char) (A) [1]) << 8)))

#define FLI3(A) ((u_int) (((u_int) ((u_char) (A) [0])) +            \
                          (((u_int) ((u_char) (A) [1])) << 8) +     \
                          (((u_int) ((u_char) (A) [2])) << 16)))

#define FLI4(A) ((u_int) (((u_int) ((u_char) (A) [0])) +            \
                          (((u_int) ((u_char) (A) [1])) << 8) +     \
                          (((u_int) ((u_char) (A) [2])) << 16) +    \
                          (((u_int) ((u_char) (A) [3])) << 24)))

#define FLI6(A) ((u_long_long) (((u_long_long) ((u_char) (A) [0])) +    \
                                (((u_long_long) ((u_char) (A) [1])) << 8) + \
                                (((u_long_long) ((u_char) (A) [2])) << 16) + \
                                (((u_long_long) ((u_char) (A) [3])) << 24) + \
                                (((u_long_long) ((u_char) (A) [3])) << 32) + \
                                (((u_long_long) ((u_char) (A) [3])) << 40)))

#define FLI8(A) ((u_long_long) (((u_long_long) ((u_char) (A) [0])) +    \
                                (((u_long_long) ((u_char) (A) [1])) << 8) + \
                                (((u_long_long) ((u_char) (A) [2])) << 16) + \
                                (((u_long_long) ((u_char) (A) [3])) << 24) + \
                                (((u_long_long) ((u_char) (A) [3])) << 32) + \
                                (((u_long_long) ((u_char) (A) [3])) << 40) + \
                                (((u_long_long) ((u_char) (A) [3])) << 48) + \
                                (((u_long_long) ((u_char) (A) [3])) << 56)))

/* Length-Encoded Integer Type */
static u_long_long
lenEncInt (u_char *pkt, u_int *len) {
    u_int prefix;

    prefix = (u_int) *pkt;
    if (prefix < 0xFB) {
        *len = 1;
        return (u_long_long) FLI1 (pkt);
    } else if (prefix == 0xFC) {
        *len = 3;
        return (u_long_long) FLI2 (pkt + 1);
    } else if (prefix == 0xFD) {
        *len = 4;
        return (u_long_long) FLI3 (pkt + 1);
    } else if (prefix == 0xFE) {
        *len = 9;
        return (u_long_long) FLI8 (pkt + 1);
    } else {
        *len = 0;
        return 0;
    }
}

/* =============================Mysql integer type============================ */

static void
resetMysqlSessionDetail (mysqlSessionDetailPtr msd);

/* =================================Handshake================================= */

static int
pktServerHandshake (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int toCopyLen;
    u_int srvVer;
    u_int caps;
    u_char charSet;
    u_short statusFlag;
    u_int authPluginDataLen;
    char authPluginData [256] = {0};
    char *authPluginName;
    u_char *pkt = payload;

    if ((direction == STREAM_FROM_CLIENT) || currSessionDetail->seqId != 0)
        return PKT_HANDLE_ERROR;

    LOGD ("Cli<------Server: init handshake packet.\n");

    /* Only support v10 protocol */
    if (!MATCH (*pkt, 0x0A)) {
        LOGW ("Only support v10 protocol.\n");
        return PKT_HANDLE_ERROR;
    }

    /* Proto version */
    currSharedInfo->protoVer = (u_int) *pkt;
    pkt += 1;

    /* Server version, example: 4.1.1 ........ */
    currSharedInfo->serverVer = strdup ((const char *) pkt);
    pkt += strlen ((const char *) pkt) + 1;
    srvVer = (currSharedInfo->serverVer [0] - '0') * 10 + (currSharedInfo->serverVer [2] - '0');
    if (srvVer >= 41)
        currSharedInfo->cliProtoIsV41 = true;
    else
        currSharedInfo->cliProtoIsV41 = false;
    LOGD ("Server version:%s\n", currSharedInfo->serverVer);

    /* Connection id */
    currSharedInfo->conId = FLI4 (pkt);
    pkt += 4;
    LOGD ("Connection id:%u\n", currSharedInfo->conId);

    /* 8 bytes auth-plugin-data-part-1 0 padding */
    memcpy (authPluginData, pkt, 8);
    pkt += 8;

    /* 1 byte filler */
    pkt += 1;

    /* Capability flags lower 2 bytes */
    caps = FLI2 (pkt);
    pkt += 2;

    /* Character set */
    charSet = FLI1 (pkt);
    pkt += 1;

    /* Status flags */
    statusFlag = FLI2 (pkt);
    pkt += 2;

    /* Capability flags upper 2 bytes */
    caps = (FLI2 (pkt) << 16) + caps;
    pkt += 2;

    /* Auth plugin data len or 0 padding */
    if (caps & CLIENT_PLUGIN_AUTH) {
        authPluginDataLen = FLI1 (pkt);
    } else
        authPluginDataLen = 8;
    pkt += 1;

    /* 10 bytes for zero-byte padding */
    pkt += 10;

    if (caps & CLIENT_SECURE_CONNECTION) {
        authPluginDataLen = MAX_NUM (13, (authPluginDataLen - 8));
        toCopyLen = MIN_NUM (authPluginDataLen, (sizeof (authPluginData) - 9));
        memcpy (authPluginData + 8, pkt, toCopyLen);
        pkt += authPluginDataLen;
        LOGD ("Auth plugin data: %s\n", authPluginData);
    }

    if (caps & CLIENT_PLUGIN_AUTH) {
        authPluginName = (char *) pkt;
        LOGD ("Auth plugin name: %s\n", authPluginName);
    }

    return PKT_HANDLE_OK;
}

static int
pktClientHandshake (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int toCopyLen;
    u_int encLen;
    u_int realLen;
    u_char charSet;
    u_char authResp [256] = {0};
    char *dbName = NULL;
    char *authPluginName = NULL;
    u_int attrsLen;
    u_char *attrsEnd;
    char attrKey [256] = {0};
    char attrValue [256] = {0};
    u_char *pkt = payload;

    if ((direction == STREAM_FROM_SERVER) || (currSessionDetail->seqId != 1))
        return PKT_HANDLE_ERROR;

    LOGD ("Cli------>Server: client handshake packet.\n");

    if (currSharedInfo->cliProtoIsV41) {
        /* Capability flags */
        currSharedInfo->cliCaps = FLI4 (pkt);
        pkt += 4;

        /* Max packet size */
        currSharedInfo->maxPktSize = FLI4 (pkt);
        pkt += 4;
        LOGD ("Max packet size: %u\n", currSharedInfo->maxPktSize);

        /* Character set */
        charSet = FLI1 (pkt);
        pkt += 1;

        /* Reserved 23 bytes of 0 */
        pkt += 23;

        /* User name */
        currSharedInfo->userName = strdup ((const char *) pkt);
        pkt += strlen ((const char *) pkt) + 1;
        LOGD ("User name: %s\n", currSharedInfo->userName);

        /* Auth response */
        if ((currSharedInfo->cliCaps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) ||
            (currSharedInfo->cliCaps & CLIENT_SECURE_CONNECTION)) {
            if (currSharedInfo->cliCaps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
                realLen = lenEncInt (pkt, &encLen);
            else {
                encLen = 1;
                realLen = FLI1 (pkt);
            }

            toCopyLen = MIN_NUM (realLen, (sizeof (authResp) - 1));
            memcpy (authResp, pkt + encLen, toCopyLen);
        } else {
            encLen = 1;
            realLen = strlen ((const char *) pkt);
            toCopyLen = MIN_NUM (realLen, (sizeof (authResp) - 1));
            memcpy (authResp, pkt, toCopyLen);
        }
        pkt += encLen + realLen;
        LOGD ("Auth response: %s\n", authResp);

        /* Database */
        if (currSharedInfo->cliCaps & CLIENT_CONNECT_WITH_DB) {
            dbName = (char *) pkt;
            encLen = 1;
            realLen = strlen ((const char *) pkt);
            pkt += encLen + realLen;
            LOGD ("Database: %s\n", dbName);
        }

        /* Auth plugin name */
        if (currSharedInfo->cliCaps & CLIENT_PLUGIN_AUTH) {
            authPluginName = (char *) pkt;
            realLen = strlen ((const char *) pkt);
            pkt += realLen + 1;
            LOGD ("Auth plugin name: %s\n", authPluginName);
        }

        /* Attributes */
        if (currSharedInfo->cliCaps & CLIENT_CONNECT_ATTRS) {
            attrsLen = lenEncInt (pkt, &encLen);
            attrsEnd = pkt + attrsLen;
            pkt += encLen;

            while (pkt < attrsEnd) {
                realLen = lenEncInt (pkt, &encLen);
                toCopyLen = MIN_NUM (realLen, (sizeof (attrKey) - 1));
                memcpy (attrKey, pkt + encLen, toCopyLen);
                attrKey [toCopyLen] = 0;
                pkt += encLen + realLen;

                realLen = lenEncInt (pkt, &encLen);
                toCopyLen = MIN_NUM (realLen, (sizeof (attrValue) - 1));
                memcpy (attrValue, pkt + encLen, toCopyLen);
                attrValue [toCopyLen] = 0;
                pkt += encLen + realLen;

                LOGD ("Attributes, %s:%s\n", attrKey, attrValue);
            }
        }
    } else {
        /* Capability flags */
        currSharedInfo->cliCaps = FLI2 (pkt);
        pkt += 2;

        /* Max packet size */
        currSharedInfo->maxPktSize = FLI3 (pkt);
        pkt += 3;
        LOGD ("Max packet size: %u\n", currSharedInfo->maxPktSize);

        /* User name */
        currSharedInfo->userName = strdup ((const char *) pkt);
        pkt += strlen ((const char *) pkt) + 1;
        LOGD ("User name: %s\n", currSharedInfo->userName);

        if (currSharedInfo->cliCaps & CLIENT_CONNECT_WITH_DB) {
            /* Auth response */            
            encLen = 1;
            realLen = strlen ((const char *) pkt);
            toCopyLen = MIN_NUM (realLen, (sizeof (authResp) - 1));
            memcpy (authResp, pkt, toCopyLen);
            pkt += encLen + realLen;
            LOGD ("Auth response: %s\n", authResp);

            /* DB name */
            dbName = (char *) pkt;
            encLen = 1;
            realLen = strlen ((const char *) pkt);
            LOGD ("Database: %s\n", dbName);
        } else {
            realLen = payload + payloadLen - pkt;
            toCopyLen = MIN_NUM (realLen, (sizeof (authResp) - 1));
            memcpy (authResp, pkt, toCopyLen);
            LOGD ("Auth response: %s\n", authResp);
        }
    }

    currSharedInfo->doSSL = ((currSharedInfo->cliCaps & CLIENT_SSL) ? true : false);
    currSharedInfo->doCompress = ((currSharedInfo->cliCaps & CLIENT_COMPRESS) ? true : false);
    LOGD ("doSSL: %s, doCompress: %s\n",
          currSharedInfo->doSSL ? "Yes" : "No",
          currSharedInfo->doCompress ? "Yes" : "No");

    return PKT_HANDLE_OK;
}

static int
pktSecureAuth (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_char *pkt = payload;

    if (MATCH (*pkt, MYSQL_RESPONSE_OK_PACKET) ||
        MATCH (*pkt, MYSQL_RESPONSE_ERROR_PACKET))
        return PKT_HANDLE_ERROR;

    if (direction == STREAM_FROM_CLIENT)
        LOGD ("Cli------>Server: Secure authentication.\n");
    else
        LOGD ("Cli<------Server: Secure authentication.\n");

    return PKT_HANDLE_OK;
}
/* =================================Handshake================================= */

/* ==================================Request================================== */

static int
pktComX (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    boolean pktEventMatch;
    u_char *pkt = payload;

    if (payloadLen > 1)
        return PKT_HANDLE_ERROR;

    switch (event) {
        case COM_SLEEP:
            pktEventMatch = MATCH (*pkt, COM_SLEEP);
            break;

        case COM_QUIT:
            pktEventMatch = MATCH (*pkt, COM_QUIT);
            break;

        case COM_STATISTICS:
            pktEventMatch = MATCH (*pkt, COM_STATISTICS);
            break;

        case COM_PROCESS_INFO:
            pktEventMatch = MATCH (*pkt, COM_PROCESS_INFO);
            break;

        case COM_CONNECT:
            pktEventMatch = MATCH (*pkt, COM_CONNECT);
            break;

        case COM_DEBUG:
            pktEventMatch = MATCH (*pkt, COM_DEBUG);
            break;

        case COM_PING:
            pktEventMatch = MATCH (*pkt, COM_PING);
            break;

        case COM_TIME:
            pktEventMatch = MATCH (*pkt, COM_TIME);
            break;

        case COM_DELAYED_INSERT:
            pktEventMatch = MATCH (*pkt, COM_DELAYED_INSERT);
            break;

        case COM_CONNECT_OUT:
            pktEventMatch = MATCH (*pkt, COM_CONNECT_OUT);
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

    if (!pktEventMatch)
        return PKT_HANDLE_ERROR;

    /* For COM_QUIT and COM_PING, doesn't do statistics */
    if (MATCH (*pkt, COM_QUIT) || MATCH (*pkt, COM_PING))
        LOGD ("Cli------>Server: %s\n", mysqlCommandName [*pkt]);
    else {
        currSessionDetail->reqStmt = strdup (mysqlCommandName [*pkt]);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;
    }

    return PKT_HANDLE_OK;
}

static int
pktInitDB (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_INIT_DB) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s db_name:", mysqlCommandName [*pkt]);
        argsLen = payloadLen - 1;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + 1), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktQuery (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    char com [4096];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_QUERY) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s schema:", mysqlCommandName [*pkt]);
        argsLen = payloadLen - 1;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + 1), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktFieldList (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    u_int tableLen;
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_FIELD_LIST) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s table:%s field_wildcard:", mysqlCommandName [*pkt], (pkt + 1));
        tableLen = strlen ((const char *) (pkt + 1));
        argsLen = payloadLen - tableLen - 2;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + tableLen + 2), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktCreateDB (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_CREATE_DB) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s db_name:", mysqlCommandName [*pkt]);
        argsLen = payloadLen - 1;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + 1), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktDropDB (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_DROP_DB) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s db_name:", mysqlCommandName [*pkt]);
        argsLen = payloadLen - 1;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + 1), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktRefresh (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_REFRESH) && (payloadLen == 2)) {
        snprintf (com, sizeof (com), "%s sub_command:%d", mysqlCommandName [*pkt], (u_int) *(pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktShutdown (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_SHUTDOWN) && ((payloadLen == 1) || (payloadLen == 2))) {
        if (payloadLen == 1)
            snprintf (com, sizeof (com), "%s", mysqlCommandName [*pkt]);
        else
            snprintf (com, sizeof (com), "%s sub_command:%d", mysqlCommandName [*pkt], (u_int) *(pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktProcessKill (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_PROCESS_KILL) && (payloadLen == 5)) {
        snprintf (com, sizeof (com), "%s sub_command:%d", mysqlCommandName [*pkt], FLI4 (pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktChangeUser (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_CHANGE_USER) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s user_name:%s", mysqlCommandName [*pkt], (pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktRegisterSlave (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_REGISTER_SLAVE) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s slave_id:%s", mysqlCommandName [*pkt], (pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktStmtPrepare (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int argsLen;
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_STMT_PREPARE) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s schema:", mysqlCommandName [*pkt]);
        argsLen = payloadLen - 1;
        if (argsLen >= sizeof (com) - strlen (com))
            argsLen = sizeof (com) - strlen (com) - 1;
        memcpy (com + strlen (com), (pkt + 1), argsLen);
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktStmtX (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if ((MATCH (*pkt, COM_STMT_EXECUTE) ||
         MATCH (*pkt, COM_STMT_CLOSE) ||
         MATCH (*pkt, COM_STMT_RESET)) && (payloadLen > 1)) {
        snprintf (com, sizeof (com), "%s stmt_id:%d", mysqlCommandName [*pkt], FLI4 (pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktSetOption (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_SET_OPTION) && (payloadLen == 3)) {
        snprintf (com, sizeof (com), "%s option:%d", mysqlCommandName [*pkt], FLI2 (pkt + 1));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktStmtFetch (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    char com [256];
    u_char *pkt = payload;

    if (MATCH (*pkt, COM_STMT_FETCH) && (payloadLen == 9)) {
        snprintf (com, sizeof (com), "%s stmt_id:%d rows:%d", mysqlCommandName [*pkt], FLI4 (pkt + 1), FLI4 (pkt + 5));
        currSessionDetail->reqStmt = strdup (com);
        currSessionDetail->state = MYSQL_REQUEST_COMPLETE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

/* ==================================Request================================== */

/* =================================Response================================== */

static int
pktOkOrError (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int len;
    u_long_long rows;
    u_long_long insertId;
    u_int status;
    u_int warn;
    char *msg;
    u_short errCode;
    char sqlState [6] = {0};
    char errMsg [512] = {0};
    u_char *pkt = payload;

    switch (*pkt) {
        case MYSQL_RESPONSE_OK_PACKET:
            /* Mysql ok packet */
            if ((!currSharedInfo->cliProtoIsV41 && (payloadLen < 5)) ||
                (currSharedInfo->cliProtoIsV41 && (payloadLen < 7)))
                return PKT_HANDLE_ERROR;

            /* Affected rows */
            rows = lenEncInt (pkt, &len);
            pkt += len;
            /* Last insert id */
            insertId = lenEncInt (pkt, &len);
            pkt += len;

            if (currSharedInfo->cliProtoIsV41) {
                status = FLI2 (pkt);
                pkt += 2;
                warn = FLI2 (pkt);
                pkt += 2;
            } else if (currSharedInfo->cliCaps & CLIENT_TRANSACTIONS) {
                status = FLI2 (pkt);
                pkt += 2;
                warn = 0;
            } else {
                status = 0;
                warn = 0;
            }

            /* Message */
            if ((pkt - payload) < payloadLen)
                msg = (char *) pkt;

            /*
             * For mysql handshake, COM_QUIT and COM_PING, there is no request
             * statement and session breakdown.
             */
            if (currSessionDetail->reqStmt) {
                currSessionDetail->state = MYSQL_RESPONSE_OK;
                currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
                currSessionState = SESSION_DONE;
            } else {
                resetMysqlSessionDetail (currSessionDetail);
                LOGD ("Cli<------Server: OK packet.\n");
            }

            return PKT_HANDLE_OK;

        case MYSQL_RESPONSE_ERROR_PACKET:
            /* Mysql error packet */
            pkt++;
            errCode = FLI2 (pkt);
            pkt += 2;
            if (currSharedInfo->cliProtoIsV41) {
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
                currSessionState = SESSION_DONE;
            } else {
                resetMysqlSessionDetail (currSessionDetail);
                LOGD ("Cli<------Server: ERROR packet, error code: %d, error msg: %s.\n", errCode, errMsg);
            }

            return PKT_HANDLE_OK;

        default:
            return PKT_HANDLE_ERROR;
    }
}

static int
pktEnd (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_short warn = 0;
    u_short status = 0;
    u_char *pkt = payload;

    if ((*pkt != 0xFE) ||
        (currSharedInfo->cliProtoIsV41 && (payloadLen != 5)) ||
        (!currSharedInfo->cliProtoIsV41 && (payloadLen != 1)))
        return PKT_HANDLE_ERROR;

    pkt++;
    if (currSharedInfo->cliProtoIsV41) {
        warn = FLI2 (pkt);
        pkt += 2;
        status = FLI2 (pkt);
        pkt += 2;

        if (((currSessionDetail->mstate == STATE_TXT_ROW) || (currSessionDetail->mstate == STATE_BIN_ROW)) &&
            (status & SERVER_MORE_RESULTS_EXISTS) &&
            event != EVENT_END_MULTI_RESULT)
            return PKT_HANDLE_ERROR;
    }

    if ((currSessionDetail->mstate == STATE_END_OR_ERROR) ||
        (currSessionDetail->mstate == STATE_FIELD_LIST) ||
        (currSessionDetail->mstate == STATE_END) ||
        (currSessionDetail->mstate == STATE_TXT_ROW) ||
        (currSessionDetail->mstate == STATE_BIN_ROW)) {
        currSessionDetail->state = MYSQL_RESPONSE_OK;
        currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
        currSessionState = SESSION_DONE;
    }

    if ((currSessionDetail->mstate == STATE_SECURE_AUTH) && (direction == STREAM_FROM_CLIENT))
        LOGD ("Cli------>Server: END packet.\n");

    return PKT_HANDLE_OK;
}

static int
pktStatistics (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    if (payloadLen > 1) {
        currSessionDetail->respTimeEnd = timeVal2MilliSecond (currTime);
        currSessionDetail->state = MYSQL_RESPONSE_OK;
        currSessionState = SESSION_DONE;

        return PKT_HANDLE_OK;
    } else
        return PKT_HANDLE_ERROR;
}

static int
pktNFields (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_int len;
    u_long_long count;
    u_char *pkt = payload;

    count = lenEncInt (pkt, &len);
    if ((len != payloadLen) || (count == 0))
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

static int
pktField (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_char *pkt = payload;

    if (*pkt == 0xFE)
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

static int
pktRow (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_char *pkt = payload;

    /* EOF packet */
    if ((*pkt == 0xFE) && ((payloadLen == 1) || (payloadLen == 5)))
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

static int
pktBinaryRow (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_char *pkt = payload;

    if (*pkt != 0x00)
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

static int
pktStmtMeta (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    if (payloadLen != 12)
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

static int
pktStmtFetchRS (mysqlEvent event, u_char *payload, u_int payloadLen, streamDirection direction) {
    u_char *pkt = payload;

    if ((*pkt == 0x00) || (*pkt == 0xFF))
        return PKT_HANDLE_ERROR;

    return PKT_HANDLE_OK;
}

/* =================================Response================================== */

static u_int
sqlParse (u_char *data, u_int dataLen, streamDirection direction) {
    u_int parseCount = 0;
    u_int parseLeft = dataLen;
    u_char *pkt;
    u_int pktLen;
    mysqlHeaderPtr hdr;
    u_int payloadLen;
    u_char *payload;
    u_int event;
    mysqlEventHandler handler;

    while (1) {
        if (parseLeft < MYSQL_HEADER_SIZE)
            break;

        /* Next mysql packet begin */
        pkt = data + parseCount;
        hdr = (mysqlHeaderPtr) pkt;
        payloadLen = hdr->payloadLen;
        currSessionDetail->seqId = hdr->pktId;
        payload = pkt + MYSQL_HEADER_SIZE;
        pktLen = MYSQL_HEADER_SIZE + payloadLen;

        /* If packet is not complete, return and wait for further processing */
        if (parseLeft < pktLen)
            break;

        if (payloadLen) {
            for (event = 0; event < mysqlStateEventMatrix [currSessionDetail->mstate].size; event++) {
                handler = mysqlStateEventMatrix [currSessionDetail->mstate].handler [event];

                if ((*handler) (event, payload, payloadLen, direction) == PKT_HANDLE_OK) {
                    currSessionDetail->mstate = mysqlStateEventMatrix [currSessionDetail->mstate].nextState [event];
                    break;
                } else
                    handler = NULL;
            }
            if (handler == NULL)
                LOGW ("Warning: has no proper handler.\n");
        }

        parseCount += pktLen;
        parseLeft -= pktLen;
    }

    return parseCount;
}

static u_int
mysqlParserExecute (u_char *data, u_int dataLen, streamDirection direction) {
    u_int parseCount = 0;
    u_int parseLeft = dataLen;
    u_char *compPkt;
    u_char *uncompPkt;
    u_int compPktLen;
    mysqlCompHeaderPtr compHdr;
    u_int payloadLen;
    u_int compPayloadLen;
    u_int uncompPayloadLen;
    u_char *compPayload;

    if (currSharedInfo->doSSL) {
        LOGD ("Doesn't support ssl for mysql analyzer.\n");
        return dataLen;
    }

    /* Mysql packet after handshake  */
    if ((currSessionDetail->mstate != STATE_NOT_CONNECTED) &&
        (currSessionDetail->mstate != STATE_CLIENT_HANDSHAKE) &&
        (currSessionDetail->mstate != STATE_SECURE_AUTH)) {
        /* For incomplete mysql packet, return directly */
        if ((currSharedInfo->doCompress && (parseLeft < MYSQL_COMPRESSED_HEADER_SIZE)) ||
            (parseLeft < MYSQL_COMPRESSED_HEADER_SIZE))
            return 0;

        /* New mysql request */
        if (direction == STREAM_FROM_CLIENT) {
            /*
             * For every mysql request has only one packet, so, every packet from client
             * thought as a new mysql request. To make sure mysql sharedInfo's state is correct
             * (some conditions like packets dropping or parsing error can cause sharedInfo's
             * state uncorrect), we need to set sharedInfo's state to STATE_SLEhEP explicitly for
             * every new client request and reset currSessionDetail.
             */
            currSessionDetail->mstate = STATE_SLEEP;
            resetMysqlSessionDetail (currSessionDetail);
            currSessionDetail->state = MYSQL_REQUEST_BEGIN;
            currSessionDetail->reqTime = timeVal2MilliSecond (currTime);
        } else if ((direction == STREAM_FROM_SERVER) && (currSessionDetail->state == MYSQL_REQUEST_COMPLETE)) {
            currSessionDetail->state = MYSQL_RESPONSE_BEGIN;
            currSessionDetail->respTimeBegin = timeVal2MilliSecond (currTime);
        }

        /* Compressed mysql packets */
        if (currSharedInfo->doCompress) {
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
                    uncompPkt = (u_char *) malloc (payloadLen);
                    if (uncompPkt == NULL) {
                        LOGE ("Alloc memory for uncompPkt error: %s.\n", strerror (errno));
                        break;
                    }

                    uncompPayloadLen = payloadLen;
                    if (uncompress ((u_char *) uncompPkt, (u_long *) &uncompPayloadLen, compPayload, compPayloadLen) != Z_OK) {
                        LOGE ("Uncompress packet error.\n");
                        free (uncompPkt);
                        uncompPkt = NULL;
                        parseCount += compPktLen;
                        parseLeft -= compPktLen;
                        continue;
                    }
                } else {
                    uncompPkt = compPayload;
                    uncompPayloadLen = compPayloadLen;
                }

                /* Real sql parse */
                sqlParse (uncompPkt, uncompPayloadLen, direction);
                /* Free uncompressed packet buffer if any */
                if (payloadLen) {
                    free (uncompPkt);
                    uncompPkt = NULL;
                }

                parseCount += compPktLen;
                parseLeft -= compPktLen;
            }
        } else  /* Non Compressed mysql packets */
            parseCount = sqlParse (data, dataLen, direction);

        if (direction == STREAM_FROM_CLIENT)
            currSessionDetail->reqSize += parseCount;
        else
            currSessionDetail->respSize += parseCount;
    } else  /* Mysql handshake packets */
        parseCount = sqlParse (data, dataLen, direction);

    return parseCount;
}

static void
initMysqlSharedInstance (void) {
    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_NOT_CONNECTED].size = 1;
    mysqlStateEventMatrix [STATE_NOT_CONNECTED].event [0] = EVENT_SERVER_HANDSHAKE;
    mysqlStateEventMatrix [STATE_NOT_CONNECTED].nextState [0] = STATE_CLIENT_HANDSHAKE;
    mysqlStateEventMatrix [STATE_NOT_CONNECTED].handler [0] = &pktServerHandshake;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_CLIENT_HANDSHAKE].size = 1;
    mysqlStateEventMatrix [STATE_CLIENT_HANDSHAKE].event [0] = EVENT_CLIENT_HANDSHAKE;
    mysqlStateEventMatrix [STATE_CLIENT_HANDSHAKE].nextState [0] = STATE_SECURE_AUTH;
    mysqlStateEventMatrix [STATE_CLIENT_HANDSHAKE].handler [0] = &pktClientHandshake;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_SECURE_AUTH].size = 2;
    mysqlStateEventMatrix [STATE_SECURE_AUTH].event [0] = EVENT_SECURE_AUTH;
    mysqlStateEventMatrix [STATE_SECURE_AUTH].nextState [0] = STATE_SECURE_AUTH;
    mysqlStateEventMatrix [STATE_SECURE_AUTH].handler [0] = &pktSecureAuth;

    mysqlStateEventMatrix [STATE_SECURE_AUTH].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SECURE_AUTH].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_SECURE_AUTH].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_SLEEP].size = 28;
    mysqlStateEventMatrix [STATE_SLEEP].event [0] = COM_SLEEP;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [0] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [0] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [1] = COM_QUIT;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [1] = STATE_NOT_CONNECTED;
    mysqlStateEventMatrix [STATE_SLEEP].handler [1] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [2] = COM_INIT_DB;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [2] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [2] = &pktInitDB;

    mysqlStateEventMatrix [STATE_SLEEP].event [3] = COM_QUERY;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [3] = STATE_TXT_RS;
    mysqlStateEventMatrix [STATE_SLEEP].handler [3] = &pktQuery;

    mysqlStateEventMatrix [STATE_SLEEP].event [4] = COM_FIELD_LIST;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [4] = STATE_FIELD_LIST;
    mysqlStateEventMatrix [STATE_SLEEP].handler [4] = &pktFieldList;

    mysqlStateEventMatrix [STATE_SLEEP].event [5] = COM_CREATE_DB;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [5] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [5] = &pktCreateDB;

    mysqlStateEventMatrix [STATE_SLEEP].event [6] = COM_DROP_DB;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [6] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [6] = &pktDropDB;

    mysqlStateEventMatrix [STATE_SLEEP].event [7] = COM_REFRESH;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [7] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [7] = &pktRefresh;

    mysqlStateEventMatrix [STATE_SLEEP].event [8] = COM_SHUTDOWN;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [8] = STATE_END_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [8] = &pktShutdown;

    mysqlStateEventMatrix [STATE_SLEEP].event [9] = COM_STATISTICS;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [9] = STATE_STATISTICS;
    mysqlStateEventMatrix [STATE_SLEEP].handler [9] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [10] = COM_PROCESS_INFO;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [10] = STATE_TXT_RS;
    mysqlStateEventMatrix [STATE_SLEEP].handler [10] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [11] = COM_CONNECT;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [11] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [11] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [12] = COM_PROCESS_KILL;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [12] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [12] = &pktProcessKill;

    mysqlStateEventMatrix [STATE_SLEEP].event [13] = COM_DEBUG;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [13] = STATE_END_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [13] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [14] = COM_PING;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [14] = STATE_PONG;
    mysqlStateEventMatrix [STATE_SLEEP].handler [14] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [15] = COM_TIME;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [15] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [15] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [16] = COM_DELAYED_INSERT;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [16] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [16] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [17] = COM_CHANGE_USER;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [17] = STATE_SECURE_AUTH;
    mysqlStateEventMatrix [STATE_SLEEP].handler [17] = &pktChangeUser;

    mysqlStateEventMatrix [STATE_SLEEP].event [18] = COM_CONNECT_OUT;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [18] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [18] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [19] = COM_REGISTER_SLAVE;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [19] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [19] = &pktRegisterSlave;

    mysqlStateEventMatrix [STATE_SLEEP].event [20] = COM_STMT_PREPARE;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [20] = STATE_STMT_META;
    mysqlStateEventMatrix [STATE_SLEEP].handler [20] = &pktStmtPrepare;

    mysqlStateEventMatrix [STATE_SLEEP].event [21] = COM_STMT_EXECUTE;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [21] = STATE_BIN_RS;
    mysqlStateEventMatrix [STATE_SLEEP].handler [21] = &pktStmtX;

    mysqlStateEventMatrix [STATE_SLEEP].event [22] = COM_STMT_CLOSE;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [22] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_SLEEP].handler [22] = &pktStmtX;

    mysqlStateEventMatrix [STATE_SLEEP].event [23] = COM_STMT_RESET;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [23] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [23] = &pktStmtX;

    mysqlStateEventMatrix [STATE_SLEEP].event [24] = COM_SET_OPTION;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [24] = STATE_END_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [24] = &pktSetOption;

    mysqlStateEventMatrix [STATE_SLEEP].event [25] = COM_STMT_FETCH;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [25] = STATE_STMT_FETCH_RS;
    mysqlStateEventMatrix [STATE_SLEEP].handler [25] = &pktStmtFetch;

    mysqlStateEventMatrix [STATE_SLEEP].event [26] = COM_DAEMON;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [26] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [26] = &pktComX;

    mysqlStateEventMatrix [STATE_SLEEP].event [27] = COM_RESET_CONNECTION;
    mysqlStateEventMatrix [STATE_SLEEP].nextState [27] = STATE_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_SLEEP].handler [27] = &pktComX;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_PONG].size = 1;
    mysqlStateEventMatrix [STATE_PONG].event [0] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_PONG].nextState [0] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_PONG].handler [0] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_OK_OR_ERROR].size = 1;
    mysqlStateEventMatrix [STATE_OK_OR_ERROR].event [0] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_OK_OR_ERROR].nextState [0] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_OK_OR_ERROR].handler [0] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_END_OR_ERROR].size = 2;
    mysqlStateEventMatrix [STATE_END_OR_ERROR].event [0] = EVENT_END;
    mysqlStateEventMatrix [STATE_END_OR_ERROR].nextState [0] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_END_OR_ERROR].handler [0] = &pktEnd;

    mysqlStateEventMatrix [STATE_END_OR_ERROR].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_END_OR_ERROR].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_END_OR_ERROR].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_STATISTICS].size = 1;
    mysqlStateEventMatrix [STATE_STATISTICS].event [0] = EVENT_STATISTICS;
    mysqlStateEventMatrix [STATE_STATISTICS].nextState [0] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_STATISTICS].handler [0] = &pktStatistics;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_FIELD_LIST].size = 2;
    mysqlStateEventMatrix [STATE_FIELD_LIST].event [0] = EVENT_FL_FIELD;
    mysqlStateEventMatrix [STATE_FIELD_LIST].nextState [0] = STATE_FIELD_LIST;
    mysqlStateEventMatrix [STATE_FIELD_LIST].handler [0] = &pktField;

    mysqlStateEventMatrix [STATE_FIELD_LIST].event [1] = EVENT_END;
    mysqlStateEventMatrix [STATE_FIELD_LIST].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_FIELD_LIST].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_FIELD].size = 2;
    mysqlStateEventMatrix [STATE_FIELD].event [0] = EVENT_FIELD ;
    mysqlStateEventMatrix [STATE_FIELD].nextState [0] = STATE_FIELD;
    mysqlStateEventMatrix [STATE_FIELD].handler [0] = &pktField;

    mysqlStateEventMatrix [STATE_FIELD].event [1] = EVENT_END;
    mysqlStateEventMatrix [STATE_FIELD].nextState [1] = STATE_TXT_ROW;
    mysqlStateEventMatrix [STATE_FIELD].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_FIELD_BIN].size = 2;
    mysqlStateEventMatrix [STATE_FIELD_BIN].event [0] = EVENT_FIELD_BIN;
    mysqlStateEventMatrix [STATE_FIELD_BIN].nextState [0] = STATE_FIELD_BIN;
    mysqlStateEventMatrix [STATE_FIELD_BIN].handler [0] = &pktField;

    mysqlStateEventMatrix [STATE_FIELD_BIN].event [1] = EVENT_END;
    mysqlStateEventMatrix [STATE_FIELD_BIN].nextState [1] = STATE_BIN_ROW;
    mysqlStateEventMatrix [STATE_FIELD_BIN].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_TXT_RS].size = 2;
    mysqlStateEventMatrix [STATE_TXT_RS].event [0] = EVENT_NUM_FIELDS;
    mysqlStateEventMatrix [STATE_TXT_RS].nextState [0] = STATE_FIELD;
    mysqlStateEventMatrix [STATE_TXT_RS].handler [0] = &pktNFields;

    mysqlStateEventMatrix [STATE_TXT_RS].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_TXT_RS].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_TXT_RS].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_BIN_RS].size = 2;
    mysqlStateEventMatrix [STATE_BIN_RS].event [0] = EVENT_NUM_FIELDS_BIN;
    mysqlStateEventMatrix [STATE_BIN_RS].nextState [0] = STATE_FIELD_BIN;
    mysqlStateEventMatrix [STATE_BIN_RS].handler [0] = &pktNFields;

    mysqlStateEventMatrix [STATE_BIN_RS].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_BIN_RS].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_BIN_RS].handler [1] = &pktOkOrError;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_END].size = 1;
    mysqlStateEventMatrix [STATE_END].event [0] = EVENT_END;
    mysqlStateEventMatrix [STATE_END].nextState [0] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_END].handler [0] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_TXT_ROW].size = 4;
    mysqlStateEventMatrix [STATE_TXT_ROW].event [0] = EVENT_ROW;
    mysqlStateEventMatrix [STATE_TXT_ROW].nextState [0] = STATE_TXT_ROW;
    mysqlStateEventMatrix [STATE_TXT_ROW].handler [0] = &pktRow;

    mysqlStateEventMatrix [STATE_TXT_ROW].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_TXT_ROW].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_TXT_ROW].handler [1] = &pktOkOrError;

    mysqlStateEventMatrix [STATE_TXT_ROW].event [2] = EVENT_END;
    mysqlStateEventMatrix [STATE_TXT_ROW].nextState [2] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_TXT_ROW].handler [2] = &pktEnd;

    mysqlStateEventMatrix [STATE_TXT_ROW].event [3] = EVENT_END_MULTI_RESULT;
    mysqlStateEventMatrix [STATE_TXT_ROW].nextState [3] = STATE_TXT_RS;
    mysqlStateEventMatrix [STATE_TXT_ROW].handler [3] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_BIN_ROW].size = 3;
    mysqlStateEventMatrix [STATE_BIN_ROW].event [0] = EVENT_ROW;
    mysqlStateEventMatrix [STATE_BIN_ROW].nextState [0] = STATE_BIN_ROW;
    mysqlStateEventMatrix [STATE_BIN_ROW].handler [0] = &pktBinaryRow;

    mysqlStateEventMatrix [STATE_BIN_ROW].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_BIN_ROW].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_BIN_ROW].handler [1] = &pktOkOrError;

    mysqlStateEventMatrix [STATE_BIN_ROW].event [2] = EVENT_END;
    mysqlStateEventMatrix [STATE_BIN_ROW].nextState [2] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_BIN_ROW].handler [2] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_STMT_META].size = 1;
    mysqlStateEventMatrix [STATE_STMT_META].event [0] = EVENT_STMT_META;
    mysqlStateEventMatrix [STATE_STMT_META].nextState [0] = STATE_STMT_PARAM;
    mysqlStateEventMatrix [STATE_STMT_META].handler [0] = &pktStmtMeta;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_STMT_PARAM].size = 2;
    mysqlStateEventMatrix [STATE_STMT_PARAM].event [0] = EVENT_STMT_PARAM;
    mysqlStateEventMatrix [STATE_STMT_PARAM].nextState [0] = STATE_STMT_PARAM;
    mysqlStateEventMatrix [STATE_STMT_PARAM].handler [0] = &pktField;

    mysqlStateEventMatrix [STATE_STMT_PARAM].event [1] = EVENT_END;
    mysqlStateEventMatrix [STATE_STMT_PARAM].nextState [1] = STATE_FIELD_LIST;
    mysqlStateEventMatrix [STATE_STMT_PARAM].handler [1] = &pktEnd;

    /* -------------------------------------------------------------- */
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].size = 2;
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].event [0] = EVENT_STMT_FETCH_RESULT;
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].nextState [0] = STATE_STMT_FETCH_RS;
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].handler [0] = &pktStmtFetchRS;

    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].event [1] = EVENT_OK_OR_ERROR;
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].nextState [1] = STATE_SLEEP;
    mysqlStateEventMatrix [STATE_STMT_FETCH_RS].handler [1] = &pktOkOrError;

    mysqlProtoDestroyOnceControl = PTHREAD_ONCE_INIT;
}

static void
destroyMysqlSharedInstance (void) {
    mysqlProtoInitOnceControl = PTHREAD_ONCE_INIT;
}

static int
initMysqlAnalyzer (void) {
    pthread_once (&mysqlProtoInitOnceControl, initMysqlSharedInstance);
    return 0;
}

static void
destroyMysqlAnalyzer (void) {
    pthread_once (&mysqlProtoDestroyOnceControl, destroyMysqlSharedInstance);
}

static int
initMysqlSharedinfo (mysqlSharedInfoPtr sharedInfo) {
    sharedInfo->protoVer = 0;
    sharedInfo->serverVer = NULL;
    sharedInfo->cliCaps = 0;
    sharedInfo->cliProtoIsV41 = false;
    sharedInfo->conId = 0;
    sharedInfo->maxPktSize = 0;
    sharedInfo->doCompress = false;
    sharedInfo->doSSL = false;
    sharedInfo->userName = NULL;

    return 0;
}

static void
destroyMysqlSharedinfo (mysqlSharedInfoPtr sharedInfo) {
    if (sharedInfo == NULL)
        return;

    free (sharedInfo->serverVer);
    free (sharedInfo->userName);
}

static void *
newMysqlSessionDetail (void) {
    int ret;
    mysqlSessionDetailPtr msd;

    msd = (mysqlSessionDetailPtr) malloc (sizeof (mysqlSessionDetail));
    if (msd == NULL)
        return NULL;

    ret = initMysqlSharedinfo (&msd->sharedInfo);
    if (ret < 0) {
        free (msd);
        return NULL;
    }
    msd->mstate = STATE_NOT_CONNECTED;
    msd->seqId = 0;
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
    /* Destroy mysql sharedInfo state */
    destroyMysqlSharedinfo (&msd->sharedInfo);
    free (msd->reqStmt);
    free (msd->errMsg);

    free (msd);
}

static void *
newMysqlSessionBreakdown (void) {
    mysqlSessionBreakdownPtr msbd;

    msbd = (mysqlSessionBreakdownPtr) malloc (sizeof (mysqlSessionBreakdown));
    if (msbd == NULL)
        return NULL;

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
    mysqlSessionDetailPtr msd = (mysqlSessionDetailPtr) sd;
    mysqlSessionBreakdownPtr msbd = (mysqlSessionBreakdownPtr) sbd;

    if (currSharedInfo->serverVer) {
        msbd->serverVer = strdup (currSharedInfo->serverVer);
        if (msbd->serverVer == NULL) {
            LOGE ("Strdup mysql server version error: %s.\n", strerror (errno));
            resetMysqlSessionDetail (msd);
            return -1;
        }
    } else {
        LOGE ("Mysql server version is NULL.\n");
        resetMysqlSessionDetail (msd);
        return -1;
    }

    if (currSharedInfo->userName) {
        msbd->userName = strdup (currSharedInfo->userName);
        if (msbd->userName == NULL) {
            LOGE ("Strdup mysql userName error: %s.\n", strerror (errno));
            resetMysqlSessionDetail (msd);
            return -1;
        }
    } else {
        LOGE ("Mysql user name is NULL.\n");
        resetMysqlSessionDetail (msd);
        return -1;
    }

    msbd->conId = currSharedInfo->conId;

    /* For MYSQL_BREAKDOWN_RESET_TYPE4 case, reqStmt is NULL */
    if (msd->reqStmt && (msbd->state != MYSQL_BREAKDOWN_RESET_TYPE4)) {
        msbd->reqStmt = strdup (msd->reqStmt);
        if (msbd->reqStmt == NULL) {
            LOGE ("Strdup mysql request error: %s.\n", strerror (errno));
            resetMysqlSessionDetail (msd);
            return -1;
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
                        resetMysqlSessionDetail (msd);
                        return -1;
                    }
                } else {
                    LOGE ("Mysql errMsg is NULL.\n");
                    resetMysqlSessionDetail (msd);
                    return -1;
                }
            }
            msbd->reqSize = msd->reqSize;
            msbd->respSize = msd->respSize;
            msbd->respLatency = (u_int) (msd->respTimeBegin - msd->reqTime);
            msbd->downloadLatency = (u_int) (msd->respTimeEnd - msd->respTimeBegin);
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
            msbd->respLatency = (u_int) (msd->respTimeBegin - msd->reqTime);
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
            resetMysqlSessionDetail (msd);
            return -1;
    }

    resetMysqlSessionDetail (msd);
    return 0;
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
mysqlSessionProcessEstb (timeValPtr tm, void *sd) {
    return;
}

static void
mysqlSessionProcessUrgData (streamDirection direction, char urgData, timeValPtr tm, void *sd) {
    return;
}

static u_int
mysqlSessionProcessData (streamDirection direction, u_char *data, u_int dataLen,
                         timeValPtr tm, void *sd, sessionState *state) {
    u_int parseCount;

    currTime = tm;
    currSessionState = SESSION_ACTIVE;
    currSharedInfo = &((mysqlSessionDetailPtr) sd)->sharedInfo;
    currSessionDetail = (mysqlSessionDetailPtr) sd;

    parseCount = mysqlParserExecute (data, dataLen, direction);
    *state = currSessionState;

    return parseCount;
}

static void
mysqlSessionProcessReset (streamDirection direction, timeValPtr tm, void *sd) {
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
mysqlSessionProcessFin (streamDirection direction, timeValPtr tm, void *sd, sessionState *state) {
    return;
}

protoAnalyzer analyzer = {
    .proto = "MYSQL",
    .initProtoAnalyzer = initMysqlAnalyzer,
    .destroyProtoAnalyzer = destroyMysqlAnalyzer,
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
