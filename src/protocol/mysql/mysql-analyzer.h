#ifndef __WDM_AGENT_MYSQL_ANALYZER_H__
#define __WDM_AGENT_MYSQL_ANALYZER_H__

#include <stdint.h>
#include "util.h"
#include "protocol.h"

#define G2(A) ((uint16_t) (((uint16_t) ((u_char) (A) [0])) +        \
                           ((uint16_t) ((u_char) (A) [1]) << 8)))

#define G3(A) ((uint32_t) (((uint32_t) ((u_char) (A) [0])) +            \
                           (((uint32_t) ((u_char) (A) [1])) << 8) +     \
                           (((uint32_t) ((u_char) (A) [2])) << 16)))

#define G4(A) ((uint32_t) (((uint32_t) ((u_char) (A) [0])) +            \
                           (((uint32_t) ((u_char) (A) [1])) << 8) +     \
                           (((uint32_t) ((u_char) (A) [2])) << 16) +    \
                           (((uint32_t) ((u_char) (A) [3])) << 24)))

#define G8(A) ((uint64_t) (((uint64_t) ((u_char) (A) [0])) +            \
                           (((uint64_t) ((u_char) (A) [1])) << 8) +     \
                           (((uint64_t) ((u_char) (A) [2])) << 16) +    \
                           (((uint64_t) ((u_char) (A) [3])) << 24) +    \
                           (((uint64_t) ((u_char) (A) [3])) << 32) +    \
                           (((uint64_t) ((u_char) (A) [3])) << 40) +    \
                           (((uint64_t) ((u_char) (A) [3])) << 48) +    \
                           (((uint64_t) ((u_char) (A) [3])) << 56)))

#define MATCH(a, b) (a == b ? 1 : 0)

/* Mysql server command */
typedef enum {
    /* 0 */
    COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST,
    /* 5 */
    COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
    /* 10 */
    COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
    /* 15 */
    COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP, COM_TABLE_DUMP,
    /* 20 */
    COM_CONNECT_OUT, COM_REGISTER_SLAVE, COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA,
    /* 25 */
    COM_STMT_CLOSE, COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON,
    /* 30 */
    COM_BINLOG_DUMP_GTID, COM_RESET_CONNECTION,
    /* Must be last */
    COM_UNKNOWN
} mysqlServerCommand;

/* Mysql server command name */
static const char *mysqlCommandName [] = {
    /* 0 */
    "COM_SLEEP", "COM_QUIT", "COM_INIT_DB", "COM_QUERY", "COM_FIELD_LIST",
    /* 5 */
    "COM_CREATE_DB", "COM_DROP_DB", "COM_REFRESH", "COM_SHUTDOWN", "COM_STATISTICS",
    /* 10 */
    "COM_PROCESS_INFO", "COM_CONNECT", "COM_PROCESS_KILL", "COM_DEBUG", "COM_PING",
    /* 15 */
    "COM_TIME", "COM_DELAYED_INSERT", "COM_CHANGE_USER", "COM_BINLOG_DUMP", "COM_TABLE_DUMP",
    /* 20 */
    "COM_CONNECT_OUT", "COM_REGISTER_SLAVE", "COM_STMT_PREPARE", "COM_STMT_EXECUTE", "COM_STMT_SEND_LONG_DATA",
    /* 25 */
    "COM_STMT_CLOSE", "COM_STMT_RESET", "COM_SET_OPTION", "COM_STMT_FETCH", "COM_DAEMON",
    /* 30 */
    "COM_BINLOG_DUMP_GTID", "COM_RESET_CONNECTION",
    /* Must be last */
    "COM_UNKNOWN"
};

/* Mysql client capabilities flag */
#define CLIENT_LONG_PASSWORD 1         /* new more secure passwords */
#define CLIENT_FOUND_ROWS 2            /* Found instead of affected rows */
#define CLIENT_LONG_FLAG 4             /* Get all column flags */
#define CLIENT_CONNECT_WITH_DB 8       /* One can specify db on connect */
#define CLIENT_NO_SCHEMA 16            /* Don't allow database.table.column */
#define CLIENT_COMPRESS 32             /* Can use compression protocol */
#define CLIENT_ODBC 64                 /* Odbc client */
#define CLIENT_LOCAL_FILES 128         /* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE 256        /* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41 512         /* New 4.1 protocol */
#define CLIENT_INTERACTIVE 1024        /* This is an interactive client */
#define CLIENT_SSL 2048                /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE 4096     /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS 8192       /* Client knows about transactions */
#define CLIENT_RESERVED 16384          /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 32768 /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS 65536  /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS 131072    /* Enable/disable multi-results */

/* Mysql server status */
#define SERVER_STATUS_IN_TRANS 1           /* Transaction has started */
#define SERVER_STATUS_AUTOCOMMIT 2         /* Server in auto_commit mode */
#define SERVER_STATUS_MORE_RESULTS 4       /* More results on server */
#define SERVER_MORE_RESULTS_EXISTS 8       /* Multi query - next query exists */
#define SERVER_QUERY_NO_GOOD_INDEX_USED 16
#define SERVER_QUERY_NO_INDEX_USED 32
#define SERVER_STATUS_CURSOR_EXISTS 64
#define SERVER_STATUS_LAST_ROW_SENT 128
#define SERVER_STATUS_DB_DROPPED 256       /* A database was dropped */
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES 512

/* Mysql field flag */
#define NOT_NULL_FLAG 1            /* Field can't be NULL */
#define PRI_KEY_FLAG 2             /* Field is part of a primary key */
#define UNIQUE_KEY_FLAG 4          /* Field is part of a unique key */
#define MULTIPLE_KEY_FLAG 8        /* Field is part of a key */
#define BLOB_FLAG 16               /* Field is a blob */
#define UNSIGNED_FLAG 32           /* Field is unsigned */
#define ZEROFILL_FLAG 64           /* Field is zerofill */
#define BINARY_FLAG 128            /* Field is binary   */
#define ENUM_FLAG 256              /* field is an enum */
#define AUTO_INCREMENT_FLAG 512    /* field is a autoincrement field */
#define TIMESTAMP_FLAG 1024        /* Field is a timestamp */
#define SET_FLAG 2048              /* field is a set */
#define NO_DEFAULT_VALUE_FLAG 4096 /* Field doesn't have default value */
#define NUM_FLAG 32768             /* Field is num (for clients) */

/* Mysql field type */
typedef enum {
    MYSQL_TYPE_DECIMAL,
    MYSQL_TYPE_TINY,
    MYSQL_TYPE_SHORT,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_FLOAT,
    MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_NULL,
    MYSQL_TYPE_TIMESTAMP,
    MYSQL_TYPE_LONGLONG,
    MYSQL_TYPE_INT24,
    MYSQL_TYPE_DATE,
    MYSQL_TYPE_TIME,
    MYSQL_TYPE_DATETIME,
    MYSQL_TYPE_YEAR,
    MYSQL_TYPE_NEWDATE,
    MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_NEWDECIMAL = 246,
    MYSQL_TYPE_ENUM = 247,
    MYSQL_TYPE_SET = 248,
    MYSQL_TYPE_TINY_BLOB = 249,
    MYSQL_TYPE_MEDIUM_BLOB = 250,
    MYSQL_TYPE_LONG_BLOB = 251,
    MYSQL_TYPE_BLOB = 252,
    MYSQL_TYPE_VAR_STRING = 253,
    MYSQL_TYPE_STRING = 254,
    MYSQL_TYPE_GEOMETRY = 255
} mysqlFieldType;

typedef enum {
    STATE_NOT_CONNECTED,
    STATE_CLIENT_HANDSHAKE,
    STATE_SECURE_AUTH,
    STATE_SLEEP,
    STATE_PONG,
    STATE_OK_OR_ERROR,
    STATE_STATISTICS,
    STATE_FIELD_LIST,
    STATE_FIELD,
    STATE_FIELD_BIN,
    STATE_TXT_RS,
    STATE_BIN_RS,
    STATE_END,
    STATE_TXT_ROW,
    STATE_BIN_ROW,
    STATE_STMT_META,
    STATE_STMT_PARAM
} mysqlState;

#define MYSQL_STATES_NUM 17

typedef enum {
    // Events 0-32 are mysqlServerCommand
    EVENT_SERVER_HANDSHAKE = 33,
    EVENT_CLIENT_HANDSHAKE,
    EVENT_SECURE_AUTH,
    EVENT_OK_OR_ERROR,
    EVENT_END,
    EVENT_NUM_FIELDS,
    EVENT_STATISTICS,
    EVENT_ROW,
    EVENT_FIELD,
    EVENT_FL_FIELD,
    EVENT_END_MULTI_RESULT,
    EVENT_STMT_META,
    EVENT_STMT_PARAM,
    EVENT_NUM_FIELDS_BIN,
    EVENT_FIELD_BIN,
    EVENT_UNKNOWN
} mysqlEvent;

typedef struct _mysqlHeader mysqlHeader;
typedef mysqlHeader *mysqlHeaderPtr;

/* Normal mysql header */
struct _mysqlHeader {
    uint32_t payloadLen:24, pktId:8;
};

typedef struct _mysqlCompHeader mysqlCompHeader;
typedef mysqlCompHeader *mysqlCompHeaderPtr;

/* Compressed mysql header */
struct _mysqlCompHeader {
    uint32_t compPlayloadLen:24, compPktId:8;
    uint32_t payloadLen:24;
};

#define MYSQL_HEADER_SIZE 4
#define MYSQL_COMPRESSED_HEADER_SIZE 7

typedef struct _mysqlParserState mysqlParserState;
typedef mysqlParserState *mysqlParserStatePtr;

struct _mysqlParserState {
    int protoVer;                       /**< Mysql protocol version */
    char *serverVer;                    /**< Mysql server version */
    int cliCaps;                        /**< Mysql client capability flags */
    char cliProtoV41;                   /**< Mysql client protocol V41 flag */
    int conId;                          /**< Mysql connection id */
    unsigned int maxPktSize;            /**< Mysq max packet size support */
    char doCompress;                    /**< Mysql client do compression flag */
    char doSSL;                         /**< Mysql client authentication with SSL flag */
    char *userName;                     /**< Mysql user name to access */
    int seqId;                          /**< Mysql sequence id */
    char state;                         /**< Mysql session state */
    char event;                         /**< Mysql session event */
};

typedef int (*mysqlHandler) (mysqlParserStatePtr parser, const u_char *payload,
                             int payloadLen, int fromClient);

#define MAX_EVENTS_PER_STATE 15

typedef struct _mysqlStateEvents mysqlStateEvents;
typedef mysqlStateEvents *mysqlStateEventsPtr;

struct _mysqlStateEvents {
    u_char numEvents;
    u_char event [MAX_EVENTS_PER_STATE];
    u_char nextState [MAX_EVENTS_PER_STATE];
    mysqlHandler handler [MAX_EVENTS_PER_STATE];
};

typedef enum {
    MYSQL_OK = 0,
    MYSQL_ERROR,
    MYSQL_RESET_TYPE1,          /**< reset during request */
    MYSQL_RESET_TYPE2,          /**< reset before response */
    MYSQL_RESET_TYPE3           /**< reset during response */
} mysqlState

typedef struct _mysqlSessionDetail mysqlSessionDetail;
typedef mysqlSessionDetail *mysqlSessionDetailPtr;

struct _mysqlSessionDetail {
    mysqlParserState parser;            /**< Mysql parser */
    char *reqStmt;                      /**< Mysql request statement */
    uint8_t state;                      /**< Mysql state */
    uint16_t errCode;                   /**< Mysql error code */
    uint32_t sqlState;                  /**< Mysql sql state */
    char *errMsg;                       /**< Mysql error message */
    uint64_t reqSize;                   /**< Mysql request size */
    uint64_t responseSize;              /**< Mysql response size */
    uint64_t requestTime;               /**< Mysql request time */
    uint64_t responseTime;              /**< Mysql response time */
};

typedef struct _mysqlSessionBreakdown mysqlSessionBreakdown;
typedef mysqlSessionBreakdown *mysqlSessionBreakdownPtr;

struct _mysqlSessionBreakdown {
    char *serverVer;                    /**< Mysql server version */
    char *userName;                     /**< Mysql user name */
    uint64_t conId;                     /**< Mysql connection id */
    char *reqStmt;                      /**< Mysql request statement */
    uint16_t state;                     /**< Mysql state */
    uint16_t errCode;                   /**< Mysql error code */
    uint32_t sqlState;                  /**< Mysql sql state */
    char *errMsg;                       /**< Mysql error message */
    uint64_t reqSize;                   /**< Mysql request size */
    uint64_t respSize;                  /**< Mysql response size */
    uint64_t respLatency;               /**< Mysql response latency */
};

/* Mysql session breakdown json key definitions */
#define MYSQL_SBKD_SERVER_VERSION      "mysql_server_version"
#define MYSQL_SBKD_USER_NAME           "mysql_user_name"
#define MYSQL_SBKD_CONNECTION_ID       "mysql_connection_id"
#define MYSQL_SBKD_REQUEST_STATEMENT   "mysql_request_statement"
#define MYSQL_SBKD_STATE               "mysql_state"
#define MYSQL_SBKD_ERROR_CODE          "mysql_error_code"
#define MYSQL_SBKD_SQL_STATE           "mysql_sql_state"
#define MYSQL_SBKD_ERROR_MESSAGE       "mysql_error_message"
#define MYSQL_SBKD_REQUEST_SIZE        "mysql_request_size"
#define MYSQL_SBKD_RESPONSE_SIZE       "mysql_response_size"
#define MYSQL_SBKD_RESPONSE_LATENCY    "mysql_response_latency"

/*========================Interfaces definition============================*/
extern protoParser mysqlParser;
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_MYSQL_ANALYZER_H__ */
