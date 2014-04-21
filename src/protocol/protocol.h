#ifndef __WDM_AGENT_PROTOCOL_H__
#define __WDM_AGENT_PROTOCOL_H__

#include <stdint.h>
#include <json/json.h>

#define MAX_PROTO_NAME_LEN 32

/* Protocol type */
typedef enum {
    PROTO_DEFAULT = 0,
    PROTO_HTTP,
    PROTO_MYSQL,
    PROTO_UNKNOWN
} protoType;

/* Protocol parser callback definition */
typedef int (*initProtoCB) (void);
typedef void (*destroyProtoCB) (void);
typedef void * (*newSessionDetailCB) (void);
typedef void (*freeSessionDetailCB) (void *sd);
typedef void * (*newSessionBreakdownCB) (void);
typedef void (*freeSessionBreakdownCB) (void *sbd);
typedef int (*generateSessionBreakdownCB) (void *sd, void *sbd);
typedef void (*sessionBreakdown2JsonCB) (struct json_object *root, void *sd, void *sbd);
typedef void (*sessionProcessEstbCB) (void *sd, timeValPtr tm);
typedef void (*sessionProcessUrgeDataCB) (int fromClient, char urgData, void *sd,
                                          timeValPtr tm);
typedef int (*sessionProcessDataCB) (int fromClient, const u_char *data, int dataLen,
                                     void *sd, timeValPtr tm, int *sessionDone);
typedef void (*sessionProcessResetCB) (int fromClient, void *sd, timeValPtr tm);
typedef void (*sessionProcessFinCB) (int fromClient, void *sd, timeValPtr tm,
                                     int *sessionDone);

typedef struct _protoParser protoParser;
typedef protoParser *protoParserPtr;

/* Protocol parser callback */
struct _protoParser {
    initProtoCB initProto;                               /**< Protocol init callback <optional> */
    destroyProtoCB destroyProto;                         /**< Protocol destroy callback <optional> */
    newSessionDetailCB newSessionDetail;                 /**< Create new session detail callback <mandatory> */
    freeSessionDetailCB freeSessionDetail;               /**< Free session detail callback <mandatory> */
    newSessionBreakdownCB newSessionBreakdown;           /**< Create new session breakdown callback <mandatory> */
    freeSessionBreakdownCB freeSessionBreakdown;         /**< Free session breakdown callback <mandatory> */
    generateSessionBreakdownCB generateSessionBreakdown; /**< Generate session breakdown callback <mandatory> */
    sessionBreakdown2JsonCB sessionBreakdown2Json;       /**< Translate session breakdown to json callback <mandatory> */
    sessionProcessEstbCB sessionProcessEstb;             /**< Tcp establishment callback <optional> */
    sessionProcessUrgeDataCB sessionProcessUrgData;      /**< Urgency data processing callback <optional> */
    sessionProcessDataCB sessionProcessData;             /**< Data processing callback <mandatory> */
    sessionProcessResetCB sessionProcessReset;           /**< Tcp reset processing callback <optional> */
    sessionProcessFinCB sessionProcessFin;               /**< Tcp fin processing callback <optional> */
};

typedef struct _protoInfo protoInfo;
typedef protoInfo *protoInfoPtr;

/* Protocol info */
struct _protoInfo {
    protoType proto;
    char name [MAX_PROTO_NAME_LEN];
    protoParserPtr parser;
};

/*========================Interfaces definition============================*/
int
initProto (void);
void
destroyProto (void);
protoType
getProtoType (const char *protoName);
const char *
getProtoName (protoType proto);
protoParserPtr
getProtoParser (protoType proto);
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_PROTOCOL_H__ */
