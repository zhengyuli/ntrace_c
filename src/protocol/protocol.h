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
typedef void (*sessionProcessUrgeDataCB) (int fromClient, char urgData, void *sd,
                                          timeValPtr tm);
typedef int (*sessionProcessDataCB) (int fromClient, const u_char *data, int dataLen,
                                     void *sd, timeValPtr tm, int *sessionDone);
typedef void (*sessionProcessResetCB) (int fromClient, void *sd, timeValPtr tm,
                                       int *sessionDone);
typedef void (*sessionProcessFinCB) (int fromClient, void *sd, timeValPtr tm,
                                     int *sessionDone);

typedef struct _protoParser protoParser;
typedef protoParser *protoParserPtr;

/* Protocol parser callback */
struct _protoParser {
    initProtoCB initProto;
    destroyProtoCB destroyProto;
    newSessionDetailCB newSessionDetail;
    freeSessionDetailCB freeSessionDetail;
    newSessionBreakdownCB newSessionBreakdown;
    freeSessionBreakdownCB freeSessionBreakdown;
    generateSessionBreakdownCB generateSessionBreakdown;
    sessionBreakdown2JsonCB sessionBreakdown2Json;
    sessionProcessUrgeDataCB sessionProcessUrgData;
    sessionProcessDataCB sessionProcessData;
    sessionProcessResetCB sessionProcessReset;
    sessionProcessFinCB sessionProcessFin;
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
