#ifndef __AGENT_PROTOCOL_H__
#define __AGENT_PROTOCOL_H__

#include <jansson.h>
#include "util.h"

typedef enum {
    STREAM_FROM_CLIENT = 0,
    STREAM_FROM_SERVER = 1
} streamDirection;

/* Protocol analyzer callback definition */
typedef int (*initProtoAnalyzerCB) (void);
typedef void (*destroyProtoAnalyzerCB) (void);
typedef void * (*newSessionDetailCB) (void);
typedef void (*freeSessionDetailCB) (void *sd);
typedef void * (*newSessionBreakdownCB) (void);
typedef void (*freeSessionBreakdownCB) (void *sbd);
typedef int (*generateSessionBreakdownCB) (void *sd, void *sbd);
typedef void (*sessionBreakdown2JsonCB) (json_t *root, void *sd, void *sbd);
typedef void (*sessionProcessEstbCB) (void *sd, timeValPtr tm);
typedef void (*sessionProcessUrgeDataCB) (boolean fromClient, char urgData, void *sd, timeValPtr tm);
typedef u_int (*sessionProcessDataCB) (boolean fromClient, u_char *data, u_int dataLen, void *sd, timeValPtr tm, boolean *sessionDone);
typedef void (*sessionProcessResetCB) (boolean fromClient, void *sd, timeValPtr tm);
typedef void (*sessionProcessFinCB) (boolean fromClient, void *sd, timeValPtr tm, boolean *sessionDone);

typedef struct _protoAnalyzer protoAnalyzer;
typedef protoAnalyzer *protoAnalyzerPtr;

/* Protocol analyzer callback */
struct _protoAnalyzer {
    char proto [32];                                     /**< Protocol type */
    initProtoAnalyzerCB initProtoAnalyzer;               /**< Protocol init callback */
    destroyProtoAnalyzerCB destroyProtoAnalyzer;         /**< Protocol destroy callback */
    newSessionDetailCB newSessionDetail;                 /**< Create new session detail callback */
    freeSessionDetailCB freeSessionDetail;               /**< Free session detail callback */
    newSessionBreakdownCB newSessionBreakdown;           /**< Create new session breakdown callback */
    freeSessionBreakdownCB freeSessionBreakdown;         /**< Free session breakdown callback */
    generateSessionBreakdownCB generateSessionBreakdown; /**< Generate session breakdown callback */
    sessionBreakdown2JsonCB sessionBreakdown2Json;       /**< Translate session breakdown to json callback */
    sessionProcessEstbCB sessionProcessEstb;             /**< Tcp establishment callback */
    sessionProcessUrgeDataCB sessionProcessUrgData;      /**< Urgency data processing callback */
    sessionProcessDataCB sessionProcessData;             /**< Data processing callback */
    sessionProcessResetCB sessionProcessReset;           /**< Tcp reset processing callback */
    sessionProcessFinCB sessionProcessFin;               /**< Tcp fin processing callback */
};

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getProtoAnalyzer (const char *proto);
int
initProtoAnalyzer (void);
void
destroyProtoAnalyzer (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_PROTOCOL_H__ */
