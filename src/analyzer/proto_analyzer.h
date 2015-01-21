#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <jansson.h>
#include "util.h"

typedef enum {
    STREAM_FROM_CLIENT = 0,
    STREAM_FROM_SERVER = 1
} streamDirection;

typedef enum {
    SESSION_ACTIVE = 0,
    SESSION_DONE = 1
} sessionState;

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
typedef void (*sessionProcessUrgeDataCB) (streamDirection direction, char urgData, void *sd, timeValPtr tm);
typedef u_int (*sessionProcessDataCB) (streamDirection direction, u_char *data, u_int dataLen, void *sd,
                                       timeValPtr tm, sessionState *state);
typedef void (*sessionProcessResetCB) (streamDirection direction, void *sd, timeValPtr tm);
typedef void (*sessionProcessFinCB) (streamDirection direction, void *sd, timeValPtr tm, sessionState *state);

typedef struct _protoAnalyzer protoAnalyzer;
typedef protoAnalyzer *protoAnalyzerPtr;

/* Proto analyzer callback */
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
getProtoAnalyzer (char *proto);
int
initProtoAnalyzer (void);
void
destroyProtoAnalyzer (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROTOCOL_H__ */
