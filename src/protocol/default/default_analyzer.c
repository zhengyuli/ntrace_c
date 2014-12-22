#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <jansson.h>
#include "util.h"
#include "default_analyzer.h"

static int
initDefaultProto (void) {
    return 0;
}

static void
destroyDefaultProto (void) {
    return;
}

static void *
newDefaultSessionDetail (void) {
    defaultSessionDetailPtr dsd;

    dsd = (defaultSessionDetailPtr) malloc (sizeof (defaultSessionDetail));
    if (dsd == NULL)
        return NULL;

    dsd->exchangeSize = 0;
    dsd->serverTimeBegin = 0;
    dsd->serverTimeEnd = 0;
    return dsd;
}

static void
freeDefaultSessionDetail (void *sd) {
    if (sd == NULL)
        return;

    free (sd);
}

static void *
newDefaultSessionBreakdown (void) {
    defaultSessionBreakdownPtr dsbd;

    dsbd = (defaultSessionBreakdownPtr) malloc (sizeof (defaultSessionBreakdown));
    if (dsbd == NULL)
        return NULL;

    dsbd->exchangeSize = 0;
    dsbd->serverLatency = 0;
    return dsbd;
}

static void
freeDefaultSessionBreakdown (void *sbd) {
    if (sbd == NULL)
        return;

    free (sbd);
}

static int
generateDefaultSessionBreakdown (void *sd, void *sbd) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;
    defaultSessionBreakdownPtr dsbd = (defaultSessionBreakdownPtr) sbd;

    dsbd->exchangeSize = dsd->exchangeSize;
    dsbd->serverLatency = (u_int) (dsd->serverTimeEnd - dsd->serverTimeBegin);

    return 0;
}

static void
defaultSessionBreakdown2Json (json_t *root, void *sd, void *sbd) {
    defaultSessionBreakdownPtr dsbd = (defaultSessionBreakdownPtr) sbd;

    json_object_set_new (root, DEFAULT_SBKD_EXCHANGE_SIZE, json_integer (dsbd->exchangeSize));
    json_object_set_new (root, DEFAULT_SBKD_SERVER_LATENCY, json_integer (dsbd->serverLatency));
}

static void
defaultSessionProcessEstb (void *sd, timeValPtr tm) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    dsd->serverTimeBegin = timeVal2MilliSecond (tm);
}

static void
defaultSessionProcessUrgData (boolean fromClient, char urgData, void *sd, timeValPtr tm) {
    return;
}

static u_int
defaultSessionProcessData (boolean fromClient, u_char *data, u_int dataLen, void *sd, timeValPtr tm, boolean *sessionDone) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    dsd->exchangeSize += dataLen;
    return dataLen;
}

static void
defaultSessionProcessReset (boolean fromClient, void *sd, timeValPtr tm) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    dsd->serverTimeEnd = timeVal2MilliSecond (tm);
}

static void
defaultSessionProcessFin (boolean fromClient, void *sd, timeValPtr tm, boolean *sessionDone) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    if (dsd->serverTimeEnd == 0)
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
    else {
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
        *sessionDone = true;
    }
}

protoParser defaultParser = {
    .initProto = initDefaultProto,
    .destroyProto = destroyDefaultProto,
    .newSessionDetail = newDefaultSessionDetail,
    .freeSessionDetail = freeDefaultSessionDetail,
    .newSessionBreakdown = newDefaultSessionBreakdown,
    .freeSessionBreakdown = freeDefaultSessionBreakdown,
    .generateSessionBreakdown = generateDefaultSessionBreakdown,
    .sessionBreakdown2Json = defaultSessionBreakdown2Json,
    .sessionProcessEstb = defaultSessionProcessEstb,
    .sessionProcessUrgData = defaultSessionProcessUrgData,
    .sessionProcessData = defaultSessionProcessData,
    .sessionProcessReset = defaultSessionProcessReset,
    .sessionProcessFin = defaultSessionProcessFin
};
