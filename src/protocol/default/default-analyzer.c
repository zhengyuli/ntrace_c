#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <json/json.h>
#include "util.h"
#include "byte-order.h"
#include "default-analyzer.h"

static void *
newDefaultSessionDetail (void) {
    defaultSessionDetailPtr dsd;

    dsd = (defaultSessionDetailPtr) malloc (sizeof (defaultSessionDetail));
    if (dsd) {
        dsd->serverTimeBegin = 0;
        dsd->serverTimeEnd = 0;
        dsd->exchangeSize = 0;
        return dsd;
    } else
        return NULL;
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
    if (dsbd) {
        dsbd->serverLatency = 0;
        dsbd->exchangeSize = 0;
        return dsbd;
    } else
        return NULL;
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

    dsbd->serverLatency = dsd->serverTimeEnd - dsd->serverTimeBegin;
    dsbd->exchangeSize = dsd->exchangeSize;

    return 0;
}

static void
defaultSessionBreakdown2Json (struct json_object *root, void *sd, void *sbd) {
    char buf [64];
    defaultSessionBreakdownPtr dsbd = (defaultSessionBreakdownPtr) sbd;

    UINT64_TO_STRING (buf, dsbd->serverLatency);
    json_object_object_add (root, DEFAULT_SBKD_SERVER_LATENCY, json_object_new_string (buf));
    UINT64_TO_STRING (buf, dsbd->exchangeSize);
    json_object_object_add (root, DEFAULT_SBKD_EXCHANGE_SIZE, json_object_new_string (buf));
}

static int
defaultSessionProcessData (int fromClient, const u_char *data, int dataLen, void *sd, timeValPtr tm, int *sessionDone) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    if (!dsd->serverTimeBegin)
        dsd->serverTimeBegin = timeVal2MilliSecond (tm);
    dsd->exchangeSize += dataLen;
    return dataLen;
}

static void
defaultSessionProcessReset (int fromClient, void *sd, timeValPtr tm, int *sessionDone) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    dsd->serverTimeEnd = timeVal2MilliSecond (tm);
    *sessionDone = 1;
}

static void
defaultSessionProcessFin (int fromClient, void *sd, timeValPtr tm, int *sessionDone) {
    defaultSessionDetailPtr dsd = (defaultSessionDetailPtr) sd;

    if (dsd->serverTimeEnd == 0)
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
    else {
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
        *sessionDone = 1;
    }
}

protoParser defaultParser = {
    .initProto = NULL,
    .destroyProto = NULL,
    .newSessionDetail = newDefaultSessionDetail,
    .freeSessionDetail = freeDefaultSessionDetail,
    .newSessionBreakdown = newDefaultSessionBreakdown,
    .freeSessionBreakdown = freeDefaultSessionBreakdown,
    .generateSessionBreakdown = generateDefaultSessionBreakdown,
    .sessionBreakdown2Json = defaultSessionBreakdown2Json,
    .sessionProcessUrgData = NULL,
    .sessionProcessData = defaultSessionProcessData,
    .sessionProcessReset = defaultSessionProcessReset,
    .sessionProcessFin = defaultSessionProcessFin
};
