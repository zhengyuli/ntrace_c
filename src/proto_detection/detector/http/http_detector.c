#include <stdlib.h>
#include "proto_detector.h"
#include "http_detector.h"

static int
initHttpDetector (void) {
    return 0;
}

static void
destroyHttpDetector (void) {
    return;
}

static char *
httpSessionDetectProto (streamDirection direction, u_char *data,
                        u_int dataLen) {
    return "HTTP";
}

protoDetector httpDetector = {
    .proto = "HTTP",
    .initProtoDetector = initHttpDetector,
    .destroyProtoDetector = destroyHttpDetector,
    .sessionDetectProto = httpSessionDetectProto
};
