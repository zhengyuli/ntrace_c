#include <stdio.h>
#include <stdlib.h>
#include <wda/proto_detector.h>
#include "template_detector.h"

static int
initTemplateDetector (void) {
    return 0;
}

static void
destroyTemplateDetector (void) {
    return;
}

static char *
templateSessionDetectProto (streamDirection direction, u_char *data,
                            u_int dataLen) {
    return TEMPLATE_PROTO_NAME;
}

protoDetector detector = {
    .proto = TEMPLATE_PROTO_NAME,
    .initProtoDetector = initTemplateDetector,
    .destroyProtoDetector = destroyTemplateDetector,
    .sessionDetectProto = templateSessionDetectProto
};
