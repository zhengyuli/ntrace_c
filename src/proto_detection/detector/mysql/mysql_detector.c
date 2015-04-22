#include <stdlib.h>
#include "proto_detector.h"
#include "mysql_detector.h"

static int
initMysqlDetector (void) {
    return 0;
}

static void
destroyMysqlDetector (void) {
    return;
}

static char *
mysqlSessionDetectProto (streamDirection direction, u_char *data,
                         u_int dataLen) {
    return "MYSQL";
}

protoDetector mysqlDetector = {
    .proto = "MYSQL",
    .initProtoDetector = initMysqlDetector,
    .destroyProtoDetector = destroyMysqlDetector,
    .sessionDetectProto = mysqlSessionDetectProto
};
