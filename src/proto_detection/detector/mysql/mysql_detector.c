#include <stdio.h>
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
    u_int i;
    u_int len, seqId;

    /* Min length */
    if (dataLen > 37) {
        len = ((u_int) data [0]) +
              (((u_int) data [1]) << 8) +
              (((u_int) data [2]) << 16);
        seqId = (u_int) data [3];

        if (len == (dataLen - 4)) {
            if (direction == STREAM_FROM_CLIENT &&
                seqId == 1) {
                /* Check initial client handshake */
                for (i = 13; i < 36; i++) {
                    if (data [i] != 0x00)
                        return NULL;
                }
                return MYSQL_PROTO_NAME;
            } else if (direction == STREAM_FROM_SERVER &&
                       seqId == 0 &&
                       data [5] > 0x30 &&  /* Server version > 0 */
                       data [5] < 0x37 &&  /* Server version < 7 */
                       data [6] == 0x2e) {
                /* Check initial server handshake */
                for (i = 7; i + 13 <= dataLen; i++) {
                    if (data [i] == 0x00 && data [i + 13] == 0x00)
                        return MYSQL_PROTO_NAME;
                }
            }
        }
    }

    return NULL;
}

protoDetector mysqlDetector = {
    .proto = MYSQL_PROTO_NAME,
    .initProtoDetector = initMysqlDetector,
    .destroyProtoDetector = destroyMysqlDetector,
    .sessionDetectProto = mysqlSessionDetectProto
};
