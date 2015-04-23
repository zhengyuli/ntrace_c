#include <stdio.h>
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
    u_int i;
    u_int preLen;

    if (direction == STREAM_FROM_CLIENT) {
        /* Normal */
        if (dataLen >= 7 && memcmp ("DELETE ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 4 && memcmp ("GET ", data, 4) == 0)
            preLen = 4;
        else if (dataLen >= 5 && memcmp ("HEAD ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 5 && memcmp ("POST ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 4 && memcmp ("PUT ", data, 4) == 0)
            preLen = 4;
        /* Pathological */
        else if (dataLen >= 8 && memcmp ("CONNECT ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 8 && memcmp ("OPTIONS ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 6 && memcmp ("TRACE ", data, 6) == 0)
            preLen = 6;
        /* Webdav */
        else if (dataLen >= 5 && memcmp ("COPY ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 5 && memcmp ("LOCK ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 6 && memcmp ("MKCOL ", data, 6) == 0)
            preLen = 6;
        else if (dataLen >= 5 && memcmp ("MOVE ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 9 && memcmp ("PROPFIND ", data, 9) == 0)
            preLen = 9;
        else if (dataLen >= 10 && memcmp ("PROPPATCH ", data, 10) == 0)
            preLen = 7;
        else if (dataLen >= 7 && memcmp ("SEARCH ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 7 && memcmp ("UNLOCK ", data, 7) == 0)
            preLen = 7;
        /* Subversion */
        else if (dataLen >= 7 && memcmp ("REPORT ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 11 && memcmp ("MKACTIVITY ", data, 11) == 0)
            preLen = 11;
        else if (dataLen >= 9 && memcmp ("CHECKOUT ", data, 9) == 0)
            preLen = 9;
        else if (dataLen >= 6 && memcmp ("MERGE ", data, 6) == 0)
            preLen = 6;
        /* Upnp */
        else if (dataLen >= 8 && memcmp ("MSEARCH ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 7 && memcmp ("NOTIFY ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 10 && memcmp ("SUBSCRIBE ", data, 10) == 0)
            preLen = 12;
        else if (dataLen >= 12 && memcmp ("UNSUBSCRIBE ", data, 12) == 0)
            preLen = 12;
        /* RFC-5789 */
        else if (dataLen >= 6 && memcmp ("PATCH ", data, 6) == 0)
            preLen = 6;
        else if (dataLen >= 6 && memcmp ("PURGE ", data, 6) == 0)
            preLen = 6;
        else
            preLen = 0;

        if (preLen) {
            /* Found the first line end flag '\r\n' */
            for (i = 0; i < dataLen - 1; i++) {
                if (data [i] == '\r' &&
                    data [i + 1] == '\n' &&
                    (memcmp ("HTTP/1.0", data + i - 8, 8) == 0 ||
                     memcmp ("HTTP/1.1", data + i - 8, 8) == 0)) {
                    return HTTP_PROTO_NAME;
                }
            }

            return NULL;
        } else
            return NULL;
    } else {
        if (dataLen >= 8 &&
            (memcmp ("HTTP/1.0", data, 8) == 0 ||
             memcmp ("HTTP/1.1", data, 8) == 0))
            return HTTP_PROTO_NAME;
        else
            return NULL;
    }
}

protoDetector httpDetector = {
    .proto = HTTP_PROTO_NAME,
    .initProtoDetector = initHttpDetector,
    .destroyProtoDetector = destroyHttpDetector,
    .sessionDetectProto = httpSessionDetectProto
};
