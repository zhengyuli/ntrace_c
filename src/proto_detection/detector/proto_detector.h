#ifndef __PROTO_DETECTOR_H__
#define __PROTO_DETECTOR_H__

#include <stdlib.h>
#include "util/util.h"

#define MAX_PROTO_DETECTOR_NUM 256

typedef enum {
    STREAM_FROM_CLIENT = 0,
    STREAM_FROM_SERVER = 1
} streamDirection;

/*=================Proto analyzer callbacks definition=====================*/
/**
 * @brief Proto detector init function.
 *        This callback will be called when proto detector module
 *        load this proto detector and do proto detector initialization.
 *
 * @return 0 if success else -1
 */
typedef int (*initProtoDetectorCB) (void);

/**
 * @brief Proto detector destroy function.
 *        This callback will be called when proto detector module exit,
 *        it will destroy proto detector context.
 */
typedef void (*destroyProtoDetectorCB) (void);

/**
 * @brief Tcp proto detect callback.
 *        This callback will be called when receive application proto data, this callback
 *        will process data and return proto name if proto match.
 *
 * @param direction data flow direction
 * @param data application proto data
 * @param dataLen application proto data length
 *
 * @return proto name if detected, else NULL
 */
typedef char * (*sessionDetectProtoCB) (streamDirection direction, u_char *data,
                                        u_int dataLen);
/*===============Proto analyzer callbacks definition end===================*/

typedef struct _protoDetector protoDetector;
typedef protoDetector *protoDetectorPtr;

struct _protoDetector {
    char proto [32];                             /**< Proto name */
    initProtoDetectorCB initProtoDetector;       /**< Proto detector init callback */
    destroyProtoDetectorCB destroyProtoDetector; /**< Proto detector destroy callback */
    sessionDetectProtoCB sessionDetectProto;     /**< Proto detector detect callback */
};

/*========================Interfaces definition============================*/
char *
protoDetect (streamDirection direction, u_char *data, u_int dataLen);
int
initProtoDetector (void);
void
destroyProtoDetector (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROTO_DETECTOR_H__ */
