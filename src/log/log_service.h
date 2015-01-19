#ifndef __LOG_SERVICE__
#define __LOG_SERVICE__

#include <czmq.h>

#define LOG_SERVICE_LOG_RECV_PORT 59001
#define LOG_SERVICE_LOG_PUBLISH_PORT 59002

typedef enum {
    LOG_SERVICE_STATUS_READY,
    LOG_SERVICE_STATUS_EXIT
} logServiceStatus;

/*========================Interfaces definition============================*/
void *
getLogServiceStatusRecvSock (void);
int
logServiceStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
int
initLogService (void);
void
destroyLogService (void);
/*=======================Interfaces definition end=========================*/

#endif /* __LOG_SERVICE__ */
