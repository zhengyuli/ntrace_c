#ifndef __LOG_SERVICE__
#define __LOG_SERVICE__

#include <czmq.h>

#define LOG_SERVICE_LOG_RECV_PORT 50001
#define LOG_SERVICE_LOG_PUBLISH_PORT 50002

typedef enum {
    LOG_SERVICE_STATUS_READY,
    LOG_SERVICE_STATUS_EXIT_NORMALLY,
    LOG_SERVICE_STATUS_EXIT_ABNORMALLY
} logServiceStatus;

typedef struct _logServiceCtxt logServiceCtxt;
typedef logServiceCtxt *logServiceCtxtPtr;

struct _logServiceCtxt {
    zctx_t *zmqCtxt;                    /**< Log service zmq context */
    void *statusSendSock;               /**< Log service status send sock */
    void *statusRecvSock;               /**< Log service status receive sock */
    void *logRecvSock;                  /**< Log service log receive sock */
    pthread_t tid;                      /**< Log service thread id */
};

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
