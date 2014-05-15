#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <czmq.h>
#include "util.h"
#include "log.h"

static zctx_t *zmqCtx = NULL;

static void *subThreadStatusSndSock = NULL;
static pthread_mutex_t subThreadStatusSndSockLock = PTHREAD_MUTEX_INITIALIZER;
static void *subThreadStatusRcvSock = NULL;
static pthread_mutex_t subThreadStatusRcvSockLock = PTHREAD_MUTEX_INITIALIZER;

void
statusPush (const char *msg) {
    pthread_mutex_lock (&subThreadStatusSndSockLock);
    zstr_send (subThreadStatusSndSock, msg);
    pthread_mutex_unlock (&subThreadStatusSndSockLock);
}

const char *
statusRecv (void)
{
    const char * status;

    pthread_mutex_lock (&subThreadStatusRcvSockLock);
    status = zstr_recv (subThreadStatusRcvSock);
    pthread_mutex_unlock (&subThreadStatusRcvSockLock);
}

const char *
statusRecvNonBlock (void)
{
    const char * status;

    pthread_mutex_lock (&subThreadStatusRcvSockLock);
    status = zstr_recv_nowait (subThreadStatusRcvSock);
    pthread_mutex_unlock (&subThreadStatusRcvSockLock);
}

inline void *
newZSock (int type) {
    return zsocket_new (zmqCtx, type);
}

int
initMessageChannel (void) {
    int ret;

    zmqCtx = zctx_new ();
    if (zmqCtx == NULL)
        ret = -1;
    zctx_set_linger (zmqCtx, 0);

    subThreadStatusSndSock = zsocket_new (zmqCtx, ZMQ_PUSH);
    if (subThreadStatusSndSock == NULL) {
        zctx_destroy (&zmqCtx);
        return -1;
    }

    subThreadStatusRcvSock = zsocket_new (zmqCtx, ZMQ_PULL);
    if (statusRecvSock == NULL) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        return -1;
    }

    ret = zsocket_bind (subThreadStatusRcvSock, SUBTHREAD_STATUS_REPORT_CHANNEL);
    if (ret < 0) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        subThreadStatusRcvSock = NULL;
        return -1;
    }

    ret = zsocket_connect (subThreadStatusSndSock, SUBTHREAD_STATUS_REPORT_CHANNEL);
    if (ret < 0) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        subThreadStatusRcvSock = NULL;
        return -1;
    }

    return 0;
}

void
destroyMessageChannel (void) {
    if (zmqCtx == NULL)
        return;
    
    zctx_destroy (&zmqCtx);
    subThreadStatusSndSock = NULL;
    subThreadStatusRcvSock = NULL;
}
