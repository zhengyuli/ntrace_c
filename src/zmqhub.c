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
static void *subThreadStatusRecvSock = NULL;
static pthread_mutex_t subThreadStatusRecvSockLock = PTHREAD_MUTEX_INITIALIZER;

void
subThreadStatusPush (const char *msg) {
    pthread_mutex_lock (&subThreadStatusSndSockLock);
    zstr_send (subThreadStatusSndSock, msg);
    pthread_mutex_unlock (&subThreadStatusSndSockLock);
}

const char *
subThreadStatusRecv (void)
{
    const char * status;

    pthread_mutex_lock (&subThreadStatusRecvSockLock);
    status = zstr_recv (subThreadStatusRecvSock);
    pthread_mutex_unlock (&subThreadStatusRecvSockLock);
}

const char *
subThreadStatusRecvNonBlock (void)
{
    const char * status;

    pthread_mutex_lock (&subThreadStatusRecvSockLock);
    status = zstr_recv_nowait (subThreadStatusRecvSock);
    pthread_mutex_unlock (&subThreadStatusRecvSockLock);
}

inline void *
getSubThreadStatusRecvSock (void) {
    return subThreadStatusRecvSock;
}

void *
newZSock (int type) {
    return zsocket_new (zmqCtx, type);
}

void
closeZSock (void *sock) {
    zsocket_destroy (zmqCtx, sock);
}

int
initZmqhub (void) {
    int ret;

    zmqCtx = zctx_new ();
    if (zmqCtx == NULL)
        ret = -1;
    zctx_set_linger (zmqCtx, 0);
    zctx_set_iothreads (zmqCtx, 5);

    subThreadStatusSndSock = zsocket_new (zmqCtx, ZMQ_PUSH);
    if (subThreadStatusSndSock == NULL) {
        zctx_destroy (&zmqCtx);
        return -1;
    }

    subThreadStatusRecvSock = zsocket_new (zmqCtx, ZMQ_PULL);
    if (statusRecvSock == NULL) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        return -1;
    }

    ret = zsocket_bind (subThreadStatusRecvSock, SUBTHREAD_STATUS_REPORT_CHANNEL);
    if (ret < 0) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        subThreadStatusRecvSock = NULL;
        return -1;
    }

    ret = zsocket_connect (subThreadStatusSndSock, SUBTHREAD_STATUS_REPORT_CHANNEL);
    if (ret < 0) {
        zctx_destroy (&zmqCtx);
        subThreadStatusSndSock = NULL;
        subThreadStatusRecvSock = NULL;
        return -1;
    }

    return 0;
}

void
destroyZmqhub (void) {
    if (zmqCtx == NULL)
        return;
    
    zctx_destroy (&zmqCtx);
    subThreadStatusSndSock = NULL;
    subThreadStatusRecvSock = NULL;
}
