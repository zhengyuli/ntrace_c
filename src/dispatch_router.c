#include "logger.h"
#include "util.h"
#include "dispatch_router.h"

/* Max/Min dispatch count */
#define MIN_DISPATCH_COUNT 5
#define MAX_DISPATCH_COUNT 1025

#define TCP_PACKET_PUSH_CHANNEL "inproc://tcpPacketPushChannel"

/* Dispatch router local instance */
static dispatchRouterPtr dispatchRouterInstance = NULL;

u_int
getDispatchCount (void) {
    return dispatchRouterInstance->dispatchCount;
}

void *
getDispatchPushSock (u_int index) {
    return dispatchRouterInstance->pushSocks [index];
}

void *
getDispatchPullSock (u_int index) {
    return dispatchRouterInstance->pullSocks [index];
}

/* Init dispatch router */
int
initDispatchRouter (void) {
    int ret;
    u_int i, size;

    dispatchRouterInstance = (dispatchRouterPtr) malloc (sizeof (dispatchRouter));
    if (dispatchRouterInstance == NULL) {
        LOGE ("Alloc dispatchRouterInstance error: %s\n.", strerror (errno));
        return -1;
    }

    dispatchRouterInstance->ctxt = zctx_new ();
    if (dispatchRouterInstance->ctxt == NULL) {
        LOGE ("Cteate zmq context of dispatch router error.\n");
        goto freeDispatchRouterInstance;
    }
    zctx_set_linger (dispatchRouterInstance->ctxt, 0);

    /* Get dispatch threads */
    dispatchRouterInstance->dispatchCount = getCpuCores () * 4 + 1;
    if (dispatchRouterInstance->dispatchCount < MIN_DISPATCH_COUNT)
        dispatchRouterInstance->dispatchCount = MIN_DISPATCH_COUNT;
    else if (dispatchRouterInstance->dispatchCount > MAX_DISPATCH_COUNT)
        dispatchRouterInstance->dispatchCount = MAX_DISPATCH_COUNT;

    size = sizeof (void *) * dispatchRouterInstance->dispatchCount;
    dispatchRouterInstance->pushSocks = malloc (size);
    if (dispatchRouterInstance->pushSocks == NULL) {
        LOGE ("Alloc dispatchRouter pushSocks error: %s.\n", strerror (errno));
        goto destroyZmqCtxt;
    }

    dispatchRouterInstance->pullSocks = malloc (size);
    if (dispatchRouterInstance->pullSocks == NULL) {
        LOGE ("Alloc dispatchRouter pullSocks error: %s.\n", strerror (errno));
        goto freePushSocks;
    }

    for (i = 0; i < dispatchRouterInstance->dispatchCount; i++) {
        dispatchRouterInstance->pushSocks [i] = zsocket_new (dispatchRouterInstance->ctxt, ZMQ_PUSH);
        if (dispatchRouterInstance->pushSocks [i] == NULL) {
            LOGE ("Create pushSocks [i] error.\n", i);
            goto freePullSocks;
        }
        /* Set pushSock sndhwm to 500,000 */
        zsocket_set_sndhwm (dispatchRouterInstance->pushSocks [i], 500000);
        ret = zsocket_bind (dispatchRouterInstance->pushSocks [i], "%s%u", TCP_PACKET_PUSH_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Bind to %s%u error.\n", TCP_PACKET_PUSH_CHANNEL, i);
            goto freePullSocks;
        }

        dispatchRouterInstance->pullSocks [i] = zsocket_new (dispatchRouterInstance->ctxt, ZMQ_PULL);
        if (dispatchRouterInstance->pullSocks [i] == NULL) {
            LOGE ("Create pullSock [i] error.\n", i);
            goto freePullSocks;
        }
        /* Set pullSock rcvhwm to 500,000 */
        zsocket_set_rcvhwm (dispatchRouterInstance->pullSocks [i], 500000);
        ret = zsocket_connect (dispatchRouterInstance->pullSocks [i], "%s%u", TCP_PACKET_PUSH_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Connect to %s%u error.\n", TCP_PACKET_PUSH_CHANNEL, i);
            goto freePullSocks;
        }
    }

    return 0;

freePullSocks:
    free (dispatchRouterInstance->pullSocks);
    dispatchRouterInstance->pullSocks = NULL;
freePushSocks:
    free (dispatchRouterInstance->pushSocks);
    dispatchRouterInstance->pushSocks = NULL;
destroyZmqCtxt:
    zctx_destroy (&dispatchRouterInstance->ctxt);
freeDispatchRouterInstance:
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;

    return -1;
}

/* Destroy dispatch router */
void
destroyDispatchRouter (void) {
    zctx_destroy (&dispatchRouterInstance->ctxt);
    free (dispatchRouterInstance->pushSocks);
    dispatchRouterInstance->pushSocks = NULL;
    free (dispatchRouterInstance->pullSocks);
    dispatchRouterInstance->pullSocks = NULL;
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;
}
