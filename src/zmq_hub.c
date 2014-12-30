#include <stdlib.h>
#include <czmq.h>
#include "logger.h"
#include "zmq_hub.h"

#define IP_PACKET_EXCHANGE_CHANNEL "inproc://ipPacketExchangeChannel"

/* Zmq hub local instance */
zmqHubPtr zmqHubIntance = NULL;

void *
getZmqHubIpPktPushSock (void) {
    return zmqHubIntance->ipPktPushSock;
}

void *
getZmqHubIpPktPullSock (void) {
    return zmqHubIntance->ipPktPullSock;
}

int
initZmqHub (void) {
    int ret;
    
    zmqHubIntance = (zmqHubPtr) malloc (sizeof(zmqHub));
    if (zmqHubIntance == NULL) {
        LOGE ("Alloc zmqHubIntance error.\n");
        return -1;
    }

    /* Create zmq context */
    zmqHubIntance->ctxt = zctx_new ();
    if (zmqHubIntance->ctxt == NULL) {
        LOGE ("Create zmq context error.\n");
        goto freeZmqHubInstance;
    }
    zctx_set_linger (zmqHubIntance->ctxt, 0);
    zctx_set_iothreads (zmqHubIntance->ctxt, 5);

    /* Create ipPktPullSock */
    zmqHubIntance->ipPktPushSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
    if (zmqHubIntance->ipPktPushSock == NULL) {
        LOGE ("Create ipPktPushSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set ipPktPushSock sndhwm to 500,000 */
    zsocket_set_sndhwm (zmqHubIntance->ipPktPushSock, 500000);
    ret = zsocket_bind (zmqHubIntance->ipPktPushSock, IP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", IP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create ipPktPullSock */
    zmqHubIntance->ipPktPullSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
    if (zmqHubIntance->ipPktPullSock == NULL) {
        LOGE ("Create ipPktPullSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set ipPktPullSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (zmqHubIntance->ipPktPullSock, 500000);
    ret = zsocket_connect (zmqHubIntance->ipPktPullSock, IP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", IP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }
    
    return 0;

destroyZmqCtxt:
    zctx_destroy (&zmqHubIntance->ctxt);
    zmqHubIntance->ipPktPushSock = NULL;
    zmqHubIntance->ipPktPullSock = NULL;
freeZmqHubInstance:
    free (zmqHubIntance);
    zmqHubIntance = NULL;
    return -1;
}

void
destroyZmqHub (void) {
    zctx_destroy (&zmqHubIntance->ctxt);
    zmqHubIntance->ipPktPushSock = NULL;
    zmqHubIntance->ipPktPullSock = NULL;
    free (zmqHubIntance);
    zmqHubIntance = NULL;
}
