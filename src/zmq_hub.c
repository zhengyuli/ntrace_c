#include <stdlib.h>
#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "logger.h"
#include "zmq_hub.h"

/* Max/Min tcp packet parsing threads number */
#define MIN_TCP_PACKET_PARSING_THREADS_NUM 5
#define MAX_TCP_PACKET_PARSING_THREADS_NUM 1025

#define IP_PACKET_EXCHANGE_CHANNEL "inproc://ipPacketExchangeChannel"
#define TCP_PACKET_EXCHANGE_CHANNEL "inproc://tcpPacketExchangeChannel"
#define TASK_STATUS_EXCHANGE_CHANNEL "inproc://taskStatusExchangeChannel"

/* Zmq hub local instance */
static zmqHubPtr zmqHubIntance = NULL;

void *
getTaskStatusPushSock (void) {
    return zmqHubIntance->taskStatusPushSock;
}

void *
getTaskStatusPullSock (void) {
    return zmqHubIntance->taskStatusPullSock;
}

void *
getManagementReplySock (void) {
    return zmqHubIntance->managementReplySock;
}

void *
getIpPktPushSock (void) {
    return zmqHubIntance->ipPktPushSock;
}

void *
getIpPktPullSock (void) {
    return zmqHubIntance->ipPktPullSock;
}

u_int
getTcpPktParsingThreadsNum (void) {
    return zmqHubIntance->tcpPktParsingThreadsNum;
}

void *
getTcpPktPushSock (u_int index) {
    return zmqHubIntance->tcpPktPushSocks [index];
}
void *
getTcpPktPullSock (u_int index) {
    return zmqHubIntance->tcpPktPullSocks [index];
}

void *
getBreakdownPushSock (u_int index) {
    return zmqHubIntance->breakdownPushSocks [index];
}

u_int *
getTcpPktParsingThreadIDHolder (u_int index) {
    return &zmqHubIntance->tcpPktParsingThreadIDsHolder [index];
}

int
initZmqHub (void) {
    int i, size;
    int ret;

    /* Alloc zmqHubIntance */
    zmqHubIntance = (zmqHubPtr) malloc (sizeof (zmqHub));
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

    /* Create taskStatusPushSock */
    zmqHubIntance->taskStatusPushSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
    if (zmqHubIntance->taskStatusPushSock == NULL) {
        LOGE ("Create taskStatusPushSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (zmqHubIntance->taskStatusPushSock, TASK_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", TASK_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create taskStatusPullSock */
    zmqHubIntance->taskStatusPullSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
    if (zmqHubIntance->taskStatusPullSock == NULL) {
        LOGE ("Create taskStatusPullSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_connect (zmqHubIntance->taskStatusPullSock, TASK_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", TASK_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create managementReplySock */
    zmqHubIntance->managementReplySock = zsocket_new (zmqHubIntance->ctxt, ZMQ_REP);
    if (zmqHubIntance->managementReplySock == NULL) {
        LOGE ("Create managementReplySock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (zmqHubIntance->managementReplySock, "tcp://*:%u", COMMAND_HANDLER_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", COMMAND_HANDLER_PORT);
        goto destroyZmqCtxt;
    }

    zctx_set_iothreads (zmqHubIntance->ctxt, 5);
    /* Create ipPktPushSock */
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

    /* Set tcp packet parsing threads number */
    zmqHubIntance->tcpPktParsingThreadsNum = getCpuCores () * 4 + 1;
    if (zmqHubIntance->tcpPktParsingThreadsNum < MIN_TCP_PACKET_PARSING_THREADS_NUM)
        zmqHubIntance->tcpPktParsingThreadsNum = MIN_TCP_PACKET_PARSING_THREADS_NUM;
    else if (zmqHubIntance->tcpPktParsingThreadsNum > MAX_TCP_PACKET_PARSING_THREADS_NUM)
        zmqHubIntance->tcpPktParsingThreadsNum = MAX_TCP_PACKET_PARSING_THREADS_NUM;

    /* Alloc tcpPktParsingThreadIDsHolder */
    zmqHubIntance->tcpPktParsingThreadIDsHolder =
            (u_int *) malloc (sizeof (u_int) * zmqHubIntance->tcpPktParsingThreadsNum);
    if (zmqHubIntance->tcpPktParsingThreadIDsHolder == NULL) {
        LOGE ("Alloc tcpPktParsingThreadIDsHolder error: %s.\n", strerror (errno));
        goto destroyZmqCtxt;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->tcpPktParsingThreadIDsHolder [i] = i;
    }

    /* Alloc tcpPktPushSocks */
    size = sizeof (void *) * zmqHubIntance->tcpPktParsingThreadsNum;
    zmqHubIntance->tcpPktPushSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpPktPushSocks == NULL) {
        LOGE ("Alloc tcpPktPushSocks error: %s\n", strerror (errno));
        goto freeTcpPktParsingThreadIDsHolder;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->tcpPktPushSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
        if (zmqHubIntance->tcpPktPushSocks [i] == NULL) {
            LOGE ("Create tcpPktPushSocks [%d] error.\n", i);
            goto freeTcpPktPushSocks;
        }
        zsocket_set_sndhwm (zmqHubIntance->tcpPktPushSocks [i], 500000);
        ret = zsocket_bind (zmqHubIntance->tcpPktPushSocks [i], "%s%u", TCP_PACKET_EXCHANGE_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Bind to %s%u error.\n", TCP_PACKET_EXCHANGE_CHANNEL, i);
            goto freeTcpPktPushSocks;
        }
    }

    /* Alloc tcpPktPullSocks */
    zmqHubIntance->tcpPktPullSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpPktPullSocks == NULL) {
        LOGE ("Alloc tcpPktPullSocks error: %s\n", strerror (errno));
        goto freeTcpPktPushSocks;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->tcpPktPullSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
        if (zmqHubIntance->tcpPktPullSocks [i] == NULL) {
            LOGE ("Create tcpPktPullSocks [%d] error.\n", i);
            goto freeTcpPktPullSocks;
        }
        zsocket_set_rcvhwm (zmqHubIntance->tcpPktPullSocks [i], 500000);
        ret = zsocket_connect (zmqHubIntance->tcpPktPullSocks [i], "%s%u", TCP_PACKET_EXCHANGE_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Connect to %s%u error.\n", TCP_PACKET_EXCHANGE_CHANNEL, i);
            goto freeTcpPktPullSocks;
        }
    }

    /* Alloc breakdownPushSocks */
    zmqHubIntance->breakdownPushSocks = (void **) malloc (size);
    if (zmqHubIntance->breakdownPushSocks == NULL) {
        LOGE ("Alloc breakdownPushSocks error: %s\n", strerror (errno));
        goto freeTcpPktPullSocks;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->breakdownPushSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
        if (zmqHubIntance->breakdownPushSocks [i] == NULL) {
            LOGE ("Create breakdownPushSocks [%d] error.\n", i);
            goto freeBreakdownPushSocks;
        }
        zsocket_set_sndhwm (zmqHubIntance->breakdownPushSocks [i], 500000);
        ret = zsocket_connect (zmqHubIntance->breakdownPushSocks [i], "tcp://%s:%u",
                               getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
        if (ret < 0) {
            LOGE ("Connect to tcp://%s:%u error.\n",
                  getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
            goto freeBreakdownPushSocks;
        }
    }

    return 0;

freeBreakdownPushSocks:
    free (zmqHubIntance->breakdownPushSocks);
    zmqHubIntance->breakdownPushSocks = NULL;
freeTcpPktPullSocks:
    free (zmqHubIntance->tcpPktPullSocks);
    zmqHubIntance->tcpPktPullSocks = NULL;
freeTcpPktPushSocks:
    free (zmqHubIntance->tcpPktPushSocks);
    zmqHubIntance->tcpPktPushSocks = NULL;
freeTcpPktParsingThreadIDsHolder:
    free (zmqHubIntance->tcpPktParsingThreadIDsHolder);
    zmqHubIntance->tcpPktParsingThreadIDsHolder = NULL;
    zmqHubIntance->tcpPktParsingThreadsNum = 0;
destroyZmqCtxt:
    zctx_destroy (&zmqHubIntance->ctxt);
freeZmqHubInstance:
    free (zmqHubIntance);
    zmqHubIntance = NULL;
    return -1;
}

void
destroyZmqHub (void) {
    free (zmqHubIntance->tcpPktParsingThreadIDsHolder);
    zmqHubIntance->tcpPktParsingThreadIDsHolder = NULL;
    free (zmqHubIntance->tcpPktPushSocks);
    zmqHubIntance->tcpPktPushSocks = NULL;
    free (zmqHubIntance->tcpPktPullSocks);
    zmqHubIntance->tcpPktPullSocks = NULL;
    free (zmqHubIntance->breakdownPushSocks);
    zmqHubIntance->breakdownPushSocks = NULL;
    zctx_destroy (&zmqHubIntance->ctxt);
    free (zmqHubIntance);
    zmqHubIntance = NULL;
}
