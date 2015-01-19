#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "log.h"
#include "zmq_hub.h"

/* Max/Min tcp packet parsing threads number */
#define MIN_TCP_PACKET_PARSING_THREADS_NUM 5
#define MAX_TCP_PACKET_PARSING_THREADS_NUM 1025

#define MANAGEMENT_REPLY_PORT 58000
#define TASK_STATUS_EXCHANGE_CHANNEL "inproc://taskStatusExchangeChannel"
#define IP_PACKET_EXCHANGE_CHANNEL "inproc://ipPacketExchangeChannel"
#define TCP_PACKET_EXCHANGE_CHANNEL "inproc://tcpPacketExchangeChannel"

/* Zmq hub local instance */
static zmqHubPtr zmqHubIntance = NULL;

void *
getManagementReplySock (void) {
    return zmqHubIntance->managementReplySock;
}

void *
getTaskStatusSendSock (void) {
    return zmqHubIntance->taskStatusSendSock;
}

void *
getTaskStatusRecvSock (void) {
    return zmqHubIntance->taskStatusRecvSock;
}

void *
getIpPktSendSock (void) {
    return zmqHubIntance->ipPktSendSock;
}

void *
getIpPktRecvSock (void) {
    return zmqHubIntance->ipPktRecvSock;
}

u_int
getTcpPktParsingThreadsNum (void) {
    return zmqHubIntance->tcpPktParsingThreadsNum;
}

void *
getTcpPktPushSock (u_int index) {
    return zmqHubIntance->tcpPktSendSocks [index];
}
void *
getTcpPktPullSock (u_int index) {
    return zmqHubIntance->tcpPktRecvSocks [index];
}

void *
getBreakdownPushSock (u_int index) {
    return zmqHubIntance->breakdownSendSocks [index];
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

    /* Create managementReplySock */
    zmqHubIntance->managementReplySock = zsocket_new (zmqHubIntance->ctxt, ZMQ_REP);
    if (zmqHubIntance->managementReplySock == NULL) {
        LOGE ("Create managementReplySock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (zmqHubIntance->managementReplySock, "tcp://*:%u", MANAGEMENT_REPLY_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", MANAGEMENT_REPLY_PORT);
        goto destroyZmqCtxt;
    }

    /* Create taskStatusSendSock */
    zmqHubIntance->taskStatusSendSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
    if (zmqHubIntance->taskStatusSendSock == NULL) {
        LOGE ("Create taskStatusSendSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (zmqHubIntance->taskStatusSendSock, TASK_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", TASK_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create taskStatusRecvSock */
    zmqHubIntance->taskStatusRecvSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
    if (zmqHubIntance->taskStatusRecvSock == NULL) {
        LOGE ("Create taskStatusRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_connect (zmqHubIntance->taskStatusRecvSock, TASK_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", TASK_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    zctx_set_iothreads (zmqHubIntance->ctxt, 5);
    /* Create ipPktSendSock */
    zmqHubIntance->ipPktSendSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
    if (zmqHubIntance->ipPktSendSock == NULL) {
        LOGE ("Create ipPktSendSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set ipPktSendSock sndhwm to 500,000 */
    zsocket_set_sndhwm (zmqHubIntance->ipPktSendSock, 500000);
    ret = zsocket_bind (zmqHubIntance->ipPktSendSock, IP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", IP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create ipPktRecvSock */
    zmqHubIntance->ipPktRecvSock = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
    if (zmqHubIntance->ipPktRecvSock == NULL) {
        LOGE ("Create ipPktRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set ipPktRecvSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (zmqHubIntance->ipPktRecvSock, 500000);
    ret = zsocket_connect (zmqHubIntance->ipPktRecvSock, IP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", IP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Set tcp packet parsing threads number */
    zmqHubIntance->tcpPktParsingThreadsNum = getCpuCoresNum () * 4 + 1;
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

    /* Alloc tcpPktSendSocks */
    size = sizeof (void *) * zmqHubIntance->tcpPktParsingThreadsNum;
    zmqHubIntance->tcpPktSendSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpPktSendSocks == NULL) {
        LOGE ("Alloc tcpPktSendSocks error: %s\n", strerror (errno));
        goto freeTcpPktParsingThreadIDsHolder;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->tcpPktSendSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
        if (zmqHubIntance->tcpPktSendSocks [i] == NULL) {
            LOGE ("Create tcpPktSendSocks [%d] error.\n", i);
            goto freeTcpPktSendSocks;
        }
        zsocket_set_sndhwm (zmqHubIntance->tcpPktSendSocks [i], 500000);
        ret = zsocket_bind (zmqHubIntance->tcpPktSendSocks [i], "%s%u", TCP_PACKET_EXCHANGE_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Bind to %s%u error.\n", TCP_PACKET_EXCHANGE_CHANNEL, i);
            goto freeTcpPktSendSocks;
        }
    }

    /* Alloc tcpPktRecvSocks */
    zmqHubIntance->tcpPktRecvSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpPktRecvSocks == NULL) {
        LOGE ("Alloc tcpPktRecvSocks error: %s\n", strerror (errno));
        goto freeTcpPktSendSocks;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->tcpPktRecvSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PULL);
        if (zmqHubIntance->tcpPktRecvSocks [i] == NULL) {
            LOGE ("Create tcpPktRecvSocks [%d] error.\n", i);
            goto freeTcpPktRecvSocks;
        }
        zsocket_set_rcvhwm (zmqHubIntance->tcpPktRecvSocks [i], 500000);
        ret = zsocket_connect (zmqHubIntance->tcpPktRecvSocks [i], "%s%u", TCP_PACKET_EXCHANGE_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Connect to %s%u error.\n", TCP_PACKET_EXCHANGE_CHANNEL, i);
            goto freeTcpPktRecvSocks;
        }
    }

    /* Alloc breakdownSendSocks */
    zmqHubIntance->breakdownSendSocks = (void **) malloc (size);
    if (zmqHubIntance->breakdownSendSocks == NULL) {
        LOGE ("Alloc breakdownSendSocks error: %s\n", strerror (errno));
        goto freeTcpPktRecvSocks;
    }
    for (i = 0; i < zmqHubIntance->tcpPktParsingThreadsNum; i++) {
        zmqHubIntance->breakdownSendSocks [i] = zsocket_new (zmqHubIntance->ctxt, ZMQ_PUSH);
        if (zmqHubIntance->breakdownSendSocks [i] == NULL) {
            LOGE ("Create breakdownSendSocks [%d] error.\n", i);
            goto freeBreakdownSendSocks;
        }
        zsocket_set_sndhwm (zmqHubIntance->breakdownSendSocks [i], 500000);
        ret = zsocket_connect (zmqHubIntance->breakdownSendSocks [i], "tcp://%s:%u",
                               getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
        if (ret < 0) {
            LOGE ("Connect to tcp://%s:%u error.\n",
                  getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
            goto freeBreakdownSendSocks;
        }
    }

    return 0;

freeBreakdownSendSocks:
    free (zmqHubIntance->breakdownSendSocks);
    zmqHubIntance->breakdownSendSocks = NULL;
freeTcpPktRecvSocks:
    free (zmqHubIntance->tcpPktRecvSocks);
    zmqHubIntance->tcpPktRecvSocks = NULL;
freeTcpPktSendSocks:
    free (zmqHubIntance->tcpPktSendSocks);
    zmqHubIntance->tcpPktSendSocks = NULL;
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
    free (zmqHubIntance->tcpPktSendSocks);
    zmqHubIntance->tcpPktSendSocks = NULL;
    free (zmqHubIntance->tcpPktRecvSocks);
    zmqHubIntance->tcpPktRecvSocks = NULL;
    free (zmqHubIntance->breakdownSendSocks);
    zmqHubIntance->breakdownSendSocks = NULL;
    zctx_destroy (&zmqHubIntance->ctxt);
    free (zmqHubIntance);
    zmqHubIntance = NULL;
}
