#include <stdlib.h>
#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "log.h"
#include "zmq_hub.h"

/* Max/Min tcp process threads number */
#define MIN_TCP_PROCESS_THREADS_NUM 5
#define MAX_TCP_PROCESS_THREADS_NUM 1025

#define TASK_STATUS_EXCHANGE_CHANNEL "inproc://taskStatusExchangeChannel"
#define IP_PACKET_EXCHANGE_CHANNEL "inproc://ipPacketExchangeChannel"
#define ICMP_PACKET_EXCHANGE_CHANNEL "inproc://icmpPacketExchangeChannel"
#define TCP_PACKET_EXCHANGE_CHANNEL "inproc://tcpPacketExchangeChannel"
#define SESSION_BREAKDOWN_EXCHANGE_CHANNEL "inproc://sessionBreakdownExchangeChannel"

/* Zmq hub instance */
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

void *
getSessionBreakdownRecvSock (void) {
    return zmqHubIntance->sessionBreakdownRecvSock;
}

void *
getSessionBreakdownPushSock (void) {
    return zmqHubIntance->sessionBreakdownPushSock;
}

void *
getIcmpPktSendSock (void) {
    return zmqHubIntance->icmpPktSendSock;
}

void *
getIcmpPktRecvSock (void) {
    return zmqHubIntance->icmpPktRecvSock;
}

void *
getIcmpBreakdownSendSock (void) {
    return zmqHubIntance->icmpBreakdownSendSock;
}

void *
getTcpPktDispatchRecvSock (void) {
    return zmqHubIntance->tcpPktDispatchRecvSock;
}

u_int
getTcpProcessThreadsNum (void) {
    return zmqHubIntance->tcpProcessThreadsNum;
}

u_int *
getTcpProcessThreadIDHolder (u_int index) {
    return &zmqHubIntance->tcpProcessThreadIDsHolder [index];
}

void *
getTcpPktSendSock (u_int index) {
    return zmqHubIntance->tcpPktSendSocks [index];
}
void *
getTcpPktRecvSock (u_int index) {
    return zmqHubIntance->tcpPktRecvSocks [index];
}

void *
getTcpBreakdownSendSock (u_int index) {
    return zmqHubIntance->tcpBreakdownSendSocks [index];
}

int
initZmqHub (void) {
    int ret;
    u_int i, size;

    /* Alloc zmqHubIntance */
    zmqHubIntance = (zmqHubPtr) malloc (sizeof (zmqHub));
    if (zmqHubIntance == NULL) {
        LOGE ("Alloc zmqHubIntance error.\n");
        return -1;
    }

    /* Create zmq context */
    zmqHubIntance->zmqCtxt = zctx_new ();
    if (zmqHubIntance->zmqCtxt == NULL) {
        LOGE ("Create zmq context error.\n");
        goto freeZmqHubInstance;
    }
    zctx_set_linger (zmqHubIntance->zmqCtxt, 0);

    /* Create managementReplySock */
    zmqHubIntance->managementReplySock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_REP);
    if (zmqHubIntance->managementReplySock == NULL) {
        LOGE ("Create managementReplySock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (zmqHubIntance->managementReplySock, "tcp://*:%u", MANAGEMENT_SERVICE_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", MANAGEMENT_SERVICE_PORT);
        goto destroyZmqCtxt;
    }

    /* Create taskStatusSendSock */
    zmqHubIntance->taskStatusSendSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
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
    zmqHubIntance->taskStatusRecvSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
    if (zmqHubIntance->taskStatusRecvSock == NULL) {
        LOGE ("Create taskStatusRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_connect (zmqHubIntance->taskStatusRecvSock, TASK_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", TASK_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Set zmq context io threads */
    zctx_set_iothreads (zmqHubIntance->zmqCtxt, 3);

    /* Create ipPktSendSock */
    zmqHubIntance->ipPktSendSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
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
    zmqHubIntance->ipPktRecvSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
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

    /* Create session breakdown recv sock */
    zmqHubIntance->sessionBreakdownRecvSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
    if (zmqHubIntance->sessionBreakdownRecvSock == NULL) {
        LOGE ("Create sessionBreakdownRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    zsocket_set_rcvhwm (zmqHubIntance->sessionBreakdownRecvSock, 500000);
    ret = zsocket_bind (zmqHubIntance->sessionBreakdownRecvSock, SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create session breakdown push sock */
    zmqHubIntance->sessionBreakdownPushSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
    if (zmqHubIntance->sessionBreakdownPushSock == NULL) {
        LOGE ("Create sessionBreakdownPushSock error.\n");
        goto destroyZmqCtxt;
    }
    zsocket_set_sndhwm (zmqHubIntance->sessionBreakdownPushSock, 500000);
    ret = zsocket_connect (zmqHubIntance->sessionBreakdownPushSock, "tcp://%s:%u",
                           getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
    if (ret < 0) {
        LOGE ("Connect to tcp://%s:%u error.\n",
              getPropertiesBreakdownSinkIp (), getPropertiesBreakdownSinkPort ());
        goto destroyZmqCtxt;
    }

    /* Create icmpPktSendSock */
    zmqHubIntance->icmpPktSendSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
    if (zmqHubIntance->icmpPktSendSock == NULL) {
        LOGE ("Create icmpPktSendSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set icmpPktSendSock sndhwm to 500,000 */
    zsocket_set_sndhwm (zmqHubIntance->icmpPktSendSock, 500000);
    ret = zsocket_bind (zmqHubIntance->icmpPktSendSock, ICMP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", ICMP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create icmpPktRecvSock */
    zmqHubIntance->icmpPktRecvSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
    if (zmqHubIntance->icmpPktRecvSock == NULL) {
        LOGE ("Create icmpPktRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set icmpPktRecvSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (zmqHubIntance->icmpPktRecvSock, 500000);
    ret = zsocket_connect (zmqHubIntance->icmpPktRecvSock, ICMP_PACKET_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", ICMP_PACKET_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Alloc icmpBreakdownSendSock */
    zmqHubIntance->icmpBreakdownSendSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
    if (zmqHubIntance->icmpBreakdownSendSock == NULL) {
        LOGE ("Create icmpBreakdownSendSock error.\n");
        goto destroyZmqCtxt;
    }
    zsocket_set_sndhwm (zmqHubIntance->icmpBreakdownSendSock, 500000);
    ret = zsocket_connect (zmqHubIntance->icmpBreakdownSendSock, SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create tcpPktDispatchRecvSock */
    zmqHubIntance->tcpPktDispatchRecvSock = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
    if (zmqHubIntance->tcpPktDispatchRecvSock == NULL) {
        LOGE ("Create tcpPktDispatchRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    /* Set tcpPktDispatchRecvSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (zmqHubIntance->tcpPktDispatchRecvSock, 500000);
    ret = zsocket_bind (zmqHubIntance->tcpPktDispatchRecvSock, "tcp://*:%u", TCP_PACKET_DISPATCH_RECV_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", TCP_PACKET_DISPATCH_RECV_PORT);
        goto destroyZmqCtxt;
    }

    /* Get tcp process threads number */
    zmqHubIntance->tcpProcessThreadsNum = getCpuCoresNum () * 4 + 1;
    if (zmqHubIntance->tcpProcessThreadsNum < MIN_TCP_PROCESS_THREADS_NUM)
        zmqHubIntance->tcpProcessThreadsNum = MIN_TCP_PROCESS_THREADS_NUM;
    else if (zmqHubIntance->tcpProcessThreadsNum > MAX_TCP_PROCESS_THREADS_NUM)
        zmqHubIntance->tcpProcessThreadsNum = MAX_TCP_PROCESS_THREADS_NUM;

    /* Alloc tcpProcessThreadIDsHolder */
    zmqHubIntance->tcpProcessThreadIDsHolder =
            (u_int *) malloc (sizeof (u_int) * zmqHubIntance->tcpProcessThreadsNum);
    if (zmqHubIntance->tcpProcessThreadIDsHolder == NULL) {
        LOGE ("Alloc tcpProcessThreadIDsHolder error: %s.\n", strerror (errno));
        goto destroyZmqCtxt;
    }
    for (i = 0; i < zmqHubIntance->tcpProcessThreadsNum; i++) {
        zmqHubIntance->tcpProcessThreadIDsHolder [i] = i;
    }

    /* Alloc tcpPktSendSocks */
    size = sizeof (void *) * zmqHubIntance->tcpProcessThreadsNum;
    zmqHubIntance->tcpPktSendSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpPktSendSocks == NULL) {
        LOGE ("Alloc tcpPktSendSocks error: %s\n", strerror (errno));
        goto freeTcpPktProcessThreadIDsHolder;
    }
    for (i = 0; i < zmqHubIntance->tcpProcessThreadsNum; i++) {
        zmqHubIntance->tcpPktSendSocks [i] = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
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
    for (i = 0; i < zmqHubIntance->tcpProcessThreadsNum; i++) {
        zmqHubIntance->tcpPktRecvSocks [i] = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PULL);
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

    /* Alloc tcpBreakdownSendSocks */
    zmqHubIntance->tcpBreakdownSendSocks = (void **) malloc (size);
    if (zmqHubIntance->tcpBreakdownSendSocks == NULL) {
        LOGE ("Alloc tcpBreakdownSendSocks error: %s\n", strerror (errno));
        goto freeTcpPktRecvSocks;
    }
    for (i = 0; i < zmqHubIntance->tcpProcessThreadsNum; i++) {
        zmqHubIntance->tcpBreakdownSendSocks [i] = zsocket_new (zmqHubIntance->zmqCtxt, ZMQ_PUSH);
        if (zmqHubIntance->tcpBreakdownSendSocks [i] == NULL) {
            LOGE ("Create tcpBreakdownSendSocks [%d] error.\n", i);
            goto freeTcpBreakdownSendSocks;
        }
        zsocket_set_sndhwm (zmqHubIntance->tcpBreakdownSendSocks [i], 500000);
        ret = zsocket_connect (zmqHubIntance->tcpBreakdownSendSocks [i], SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
        if (ret < 0) {
            LOGE ("Connect to %s error.\n", SESSION_BREAKDOWN_EXCHANGE_CHANNEL);
            goto freeTcpBreakdownSendSocks;
        }
    }

    return 0;

freeTcpBreakdownSendSocks:
    free (zmqHubIntance->tcpBreakdownSendSocks);
    zmqHubIntance->tcpBreakdownSendSocks = NULL;
freeTcpPktRecvSocks:
    free (zmqHubIntance->tcpPktRecvSocks);
    zmqHubIntance->tcpPktRecvSocks = NULL;
freeTcpPktSendSocks:
    free (zmqHubIntance->tcpPktSendSocks);
    zmqHubIntance->tcpPktSendSocks = NULL;
freeTcpPktProcessThreadIDsHolder:
    free (zmqHubIntance->tcpProcessThreadIDsHolder);
    zmqHubIntance->tcpProcessThreadIDsHolder = NULL;
    zmqHubIntance->tcpProcessThreadsNum = 0;
destroyZmqCtxt:
    zctx_destroy (&zmqHubIntance->zmqCtxt);
freeZmqHubInstance:
    free (zmqHubIntance);
    zmqHubIntance = NULL;
    return -1;
}

void
destroyZmqHub (void) {
    free (zmqHubIntance->tcpProcessThreadIDsHolder);
    zmqHubIntance->tcpProcessThreadIDsHolder = NULL;
    free (zmqHubIntance->tcpPktSendSocks);
    zmqHubIntance->tcpPktSendSocks = NULL;
    free (zmqHubIntance->tcpPktRecvSocks);
    zmqHubIntance->tcpPktRecvSocks = NULL;
    free (zmqHubIntance->tcpBreakdownSendSocks);
    zmqHubIntance->tcpBreakdownSendSocks = NULL;
    zctx_destroy (&zmqHubIntance->zmqCtxt);
    free (zmqHubIntance);
    zmqHubIntance = NULL;
}
