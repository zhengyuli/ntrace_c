#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <czmq.h>
#include "util.h"
#include "log.h"
#include "zmqhub.h"
#include "task-manager.h"
#include "dispatch-router.h"

/* Dispatch router instance */
static dispatchRouterPtr dispatchRouterInstance;

static size_t
dispatchHash (const char *key1, const char *key2) {
    u_int sum, hash = 0;
    u_int seed = 16777619;
    const char *tmp;

    if (strlen (key1) < strlen (key2)) {
        tmp = key1;
        key1 = key2;
        key2 = tmp;
    }

    while (*key2) {
        hash *= seed;
        sum = *key1 + *key2;
        hash ^= sum;
        key1++;
        key2++;
    }

    while (*key1) {
        hash *= seed;
        hash ^= (size_t) (*key1);
        key1++;
    }

    return hash;
}

/*
 * @brief Router dispatch ip packet and timestamp to specific
 *        parsing thread.
 *
 * @param iphdr ip packet to dispatch
 * @param tm capture timestamp to dispatch
 */
void
routerDispatch (struct ip *iphdr, timeValPtr tm) {
    int ret;
    u_int index;
    u_int ipPktLen;
    struct ip *iph = iphdr;
    struct tcphdr *tcph;
    char key1 [32] = {0};
    char key2 [32] = {0};
    zframe_t *frame;

    ipPktLen = ntohs (iph->ip_len);

    switch (iph->ip_p) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *) ((u_char *) iph + (iph->ip_hl * 4));
            snprintf (key1, sizeof (key1) - 1, "%s:%d", inet_ntoa (iph->ip_src), ntohs (tcph->source));
            snprintf (key2, sizeof (key2) - 1, "%s:%d", inet_ntoa (iph->ip_dst), ntohs (tcph->dest));
            break;

        default:
            return;
    }

    /* Get dispatch index */
    index = dispatchHash (key1, key2) % dispatchRouterInstance->routerNum;

    /* Push timeVal */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, dispatchRouterInstance->routers [index].pushSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Push timestamp zframe error.\n");
        zframe_destroy (&frame);
        return;
    }

    /* Push ip packet */
    frame = zframe_new (iphdr, ipPktLen);
    if (frame == NULL) {
        LOGE ("Create ip packet zframe error.");
        return;
    }
    ret = zframe_send (&frame, dispatchRouterInstance->routers [index].pushSock, 0);
    if (ret < 0) {
        LOGE ("Push ip packet zframe error.\n");
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Init dispatch router
 *
 * @param routine dispatch routine
 *
 * @return 0 if success else -1
 */
int
initDispatchRouter (dispatchRoutine routine) {
    int ret;
    u_int i, n, size;
    taskId tid;

    dispatchRouterInstance = (dispatchRouterPtr) malloc (sizeof (dispatchRouter));
    if (dispatchRouterInstance == NULL) {
        LOGE ("Alloc dispatchRouterInstance error: %s\n.", strerror (errno));
        return -1;
    }

    /* Get dispatch router number */
    dispatchRouterInstance->routerNum = (getCpuCores () * 2 + 1);
    if (dispatchRouterInstance->routerNum < MIN_ROUTER_NUM)
        dispatchRouterInstance->routerNum = MIN_ROUTER_NUM;
    else if (dispatchRouterInstance->routerNum > MAX_ROUTER_NUM)
        dispatchRouterInstance->routerNum = MAX_ROUTER_NUM;

    size = sizeof (router) * dispatchRouterInstance->routerNum;
    dispatchRouterInstance->routers = (routerPtr) malloc (size);
    if (dispatchRouterInstance->routers == NULL) {
        LOGE ("Alloc dispatchRouter routers error: %s.\n", strerror (errno));
        goto destroyDispatchRouterInstance;
    }

    dispatchRouterInstance->zmqCtxt = zctx_new ();
    if (dispatchRouterInstance->zmqCtxt == NULL) {
        LOGE ("Create zmqCtxt error.\n");
        goto destroyRouters;
    }

    for (i = 0; i < dispatchRouterInstance->routerNum; i++) {
        dispatchRouterInstance->routers [i].pushSock = zsocket_new (dispatchRouterInstance->zmqCtxt, ZMQ_PUSH);
        if (dispatchRouterInstance->routers [i].pushSock == NULL) {
            LOGE ("Create pushSock error.\n");
            goto destroyZmqctxt;
        }
        /* Set pushSock sndhwm to 500,000 */
        zsocket_set_sndhwm (dispatchRouterInstance->routers [i].pushSock, 500000);
        ret = zsocket_bind (dispatchRouterInstance->routers [i].pushSock, "%s%u", TCP_PACKET_PUSH_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Bind to %s%u error.\n", TCP_PACKET_PUSH_CHANNEL, i);
            goto destroyZmqctxt;
        }

        dispatchRouterInstance->routers [i].pullSock = zsocket_new (dispatchRouterInstance->zmqCtxt, ZMQ_PULL);
        if (dispatchRouterInstance->routers [i].pullSock == NULL) {
            LOGE ("Create pullSock error.\n");
            goto destroyZmqctxt;
        }
        /* Set pullSock rcvhwm to 500,000 */
        zsocket_set_rcvhwm (dispatchRouterInstance->routers [i].pullSock, 500000);
        ret = zsocket_connect (dispatchRouterInstance->routers [i].pullSock, "%s%u", TCP_PACKET_PUSH_CHANNEL, i);
        if (ret < 0) {
            LOGE ("Connect to %s%u error.\n", TCP_PACKET_PUSH_CHANNEL, i);
            goto destroyZmqctxt;
        }

        tid = newTask (routine, dispatchRouterInstance->routers [i].pullSock);
        if (tid < 0) {
            LOGE ("Create dispatchRoutine:%u error", i);
            goto destroyZmqctxt;
        }
    }

    return 0;

destroyZmqctxt:
    zctx_destroy (&dispatchRouterInstance->zmqCtxt);
destroyRouters:
    free (dispatchRouterInstance->routers);
    dispatchRouterInstance->routers = NULL;
destroyDispatchRouterInstance:
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;

    return -1;
}

/* Destroy dispatch router */
void
destroyDispatchRouter (void) {
    zctx_destroy (&dispatchRouterInstance->zmqCtxt);
    free (dispatchRouterInstance->routers);
    dispatchRouterInstance->routers = NULL;
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;
}
