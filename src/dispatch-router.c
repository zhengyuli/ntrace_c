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
    index = dispatchHash (key1, key2) % dispatchRouterInstance->pktParsingThreads;

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
 * @param pktParsingThreads packet parsing threads
 * @param routine dispatch routine
 * @param dispatchAddress dispatch address
 *
 * @return 0 if success else -1
 */
int
initDispatchRouter (u_int pktParsingThreads, dispatchRoutine routine, const char *dispatchAddress) {
    int ret;
    u_int i, n, size;
    taskId tid;

    dispatchRouterInstance = (dispatchRouterPtr) malloc (sizeof (dispatchRouter));
    if (dispatchRouterInstance == NULL) {
        LOGE ("Alloc dispatchRouterInstance error: %s\n.", strerror (errno));
        return -1;
    }

    dispatchRouterInstance->pktParsingThreads = pktParsingThreads;
    size = sizeof (router) * dispatchRouterInstance->pktParsingThreads;
    dispatchRouterInstance->routers = (routerPtr) malloc (size);
    if (dispatchRouterInstance->routers == NULL) {
        LOGE ("Alloc dispatchRouter routers error: %s.\n", strerror (errno));
        goto freeDispatchRouterInstance;
    }

    for (i = 0; i < dispatchRouterInstance->pktParsingThreads; i++) {
        dispatchRouterInstance->routers [i].id = i;
        dispatchRouterInstance->routers [i].pushSock = zsocket_new (zmqHubContext (), ZMQ_PUSH);
        if (dispatchRouterInstance->routers [i].pushSock == NULL) {
            LOGE ("Create zsocket error.\n");
            goto freeRouters;
        }
        /* Set pushSock sndhwm to 500,000 */
        zsocket_set_sndhwm (dispatchRouterInstance->routers [i].pushSock, 500000);
        ret = zsocket_bind (dispatchRouterInstance->routers [i].pushSock, "%s%u", dispatchAddress, i);
        if (ret < 0) {
            LOGE ("Bind to %s%u error.\n", dispatchAddress, i);
            goto freeRouters;
        }

        /* Create new task for routine */
        tid = newTask (routine, &dispatchRouterInstance->routers [i].id);
        if (tid < 0) {
            LOGE ("Create dispatchRoutine %u error", dispatchRouterInstance->routers [i].id);
            goto freeRouters;
        }
    }

    return 0;

freeRouters:
    for (n = 0; n <= i; n++) {
        if (dispatchRouterInstance->routers [n].pushSock)
            zsocket_destroy (zmqHubContext (), dispatchRouterInstance->routers [n].pushSock);
    }
    free (dispatchRouterInstance->routers);
    dispatchRouterInstance->routers = NULL;
freeDispatchRouterInstance:
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;

    return -1;
}

/* Destroy dispatch router */
void
destroyDispatchRouter (void) {
    u_int i;

    for (i = 0; i < dispatchRouterInstance->pktParsingThreads; i++) {
        if (dispatchRouterInstance->routers [i].pushSock)
            zsocket_destroy (zmqHubContext (), dispatchRouterInstance->routers [i].pushSock);
    }
    free (dispatchRouterInstance->routers);
    dispatchRouterInstance->routers = NULL;
    free (dispatchRouterInstance);
    dispatchRouterInstance = NULL;
}
