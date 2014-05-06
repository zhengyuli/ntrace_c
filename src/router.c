#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "log.h"
#include "util.h"
#include "router.h"

#define DEFAULT_ROUTER_WORKERS 5
#define MAX_ROUTER_WORKERS 128

typedef struct _router router;
typedef router *routerPtr;

struct _router {
    u_int workers;
    zctx_t *zmqCtx;
    pthread_t workerTids [MAX_ROUTER_WORKERS];
    routerSockPtr workerSocks;
};

/* Global dispatch router */
static routerPtr dispatchRouter;

static size_t
routerHash (const char *key1, const char *key2) {
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
 * @brief Dispatch ip packet to one specific worker thread
 *        to process.
 *
 * @param iphdr ip packet to dispatch
 * @param tm capture time to dispatch
 */
void
routerDispatch (struct ip *iphdr, timeValPtr tm) {
    int ret;
    u_int index;
    u_int hash;
    u_int ipTotalLen;
    struct ip *iph = iphdr;
    struct tcphdr *tcph;
    char key1 [32] = {0};
    char key2 [32] = {0};
    routerSockPtr rs;
    zframe_t *frame;

    ipTotalLen = ntohs (iph->ip_len);

    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *) ((u_char *) iph + (iph->ip_hl * 4));
            snprintf (key1, sizeof (key1) - 1, "%s:%d", inet_ntoa (iph->ip_src), ntohs (tcph->source));
            snprintf (key2, sizeof (key2) - 1, "%s:%d", inet_ntoa (iph->ip_dst), ntohs (tcph->dest));
            break;

        default:
            return;
    }

    hash = routerHash (key1, key2);
    if (dispatchRouter->workers == 1)
        index = 0;
    else
        index = hash % dispatchRouter->workers;
    rs = &dispatchRouter->workerSocks [index];

    /* Send timeVal */
    frame = zframe_new ((void *) tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Zframe_new error: %s.\n", strerror (errno));
        return;
    }
    ret = zframe_send (&frame, rs->pktSndSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Zframe_send error: %s.\n", strerror (errno));
        zframe_destroy (&frame);
        return;
    }

    /* Send ip packet */
    frame = zframe_new (iphdr, ipTotalLen);
    if (frame == NULL) {
        LOGE ("Zframe_new error: %s.\n", strerror (errno));
        return;
    }
    ret = zframe_send (&frame, rs->pktSndSock, 0);
    if (ret < 0) {
        LOGE ("Zframe_send error: %s.\n", strerror (errno));
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Init packet processing router
 *
 * @param zmqCtx zmq context
 * @param workers worker thread number
 * @param worker worker thread
 * @param tbdSinkAddress tcp breakdown sink address
 *
 * @return 0 if success else -1
 */
int
initRouter (zctx_t *zmqCtx, u_int workers, packetProcessThread worker, const char *tbdSinkAddress) {
    int ret;
    u_int i, n;

    dispatchRouter = malloc (sizeof (router));
    if (dispatchRouter == NULL) {
        LOGE ("Alloc session router error: %s\n.", strerror (errno));
        goto exit;
    }
    memset(dispatchRouter, 0, sizeof (router));

    if (workers == 0)
        dispatchRouter->workers = DEFAULT_ROUTER_WORKERS;
    else {
        if (workers > MAX_ROUTER_WORKERS)
            dispatchRouter->workers = MAX_ROUTER_WORKERS;
        else
            dispatchRouter->workers = workers;
    }

    dispatchRouter->zmqCtx = zmqCtx;
    dispatchRouter->workerSocks = (routerSockPtr) malloc (sizeof (routerSock) * dispatchRouter->workers);
    if (dispatchRouter->workerSocks == NULL) {
        LOGE ("Alloc session router workerSocks error: %s.\n", strerror (errno));
        goto freeRouter;
    }

    for (i = 0; i < dispatchRouter->workers; i++) {
        dispatchRouter->workerSocks [i].pktSndSock = zsocket_new (dispatchRouter->zmqCtx, ZMQ_PAIR);
        dispatchRouter->workerSocks [i].pktRecvSock = zsocket_new (dispatchRouter->zmqCtx, ZMQ_PAIR);
        dispatchRouter->workerSocks [i].tbdSndSock = zsocket_new (dispatchRouter->zmqCtx, ZMQ_PUSH);
        if (dispatchRouter->workerSocks [i].pktSndSock == NULL ||
            dispatchRouter->workerSocks [i].pktRecvSock == NULL ||
            dispatchRouter->workerSocks [i].tbdSndSock == NULL) {
            LOGE ("Create workerSocks [%d] error: %s.\n", i, strerror (errno));
            goto freeWorkerSocks;
        }
        /* Set pktSndSock hwm to 50000 */
        zsocket_set_sndhwm (dispatchRouter->workerSocks [i].pktSndSock, 50000);
        /* Set pktRecvSock hwm to 50000 */
        zsocket_set_rcvhwm (dispatchRouter->workerSocks [i].pktRecvSock, 50000);
        /* Set tbdSndSock hwm to 50000 */
        zsocket_set_sndhwm (dispatchRouter->workerSocks [i].tbdSndSock, 50000);

        ret = zsocket_bind (dispatchRouter->workerSocks [i].pktSndSock, "inproc://workerSocks%d", i);
        if (ret < 0) {
            LOGE ("Bind to \"inproc://workerSocks%d\" error: %s.\n", i, strerror (errno));
            goto freeWorkerSocks;
        }

        ret = zsocket_connect (dispatchRouter->workerSocks [i].pktRecvSock, "inproc://workerSocks%d", i);
        if (ret < 0) {
            LOGE ("Connect to \"inproc://workerSocks%d\" error: %s.\n", i, strerror (errno));
            goto freeWorkerSocks;
        }

        ret = zsocket_connect (dispatchRouter->workerSocks [i].tbdSndSock, tbdSinkAddress);
        if (ret < 0) {
            LOGE ("Connect to \"%s\" error: %s.\n", tbdSinkAddress, strerror (errno));
            goto freeWorkerSocks;
        }

        ret = pthread_create (&dispatchRouter->workerTids [i], NULL, worker, (void *) &dispatchRouter->workerSocks [i]);
        if (ret) {
            LOGE ("Create worker thread:%d error: %s.\n", i, strerror (errno));
            goto freeWorkerSocks;
        }
    }

    return 0;

freeWorkerSocks:
    /* Kill threads created */
    for (n = 0; n <= i; n++) {
        if (dispatchRouter->workerTids [n])
            pthread_kill (dispatchRouter->workerTids [i], SIGINT);
    }
    free (dispatchRouter->workerSocks);
    dispatchRouter->workerSocks = NULL;
freeRouter:
    free (dispatchRouter);
    dispatchRouter = NULL;
exit:
    return -1;
}

/* Destroy dispatch router */
void
destroyRouter (void) {
    u_int i;

    if (dispatchRouter) {
        for (i = 0; i < dispatchRouter->workers; i++) {
            if (dispatchRouter->workerTids [i])
                pthread_kill (dispatchRouter->workerTids [i], SIGINT);
        }
        /* Destroy other contexts */
        free (dispatchRouter->workerSocks);
        dispatchRouter->workerSocks = NULL;
        free (dispatchRouter);
        dispatchRouter = NULL;
    }
}
