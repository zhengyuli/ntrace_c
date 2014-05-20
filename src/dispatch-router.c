#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "util.h"
#include "log.h"
#include "dispatch-router.h"

typedef struct _dispatchRouter dispatchRouter;
typedef dispatchRouter *dispatchRouterPtr;

struct _dispatchRouter {
    u_int parsingThreads;
    void **pushSocks;
};

/* Dispatch router */
static dispatchRouterPtr router;

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
    u_int ipTotalLen;
    struct ip *iph = iphdr;
    struct tcphdr *tcph;
    char key1 [32] = {0};
    char key2 [32] = {0};
    zframe_t *frame;

    ipTotalLen = ntohs (iph->ip_len);

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
    index = dispatchHash (key1, key2) % router->parsingThreads;

    /* Push timeVal */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, router->pushSocks [index], ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Push timestamp zframe error.\n");
        zframe_destroy (&frame);
        return;
    }

    /* Push ip packet */
    frame = zframe_new (iphdr, ipTotalLen);
    if (frame == NULL) {
        LOGE ("Create ip packet zframe error.");
        return;
    }
    ret = zframe_send (&frame, router->pushSocks [index], 0);
    if (ret < 0) {
        LOGE ("Push ip packet zframe error.\n");
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Init packet dispatch router
 *
 * @param parsingThreads parsing threads number
 *
 * @return 0 if success else -1
 */
int
initDispatchRouter (u_int parsingThreads) {
    int ret;
    u_int i, size;

    router = (dispatchRouterPtr) malloc (sizeof (dispatchRouter));
    if (router == NULL) {
        LOGE ("Alloc dispatchRouter error: %s\n.", strerror (errno));
        return -1;
    }

    router->parsingThreads = parsingThreads;
    size = sizeof (void *) * router->parsingThreads;
    router->pushSocks = (void **) malloc (size);
    if (router->pushSocks == NULL) {
        LOGE ("Alloc dispatchRouter pushSocks error: %s.\n", strerror (errno));

        goto freeDispatchRouter;
    }
    memset (router->pushSocks, 0, size);

    for (i = 0; i < router->parsingThreads; i++) {
        router->pushSocks [i] = newZSock (ZMQ_PUSH);
        if (router->pushSocks [i] == NULL) {
            LOGE ("Create pushSocks [%u] error.\n", i);
            goto freePushSocks;
        }

        /* Set pushSocks [i] sndhwm to 500000 */
        zsocket_set_sndhwm (router->pushSocks [i], 500000);

        /* Connect to tcpPacketParsingPushChannel */
        ret = zsocket_connect (router->pushSocks [i], TCP_PACKET_PARSING_PUSH_CHANNEL ":%u", i);
        if (ret < 0) {
            LOGE ("Connect to %s:%u error.\n", TCP_PACKET_PARSING_PUSH_CHANNEL, i);
            goto freePushSocks;
        }
    }

    return 0;

freePushSocks:
    for (i = 0; i < router->parsingThreads; i++) {
        if (router->pushSocks [i]) {
            closeZSock (router->pushSocks);
        }
    }
    free (router->pushSocks);
    router->pushSocks = NULL;
freeDispatchRouter:
    free (router);
    router = NULL;

    return -1;
}

/* Destroy dispatch router */
void
destroyDispatchRouter (void) {
    u_int i;

    for (i = 0; i < router->parsingThreads; i++) {
        if (router->pushSocks [i]) {
            closeZSock (router->pushSocks);
        }
    }
    free (router->pushSocks);
    router->pushSocks = NULL;
    free (router);
    router = NULL;
}
