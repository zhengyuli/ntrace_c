#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "util.h"
#include "log.h"
#include "router.h"

typedef struct _router router;
typedef router *routerPtr;

struct _router {
    u_int parsingThreads;
    void **pushSocks;
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

    /* Get dispatch router index */
    index = routerHash (key1, key2) % dispatchRouter->parsingThreads;

    /* Push timeVal */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, dispatchRouter->pushSocks [index], ZFRAME_MORE);
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
    ret = zframe_send (&frame, dispatchRouter->pushSocks [index], 0);
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
initRouter (u_int parsingThreads) {
    int ret;
    u_int i;

    dispatchRouter = (routerPtr) malloc (sizeof (router));
    if (dispatchRouter == NULL) {
        LOGE ("Alloc router error: %s\n.", strerror (errno));
        return -1;
    }

    dispatchRouter->parsingThreads = parsingThreads;
    dispatchRouter->pushSocks = (void **) malloc (sizeof (void *) * dispatchRouter->parsingThreads);
    if (dispatchRouter->pushSocks == NULL) {
        LOGE ("Alloc router pushSocks error: %s.\n", strerror (errno));
        goto freeRouter;
    }

    for (i = 0; i < dispatchRouter->parsingThreads; i++) {
        dispatchRouter->pushSocks [i] = newZSock (ZMQ_PUSH);
        if (dispatchRouter->pushSocks [i] == NULL) {
            LOGE ("Create pushSocks [%u] error.\n", i);
            goto freePushSocks;
        }

        /* Set pushSocks [i] hwm to 500000 */
        zsocket_set_sndhwm (dispatchRouter->pushSocks [i], 500000);

        /* Connect to tcpPacketParsingPushChannel */
        ret = zsocket_connect (dispatchRouter->pushSocks [i], TCP_PACKET_PARSING_PUSH_CHANNEL ":%u", i);
        if (ret < 0) {
            LOGE ("Connect to %s:%u error.\n", TCP_PACKET_PARSING_PUSH_CHANNEL, i);
            goto freePushSocks;
        }
    }

    return 0;

freePushSocks:
    free (dispatchRouter->pushSocks);
    dispatchRouter->pushSocks = NULL;
freeRouter:
    free (dispatchRouter);
    dispatchRouter = NULL;

    return -1;
}

/* Destroy dispatch router */
void
destroyRouter (void) {
    free (dispatchRouter->pushSocks);
    dispatchRouter->pushSocks = NULL;
    free (dispatchRouter);
    dispatchRouter = NULL;
}
