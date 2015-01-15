#include <stdlib.h>
#include <net/if.h>
#include <netinet/ip.h>
#include "util.h"
#include "logger.h"
#include "zmq_hub.h"
#include "properties.h"
#include "task_manager.h"
#include "ip_packet.h"
#include "ip_packet_service.h"

/* Dispatch hash */
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
 * @brief Dispatch ip packet and timestamp to specific parsing
 *        thread.
 *
 * @param iphdr ip packet to dispatch
 * @param tm capture timestamp to dispatch
 */
static void
packetDispatch (struct ip *iphdr, timeValPtr tm) {
    int ret;
    u_int index;
    u_int ipPktLen;
    struct ip *iph = iphdr;
    struct tcphdr *tcph;
    char key1 [32];
    char key2 [32];
    zframe_t *frame;
    void *pushSock;

    ipPktLen = ntohs (iph->ip_len);

    switch (iph->ip_p) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *) ((u_char *) iph + (iph->ip_hl * 4));
            snprintf (key1, sizeof (key1), "%s:%d", inet_ntoa (iph->ip_src), ntohs (tcph->source));
            snprintf (key2, sizeof (key2), "%s:%d", inet_ntoa (iph->ip_dst), ntohs (tcph->dest));
            break;

        default:
            return;
    }

    /* Get dispatch index */
    index = dispatchHash (key1, key2) % getTcpPktParsingThreadsNum ();
    pushSock = getTcpPktPushSock (index);

    /* Push timeVal */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, pushSock, ZFRAME_MORE);
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
    ret = zframe_send (&frame, pushSock, 0);
    if (ret < 0) {
        LOGE ("Push ip packet zframe error.\n");
        zframe_destroy (&frame);
        return;
    }
}

/*
 * Ip packet parsing service.
 * Pull ip packet pushed from rawPktCaptureService, then do ip parsing and
 * dispatch defragment ip packet to specific tcpPktParsingService thread.
 */
void *
ipPktParsingService (void *args) {
    int ret;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    struct ip *newIphdr;
    void *ipPktPullSock;

    /* Reset task interrupt flag */
    resetTaskInterruptFlag ();

    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        LOGE ("Init log context error.\n");
        goto exit;
    }

    /* Get ipPktPullSock */
    ipPktPullSock = getIpPktPullSock ();

    /* Init ip context */
    ret = initIp ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLog;
    }

    while (!taskInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (ipPktPullSock);
            if (tmFrame == NULL) {
                if (!taskInterrupted ())
                    LOGE ("Receive timestamp zframe fatal error.\n");
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (ipPktPullSock);
        if (pktFrame == NULL) {
            if (!taskInterrupted ())
                LOGE ("Receive ip packet zframe fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        ret = ipDefrag ((struct ip *) zframe_data (pktFrame), (timeValPtr) zframe_data (tmFrame), &newIphdr);
        if (ret < 0)
            LOGE ("Ip packet defragment error.\n");
        else if (newIphdr) {
            packetDispatch ((struct ip *) newIphdr, (timeValPtr) zframe_data (tmFrame));
            /* New ip packet after defragment */
            if (newIphdr != (struct ip *) zframe_data (pktFrame))
                free (newIphdr);
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("IpPktParsingService will exit...\n");
    destroyIp ();
destroyLog:
    destroyLog ();
exit:
    if (!taskInterrupted ())
        sendTaskExit ();

    return NULL;
}
