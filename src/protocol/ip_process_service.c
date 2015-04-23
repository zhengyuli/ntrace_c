#include <stdlib.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ownership_manager.h"
#include "ip.h"
#include "tcp.h"
#include "ip_packet.h"
#include "ip_process_service.h"

static u_int
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

/**
 * @brief Dispatch timestamp and ip packet to local or remote
 *        tcp packet dispatch service.
 *
 * @param iph ip packet to dispatch
 * @param tm timestamp to dispatch
 */
static void
tcpPacketDispatch (iphdrPtr iph, timeValPtr tm) {
    int ret;
    u_int hash;
    u_int ipPktLen;
    tcphdrPtr tcph;
    char key1 [32];
    char key2 [32];
    zframe_t *frame;
    void *tcpPktSendSock = NULL;

    ipPktLen = ntohs (iph->ipLen);

    tcph = (tcphdrPtr) ((u_char *) iph + (iph->iphLen * 4));
    snprintf (key1, sizeof (key1), "%s:%d", inet_ntoa (iph->ipSrc), ntohs (tcph->source));
    snprintf (key2, sizeof (key2), "%s:%d", inet_ntoa (iph->ipDest), ntohs (tcph->dest));

    hash = dispatchHash (key1, key2);
    tcpPktSendSock = getOwnershipPktDispatchSock (hash);

    /* Send tm zframe */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, tcpPktSendSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Send tm zframe error.\n");
        return;
    }

    /* Send ip packet */
    frame = zframe_new (iph, ipPktLen);
    if (frame == NULL) {
        LOGE ("Create ip packet zframe error.");
        return;
    }
    ret = zframe_send (&frame, tcpPktSendSock, 0);
    if (ret < 0) {
        LOGE ("Send ip packet zframe error.\n");
        return;
    }
}

/**
 * @brief Dispatch timestamp and ip packet to icmp
 *        packet process service.
 *
 * @param iph ip packet to dispatch
 * @param tm capture timestamp to dispatch
 */
static void
icmpPacketDispatch (iphdrPtr iph, timeValPtr tm) {
    int ret;
    u_int ipPktLen;
    zframe_t *frame;
    void *icmpPktSendSock;

    ipPktLen = ntohs (iph->ipLen);

    /* Get icmp packet send sock */
    icmpPktSendSock = getIcmpPktSendSock ();

    /* Send tm zframe */
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, icmpPktSendSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Send tm zframe error.\n");
        return;
    }

    /* Send ip packet */
    frame = zframe_new (iph, ipPktLen);
    if (frame == NULL) {
        LOGE ("Create ip packet zframe error.");
        return;
    }
    ret = zframe_send (&frame, icmpPktSendSock, 0);
    if (ret < 0) {
        LOGE ("Send ip packet zframe error.\n");
        return;
    }
}

/*
 * Ip packet process service.
 * Read ip packet send by rawPktCaptureService, then do ip process and
 * dispatch ip defragment packet to specific tcpPktProcessService thread.
 */
void *
ipProcessService (void *args) {
    int ret;
    void *ipPktRecvSock;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    iphdrPtr newIphdr;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("IpProcessService");

    /* Get ipPktRecvSock */
    ipPktRecvSock = getIpPktRecvSock ();

    /* Init ip context */
    ret = initIpContext ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLogContext;
    }

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (ipPktRecvSock);
            if (tmFrame == NULL) {
                if (!SIGUSR1IsInterrupted ())
                    LOGE ("Receive timestamp zframe fatal error.\n");
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (ipPktRecvSock);
        if (pktFrame == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive ip packet zframe fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        ret = ipDefrag ((iphdrPtr) zframe_data (pktFrame),
                        (timeValPtr) zframe_data (tmFrame), &newIphdr);
        if (ret < 0)
            LOGE ("Ip packet defragment error.\n");

        if (newIphdr) {
            switch (newIphdr->ipProto) {
                case IPPROTO_TCP:
                    tcpPacketDispatch (newIphdr, (timeValPtr) zframe_data (tmFrame));
                    break;

                case IPPROTO_ICMP:
                    icmpPacketDispatch (newIphdr, (timeValPtr) zframe_data (tmFrame));

                default:
                    break;
            }

            /* Free new ip packet after defragment */
            if (newIphdr != (iphdrPtr) zframe_data (pktFrame))
                free (newIphdr);
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGI ("IpProcessService will exit ... .. .\n");
    destroyIpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
