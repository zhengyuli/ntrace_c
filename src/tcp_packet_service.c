#include <stdlib.h>
#include <czmq.h>
#include "util.h"
#include "logger.h"
#include "properties_manager.h"
#include "runtime_context.h"
#include "task_manager.h"
#include "zmq_hub.h"
#include "protocol.h"
#include "tcp_packet.h"
#include "tcp_packet_service.h"

/* Publish session breakdown callback */
static void
publishSessionBreakdown (const char *sessionBreakdown, void *args) {
    void *pubSock = args;

    zstr_send (pubSock, sessionBreakdown);
    LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
}

/*
 * Tcp packet parsing service.
 * Pull ip packets pushed from ipPktParsingService, then do tcp parsing and
 * push session breakdown to session breakdown sink service.
 */
void *
tcpPktParsingService (void *args) {
    int ret;
    zctx_t *ctxt;
    u_int dispatchIndex;
    void *tcpPktPullSock;
    void *breakdownPushSock;
    timeValPtr tm;
    struct ip *iphdr;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;

    dispatchIndex = *((u_int *) args);
    tcpPktPullSock = getTcpPktPullSock (dispatchIndex);

    /* Reset task interrupt flag */
    resetTaskInterruptFlag ();
    
    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Create zmq context */
    ctxt = zctx_new ();
    if (ctxt == NULL) {
        LOGE ("Create zmq context error.\n");
        goto destroyLog;
    }
    zctx_set_linger (ctxt, 0);

    /* Create breakdownPushSock */
    breakdownPushSock = zsocket_new (ctxt, ZMQ_PUSH);
    if (breakdownPushSock == NULL) {
        LOGE ("Create breakdownPushSock error.\n");
        goto destroyZmqCtxt;
    }
    zsocket_set_sndhwm (breakdownPushSock, 50000);
    ret = zsocket_connect (breakdownPushSock, "tcp://%s:%u",
                           getBreakdownSinkIp (), getBreakdownSinkPort ());
    if (ret < 0) {
        LOGE ("Connect tcp://%s:%u error.\n", getBreakdownSinkIp (), getBreakdownSinkPort ());
        goto destroyZmqCtxt;
    }

    /* Init tcp context */
    ret = initTcp (publishSessionBreakdown, breakdownPushSock);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyLog;
    }

    /* Init proto context */
    ret = initProto ();
    if (ret < 0) {
        LOGE ("Init proto context error.\n");
        goto destroyTcp;
    }

    while (!taskInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktPullSock);
            if (tmFrame == NULL) {
                if (!taskInterrupted ()) {
                    LOGE ("Receive timestamp zframe fatal error.\n");
                }
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (tcpPktPullSock);
        if (pktFrame == NULL) {
            if (!taskInterrupted ()) {
                LOGE ("Receive ip packet zframe fatal error.\n");
            }
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iphdr = (struct ip *) zframe_data (pktFrame);
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcpProcess (iphdr, tm);
                break;

            default:
                break;
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("TcpPktParsingService will exit...\n");
    destroyProto ();
destroyTcp:
    destroyTcp ();
destroyZmqCtxt:
    zctx_destroy (&ctxt);
destroyLog:
    destroyLog ();
exit:
    if (!taskInterrupted ())
        sendTaskExit ();

    return NULL;
}
