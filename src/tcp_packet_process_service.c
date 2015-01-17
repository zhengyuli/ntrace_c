#include "util.h"
#include "log.h"
#include "properties.h"
#include "task_manager.h"
#include "zmq_hub.h"
#include "tcp_packet.h"
#include "tcp_packet_process_service.h"

/* Publish session breakdown callback */
static void
publishSessionBreakdown (const char *sessionBreakdown, void *args) {
    void *pubSock = args;

    zstr_send (pubSock, sessionBreakdown);
    LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
}

/*
 * Tcp packet process service.
 * Pull ip packets pushed from ipPktParsingService, then do tcp process and
 * push session breakdown to session breakdown sink service.
 */
void *
tcpPktProcessService (void *args) {
    int ret;
    u_int dispatchIndex;
    void *tcpPktPullSock;
    void *breakdownPushSock;
    timeValPtr tm;
    struct ip *iphdr;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;

    dispatchIndex = *((u_int *) args);
    tcpPktPullSock = getTcpPktPullSock (dispatchIndex);
    breakdownPushSock = getBreakdownPushSock (dispatchIndex);

    /* Reset task interrupt flag */
    resetTaskInterruptFlag ();

    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Init tcp context */
    ret = initTcp (publishSessionBreakdown, breakdownPushSock);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyLog;
    }

    while (!taskIsInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktPullSock);
            if (tmFrame == NULL) {
                if (!taskIsInterrupted ())
                    LOGE ("Receive timestamp zframe fatal error.\n");
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (tcpPktPullSock);
        if (pktFrame == NULL) {
            if (!taskIsInterrupted ())
                LOGE ("Receive ip packet zframe fatal error.\n");
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

    destroyTcp ();
destroyLog:
    destroyLog ();
exit:
    if (!taskIsInterrupted ())
        sendTaskExit ();

    return NULL;
}
