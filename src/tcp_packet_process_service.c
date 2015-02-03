#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
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
 * Read ip packets send by ipPktProcessService, then do tcp process and
 * send session breakdown to session breakdown sink service.
 */
void *
tcpPktProcessService (void *args) {
    int ret;
    u_int dispatchIndex;
    void *tcpPktRecvSock;
    void *breakdownSendSock;
    zframe_t *tmFrame = NULL;
    zframe_t *ipPktFrame = NULL;
    timeValPtr tm;
    struct ip *iphdr;

    dispatchIndex = *((u_int *) args);
    tcpPktRecvSock = getTcpPktRecvSock (dispatchIndex);
    breakdownSendSock = getBreakdownSendSock (dispatchIndex);

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Init tcp context */
    ret = initTcp (publishSessionBreakdown, breakdownSendSock);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyLog;
    }

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktRecvSock);
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
        ipPktFrame = zframe_recv (tcpPktRecvSock);
        if (ipPktFrame == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive ip packet zframe fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (ipPktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = ipPktFrame;
            ipPktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iphdr = (struct ip *) zframe_data (ipPktFrame);
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcpProcess (iphdr, tm);
                break;

            default:
                break;
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&ipPktFrame);
    }

    LOGI ("TcpPktProcessService will exit ... .. .\n");
    destroyTcp ();
destroyLog:
    destroyLog ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
