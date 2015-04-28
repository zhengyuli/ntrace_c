#define _GNU_SOURCE
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ip.h"
#include "tcp_packet.h"
#include "tcp_process_service.h"

/* Tcp session breakdown send sock */
static __thread void *tcpBreakdownSendSock = NULL;

static void
publishTcpBreakdown (void *args) {
    int ret;
    char *tcpBreakdown = (char *) args;
    zframe_t *frame;

    frame = zframe_new (tcpBreakdown, strlen (tcpBreakdown));
    if (frame == NULL) {
        LOGE ("Create tcp breakdown zframe error.\n");
        return;
    }

    ret = zframe_send (&frame, tcpBreakdownSendSock, 0);
    if (ret < 0)
        LOGE ("Send tcp breakdown error.\n");
}

/*
 * Tcp packet process service.
 * Read ip packets send by ipPktProcessService, then do tcp process and
 * send session breakdown to session breakdown sink service.
 */
void *
tcpProcessService (void *args) {
    int ret;
    u_int dispatchIndex;
    cpu_set_t cpuset;
    void *tcpPktRecvSock;
    zframe_t *tmFrame = NULL;
    zframe_t *ipPktFrame = NULL;
    timeValPtr tm;
    iphdrPtr iph;

    dispatchIndex = *((u_int *) args);
    tcpPktRecvSock = getTcpPktRecvSock (dispatchIndex);
    tcpBreakdownSendSock = getTcpBreakdownSendSock (dispatchIndex);

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Bind tcpProcessService to CPU# */
    CPU_ZERO (&cpuset);
    CPU_SET (dispatchIndex, &cpuset);
    ret = pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
    if (ret < 0) {
        LOGE ("Binding tcpProcessService:%u to CPU%u error.\n", dispatchIndex, dispatchIndex);
        goto destroyLogContext;
    }
    LOGI ("Binding tcpProcessService:%u to CPU%u success.\n", dispatchIndex, dispatchIndex);

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("TcpProcessService");

    /* Init tcp context */
    ret = initTcpContext (False, publishTcpBreakdown);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyLogContext;
    }

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktRecvSock);
            if (tmFrame == NULL) {
                if (!SIGUSR1IsInterrupted ())
                    LOGE ("Receive timestamp zframe with fatal error.\n");
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
                LOGE ("Receive ip packet zframe with fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (ipPktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = ipPktFrame;
            ipPktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iph = (iphdrPtr) zframe_data (ipPktFrame);

        /* Do tcp process */
        tcpProcess (iph, tm);

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&ipPktFrame);
    }

    LOGI ("TcpProcessService will exit ... .. .\n");
    destroyTcpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
