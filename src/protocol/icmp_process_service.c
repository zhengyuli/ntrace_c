#include <stdlib.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ip.h"
#include "icmp_packet.h"
#include "icmp_process_service.h"

/*
 * Icmp packet process service.
 * Read ip packets send by ipPktProcessService, then do icmp process and
 * send session breakdown to session breakdown sink service.
 */
void *
icmpProcessService (void *args) {
    int ret;
    void *icmpPktRecvSock;
    void *icmpBreakdownSendSock;
    zframe_t *tmFrame = NULL;
    zframe_t *ipPktFrame = NULL;
    timeValPtr tm;
    iphdrPtr iph;

    icmpPktRecvSock = getIcmpPktRecvSock ();
    icmpBreakdownSendSock = getIcmpBreakdownSendSock ();

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Init icmp context */
    ret = initIcmp (icmpBreakdownSendSock);
    if (ret < 0) {
        LOGE ("Init icmp context error.\n");
        goto destroyLogContext;
    }

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (icmpPktRecvSock);
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
        ipPktFrame = zframe_recv (icmpPktRecvSock);
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
        iph = (iphdrPtr) zframe_data (ipPktFrame);

        /* Do icmp process */
        icmpProcess (iph, tm);

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&ipPktFrame);
    }

    LOGI ("IcmpProcessService will exit ... .. .\n");
    destroyIcmp ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
