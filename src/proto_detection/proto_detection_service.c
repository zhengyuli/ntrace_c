#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "netdev.h"
#include "task_manager.h"
#include "ip.h"
#include "raw_packet.h"
#include "ip_packet.h"
#include "proto_detector.h"
#include "proto_detection_packet.h"
#include "proto_detection_service.h"

/*
 * Proto detection service.
 */
void *
protoDetectionService (void *args) {
    int ret;
    pcap_t * pcapDev;
    int datalinkType;
    struct pcap_pkthdr *capPktHdr;
    u_char *rawPkt;
    timeVal captureTime;
    iphdrPtr iph, newIphdr;
    boolean exitNormally = False;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Get net device pcap descriptor for proto detection */
    pcapDev = getNetDevPcapDescForProtoDetection ();
    /* Get net device datalink type for proto detection */
    datalinkType = getNetDevDatalinkTypeForProtoDetection ();

    /* Update proto detection filter */
    ret = updateNetDevFilterForProtoDetection ("tcp");
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        goto destroyLogContext;
    }

    /* Init ip context */
    ret = initIpContext ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLogContext;
    }

    /* Init proto detection context */
    ret = initProtoDetectionContext ();
    if (ret < 0) {
        LOGE ("Init proto detection context error.\n");
        goto destroyIpContext;
    }

    /* Init proto detector */
    ret = initProtoDetector ();
    if (ret < 0) {
        LOGE ("Init proto detector error.\n");
        goto destroyProtoDetectionContext;
    }

    while (!SIGUSR1IsInterrupted ()) {
        ret = pcap_next_ex (pcapDev, &capPktHdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter out incomplete raw packet */
            if (capPktHdr->caplen != capPktHdr->len)
                continue;

            /* Get ip packet and filter non-tcp packets */
            iph = (iphdrPtr) getIpPacket (rawPkt, datalinkType);
            if (iph == NULL || iph->ipProto != IPPROTO_TCP)
                continue;

            /* Get packet capture timestamp */
            captureTime.tvSec = htonll (capPktHdr->ts.tv_sec);
            captureTime.tvUsec = htonll (capPktHdr->ts.tv_usec);

            ret = ipDefrag (iph, &captureTime, &newIphdr);
            if (ret < 0)
                LOGE ("Ip packet defragment error.\n");

            if (newIphdr) {
                switch (newIphdr->ipProto) {
                    case IPPROTO_TCP:
                        protoDetectionProcess (newIphdr, &captureTime);
                        break;

                    default:
                        break;
                }

                /* Free new ip packet after defragment */
                if (newIphdr != iph)
                    free (newIphdr);
            }
        } else if (ret == -1) {
            LOGE ("Capture raw packets for proto detection with fatal error.\n");
            break;
        } else if (ret == -2) {
            exitNormally = True;
            break;
        }
    }

    LOGI ("ProtoDetectionService will exit ... .. .\n");
    destroyProtoDetector ();
destroyProtoDetectionContext:
    destroyProtoDetectionContext ();
destroyIpContext:
    destroyIpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (exitNormally)
        sendTaskStatus ("ProtoDetectionService", TASK_STATUS_EXIT_NORMALLY);
    else if (!SIGUSR1IsInterrupted ())
        sendTaskStatus ("ProtoDetectionService", TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
