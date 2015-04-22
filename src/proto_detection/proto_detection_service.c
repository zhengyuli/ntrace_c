#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "netdev.h"
#include "ip.h"
#include "raw_packet.h"
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
    ret = initIp ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLogContext;
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

            ret = ipDefrag (iph, captureTime, &newIphdr);
            if (ret < 0)
                LOGE ("Ip packet defragment error.\n");

            if (newIphdr) {
                switch (newIphdr->ipProto) {
                    case IPPROTO_TCP:
                        tcpPacketDispatch (newIphdr, (timeValPtr) zframe_data (tmFrame));
                        break;

                    default:
                        break;
                }

                /* Free new ip packet after defragment */
                if (newIphdr != iph)
                    free (newIphdr);
            }
        } else if (ret == -1) {
            LOGE ("Capture raw packets with fatal error.\n");
            break;
        } else if (ret == -2) {
            LOGI ("Capture raw packets complete.\n");
            break;
        }
    }

    LOGI ("ProtoDetectionService will exit ... .. .\n");
destroyIp:
    destroyIp ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus ("ProtoDetectionService", TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
