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
#include "tcp.h"
#include "raw_packet.h"
#include "ip_packet.h"
#include "tcp_packet.h"
#include "proto_detect_service.h"

/*
 * Proto detect service.
 * Capture raw packets from pcap file or mirror interface,
 * then do ip defragment and tcp packet process to detect
 * application level proto.
 */
void *
protoDetectService (void *args) {
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

    /* Init tcp context */
    ret = initTcpContext (True, NULL);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyIpContext;
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
                        tcpProcess (newIphdr, &captureTime);
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

    LOGI ("ProtoDetectService will exit ... .. .\n");
    destroyTcpContext ();
destroyIpContext:
    destroyIpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (exitNormally)
        sendTaskStatus (TASK_STATUS_EXIT_NORMALLY);
    else if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
