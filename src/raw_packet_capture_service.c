#include <netinet/ip.h>
#include <pcap.h>
#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "netdev.h"
#include "raw_packet.h"
#include "raw_packet_capture_service.h"

/*
 * Raw packet capture service.
 * Capture raw packet from mirror interface, then extract ip packet
 * from raw packet and send it to ip packet process service.
 */
void *
rawPktCaptureService (void *args) {
    int ret;
    pcap_t *pcapDev;
    int datalinkType;
    void *ipPktSendSock;
    char *filter;
    struct pcap_pkthdr *capturePktHdr;
    u_char *rawPkt;
    struct ip *ipPkt;
    timeVal captureTime;
    zframe_t *frame;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Get net device pcap descriptor */
    pcapDev = getNetDev ();
    /* Get net device datalink type */
    datalinkType = getNetDevDatalinkType ();
    /* Get ipPktSendSock */
    ipPktSendSock = getIpPktSendSock ();

    /* Update application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application services filter error.\n");
        goto destroyLog;
    }
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        free (filter);
        goto destroyLog;
    }
    LOGI ("Update BPF filter with: %s\n", filter);
    free (filter);

    while (!SIGUSR1IsInterrupted ())
    {
        ret = pcap_next_ex (pcapDev, &capturePktHdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter out incomplete raw packet */
            if (capturePktHdr->caplen != capturePktHdr->len)
                continue;

            /* Get ip packet */
            ipPkt = (struct ip *) getIpPacket (rawPkt, datalinkType);
            if (ipPkt == NULL)
                continue;

            /* Get packet capture timestamp */
            captureTime.tvSec = htonll (capturePktHdr->ts.tv_sec);
            captureTime.tvUsec = htonll (capturePktHdr->ts.tv_usec);

            /* Send capture timestamp zframe */
            frame = zframe_new (&captureTime, sizeof (timeVal));
            if (frame == NULL) {
                LOGE ("Create packet timestamp zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktSendSock, ZFRAME_MORE);
            if (ret < 0) {
                LOGE ("Send packet timestamp zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }

            /* Send ip packet zframe */
            frame = zframe_new (ipPkt, ntohs (ipPkt->ip_len));
            if (frame == NULL) {
                LOGE ("Create ip packet zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktSendSock, 0);
            if (ret < 0) {
                LOGE ("Send ip packet zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }
        } else if (ret == -1) {
            LOGE ("Capture raw packet with fatal error.\n");
            break;
        }
    }

    LOGI ("RawPktCaptureService will exit ... .. .\n");
destroyLog:
    destroyLog ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
