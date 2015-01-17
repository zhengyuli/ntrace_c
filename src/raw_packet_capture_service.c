#include <netinet/ip.h>
#include <pcap.h>
#include <czmq.h>
#include "util.h"
#include "log.h"
#include "properties.h"
#include "zmq_hub.h"
#include "app_service_manager.h"
#include "task_manager.h"
#include "netdev.h"
#include "raw_packet.h"
#include "raw_packet_capture_service.h"

/*
 * Raw packet capture service.
 * Capture raw packet from mirror interface, then get ip packet
 * from raw packet and push it to ip packet parsing service.
 */
void *
rawPktCaptureService (void *args) {
    int ret;
    pcap_t *pcapDev;
    int linkType;
    char *filter;
    struct pcap_pkthdr *capPkthdr;
    void *ipPktPushSock;
    u_char *rawPkt;
    struct ip *ipPkt;
    timeVal capTime;
    zframe_t *frame;

    /* Reset task interrupt flag */
    resetTaskInterruptFlag ();

    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Get net device pcap descriptor */
    pcapDev = getNetDev ();
    /* Get net device link type */
    linkType = getNetDevLinkType ();
    /* Get ipPktPushSock */
    ipPktPushSock = getIpPktPushSock ();

    /* Update application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application service filter error.\n");
        goto destroyLog;
    }
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        free (filter);
        goto destroyLog;
    }
    LOGD ("Update application services filter: %s\n", filter);
    free (filter);

    while (!taskIsInterrupted ())
    {
        ret = pcap_next_ex (pcapDev, &capPkthdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter out incomplete packet */
            if (capPkthdr->caplen != capPkthdr->len)
                continue;

            /* Get ip packet */
            ipPkt = (struct ip *) getIpPacket (rawPkt, linkType);
            if (ipPkt == NULL)
                continue;

            /* Get packet capture timestamp */
            capTime.tvSec = htonll (capPkthdr->ts.tv_sec);
            capTime.tvUsec = htonll (capPkthdr->ts.tv_usec);

            /* Push capture timestamp zframe */
            frame = zframe_new (&capTime, sizeof (timeVal));
            if (frame == NULL) {
                LOGE ("Create packet timestamp zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktPushSock, ZFRAME_MORE);
            if (ret < 0) {
                LOGE ("Push packet timestamp zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }

            /* Push ip packet zframe */
            frame = zframe_new (ipPkt, ntohs (ipPkt->ip_len));
            if (frame == NULL) {
                LOGE ("Create ip packet zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktPushSock, 0);
            if (ret < 0) {
                LOGE ("Push ip packet zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }
        } else if (ret == -1) {
            LOGE ("Capture packet fatal error, rawPktCaptureService will exit...\n");
            break;
        }
    }

destroyLog:
    destroyLog ();
exit:
    if (!taskIsInterrupted ())
        sendTaskExit ();

    return NULL;
}
