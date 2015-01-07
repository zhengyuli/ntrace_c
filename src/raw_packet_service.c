#include <stdlib.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <czmq.h>
#include "util.h"
#include "logger.h"
#include "properties_manager.h"
#include "zmq_hub.h"
#include "app_service_manager.h"
#include "task_manager.h"
#include "raw_packet.h"
#include "raw_packet_service.h"

/* Pcap configurations */
#define PCAP_MAX_CAPTURE_LENGTH 65535
#define PCAP_CAPTURE_TIMEOUT 500
#define PCAP_CAPTURE_IN_PROMISC 1
#define PCAP_CAPTURE_BUFFER_SIZE (16 << 20)

static pcap_t *pcapDesc = NULL;
static int linkType = -1;

/*
 * @brief Create a new pcap descriptor
 *
 * @param interface net interface bind to pcap descriptor
 *
 * @return pcap descriptor if success else NULL
 */
static pcap_t *
newPcapDev (const char *interface) {
    int ret;
    pcap_t *pcapDev;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("No network devices found.\n");
        return NULL;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (strEqual (devptr->name, interface))
            break;
    }
    if (devptr == NULL)
        return NULL;

    /* Create pcap descriptor */
    pcapDev = pcap_create (interface, errBuf);
    if (pcapDev == NULL) {
        LOGE ("Create pcap device error: %s.\n", errBuf);
        return NULL;
    }

    /* Set pcap max capture length */
    ret = pcap_set_snaplen (pcapDev, PCAP_MAX_CAPTURE_LENGTH);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (pcapDev, PCAP_CAPTURE_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set capture timeout error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (pcapDev, PCAP_CAPTURE_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDev, PCAP_CAPTURE_IN_PROMISC);
    if (ret < 0) {
        LOGE ("Set pcap promisc mode error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Activate pcap device */
    ret = pcap_activate (pcapDev);
    if (ret < 0) {
        LOGE ("Activate pcap device error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    return pcapDev;
}

/* Update BPF filter */
int
updateFilter (const char *filter) {
    int ret;
    struct bpf_program pcapFilter;

    ret = pcap_compile (pcapDesc, &pcapFilter, filter, 1, 0);
    if (ret < 0) {
        pcap_freecode (&pcapFilter);
        return -1;
    }

    ret = pcap_setfilter (pcapDesc, &pcapFilter);
    pcap_freecode (&pcapFilter);
    return ret;
}

/*
 * Raw packet capture service.
 * Capture raw packet from mirror interface, then get ip packet
 * from raw packet and push it to ip packet parsing service.
 */
void *
rawPktCaptureService (void *args) {
    int ret;
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

    /* Get ipPktPushSock */
    ipPktPushSock = getIpPktPushSock ();
    
    /* Create pcap descriptor */
    pcapDesc = newPcapDev (getPropertiesMirrorInterface ());
    if (pcapDesc == NULL) {
        LOGE ("Create pcap descriptor for %s error.\n", getPropertiesMirrorInterface ());
        goto destroyLog;
    }

    /* Get link type */
    linkType = pcap_datalink (pcapDesc);
    if (linkType < 0) {
        LOGE ("Get datalink type error.\n");
        goto destroyPcapDesc;
    }

    /* Get application service filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application service filter error.\n");
        goto destroyPcapDesc;
    }

    /* Update application services filter */
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        free (filter);
        goto destroyPcapDesc;
    }
    LOGD ("Update application services filter: %s\n", filter);
    free (filter);

    while (!taskInterrupted ())
    {
        ret = pcap_next_ex (pcapDesc, &capPkthdr, (const u_char **) &rawPkt);
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

    LOGD ("RawPktCaptureService will exit...\n");
destroyPcapDesc:
    pcap_close (pcapDesc);
    linkType = -1;
destroyLog:
    destroyLog ();
exit:
    if (!taskInterrupted ())
        sendTaskExit ();

    return NULL;
}

