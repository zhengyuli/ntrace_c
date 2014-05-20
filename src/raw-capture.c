#include <sys/types.h>
#include <pcap.h>
#include "log.h"

#define PCAP_MAX_CAPTURE_LENGTH 65535
#define PCAP_CAPTURE_TIMEOUT 1000
#define PCAP_CAPTURE_PROMISIC 1
#define PCAP_DEFAULT_BUFFER_SIZE (16 * 1024 * 1024)

/*
 * @brief Extract ip packet from raw packet
 *
 * @param capPkthdr packet pcap header
 * @param rawPkt raw packet captured by pcap
 * @param linkType datalink type
 *
 * @return Ip packet address if success else NULL
 */
u_char *
getIpPacket (struct pcap_pkthdr *capPkthdr, u_char *rawPkt, int linkType) {
    u_int offset;

    switch (linkType) {
        /* BSD loopback encapsulation */
        case DLT_NULL:
            offset = 4;
            break;

            /* Ethernet (10Mb, 100Mb, 1000Mb or higher) */
        case DLT_EN10MB:
            /* Regular ip frame */
            if ((rawPkt [12] == 0x08) && (rawPkt [13] == 0x00))
                offset = 14;
            else if ((rawPkt [12] == 0x81) && (rawPkt [13] == 0x00)) {
                /*
                 * 802.1Q VLAN frame
                 * +----------------------------------------------------------------------+
                 * | Dest Mac: 6 bytes | Src Mac: 6 bytes ||TPID|PCP|CFI|VID|| Ether type |
                 * +----------------------------------------------------------------------+
                 *                                        ^                  ^
                 *                                        |  802.1Q header   |
                 * skip VLAN header, include TPID(Tag Protocal Identifier: 16 bits),
                 * PCP(Priority Code Point: 3 bits), CFI(Canonical Format Indicator: 1 bits) ,
                 * VID(VLAN Identifier: 12 bits)
                 */
                offset = 18;
            } else {
                /* Wrong ip packet */
                LOGE ("Wrong ip packet.\n");
                return NULL;
            }
            break;

            /* Token Ring Support */
        case DLT_IEEE802:
            offset = 22;
            break;

            /* Serial line ip packet */
        case DLT_SLIP:
            offset = 0;
            break;

            /* Point-to-point Protocol */
        case DLT_PPP:
            offset = 4;
            break;

            /* FDDI */
        case DLT_FDDI:
            offset = 21;
            break;

            /* Raw ip packet */
        case DLT_RAW:
            offset = 0;
            break;

            /* This is for Linux cooked sockets */
        case DLT_LINUX_SLL:
            offset = 16;
            break;

            /* PPP over serial with HDLC encapsulation */
        case DLT_PPP_SERIAL:
            offset = 4;
            break;

        default:
            LOGE ("Unknown link type.\n");
            return NULL;
    }

    if (capPkthdr->caplen < offset)
        return NULL;

    return (rawPkt + offset);
}

pcap_t *
newPcapDev (const char *interface) {
    int ret;
    pcap_t *pcapDev;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
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
    ret = pcap_set_buffer_size (pcapDev, PCAP_DEFAULT_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDev, PCAP_CAPTURE_PROMISIC);
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

inline void
freePcapDev (pcap_t *pcapDev) {
    pcap_close (pcapDev);
}
