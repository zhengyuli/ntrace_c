#include <pcap.h>
#include "log.h"

/*
 * @brief Extract ip packet from raw packet
 *
 * @param rawPkt raw packet captured by pcap
 * @param dataLinkType datalink type
 *
 * @return Ip packet address if success else NULL
 */
u_char *
getIpPacket (u_char *rawPkt, u_int datalinkType) {
    u_int offset;

    switch (datalinkType) {
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
            LOGE ("Unknown datalink type.\n");
            return NULL;
    }

    return (rawPkt + offset);
}
