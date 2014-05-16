
/*
 * @brief Get datalink offset
 *
 * @param datalinkType datalink type
 *
 * @return Link offset of packet frame, else return -1
 */
static int
getDatalinkOffset (u_int datalinkType) {
    u_int offset;

    switch (datalinkType) {
        /* BSD loopback encapsulation */
        case DLT_NULL:
            offset = 4;
            break;

            /* Ethernet (10Mb, 100Mb, 1000Mb or higher) */
        case DLT_EN10MB:
            offset = 14;
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
            offset = -1;
            break;
    }

    return offset;
}

/*
 * @brief Get ip header from raw packet
 *
 * @param pkthdr packet pcap header
 * @param rawPkt raw packet captured by pcap
 *
 * @return Ip header if success else null
 */
static u_char *
getIpHeader (struct pcap_pkthdr *pkthdr, u_char *rawPkt) {
    /* Filter incomplete packet */
    if (pkthdr->caplen != pkthdr->len)
        return NULL;

    switch (mirrorNic.linkType) {
        case DLT_EN10MB:
            /* Wrong packet */
            if (pkthdr->caplen < 14)
                return NULL;
            /* Recheck link offset */
            if ((rawPkt [12] == 0x08) && (rawPkt [13] == 0x00))
                /* Regular ip frame */
                mirrorNic.linkOffset = 14;
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
                mirrorNic.linkOffset = 18;
            } else {
                /* Non-ip packet */
                LOGE ("Wrong ip packet.\n");
                return NULL;
            }
            break;

        default:
            /* For other link type do nothing */
            break;
    }

    /* Recheck packet len, especially for DLT_EN10MB */
    if (pkthdr->caplen < mirrorNic.linkOffset) {
        LOGE ("Packet capture length:%d less than data link offset:%d.\n",
              pkthdr->caplen, mirrorNic.linkOffset);
        return NULL;
    }
    return (rawPkt + mirrorNic.linkOffset);
}
