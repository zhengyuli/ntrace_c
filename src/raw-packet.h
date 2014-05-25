#ifndef __AGENT_RAW_PACKET_H__
#define __AGENT_RAW_PACKET_H__

#include <sys/types.h>
#include <pcap.h>

/*========================Interfaces definition============================*/
u_char *
getIpPacket (u_char *rawPkt, u_int linkType);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_RAW_PACKET_H__ */
