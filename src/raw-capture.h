#ifndef __AGENT_RAW_CAPTURE_H__
#define __AGENT_RAW_CAPTURE_H__

#include <sys/types.h>
#include <pcap.h>

/*========================Interfaces definition============================*/
u_char *
getIpPacket (struct pcap_pkthdr *pkthdr, u_char *rawPkt);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_RAW_CAPTURE_H__ */
