#ifndef __AGENT_CHECKSUM_H__
#define __AGENT_CHECKSUM_H__

#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
u_short
ipFastCheckSum (u_char *iph, u_int iphLen);
u_short
tcpFastCheckSum (u_char *tcph, int tcpLen, u_int saddr, u_int daddr);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_CHECKSUM_H__ */
