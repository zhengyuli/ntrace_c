#ifndef __AGENT_CHECKSUM_H__
#define __AGENT_CHECKSUM_H__
#include <sys/types.h>
#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
u_short
ipFastCheckSum (u_char *iph, u_int ihl);
u_short
tcpFastCheckSum (struct tcphdr *th, int len, u_int saddr, u_int daddr);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_CHECKSUM_H__ */
