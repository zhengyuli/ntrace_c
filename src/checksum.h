#ifndef __AGENT_CHECKSUM_H__
#define __AGENT_CHECKSUM_H__
#include <sys/types.h>
#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
u_int
ipFastCheckSum (const u_char *iph, u_int ihl);
u_int
tcpFastCheckSum (const struct tcphdr *th, u_int len, u_int saddr, u_int daddr);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_CHECKSUM_H__ */
