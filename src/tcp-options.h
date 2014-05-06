#ifndef __AGENT_TCP_OPTIONS_H__
#define __AGENT_TCP_OPTIONS_H__

#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
BOOL
getTimeStampOption (struct tcphdr *tcph, u_int *ts);
BOOL
getTcpWindowScaleOption (struct tcphdr *tcph, u_short *ws);
BOOL
getTcpMssOption (struct tcphdr *tcph, u_short *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TCP_OPTIONS_H__ */
