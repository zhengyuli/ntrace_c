#ifndef __AGENT_TCP_OPTIONS_H__
#define __AGENT_TCP_OPTIONS_H__

#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
bool
getTimeStampOption (struct tcphdr *tcph, u_int *ts);
bool
getTcpWindowScaleOption (struct tcphdr *tcph, u_short *ws);
bool
getTcpMssOption (struct tcphdr *tcph, u_short *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TCP_OPTIONS_H__ */
