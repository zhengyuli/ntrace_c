#ifndef __WDM_AGENT_TCP_OPTIONS_H__
#define __WDM_AGENT_TCP_OPTIONS_H__

#include <stdint.h>
#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
int
getTimeStampOption (struct tcphdr *tcph, u_int *ts);
int
getTcpWindowScaleOption (struct tcphdr *tcph, u_int *ws);
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_TCP_OPTIONS_H__ */
