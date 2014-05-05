#ifndef __WDM_AGENT_TCP_OPTIONS_H__
#define __WDM_AGENT_TCP_OPTIONS_H__

#include <stdint.h>
#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
BOOL
getTimeStampOption (struct tcphdr *tcph, uint32_t *ts);
BOOL
getTcpWindowScaleOption (struct tcphdr *tcph, uint16_t *ws);
BOOL
getTcpMssOption (struct tcphdr *tcph, uint16_t *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_TCP_OPTIONS_H__ */
