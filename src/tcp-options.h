#ifndef __AGENT_TCP_OPTIONS_H__
#define __AGENT_TCP_OPTIONS_H__

#include <stdint.h>
#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
int
getTimeStampOption (struct tcphdr *tcph, uint32_t *ts);
int
getTcpWindowScaleOption (struct tcphdr *tcph, uint16_t *ws);
int
getTcpMssOption (struct tcphdr *tcph, uint16_t *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TCP_OPTIONS_H__ */
