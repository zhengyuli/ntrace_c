#ifndef __TCP_OPTIONS_H__
#define __TCP_OPTIONS_H__

#include <netinet/tcp.h>

/*========================Interfaces definition============================*/
boolean
getTimeStampOption (struct tcphdr *tcph, u_int *ts);
boolean
getTcpWindowScaleOption (struct tcphdr *tcph, u_short *ws);
boolean
getTcpMssOption (struct tcphdr *tcph, u_short *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __TCP_OPTIONS_H__ */
