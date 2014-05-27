#ifndef __AGENT_ZMQHUB_H__
#define __AGENT_ZMQHUB_H__

/* Zmqhub inproc address */
#define SHARED_STATUS_PUSH_CHANNEL "inproc://sharedStatusPushChannel"
#define IP_PACKET_PUSH_CHANNEL "inproc://ipPacketPushChannel"
#define TCP_PACKET_PUSH_CHANNEL "inproc://tcpPacketPushChannel"

/*========================Interfaces definition============================*/
void *
zmqhubContext (void);
int
initZmqhub (void);
void
destroyZmqhub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ZMQHUB_H__ */

