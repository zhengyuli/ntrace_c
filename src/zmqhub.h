#ifndef __AGENT_ZMQHUB_H__
#define __AGENT_ZMQHUB_H__

#define SUBTHREAD_STATUS_REPORT_CHANNEL "inproc://subThreadStatusReport"
#define IP_PACKET_PARSING_PUSH_CHANNEL "inproc://ipPacketParsingPushChannel"
#define TCP_PACKET_PARSING_PUSH_CHANNEL "inproc://tcpPacketParsingPushChannel"
#define SESSION_BREAKDOWN_SINK_PUSH_CHANNEL "inproc://sessionBreakdownSinkPushChannel"

#define SUB_THREAD_EXIT "Exit"

/*========================Interfaces definition============================*/
void
subThreadStatusPush (const char *msg);
const char *
subThreadStatusRecv (void);
const char *
subThreadStatusRecvNonBlock (void);
void *
getSubThreadStatusRecvSock (void);
void *
newZSock (int type);
void
destroyZSock (void *sock);
int
initZmqhub (void);
void
destroyZmqhub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ZMQHUB_H__ */

