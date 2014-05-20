#ifndef __AGENT_MESSAGE_CHANNEL_H__
#define __AGENT_MESSAGE_CHANNEL_H__

#define SUBTHREAD_STATUS_REPORT_CHANNEL "inproc://subThreadStatusReport"
#define IP_PACKET_PARSING_PUSH_CHANNEL "inproc://ipPacketParsingPushChannel"
#define TCP_PACKET_PARSING_PUSH_CHANNEL "inproc://tcpPacketParsingPushChannel"
#define BREAKDOWN_SINK_PUSH_CHANNEL "inproc://breakdownSinkPushChannel"

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
newZSock (int type)
int
initMessageChannel (void);
void
destroyMessageChannel (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_MESSAGE_CHANNEL_H__ */

