#ifndef __AGENT_MESSAGE_CHANNEL_H__
#define __AGENT_MESSAGE_CHANNEL_H__

#define SUBTHREAD_STATUS_REPORT_CHANNEL "inproc://subThreadStatusReport"
#define PACKET_CAPTURE_CONTROL_CHANNEL "inproc://packetCaptureControlChannel"
#define IP_PACKET_PARSING_PUSH_CHANNEL "inproc://ipPacketPushChannel"
#define TCP_PACKET_PARSING_PUSH_CHANNEL "inproc://tcpPacketPushChannel:%d"
#define BREAKDOWN_PUSH_CHANNEL "inproc://breakdownPushChannel"
#define PROFILE_PUSH_CHANNEL "inproc://profilePushChannel"

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

