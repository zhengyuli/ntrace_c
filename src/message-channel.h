#ifndef __AGENT_MESSAGE_CHANNEL_H__
#define __AGENT_MESSAGE_CHANNEL_H__

#define SUBTHREAD_STATUS_REPORT_CHANNEL "inproc://subThreadStatusReport"
#define PACKET_CAPTURE_CONTROL_CHANNEL "inproc://packetCaptureControlChannel"
#define IP_PACKET_PARSING_PUSH_CHANNEL "inproc://ipPacketParsingPushChannel"
#define TCP_PACKET_PARSING_PUSH_CHANNEL "inproc://tcpPacketParsingPushChannel:%d"
#define BREAKDOWN_SINK_PUSH_CHANNEL "inproc://breakdownSinkPushChannel"
#define UPDATE_SERVICE_PUSH_CHANNEL "inproc://updateServicePushChannel"

#endif /* __AGENT_MESSAGE_CHANNEL_H__ */

/*========================Interfaces definition============================*/
void
statusPush (const char *msg);
const char *
statusRecv (void);
const char *
statusRecvNonBlock (void);
void *
newZSock (int type);
int
initMessageChannel (void);
void
destroyMessageChannel (void);
/*=======================Interfaces definition end=========================*/
