#ifndef __ZMQ_HUB_H__
#define __ZMQ_HUB_H__

#include <stdlib.h>
#include <czmq.h>

#define MANAGEMENT_SERVICE_PORT 58000
#define PROFILE_PUBLISH_PORT 58001
#define OWNERSHIP_OBSERVE_PORT 58002
#define IP_PACKET_RECV_PORT 58003

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *zmqCtxt;                    /**< Zmq context */

    void *managementReplySock;          /**< Management reply sock */

    void *profilePubSock;               /**< Profile publish sock */
    void *profileSubSock;               /**< Profile subscribe sock */

    void *slaveObserveSock;             /**< Slave observe sock */
    void *slaveRegisterSock;            /**< Slave register sock */

    void *taskStatusSendSock;           /**< Task status send sock */
    void *taskStatusRecvSock;           /**< Task status recv sock */

    void *ipPktSendSock;                /**< Ip packet send sock */
    void *ipPktRecvSock;                /**< Ip packet recv sock */

    void *icmpPktSendSock;              /**< Icmp packet send sock */
    void *icmpPktRecvSock;              /**< Icmp packet recv sock */
    void *icmpBreakdownSendSock;        /**< Icmp breakdown send sock */

    u_int tcpProcessThreadsNum;         /**< Tcp process threads number */
    u_int *tcpProcessThreadIDsHolder;   /**< Tcp process thread IDs holder */
    void **tcpPktSendSocks;             /**< Tcp packet dispatch send socks */
    void **tcpPktRecvSocks;             /**< Tcp packet dispatch recv socks */
    void **tcpBreakdownSendSocks;       /**< Tcp breakdown send socks */
};

/*========================Interfaces definition============================*/
void *
getManagementReplySock (void);
void *
getProfilePubSock (void);
void *
getProfileSubSock (void);
void *
getSlaveObserveSock (void);
void *
getSlaveRegisterSock (void);
void *
getTaskStatusSendSock (void);
void *
getTaskStatusRecvSock (void);
void *
getIpPktSendSock (void);
void *
getIpPktRecvSock (void);
void *
getIcmpPktSendSock (void);
void *
getIcmpPktRecvSock (void);
void *
getIcmpBreakdownSendSock (void);
u_int
getTcpProcessThreadsNum (void);
u_int *
getTcpProcessThreadIDHolder (u_int index);
void *
getTcpPktSendSock (u_int index);
void *
getTcpPktRecvSock (u_int index);
void *
getTcpBreakdownSendSock (u_int index);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ZMQ_HUB_H__ */
