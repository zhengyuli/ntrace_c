#ifndef __ZMQ_HUB_H__
#define __ZMQ_HUB_H__

#include <czmq.h>

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *ctxt;                       /**< Zmq context */

    void *managementReplySock;          /**< Management reply sock */
    
    void *taskStatusSendSock;           /**< Task status send sock */
    void *taskStatusRecvSock;           /**< Task status recv sock */
        
    void *ipPktSendSock;                /**< Ip packet send sock */
    void *ipPktRecvSock;                /**< Ip packet recv sock */

    u_int tcpPktParsingThreadsNum;      /**< Tcp packet parsing threads number */
    u_int *tcpPktParsingThreadIDsHolder; /**< Tcp packet parsing thread IDs holder */
    void **tcpPktSendSocks;             /**< Tcp packet dispatch send socks */
    void **tcpPktRecvSocks;             /**< Tcp packet dispatch recv socks */
    void **breakdownSendSocks;          /**< Breakdown send socks */
};

/*========================Interfaces definition============================*/
void *
getManagementReplySock (void);
void *
getTaskStatusSendSock (void);
void *
getTaskStatusRecvSock (void);
void *
getIpPktSendSock (void);
void *
getIpPktRecvSock (void);
u_int
getTcpPktParsingThreadsNum (void);
void *
getTcpPktPushSock (u_int index);
void *
getTcpPktPullSock (u_int index);
void *
getBreakdownPushSock (u_int index);
u_int *
getTcpPktParsingThreadIDHolder (u_int index);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ZMQ_HUB_H__ */
