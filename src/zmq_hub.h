#ifndef __ZMQ_HUB_H__
#define __ZMQ_HUB_H__

#include <stdlib.h>
#include <czmq.h>

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *zmqCtxt;                    /**< Zmq context */

    void *managementReplySock;          /**< Management reply sock */

    void *taskStatusSendSock;           /**< Task status send sock */
    void *taskStatusRecvSock;           /**< Task status recv sock */

    void *ipPktSendSock;                /**< Ip packet send sock */
    void *ipPktRecvSock;                /**< Ip packet recv sock */

    u_int tcpPktProcessThreadsNum;      /**< Tcp packet process threads number */
    u_int *tcpPktProcessThreadIDsHolder; /**< Tcp packet process thread IDs holder */
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
getTcpPktProcessThreadsNum (void);
u_int *
getTcpPktProcessThreadIDHolder (u_int index);
void *
getTcpPktSendSock (u_int index);
void *
getTcpPktRecvSock (u_int index);
void *
getBreakdownSendSock (u_int index);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ZMQ_HUB_H__ */
