#ifndef __AGENT_ZMQ_HUB_H__
#define __AGENT_ZMQ_HUB_H__

#include <czmq.h>
#include <pthread.h>

#define MANAGEMENT_RESPONSE_PORT 59000

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *ctxt;                       /**< Zmq context */
    
    void *taskStatusPushSock;           /**< Task status push sock */
    void *taskStatusPullSock;           /**< Task status pull sock */

    void *managementRespSock;           /**< Management response sock */

    void *ipPktPushSock;                /**< Ip packet push sock pair */
    void *ipPktPullSock;                /**< Ip packet pull sock pair */

    u_int tcpPktParsingThreadsNum;      /**< Tcp packet parsing threads number */
    u_int *tcpPktParsingThreadIDsHolder; /**< Tcp packet parsing threads number holder */
    void **tcpPktPushSocks;             /**< Tcp packet dispatch push socks */
    void **tcpPktPullSocks;             /**< Tcp packet dispatch pull socks */
};

/*========================Interfaces definition============================*/
void *
getTaskStatusPushSock (void);
void *
getTaskStatusPullSock (void);
void *
getManagementRespSock (void);
void *
getIpPktPushSock (void);
void *
getIpPktPullSock (void);
u_int
getTcpPktParsingThreadsNum (void);
void *
getTcpPktPushSock (u_int index);
void *
getTcpPktPullSock (u_int index);
u_int *
getTcpPktParsingThreadIDHolder (u_int index);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ZMQ_HUB_H__ */
