#ifndef __AGENT_ZMQ_HUB_H__
#define __AGENT_ZMQ_HUB_H__

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *ctxt;
    void *ipPktPushSock;
    void *ipPktPullSock;
};

/*========================Interfaces definition============================*/
void *
getZmqHubIpPktPushSock (void);
void *
getZmqHubIpPktPullSock (void);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ZMQ_HUB_H__ */
