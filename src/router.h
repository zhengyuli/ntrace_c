#ifndef __AGENT_ROUTER_H__
#define __AGENT_ROUTER_H__

#include <sys/types.h>
#include <czmq.h>

typedef struct _routerSock routerSock;
typedef routerSock *routerSockPtr;

struct _routerSock {
    void *pktSndSock;
    void *pktRecvSock;
    void *tbdSndSock;
};

typedef void * (*packetProcessWorker) (void *args);

/*========================Interfaces definition============================*/
int
initRouter (zctx_t *context, u_int workers, packetProcessWorker fun, const char *tbdSinkAddress);
void
destroyRouter (void);
void
routerDispatch (struct ip *iphdr, timeValPtr tm);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ROUTER_H__ */
