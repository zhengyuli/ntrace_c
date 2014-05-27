#ifndef __AGENT_DISPATCH_ROUTER_H__
#define __AGENT_DISPATCH_ROUTER_H__

#include <sys/types.h>
#include <czmq.h>

/* Minimal dispatch router number */
#define MIN_ROUTER_NUM 5
/* Max dispatch router number */
#define MAX_ROUTER_NUM 61

typedef struct _router router;
typedef router *routerPtr;

struct _router {
    void *pushSock;
    void *pullSock;
};

typedef struct _dispatchRouter dispatchRouter;
typedef dispatchRouter *dispatchRouterPtr;

struct _dispatchRouter {
    zctx_t *zmqCtxt;
    u_int routerNum;
    routerPtr routers;
};

typedef void * (*dispatchRoutine) (void *args);

/*========================Interfaces definition============================*/
void
routerDispatch (struct ip *iphdr, timeValPtr tm);
int
initDispatchRouter (dispatchRoutine routine);
void
destroyDispatchRouter (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_DISPATCH_ROUTER_H__ */
