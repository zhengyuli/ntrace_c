#ifndef __AGENT_DISPATCH_ROUTER__
#define __AGENT_DISPATCH_ROUTER__

#include <stdlib.h>
#include <czmq.h>

typedef struct _dispatchRouter dispatchRouter;
typedef dispatchRouter *dispatchRouterPtr;

struct _dispatchRouter {
    zctx_t *ctxt;                       /**< Zmq context */
    u_int dispatchCount;                /**< Dispatch count */
    void **pushSocks;                   /**< Dispatch push sockets */
    void **pullSocks;                   /**< Dispatch pull sockets */
};

/*========================Interfaces definition============================*/
u_int
getDispatchCount (void);
void *
getDispatchPushSock (u_int index);
void *
getDispatchPullSock (u_int index);
int
initDispatchRouter (void);
void
destroyDispatchRouter (void);
/*=======================Interfaces definition end=========================*/
#endif /* __AGENT_DISPATCH_ROUTER__ */
