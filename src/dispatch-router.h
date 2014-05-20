#ifndef __AGENT_DISPATCH_ROUTER_H__
#define __AGENT_DISPATCH_ROUTER_H__

#include <sys/types.h>

/*========================Interfaces definition============================*/
int
initDispatchRouter (u_int parsingThreads);
void
destroyDispatchRouter (void);
void
routerDispatch (struct ip *iphdr, timeValPtr tm);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_DISPATCH_ROUTER_H__ */
