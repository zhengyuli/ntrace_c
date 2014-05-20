#ifndef __AGENT_ROUTER_H__
#define __AGENT_ROUTER_H__

#include <sys/types.h>

/*========================Interfaces definition============================*/
int
initRouter (u_int parsingThreads);
void
destroyRouter (void);
void
routerDispatch (struct ip *iphdr, timeValPtr tm);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_ROUTER_H__ */
