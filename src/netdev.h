#ifndef __AGENT_NETDEV_H__
#define __AGENT_NETDEV_H__

#include <stdlib.h>
#include <pcap.h>

/*========================Interfaces definition============================*/
int
updateFilter (const char *filter);
pcap_t *
getNetDev (void);
int
getNetDevLinkType (void);
int
initNetDev (void);
void
destroyNetDev (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_NETDEV_H__ */
