#ifndef __NETDEV_H__
#define __NETDEV_H__

#include <pcap.h>

/*========================Interfaces definition============================*/
pcap_t *
getNetDev (void);
int
getNetDevDatalinkType (void);
int
getNetDevPakcetsStatistic (u_int *pktsRecv, u_int *pktsDrop);
int
updateFilter (char *filter);
int
initNetDev (void);
void
destroyNetDev (void);
/*=======================Interfaces definition end=========================*/

#endif /* __NETDEV_H__ */
