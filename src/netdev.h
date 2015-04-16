#ifndef __NETDEV_H__
#define __NETDEV_H__

#include <pcap.h>

/*========================Interfaces definition============================*/
pcap_t *
getNetDevPcapDesc (void);
int
getNetDevDatalinkType (void);
int
getNetDevPakcetsStatistic (u_int *pktsRecv, u_int *pktsDrop);
int
updateNetDevFilter (char *filter);
int
reloadNetDev (void);
int
initNetDev (void);
void
destroyNetDev (void);
/*=======================Interfaces definition end=========================*/

#endif /* __NETDEV_H__ */
