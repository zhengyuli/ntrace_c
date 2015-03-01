#ifndef __ICMP_PACKET_H__
#define __ICMP_PACKET_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include "util.h"
#include "ip.h"
#include "icmp.h"

typedef struct _icmpBreakdown icmpBreakdown;
typedef icmpBreakdown *icmpBreakdownPtr;

struct _icmpBreakdown {
    u_long_long timestamp;              /**< Timestamp in seconds */
    u_char type;                        /**< Icmp type */
    u_char code;                        /**< Icmp code */
    struct in_addr ip;                  /**< Icmp dest unreachable ip */
    u_short port;                       /**< Icmp dest unreachable port */
};

/* Icmp breakdown json key definitions */
#define ICMP_SKBD_TIMESTAMP "timestamp"
#define ICMP_SKBD_ICMP_TYPE "icmp_type"
#define ICMP_SKBD_ICMP_CODE "icmp_code"
#define ICMP_SKBD_ICMP_DEST_UNREACH_IP "icmp_dest_unreach_ip"
#define ICMP_SKBD_ICMP_DEST_UNREACH_PORT "icmp_dest_unreach_port"

/*========================Interfaces definition============================*/
void
icmpProcess (iphdrPtr iph, timeValPtr tm);
int
initIcmp (void *sock);
void
destroyIcmp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ICMP_PACKET_H__ */
