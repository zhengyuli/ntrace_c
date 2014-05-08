#ifndef __AGENT_IP_PACKET_H__
#define __AGENT_IP_PACKET_H__

#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include "util.h"
#include "list.h"

#define IPF_NOTF 1
#define IPF_ISF 2
#define IPF_NEW 3
#define IPF_ERROR 4

typedef struct _ipFrag ipFrag;
typedef ipFrag *ipFragPtr;

struct _ipFrag {
    u_short offset;                     /**< Offset of ip fragment data */
    u_short end;                        /**< End of ip fragment data */
    u_short len;                        /**< Length of ip fragment data */
    u_char *dataPtr;                    /**< Point to ip fragment data */
    u_char *skbuf;                      /**< Ip fragment */
    listHead node;                      /**< Ipqueue list node */
};

typedef struct _ipQueue ipQueue;
typedef ipQueue *ipQueuePtr;

struct _ipQueue {
    struct in_addr sourcIp;             /**< Source ip */
    struct in_addr destIp;              /**< Destination ip */
    u_short id;                         /**< Ip packet id */
    struct ip *iph;                     /**< Ip header */
    u_short iphLen;                     /**< Ip header length */
    u_short dataLen;                    /**< Ip data length */
    listHead fragments;                 /**< Ip fragments list */
};

typedef struct _ipQueueTimeout ipQueueTimeout;
typedef ipQueueTimeout *ipQueueTimeoutPtr;

struct _ipQueueTimeout {
    ipQueuePtr queue;                   /**< Ip fragment queue */
    u_long_long timeout;                /**< Timeout for ip fragment queue */
    listHead node;                      /**< Ip fragment queue timout list node */
};

/*========================Interfaces definition============================*/
int
ipDefragProcess (struct ip *iph, u_int ipCaptureLen, struct ip **new);
int
initIp (void);
void
destroyIp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_IP_PACKET_H__ */
