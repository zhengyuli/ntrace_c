#ifndef __AGENT_AGENT_H__
#define __AGENT_AGENT_H__

#include <pcap.h>
#include <hiredis/hiredis.h>
#include <sys/types.h>
#include "typedef.h"
#include "util.h"

typedef struct _pcapStat pcapStat;
typedef pcapStat *pcapStatPtr;

struct _pcapStat {
    u_int pktRecv;                      /**< Pkts received by NIC */
    u_int pktDrop;                      /**< Pkts dropped by NIC */
};

typedef struct _agentParams agentParams;
typedef agentParams *agentParamsPtr;

/* Structure used to describes global parameters of agent */
struct _agentParams {
    u_int agentId;                      /**< Agent id */
    BOOL daemonMode;                    /**< Run as daemon */
    u_int parsingThreads;               /**< Parsing threads number */
    char *mirrorInterface;              /**< Mirror interface */
    u_int pcapDumpTimeout;              /**< Pcap statistic dump timeout */
    u_int logLevel;                     /**< Log level */
    char *redisSrvIp;                   /**< Redis server ip */
    u_short redisSrvPort;               /**< Redis server port */
};

typedef struct _netInterface netInterface;
typedef netInterface *netInterfacePtr;

/* Options for network interface */
struct _netInterface {
    char *name;                         /**< Name of NIC */
    char *ipaddr;                       /**< Ip address of NIC */
    pcap_t *pcapDesc;                   /**< Pcap descriptor of NIC */
    u_int linkType;                     /**< Datalink type */
    u_int linkOffset;                   /**< Datalink offset */
    pcapStat pstat;                     /**< Pcap statistic info */
};

#endif /* __AGENT_AGENT_H__ */
