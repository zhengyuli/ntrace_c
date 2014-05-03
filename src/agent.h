#ifndef __WDM_AGENT_AGENT_H__
#define __WDM_AGENT_AGENT_H__

#include <pcap.h>
#include <hiredis/hiredis.h>

typedef struct _pcapStat pcapStat;
typedef pcapStat *pcapStatPtr;

struct _pcapStat {
    uint64_t pktRecv;           /**< Pkts received by NIC */
    uint64_t pktDrop;           /**< Pkts dropped by NIC */
};

typedef struct _agentParams agentParams;
typedef agentParams *agentParamsPtr;

/* Structure used to describes global parameters of agent */
struct _agentParams {
    int agentId;                        /**< Agent id */
    int daemonMode;                     /**< Run as daemon */
    int parsingThreads;                 /**< Parsing threads number */
    char *mirrorInterface;              /**< Mirror interface */
    int pcapDumpTimeout;                /**< Pcap statistic dump timeout */
    int logLevel;                       /**< Log level */
    char *logFileDir;                   /**< Log file dir */
    char *logFileName;                  /**< Log file name */
    char *redisSrvIp;                   /**< Redis server ip */
    uint16_t redisSrvPort;              /**< Redis server port */
};

typedef struct _netInterface netInterface;
typedef netInterface *netInterfacePtr;

/* Options for network interface */
struct _netInterface {
    char *name;                 /**< Name of NIC */
    char *ipaddr;               /**< Ip address of NIC */
    pcap_t *pcapDesc;           /**< Pcap descriptor of NIC */
    int linkType;               /**< Datalink type */
    int linkOffset;             /**< Datalink offset */
    pcapStat pstat;             /**< Pcap statistic info */
};

#endif /* __WDM_AGENT_AGENT_H__ */
