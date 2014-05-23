#ifndef __AGENT_H__
#define __AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

typedef struct _agentConfig agentConfig;
typedef agentConfig *agentConfigPtr;

/* Agent configuration */
struct _agentConfig {
    BOOL daemonMode;                    /**< Run as daemon */
    char *mirrorInterface;              /**< Mirror interface */
    u_int logLevel;                     /**< Log level */
};

typedef struct _netInterface netInterface;
typedef netInterface *netInterfacePtr;

/* Network interface */
struct _netInterface {
    char *name;                         /**< Net interface name */
    pcap_t *pcapDesc;                   /**< Net interface pcap descriptor */
    u_int linkType;                     /**< Net interface link type */
};

/* Agent state */
typedef enum {
    AGENT_STATE_INIT,                   /**< Agent init state */
    AGENT_STATE_STOPPED,                /**< Agent stopped state */
    AGENT_STATE_RUNNING,                /**< Agent running state */
    AGENT_STATE_ERROR                   /**< Agent error state */
} agentState;

typedef struct _agentStateCache agentStateCache;
typedef agentStateCache *agentStateCachePtr;

/* Agent state cache */
struct _agentStateCache {
    agentState state;                   /**< Agent state */
    char *agentId;                      /**< Agent id */
    char *pubIp;                        /**< Publish ip */
    u_short pubPort;                    /**< Publish port */
    char *services;                     /**< Services in json */
};

#endif /* __AGENT_H__ */
