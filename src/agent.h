#ifndef __AGENT_H__
#define __AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

/* Agent management response port */
#define AGENT_MANAGEMENT_RESPONSE_PORT 59000

typedef struct _agentConfig agentConfig;
typedef agentConfig *agentConfigPtr;

/* Agent configuration */
struct _agentConfig {
    BOOL daemonMode;                    /**< Run as daemon */
    char *mirrorInterface;              /**< Mirror interface */
    u_int logLevel;                     /**< Log level */
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
    char *pushIp;                       /**< Agent push ip */
    u_short pushPort;                   /**< Agent push port */
    json_t *services;                   /**< Agent services */
};

typedef struct _dispatchRouter dispatchRouter;
typedef dispatchRouter *dispatchRouterPtr;

struct _dispatchRouter {
    u_int dispatchThreads;              /**< Dispatch threads number */
    void **pushSocks;                   /**< Dispatch push sockets */
    void **pullSocks;                   /**< Dispatch pull sockets */
};

#endif /* __AGENT_H__ */
