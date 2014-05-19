#ifndef __AGENT_AGENT_H__
#define __AGENT_AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

#define AGENT_CONTROL_PORT 59000

typedef struct _agentParams agentParams;
typedef agentParams *agentParamsPtr;

/* Structure used to describes global parameters of agent */
struct _agentParams {
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

struct _agentStateCache {
    agentState state;                   /**< Agent state */
    char *agentId;                      /**< Agent id */
    char *pubIp;                        /**< Publish ip */
    u_short pubPort;                    /**< Publish port */
    char *servies;                      /**< Services in json */
};

#endif /* __AGENT_AGENT_H__ */
