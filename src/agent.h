#ifndef __AGENT_AGENT_H__
#define __AGENT_AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

/* Agent management command */
#define AGENT_MANAGEMENT_CMD_ADD_AGENT "add-agent"
#define AGENT_MANAGEMENT_CMD_REMOVE_AGENT "remove-agent"
#define AGENT_MANAGEMENT_CMD_START_AGENT "start-agent"
#define AGENT_MANAGEMENT_CMD_STOP_AGENT "stop-agent"
#define AGENT_MANAGEMENT_CMD_HEARTBEAT "heartbeat"
#define AGENT_MANAGEMENT_CMD_PUSH_PROFILE "push-profile"

/* Agent management success response */
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS 0
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS_MESSAGE "{\"code\":0}"

/* Agent management error response */
#define AGENT_MANAGEMENT_RESPONSE_ERROR 1
#define AGENT_MANAGEMENT_RESPONSE_ERROR_MESSAGE "{\"code\":1}"

/* Agent management response port */
#define AGENT_MANAGEMENT_RESPONSE_PORT 59000

typedef struct _agentConfig agentConfig;
typedef agentConfig *agentConfigPtr;

/* Agent configuration */
struct _agentConfig {
    bool daemonMode;                    /**< Run as daemon */
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

#endif /* __AGENT_AGENT_H__ */
