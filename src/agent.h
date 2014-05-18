#ifndef __AGENT_AGENT_H__
#define __AGENT_AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

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
    AGENT_STATE_RUNNING                 /**< Agent running state */
} agentState;

typedef enum {
    AGENT_EVENT_ADD_AGENT,              /**< Add agent */
    AGENT_EVENT_REMOVE_AGENT,           /**< Remove agent */
    AGENT_EVENT_START_AGENT,            /**< Start agent */
    AGENT_EVENT_STOP_AGENT,             /**< Stop agent */
    AGENT_EVENT_PUSH_PROFILE,           /**< Push profile */
    AGENT_EVENT_HEARTBEAT               /**< Heartbeat */
} agentEvent;

#define AGENT_EVNET_ADD_AGENT_KEY       "add-agent"
#define AGENT_EVNET_REMOVE_AGENT_KEY    "remove-agent"
#define AGENT_EVNET_START_AGENT_KEY     "start-agent"
#define AGENT_EVNET_STOP_AGENT_KEY      "stop-agent"
#define AGENT_EVNET_PUSH_PROFILE_KEY    "push-profile"
#define AGENT_EVNET_HEARTBEAT_KEY       "heartbeat"

typedef struct _agentRun agentRun;
typedef agentRun *agentRunPtr;

struct _agentRun {
    agentState state;                   /**< Agent current state */
    char *agentId;                      /**< Agent id */
    char *srvIp;                        /**< Server ip */
    u_short srvPort;                    /**< Server port */
    char *servies;                      /**< Services in json */
};

#endif /* __AGENT_AGENT_H__ */
