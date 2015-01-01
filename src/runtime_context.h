#ifndef __AGENT_RUNTIME_CONTEXT_H__
#define __AGENT_RUNTIME_CONTEXT_H__

#include <sys/types.h>
#include <jansson.h>
#include "app_service.h"

typedef enum {
    AGENT_STATE_INIT,
    AGENT_STATE_STOPPED,
    AGENT_STATE_RUNNING,
    AGENT_STATE_ERROR
} agentState;

typedef struct _runtimeContext runtimeContext;
typedef runtimeContext *runtimeContextPtr;

struct _runtimeContext {
    agentState state;                   /**< Agent state */
    char *agentId;                      /**< Agent id */
    char *breakdownSinkIp;              /**< Session breakdown sink ip */
    u_short breakdownSinkPort;          /**< Session breakdown sink port */
    appServicePtr *appServices;         /**< Application services to monitor */
    u_int appServicesCount;             /**< Application services count */
};

/* Context cache json key definitions */
#define RUNTIME_CONTEXT_CACHE_AGENT_STATE "agent_state"
#define RUNTIME_CONTEXT_CACHE_AGENT_ID "agent_id"
#define RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_IP "breakdown_sink_ip"
#define RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_PORT "breakdown_sink_port"
#define RUNTIME_CONTEXT_CACHE_APP_SERVICES "app_services"

/*========================Interfaces definition============================*/
agentState
getAgentState (void);
int
setAgentState (agentState state);
char *
getAgentId (void);
int
setAgentId (char *agentId);
char *
getBreakdownSinkIp (void);
int
setBreakdownSinkIp (char *ip);
u_short
getBreakdownSinkPort (void);
int
setBreakdownSinkPort (u_short port);
appServicePtr *
getAppServices (void);
int
setAppServices (json_t *appServices);
u_int
getAppServicesCount (void);
int
setAppServicesCount (u_int);
void
resetRuntimeContext (void);
void
dumpRuntimeContext (void);
int
initRuntimeContext (void);
void
destroyRuntimeContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_RUNTIME_CONTEXT_H__ */
