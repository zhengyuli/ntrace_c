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
    char *pushIp;                       /**< Breakdown push ip */
    u_short pushPort;                   /**< Breakdown push port */
    appServicePtr *appServices;         /**< Application services to monitor */
    u_int appServiceCount;              /**< Application service count */
};

/* Context cache json key definitions */
#define RUNTIME_CONTEXT_AGENT_STATE "agent_state"
#define RUNTIME_CONTEXT_AGENT_ID "agent_id"
#define RUNTIME_CONTEXT_PUSH_IP "push_ip"
#define RUNTIME_CONTEXT_PUSH_PORT "push_port"
#define RUNTIME_CONTEXT_APP_SERVICES "app_services"

/*========================Interfaces definition============================*/
void
displayRuntimeContextDetail (runtimeContextPtr runtimeContextInstance);
int
dumpRuntimeContext (runtimeContextPtr runtimeContextInstance);
void
resetRuntimeContext (runtimeContextPtr runtimeContextInstance);
int
updateRuntimeContextAppServices (runtimeContextPtr runtimeContextInstance, json_t *appServices);
runtimeContextPtr
loadRuntimeContext (void);
void
destroyRuntimeContext (runtimeContextPtr runtimeContextInstance);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_RUNTIME_CONTEXT_H__ */