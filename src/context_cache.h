#ifndef __AGENT_CONTEXT_CACHE_H__
#define __AGENT_CONTEXT_CACHE_H__

#include <sys/types.h>
#include <jansson.h>

#define CONTEXT_CACHE_STATE_INIT 0
#define CONTEXT_CACHE_STATE_STOPPED 1
#define CONTEXT_CACHE_STATE_RUNNING 2
#define CONTEXT_CACHE_STATE_ERROR 3

typedef struct _contextCache contextCache;
typedef contextCache *contextCachePtr;

struct _contextCache {
    u_char state;                       /**< Context state */
    char *agentId;                      /**< Agent id */
    char *pushIp;                       /**< Breakdown push ip */
    u_short pushPort;                   /**< Breakdown push port */
    json_t *services;                   /**< Services to monitor */
};

/* Json keys for context cache sync */
#define CONTEXT_CACHE_SYNC_STATE "state"
#define CONTEXT_CACHE_SYNC_AGENT_ID "agent_id"
#define CONTEXT_CACHE_SYNC_PUSH_IP "push_ip"
#define CONTEXT_CACHE_SYNC_PUSH_PORT "push_port"
#define CONTEXT_CACHE_SYNC_SERVICES "services"

/*========================Interfaces definition============================*/
void
displayContextCacheState (contextCachePtr contextCacheInstance);
int
syncContextCache (contextCachePtr contextCacheInstance);
void
resetContextCache (contextCachePtr contextCacheInstance);
contextCachePtr
loadContextCache (void);
void
destroyContextCache (contextCachePtr contextCacheInstance);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_CONTEXT_CACHE_H__ */
