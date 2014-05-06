#ifndef __AGENT_REDIS_CLIENT_H__
#define __AGENT_REDIS_CLIENT_H__

#include <hiredis/hiredis.h>
#include "service.h"

typedef struct _redisCtxt redisCtxt;
typedef redisCtxt *redisCtxtPtr;

struct _redisCtxt {
    u_int agentId;
    char *redisIp;
    u_short redisPort;
    redisContext *ctxt;
};

typedef void (*svcUpdateCallback) (svcUpdateType updateType, servicePtr svc);

/*========================Interfaces definition============================*/
int
initServiceFromRedis (void);
void
serviceUpdateSub (svcUpdateCallback callbackFun);
void
pushSessionBreakdown (const char *sessionBreakdownJson);
void
pubPcapStat (const char *pstatJson);
int
initRedisContext (u_int agentId, const char *redisSrvIp, u_short redisSrvPort);
void
destroyRedisContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_REDIS_CLIENT_H__ */
