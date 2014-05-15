#ifndef __AGENT_SERVICE_H__
#define __AGENT_SERVICE_H__

#include <stdlib.h>
#include "list.h"
#include "hash.h"
#include "protocol.h"

/* This structure is used to describe a tcp service */
typedef struct _service service;
typedef service *servicePtr;

struct _service {
    u_int id;                           /**< service id */
    protoType proto;                    /**< service proto type */
    char *ip;                           /**< service ip */
    u_short port;                       /**< service port */
};

/*========================Interfaces definition============================*/
u_int
serviceNum (void);
int
serviceLoopDo (hashForEachItemDoCB fun, void *args);
int
updateService (const char *svcJson);
protoType
lookupServiceProtoType (const char *key);
int
initServiceContext (void);
void
destroyServiceContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_SERVICE_H__ */
