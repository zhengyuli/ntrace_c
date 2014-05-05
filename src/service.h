#ifndef __AGENT_SERVICE_H__
#define __AGENT_SERVICE_H__

#include <stdint.h>
#include "list.h"
#include "hash.h"
#include "protocol.h"

typedef enum {
    SVC_UPDATE_ADD = 1,
    SVC_UPDATE_MOD,
    SVC_UPDATE_DEL
} svcUpdateType;

/* This structure is used to describe a tcp service */
typedef struct _service service;
typedef service *servicePtr;

struct _service {
    uint32_t id;                /**< service id */
    protoType proto;            /**< service proto type */
    char *ip;                   /**< service ip */
    uint16_t port;              /**< service port */
};

/*========================Interfaces definition============================*/
int
serviceNum (void);
int
serviceLoopDo (hashForEachItemDoFun fun, void *args);
int
updateService (svcUpdateType updateType, servicePtr svc);
protoType
lookupServiceProtoType (const char *key);
servicePtr
json2Service (const char *jsonData);
int
initServiceContext (void);
void
destroyServiceContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_SERVICE_H__ */
