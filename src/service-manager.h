#ifndef __AGENT_SERVICE_MANAGER_H__
#define __AGENT_SERVICE_MANAGER_H__

#include <stdlib.h>
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
int
updateService (json_t *services);
protoType
lookupServiceProtoType (const char *key);
char *
getServiceFilter (void);
int
initServiceManager (void);
void
destroyServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_SERVICE_MANAGER_H__ */

