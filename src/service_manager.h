#ifndef __AGENT_SERVICE_MANAGER_H__
#define __AGENT_SERVICE_MANAGER_H__

#include <stdlib.h>
#include "protocol.h"
#include "service.h"

/*========================Interfaces definition============================*/
protoType
lookupServiceProtoType (const char *key);
char *
getServicesFilter (void);
int
updateServiceManager (json_t *services);
void
cleanServiceManager (void);
int
initServiceManager (void);
void
destroyServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_SERVICE_MANAGER_H__ */

