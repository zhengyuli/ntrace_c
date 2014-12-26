#ifndef __AGENT_APP_SERVICE_H__
#define __AGENT_APP_SERVICE_H__

#include <stdlib.h>
#include <jansson.h>
#include "protocol.h"

typedef struct _appService appService;
typedef appService *appServicePtr;

/* Application service definition */
struct _appService {
    u_int id;                           /**< application service id */
    protoType proto;                    /**< application service proto type */
    char *ip;                           /**< application service ip */
    u_short port;                       /**< application service port */
};

/* Application service json key definitions */
#define APP_SERVICE_ID "id"
#define APP_SERVICE_PROTO "proto"
#define APP_SERVICE_IP "ip"
#define APP_SERVICE_PORT "port"

/*========================Interfaces definition============================*/
appServicePtr
newAppService (void);
appServicePtr
copyAppService (appServicePtr appService);
void
freeAppService (appServicePtr svc);
void
freeAppServiceForHash (void *data);
json_t *
appService2Json (appServicePtr svc);
appServicePtr
json2AppService (json_t *json);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_APP_SERVICE_H__ */
