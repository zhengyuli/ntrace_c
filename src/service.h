#ifndef __AGENT_SERVICE_H__
#define __AGENT_SERVICE_H__

#include <stdlib.h>
#include <jansson.h>
#include "protocol.h"

typedef struct _service service;
typedef service *servicePtr;

struct _service {
    u_int id;                           /**< service id */
    protoType proto;                    /**< service proto type */
    char *ip;                           /**< service ip */
    u_short port;                       /**< service port */
};

/*========================Interfaces definition============================*/
servicePtr
newService (void);
void
freeService (void *data);
void
displayServiceDetail (servicePtr svc);
servicePtr
json2Service (json_t *json);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_SERVICE_H__ */
