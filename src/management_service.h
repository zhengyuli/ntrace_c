#ifndef __AGENT_MANAGEMENT_SERVICE_H__
#define __AGENT_MANAGEMENT_SERVICE_H__

#include <czmq.h>

#define MANAGEMENT_COMMAND_TAG "command"
/* Management command definitions */
#define MANAGEMENT_COMMAND_RESUME "resume"
#define MANAGEMENT_COMMAND_PAUSE "pause"
#define MANAGEMENT_COMMAND_HEARTBEAT "heartbeat"
#define MANAGEMENT_COMMAND_UPDATE_PROFILE "update_profile"

#define MANAGEMENT_BODY_TAG "body"
/* Management body definitions */
#define MANAGEMENT_BODY_APP_SERVICES "app_services"

/* Management handle success response */
#define MANAGEMENT_HANDLE_SUCCESS_RESPONSE "{\"code\":0, \"body\":{}}"
/* Management handle error response */
#define MANAGEMENT_HANDLE_ERROR_RESPONSE "{\"code\":1, \"body\":{}}"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_MANAGEMENT_SERVICE_H__ */
