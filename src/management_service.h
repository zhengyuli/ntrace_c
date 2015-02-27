#ifndef __MANAGEMENT_SERVICE_H__
#define __MANAGEMENT_SERVICE_H__

#include <czmq.h>

/* Management request json key definitions */
#define MANAGEMENT_REQUEST_COMMAND "command"
#define MANAGEMENT_REQUEST_BODY "body"

/* Management request command definitions */
#define MANAGEMENT_REQUEST_COMMAND_RESUME "resume"
#define MANAGEMENT_REQUEST_COMMAND_PAUSE "pause"
#define MANAGEMENT_REQUEST_COMMAND_HEARTBEAT "heartbeat"
#define MANAGEMENT_REQUEST_COMMAND_UPDATE_PROFILE "update_profile"

/* Management response json key definitions */
#define MANAGEMENT_RESPONSE_CODE "code"
#define MANAGEMENT_RESPONSE_BODY "body"
#define MANAGEMENT_RESPONSE_ERROR_MESSAGE "error_message"

/* Default management error response */
#define DEFAULT_MANAGEMENT_ERROR_RESPONSE "{\"code\":1, \"error_message\":\"internal error\"}"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __MANAGEMENT_SERVICE_H__ */
