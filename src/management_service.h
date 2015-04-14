#ifndef __MANAGEMENT_SERVICE_H__
#define __MANAGEMENT_SERVICE_H__

#include <czmq.h>

/* Management register expire interval is 3000ms */
#define MANAGEMENT_REGISTER_TASK_EXPIRE_INTERVAL 3000

/*=========================================================================*/

/* Management control request json key definitions */
#define MANAGEMENT_CONTROL_REQUEST_COMMAND "command"
#define MANAGEMENT_CONTROL_REQUEST_BODY "body"

/* Management control request command definitions */
#define MANAGEMENT_CONTROL_REQUEST_COMMAND_RESUME "resume"
#define MANAGEMENT_CONTROL_REQUEST_COMMAND_PAUSE "pause"
#define MANAGEMENT_CONTROL_REQUEST_COMMAND_HEARTBEAT "heartbeat"
#define MANAGEMENT_CONTROL_REQUEST_COMMAND_UPDATE_PROFILE "update_profile"
#define MANAGEMENT_CONTROL_REQUEST_COMMAND_PACKETS_STATISTIC "packets_statistic"

/* Management control response json key definitions */
#define MANAGEMENT_CONTROL_RESPONSE_CODE "code"
#define MANAGEMENT_CONTROL_RESPONSE_BODY "body"
#define MANAGEMENT_CONTROL_RESPONSE_ERROR_MESSAGE "error_message"

/* Management control response body json key definitions */
#define MANAGEMENT_CONTROL_RESPONSE_BODY_PACKETS_RECEIVE "packets_receive"
#define MANAGEMENT_CONTROL_RESPONSE_BODY_PACKETS_DROP "packets_drop"
#define MANAGEMENT_CONTROL_RESPONSE_BODY_PACKETS_DROP_RATE "packets_drop_rate"

/* Default management control error response */
#define DEFAULT_MANAGEMENT_CONTROL_ERROR_RESPONSE           \
    "{\"code\":1, \"error_message\":\"internal error\"}"

/*=========================================================================*/

/* Management register request json key definitions */
#define MANAGEMENT_REGISTER_REQUEST_COMMAND "command"
#define MANAGEMENT_REGISTER_REQUEST_BODY "body"

/* Management register request command definitions */
#define MANAGEMENT_REGISTER_REQUEST_COMMAND_REGISTER "register"

/* Management register request body json key definitions */
#define MANAGEMENT_REGISTER_REQUEST_BODY_MANAGEMENT_IP "ip"
#define MANAGEMENT_REGISTER_REQUEST_BODY_MANAGEMENT_PORT "port"

/* Management register response json key definitions */
#define MANAGEMENT_REGISTER_RESPONSE_CODE "code"
#define MANAGEMENT_REGISTER_RESPONSE_BODY "body"
#define MANAGEMENT_REGISTER_RESPONSE_ERROR_MESSAGE "error_message"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __MANAGEMENT_SERVICE_H__ */
