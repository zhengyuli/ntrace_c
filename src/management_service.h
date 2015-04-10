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
#define MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC "packets_statistic"

/* Management response json key definitions */
#define MANAGEMENT_RESPONSE_CODE "code"
#define MANAGEMENT_RESPONSE_BODY "body"
#define MANAGEMENT_RESPONSE_ERROR_MESSAGE "error_message"

/* Management response body json key definitions */
#define MANAGEMENT_RESPONSE_BODY_PACKETS_RECEIVE "packets_receive"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP "packets_drop"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP_RATE "packets_drop_rate"

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

/* Default management error response */
#define DEFAULT_MANAGEMENT_ERROR_RESPONSE "{\"code\":1, \"error_message\":\"internal error\"}"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __MANAGEMENT_SERVICE_H__ */
