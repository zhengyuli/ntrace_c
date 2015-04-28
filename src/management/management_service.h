#ifndef __MANAGEMENT_SERVICE_H__
#define __MANAGEMENT_SERVICE_H__

#include <czmq/czmq.h>

/*=========================================================================*/

/* Management request json key definitions */
#define MANAGEMENT_REQUEST_COMMAND "command"
#define MANAGEMENT_REQUEST_BODY "body"

/* Management request command definitions */
#define MANAGEMENT_REQUEST_COMMAND_RESUME "resume"
#define MANAGEMENT_REQUEST_COMMAND_PAUSE "pause"
#define MANAGEMENT_REQUEST_COMMAND_HEARTBEAT "heartbeat"
#define MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC "packets_statistic"
#define MANAGEMENT_REQUEST_COMMAND_PROTO_INFO "proto_info"

/* Management response json key definitions */
#define MANAGEMENT_RESPONSE_CODE "code"
#define MANAGEMENT_RESPONSE_BODY "body"
#define MANAGEMENT_RESPONSE_ERROR_MESSAGE "error_message"

/* Management response body json key definitions */
#define MANAGEMENT_RESPONSE_BODY_PACKETS_RECEIVE "packets_receive"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP "packets_drop"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP_RATE "packets_drop_rate"

#define MANAGEMENT_RESPONSE_BODY_PROTO_NUM "proto_num"
#define MANAGEMENT_RESPONSE_BODY_PROTO_NAMES "proto_names"

/* Default management error response */
#define DEFAULT_MANAGEMENT_ERROR_RESPONSE           \
    "{\"code\":1, \"error_message\":\"internal error\"}"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __MANAGEMENT_SERVICE_H__ */
