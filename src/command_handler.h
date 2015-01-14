#ifndef __AGENT_COMMAND_HANDLER_H__
#define __AGENT_COMMAND_HANDLER_H__

#include <czmq.h>

/* Agent command */
#define AGENT_CMD_HEARTBEAT "heartbeat"
#define AGENT_CMD_UPDATE_PROFILE "update_profile"

/* Agent management success response */
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS 0
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS_MESSAGE "{\"code\":0}"

/* Agent management error response */
#define AGENT_MANAGEMENT_RESPONSE_ERROR 1
#define AGENT_MANAGEMENT_RESPONSE_ERROR_MESSAGE "{\"code\":1}"

/*========================Interfaces definition============================*/
int
commandHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_COMMAND_HANDLER_H__ */
