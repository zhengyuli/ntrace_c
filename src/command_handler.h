#ifndef __AGENT_COMMAND_HANDLER_H__
#define __AGENT_COMMAND_HANDLER_H__

#include <czmq.h>

/* Command definitions */
#define COMMAND_RESUME "resume"
#define COMMAND_PAUSE "pause"
#define COMMAND_HEARTBEAT "heartbeat"
#define COMMAND_UPDATE_PROFILE "update_profile"

/* Command handle success response */
#define COMMAND_HANDLE_SUCCESS 0
#define COMMAND_HANDLE_SUCCESS_DEFAULT_MESSAGE "{\"code\":0, \"body\":{}}"

/* Command handle error response */
#define COMMAND_HANDLE_ERROR 1
#define COMMAND_HANDLE_ERROR_DEFAULT_MESSAGE "{\"code\":1, \"body\":{}}"

/*========================Interfaces definition============================*/
int
commandHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_COMMAND_HANDLER_H__ */
