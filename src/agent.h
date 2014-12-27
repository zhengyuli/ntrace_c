#ifndef __AGENT_AGENT_H__
#define __AGENT_AGENT_H__

#include <sys/types.h>
#include <pcap.h>
#include "util.h"

#define AGENT_MANAGEMENT_CMD_KEY "command"
#define AGENT_MANAGEMENT_BODY_KEY "body"

/* Agent management command */
#define AGENT_MANAGEMENT_CMD_ADD_AGENT "add_agent"
#define AGENT_MANAGEMENT_CMD_REMOVE_AGENT "remove_agent"
#define AGENT_MANAGEMENT_CMD_START_AGENT "start_agent"
#define AGENT_MANAGEMENT_CMD_STOP_AGENT "stop_agent"
#define AGENT_MANAGEMENT_CMD_HEARTBEAT "heartbeat"
#define AGENT_MANAGEMENT_CMD_PUSH_PROFILE "push_profile"

/* Agent management success response */
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS 0
#define AGENT_MANAGEMENT_RESPONSE_SUCCESS_MESSAGE "{\"code\":0}"

/* Agent management error response */
#define AGENT_MANAGEMENT_RESPONSE_ERROR 1
#define AGENT_MANAGEMENT_RESPONSE_ERROR_MESSAGE "{\"code\":1}"

/* Agent management response port */
#define AGENT_MANAGEMENT_RESPONSE_PORT 59000

#endif /* __AGENT_AGENT_H__ */
