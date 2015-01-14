#include <jansson.h>
#include "logger.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "raw_packet_service.h"
#include "ip_packet_service.h"
#include "tcp_packet_service.h"
#include "command_handler.h"

int
commandHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    char *msg;

    msg = zstr_recv_nowait (getControlSock ());
    if (msg == NULL)
        return 0;

    LOGD ("Management message: %s\n", msg);
    return 0;
}

