#include <jansson.h>
#include "logger.h"
#include "zmq_hub.h"
#include "app_service_manager.h"
#include "netdev.h"
#include "command_handler.h"

/*
 * @brief command resume handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
resumeHandler (json_t *body) {
    int ret;
    char *filter;

    /* Get Latest application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application services filter error.\n");
        return -1;
    }

    /* Update application services filter */
    ret = updateFilter (filter);
    if (ret < 0)
        LOGE ("Update application services filter error.\n");
    else
        LOGD ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

/*
 * @brief command pause handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
pauseHandler (json_t *body) {
    int ret;
    char *filter = "icmp";

    /* Update application services filter */
    ret = updateFilter (filter);
    if (ret < 0)
        LOGE ("Update application services filter error.\n");
    else
        LOGD ("Update application services filter: %s\n", filter);

    return ret;
}

/*
 * @brief command heartbeat handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
heartbeatHandler (json_t *body) {
    return 0;
}

/*
 * @brief command "update_profile" handler
 *
 * @param  body data to handle
 *
 * @return 0 if success else -1
 */
static int
updateProfileHandler (json_t *body) {
    int ret;
    char *filter;

    /* Update application service manager */
    ret = updateAppServiceManager (body);
    if (ret < 0) {
        LOGE ("Update application service manager error.\n");
        return -1;
    }

    /* Get Latest application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application services filter error.\n");
        return -1;
    }

    /* Update application services filter */
    ret = updateFilter (filter);
    if (ret < 0)
        LOGE ("Update application services filter error.\n");
    else
        LOGD ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

int
commandHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    char *msg;
    const char *cmd, *resp;
    json_error_t error;
    json_t *root, *tmp, *body;

    msg = zstr_recv_nowait (getCommandHandlerSock ());
    if (msg == NULL)
        return 0;

    root = json_loads (msg, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "command") == NULL) ||
        (json_object_get (root, "body") == NULL)) {
        LOGE ("Command message parse error: %s\n", error.text);
        ret = -1;
    } else {
        tmp = json_object_get (root, "command");
        cmd = json_string_value (tmp);
        body = json_object_get (root, "body");


        if (strEqual (COMMAND_RESUME, cmd))
            ret = resumeHandler (body);
        else if (strEqual (COMMAND_PAUSE, cmd))
            ret = pauseHandler (body);
        else if (strEqual (COMMAND_HEARTBEAT, cmd))
            ret = heartbeatHandler (body);
        else if (strEqual (COMMAND_UPDATE_PROFILE, cmd))
            ret = updateProfileHandler (body);
        else {
            LOGE ("Unknown command: %s.\n", cmd);
            ret = -1;
        }
    }

    if (ret < 0)
        resp = COMMAND_HANDLE_ERROR_DEFAULT_MESSAGE;
    else
        resp = COMMAND_HANDLE_SUCCESS_DEFAULT_MESSAGE;
    zstr_send (getCommandHandlerSock (), resp);

    json_object_clear (root);
    free (msg);
    return 0;
}
