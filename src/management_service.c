#include <jansson.h>
#include "properties.h"
#include "logger.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "netdev.h"
#include "management_service.h"

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
    char *filter;

    /* Get application services padding filter */
    filter = getAppServicesPaddingFilter ();
    if (filter == NULL) {
        LOGE ("Get application services padding filter error.\n");
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
    json_t *appServices;

    appServices = json_object_get (body, MANAGEMENT_BODY_APP_SERVICES);
    if ((appServices == NULL) || !json_is_array (appServices)) {
        LOGE ("Invalid format body of update profile\n.");
        return -1;
    }

    /* Update application service manager */
    ret = updateAppServiceManager (appServices);
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

/*
 * Management service.
 * Handle all kinds management request.
 */
void *
managementService (void *args) {
    int ret;
    void *managementReplySock;
    char *msg;
    const char *cmdStr, *resp;
    json_error_t error;
    json_t *root, *cmd, *body;

    /* Reset task interrupt flag */
    resetTaskInterruptFlag ();

    /* Get management receive sock */
    managementReplySock = getManagementReplySock ();

    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        LOGE ("Init log context error.\n");
        goto exit;
    }

    while (!taskInterrupted ()) {
        msg = zstr_recv (managementReplySock);
        if (msg == NULL) {
            if (!taskInterrupted ())
                LOGE ("Receive management request fatal error.\n");
            break;
        }

        root = json_loads (msg, JSON_DISABLE_EOF_CHECK, &error);
        if (root == NULL) {
            LOGE ("Management request parse error: %s\n", error.text);
            zstr_send (managementReplySock, MANAGEMENT_HANDLE_ERROR_RESPONSE);
            free (msg);
            continue;
        }

        cmd = json_object_get (root, MANAGEMENT_COMMAND_TAG);
        body = json_object_get (root, MANAGEMENT_BODY_TAG);
        if ((cmd == NULL) || (body == NULL)) {
            LOGE ("Invalid management request: %s.\n", msg);
            zstr_send (managementReplySock, MANAGEMENT_HANDLE_ERROR_RESPONSE);
            json_object_clear (root);
            free (msg);
            continue;
        }

        cmdStr = json_string_value (cmd);
        if (strEqual (MANAGEMENT_COMMAND_RESUME, cmdStr))
            ret = resumeHandler (body);
        else if (strEqual (MANAGEMENT_COMMAND_PAUSE, cmdStr))
            ret = pauseHandler (body);
        else if (strEqual (MANAGEMENT_COMMAND_HEARTBEAT, cmdStr))
            ret = heartbeatHandler (body);
        else if (strEqual (MANAGEMENT_COMMAND_UPDATE_PROFILE, cmdStr))
            ret = updateProfileHandler (body);
        else {
            LOGE ("Unknown command: %s.\n", cmdStr);
            ret = -1;
        }

        if (ret < 0)
            resp = MANAGEMENT_HANDLE_ERROR_RESPONSE;
        else
            resp = MANAGEMENT_HANDLE_SUCCESS_RESPONSE;
        zstr_send (managementReplySock, resp);
        json_object_clear (root);
        free (msg);
    }

    LOGD ("ManagementService will exit...\n");
    destroyLog ();
exit:
    if (!taskInterrupted ())
        sendTaskExit ();

    return NULL;
}
