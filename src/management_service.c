#include <jansson.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "profile_cache.h"
#include "netdev.h"
#include "management_service.h"

/*
 * @brief Build management response based on command
 *
 * @param cmd command for response
 *
 * @return response if success else NULL
 */
static char *
buildManagementResponse (char *cmd, int code) {
    char *response;
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    if (!code) {
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (0));
        json_object_set_new (root, MANAGEMENT_RESPONSE_BODY, json_object ());
    } else {
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (1));
        json_object_set_new (root, MANAGEMENT_RESPONSE_ERROR_MESSAGE, json_string ("Internal error."));
    }

    response = json_dumps (root, JSON_INDENT (4));

    json_object_clear (root);
    return response;
}

/*
 * @brief resume request handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleResumeRequest (json_t *body) {
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
        LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

/*
 * @brief pause request handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handlePauseRequest (json_t *body) {
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
        LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

/*
 * @brief heartbeat request handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleHeartbeatRequest (json_t *body) {
    return 0;
}

/*
 * @brief update_profile request handler
 *
 * @param  body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleUpdateProfileRequest (json_t *body) {
    int ret;
    json_t *appServices;
    char *filter;

    if (body == NULL) {
        LOGE ("Invalid format of update profile request, miss body item.\n");
        return -1;
    }

    appServices = getAppServicesFromProfile (body);
    if ((appServices == NULL) || !json_is_array (appServices)) {
        LOGE ("Invalid format of update profile\n.");
        return -1;
    }

    /* Update application service manager */
    ret = updateAppServiceManager (appServices);
    if (ret < 0) {
        LOGE ("Update application service manager error.\n");
        return -1;
    }

    /* Get latest application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application services filter error.\n");
        return -1;
    }

    /* Update application services filter */
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        free (filter);
        return -1;
    }

    LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    /* Sync profile cache */
    ret = syncProfileCache (body);
    if (ret < 0) {
        LOGE ("Sync profile cache error.\n");
        return -1;
    }

    return 0;
}

/*
 * Management service.
 * Handle management requests.
 */
void *
managementService (void *args) {
    int ret;
    void *managementReplySock;
    char *request, *response, *cmdStr;
    json_t *root, *cmd, *body;
    json_error_t error;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Get management reply sock */
    managementReplySock = getManagementReplySock ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    while (!SIGUSR1IsInterrupted ()) {
        request = zstr_recv (managementReplySock);
        if (request == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive management request with fatal error.\n");
            break;
        }

        root = json_loads (request, JSON_DISABLE_EOF_CHECK, &error);
        free (request);
        if (root == NULL) {
            LOGE ("Management request parse error: %s\n", error.text);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            continue;
        }

        cmd = json_object_get (root, MANAGEMENT_REQUEST_COMMAND);
        body = json_object_get (root, MANAGEMENT_REQUEST_BODY);
        if (cmd == NULL) {
            LOGE ("Invalid format of management request: %s.\n", request);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            json_object_clear (root);
            continue;
        }

        cmdStr = (char *) json_string_value (cmd);
        if (strEqual (MANAGEMENT_REQUEST_COMMAND_RESUME, cmdStr))
            ret = handleResumeRequest (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PAUSE, cmdStr))
            ret = handlePauseRequest (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_HEARTBEAT, cmdStr))
            ret = handleHeartbeatRequest (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_UPDATE_PROFILE, cmdStr))
            ret = handleUpdateProfileRequest (body);
        else {
            LOGE ("Unknown request: %s.\n", cmdStr);
            ret = -1;
        }

        response = buildManagementResponse (cmdStr, ret);
        if (response == NULL) {
            LOGE ("Build management response error.\n");
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        } else {
            zstr_send (managementReplySock, response);
            free (response);
        }

        json_object_clear (root);
    }

    LOGI ("ManagementService will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
