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
 * @brief command resume handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleResume (json_t *body) {
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
 * @brief command pause handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handlerPause (json_t *body) {
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
 * @brief command heartbeat handler
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleHeartbeat (json_t *body) {
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
handleUpdateProfile (json_t *body) {
    int ret;
    void *profilePubSock;
    char *profileStr;
    json_t *appServices;
    char *filter;

    /* Get publish profile to slave if any */
    profilePubSock = getProfilePubSock ();

    profileStr = json_dumps (body, JSON_INDENT (4));
    if (profileStr == NULL) {
        LOGE ("Json dump profile error.\n");
        return -1;
    }

    appServices = getAppServicesFromProfile (body);
    if ((appServices == NULL) || !json_is_array (appServices)) {
        LOGE ("Invalid format of update profile\n.");
        free (profileStr);
        return -1;
    }

    /* Update application service manager */
    ret = updateAppServiceManager (appServices);
    if (ret < 0) {
        LOGE ("Update application service manager error.\n");
        free (profileStr);
        return -1;
    }

    /* Get Latest application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        LOGE ("Get application services filter error.\n");
        free (profileStr);
        return -1;
    }

    /* Update application services filter for master */
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        free (filter);
        free (profileStr);
        return -1;
    }

    LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    /* Publish profile to slave if any */
    zstr_send (profilePubSock, profileStr);
    /* Sync profile cache */
    syncProfileCache (profileStr);

    free (profileStr);
    return 0;
}

/*
 * @brief Build management response based on command and code
 *
 * @param cmd command for response
 * @param code return code for response
 *
 * @return management resp if success else NULL
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
        json_object_set_new (root, MANAGEMENT_COMMON_BODY, json_object ());
    } else {
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (1));
        json_object_set_new(root, MANAGEMENT_RESPONSE_ERROR_MESSAGE, json_string ("internal error"));
    }

    response = json_dumps (root, JSON_INDENT (4));

    json_object_clear (root);
    return response;
}

/*
 * Management service.
 * Handle management requests.
 */
void *
managementService (void *args) {
    int ret;
    void *managementReplySock;
    char *requestMsg;
    char *cmdStr, *resp;
    json_error_t error;
    json_t *root, *cmd, *body;

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
        requestMsg = zstr_recv (managementReplySock);
        if (requestMsg == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive management request with fatal error.\n");
            break;
        }

        root = json_loads (requestMsg, JSON_DISABLE_EOF_CHECK, &error);
        if (root == NULL) {
            LOGE ("Management request parse error: %s\n", error.text);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            free (requestMsg);
            continue;
        }

        cmd = json_object_get (root, MANAGEMENT_REQUEST_COMMAND);
        body = json_object_get (root, MANAGEMENT_COMMON_BODY);
        if ((cmd == NULL) || (body == NULL)) {
            LOGE ("Invalid format of management request: %s.\n", requestMsg);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            json_object_clear (root);
            free (requestMsg);
            continue;
        }

        cmdStr = (char *) json_string_value (cmd);
        if (strEqual (MANAGEMENT_REQUEST_COMMAND_RESUME, cmdStr))
            ret = handleResume (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PAUSE, cmdStr))
            ret = handlerPause (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_HEARTBEAT, cmdStr))
            ret = handleHeartbeat (body);
        else if (strEqual (MANAGEMENT_REQUEST_COMMAND_UPDATE_PROFILE, cmdStr))
            ret = handleUpdateProfile (body);
        else {
            LOGE ("Unknown command: %s.\n", cmdStr);
            ret = -1;
        }

        resp = buildManagementResponse (cmdStr, ret);
        if (resp == NULL) {
            LOGE ("Build management response error.\n");
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        } else {
            zstr_send (managementReplySock, resp);
            free (resp);
        }

        json_object_clear (root);
        free (requestMsg);
    }

    LOGI ("ManagementService will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
