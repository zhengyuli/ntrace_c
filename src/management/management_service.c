#include <jansson.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "netdev.h"
#include "proto_analyzer.h"
#include "management_service.h"

/* Packets statistic related variables */
static u_int packetsStatisticPktsReceive = 0;
static u_int packetsStatisticPktsDrop = 0;

/* Proto analyzer information */
static protoAnalyzerInfo protoAnalyzerInformation;

/**
 * @brief Resume request handler.
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
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0)
        LOGE ("Update application services filter error.\n");
    else
        LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

/**
 * @brief Pause request handler.
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
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0)
        LOGE ("Update application services filter error.\n");
    else
        LOGI ("Update application services filter: %s\n", filter);
    free (filter);

    return ret;
}

/**
 * @brief Heartbeat request handler.
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleHeartbeatRequest (json_t *body) {
    return 0;
}

/**
 * @brief Packets_statistic request handler.
 *
 * @param  body data to handle
 *
 * @return 0 if success else -1
 */
static int
handlePacketsStatisticRequest (json_t *body) {
    int ret;

    ret = getNetDevStatisticInfoForSniff (&packetsStatisticPktsReceive,
                                          &packetsStatisticPktsDrop);
    if (ret < 0) {
        LOGE ("Get packets statistic info error.\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Get proto information handler.
 *
 * @param body data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetProtoInfoRequest (json_t *body) {
    int ret;

    ret = getProtoAnalyzerInfo (&protoAnalyzerInformation);
    if (ret < 0) {
        LOGE ("Get proto analyzer information error.\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Build management response based on command.
 *
 * @param cmd command for response
 *
 * @return response if success else NULL
 */
static char *
buildManagementResponse (char *cmd, int code) {
    u_int i;
    char *response;
    json_t *root, *body, *protoNames;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object root error.\n");
        return NULL;
    }

    if (!code) {
        body = json_object ();
        if (body == NULL) {
            LOGE ("Create json object body error.\n");
            json_object_clear (root);
            return NULL;
        }

        if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_RECEIVE,
                                 json_integer (packetsStatisticPktsReceive));
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_DROP,
                                 json_integer (packetsStatisticPktsDrop));
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_DROP_RATE,
                                 json_real (((double) packetsStatisticPktsDrop /
                                             (double) packetsStatisticPktsReceive) * 100));
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_PROTO_INFO)) {
            protoNames = json_array ();
            if (protoNames == NULL) {
                LOGE ("Create json array protoNames error.\n");
                json_object_clear (body);
                json_object_clear (root);
                return NULL;
            }

            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PROTO_NUM,
                                 json_integer (protoAnalyzerInformation.registeredAnalyzerSize));

            for (i = 0; i < protoAnalyzerInformation.registeredAnalyzerSize; i++)
                json_array_append_new (protoNames, json_string (protoAnalyzerInformation.protoNames [i]));

            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PROTO_NAMES, protoNames);
        }

        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (0));
        json_object_set_new (root, MANAGEMENT_RESPONSE_BODY, body);
    } else {
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (1));
        json_object_set_new (root, MANAGEMENT_RESPONSE_ERROR_MESSAGE,
                             json_string ("Internal error."));
    }

    response = json_dumps (root, JSON_INDENT (4) | JSON_PRESERVE_ORDER);

    json_object_clear (root);
    return response;
}

/*
 * Management service.
 */
void *
managementService (void *args) {
    int ret;
    void *managementReplySock;
    char *request, *cmdStr, *response;
    json_t *root, *cmd, *body;
    json_error_t error;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Get management reply sock */
    managementReplySock = getManagementReplySock ();

    while (!SIGUSR1IsInterrupted ()) {
        request = zstr_recv (managementReplySock);
        if (request == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive management request with fatal error.\n");
            break;
        }

        LOGI ("Management request: %s\n", request);

        root = json_loads (request, JSON_DISABLE_EOF_CHECK, &error);
        if (root == NULL) {
            LOGE ("Management request parse error: %s\n", error.text);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        } else {
            cmd = json_object_get (root, MANAGEMENT_REQUEST_COMMAND);
            body = json_object_get (root, MANAGEMENT_REQUEST_BODY);

            if (cmd == NULL) {
                LOGE ("Invalid format of management request: %s.\n", request);
                zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            } else {
                cmdStr = (char *) json_string_value (cmd);
                if (strEqual (MANAGEMENT_REQUEST_COMMAND_RESUME, cmdStr))
                    ret = handleResumeRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PAUSE, cmdStr))
                    ret = handlePauseRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_HEARTBEAT, cmdStr))
                    ret = handleHeartbeatRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC, cmdStr))
                    ret = handlePacketsStatisticRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PROTO_INFO, cmdStr))
                    ret = handleGetProtoInfoRequest (body);
                else
                    LOGE ("Unknown management request command: %s.\n", cmdStr);

                response = buildManagementResponse (cmdStr, ret);
                if (response == NULL) {
                    LOGE ("Build management response error.\n");
                    zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
                } else {
                    zstr_send (managementReplySock, response);
                    free (response);
                }
            }

            json_object_clear (root);
        }

        free (request);
    }

    LOGI ("ManagementService will exit... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
