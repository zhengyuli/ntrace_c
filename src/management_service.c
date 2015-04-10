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

/* Register expire time 3000ms */
#define REGISTER_TASK_EXPIRE_TIME 3000

static boolean registerSuccess = False;

static boolean registerTaskStarted = False;
static u_long_long registerTaskExpireTime;

static zctx_t *zmqCtxt = NULL;
static zmq_pollitem_t registerTaskPollItem;

/* Packets statistic related variables */
static u_int packetsStatisticPktsReceive = 0;
static u_int packetsStatisticPktsDrop = 0;

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
    json_t *root, *body;

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
                                 json_real (((double) packetsStatisticPktsDrop / (double) packetsStatisticPktsReceive) * 100));
        }

        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (0));
        json_object_set_new (root, MANAGEMENT_RESPONSE_BODY, body);
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
 * @brief packets_statistic request handler
 *
 * @param  body data to handle
 *
 * @return 0 if success else -1
 */
static int
handlePacketsStatisticRequest (json_t *body) {
    int ret;

    ret = getNetDevPakcetsStatistic (&packetsStatisticPktsReceive,
                                     &packetsStatisticPktsDrop);
    if (ret < 0) {
        LOGE ("Get packets statistic info error.\n");
        return -1;
    }

    return 0;
}

static int
managementRequestHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    void *managementReplySock;
    char *request, *response, *cmdStr;
    json_t *root, *cmd, *body;
    json_error_t error;

    /* Get management reply sock */
    managementReplySock = getManagementReplySock ();

    request = zstr_recv (managementReplySock);
    if (request == NULL) {
        if (!SIGUSR1IsInterrupted ()) {
            LOGE ("Receive management request with fatal error.\n");
            return -1;
        }

        return 0;
    }

    root = json_loads (request, JSON_DISABLE_EOF_CHECK, &error);
    free (request);
    if (root == NULL) {
        LOGE ("Management request parse error: %s\n", error.text);
        zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        return 0;
    }

    cmd = json_object_get (root, MANAGEMENT_REQUEST_COMMAND);
    body = json_object_get (root, MANAGEMENT_REQUEST_BODY);
    if (cmd == NULL) {
        LOGE ("Invalid format of management request: %s.\n", request);
        zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        json_object_clear (root);
        return 0;
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
    else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC, cmdStr), cmdStr)
        ret = handlePacketsStatisticRequest (body);
    else {
        LOGE ("Unknown request command: %s.\n", cmdStr);
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

    return 0;
}

static int
registerResponseHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    char *response;
    json_t *root;
    json_t *code;
    json_t *errMsg;
    json_error_t error;

    response = zstr_recv (item->socket);
    if (response == NULL) {
        if (!SIGUSR1IsInterrupted ()) {
            LOGE ("Receive register reponse with fatal error.\n");
            return -1;
        }

        return 0;
    }

    root = json_loads (response, JSON_DISABLE_EOF_CHECK, &error);
    free (response);
    if (root == NULL) {
        LOGE ("Register response parse error: %s\n", error.text);
        return 0;
    }


    code = json_object_get (root, MANAGEMENT_REGISTER_RESPONSE_CODE);
    if (code == NULL) {
        LOGE ("Register response parse error: %s\n", error.text);
        return 0;
    }

    if (json_integer_value (code)) {
        errMsg = json_object_get (root, MANAGEMENT_REGISTER_RESPONSE_ERROR_MESSAGE);
        if (errMsg)
            LOGE ("Register error: %s.\n", json_string_value (errMsg));
        else
            LOGE ("Register error.\n");
        return 0;
    }

    registerTaskStarted = False;
    registerSuccess = True;
    LOGI ("Register success.\n");
    return 0;
}

static char *
buildRegisterRequest (void) {
    char *request;
    json_t *root, *body;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object root error.\n");
        return NULL;
    }

    body = json_object ();
    if (body == NULL) {
        LOGE ("Create json object body error.\n");
        json_object_clear (root);
        return NULL;
    }

    json_object_set_new (root, MANAGEMENT_REGISTER_REQUEST_COMMAND,
                         json_string (MANAGEMENT_REGISTER_REQUEST_COMMAND_REGISTER));

    json_object_set_new (body, MANAGEMENT_REGISTER_REQUEST_BODY_MANAGEMENT_IP,
                         json_string (getPropertiesManagementServiceIp ()));
    json_object_set_new (body, MANAGEMENT_REGISTER_REQUEST_BODY_MANAGEMENT_PORT,
                         json_integer (getPropertiesManagementServicePort ()));

    json_object_set_new (root, MANAGEMENT_REGISTER_REQUEST_BODY, body);

    request = json_dumps (root, JSON_INDENT (4));

    json_object_clear (root);
    return request;
}

static void
startRegisterTask (zloop_t *loop) {
    int ret;
    char *request;
    void *registerRequestSock;

    registerRequestSock = zsocket_new (zmqCtxt, ZMQ_REQ);
    if (registerRequestSock == NULL) {
        LOGE ("Create registerRequestSock error.\n");
        return;
    }
    ret = zsocket_connect (registerRequestSock, "tcp://%s:%u",
                           getPropertiesServerIp (),
                           getPropertiesAgentRegisterPort ());
    if (ret < 0) {
        LOGE ("Bind to tcp://%s:%u error.\n",
              getPropertiesServerIp (),
              getPropertiesAgentRegisterPort ());
        zsocket_destroy (zmqCtxt, registerRequestSock);
    }

    request = buildRegisterRequest ();
    if (request == NULL) {
        LOGE ("Build register request error.\n");
        zsocket_destroy (zmqCtxt, registerRequestSock);
        return;
    }

    ret = zstr_send (registerRequestSock, request);
    if (ret < 0) {
        LOGE ("Send register request error.\n");
        return;
    }
    LOGD ("Send register request: %s\n", request);

    registerTaskPollItem.socket =  registerRequestSock;
    registerTaskPollItem.fd = 0;
    registerTaskPollItem.events = ZMQ_POLLIN;
    ret = zloop_poller (loop, &registerTaskPollItem, registerResponseHandler, NULL);
    if (ret < 0) {
        LOGE ("Register registerTaskPollItem error.\n");
        zsocket_destroy (zmqCtxt, registerRequestSock);
    }

    registerTaskStarted = True;
    registerTaskExpireTime = getSysTime () + REGISTER_TASK_EXPIRE_TIME;
}

static int
managementTimerHandler (zloop_t *loop, int timerId, void *arg) {
    if (!registerSuccess) {
        if (!registerTaskStarted)
            startRegisterTask (loop);
        else if (getSysTime () > registerTaskExpireTime) {
            LOGD ("Register request expire.\n");
            zsocket_destroy (zmqCtxt, registerTaskPollItem.socket);
            zloop_poller_end (loop, &registerTaskPollItem);
            startRegisterTask (loop);
        }
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
    zmq_pollitem_t pollItems [1];
    zloop_t *loop;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Create zmq context */
    zmqCtxt = zctx_new ();
    if (zmqCtxt == NULL) {
        LOGE ("Create zmq context error.\n");
        goto destroyLogContext;
    }
    zctx_set_linger (zmqCtxt, 0);

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto destroyZmqCtxt;
    }

    /* Init poll item 0 */
    pollItems [0].socket = getManagementReplySock ();
    pollItems [0].fd = 0;
    pollItems [0].events = ZMQ_POLLIN;
    /* Register poll item 0 */
    ret = zloop_poller (loop, &pollItems [0], managementRequestHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [0] error.\n");
        goto destroyZloop;
    }

    ret = zloop_timer (loop, 1000, 0, managementTimerHandler, NULL);
    if (ret < 0) {
        LOGE ("Register management timer error.\n");
        goto destroyZloop;
    }

    /* Start zloop */
    ret = zloop_start (loop);
    if (ret < 0)
        LOGE ("ManagementService exit abnormally... .. .\n");
    else
        LOGI ("ManagementService will exit... .. .\n");

destroyZloop:
    zloop_destroy (&loop);
destroyZmqCtxt:
    zctx_destroy (&zmqCtxt);
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
