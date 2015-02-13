#include <jansson.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "profile_cache.h"
#include "app_service_manager.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ownership_observe_service.h"

static char *
getSlaveHandleResponse (char *cmd, int code) {
    char *out;
    json_t *root, *body;

    if (!code)
        return strdup (SLAVE_HANDLE_ERROR_RESPONSE);

    if (strEqual (cmd, "slave_register_request")) {
        root = json_object ();
        if (root == NULL) {
            LOGE ("Create json object error.\n");
            return strdup (SLAVE_HANDLE_ERROR_RESPONSE);
        }

        body = getProfileCache ();
        if (body == NULL) {
            LOGE ("Get profile cache error.\n");
            json_object_clear (root);
            return strdup (SLAVE_HANDLE_ERROR_RESPONSE);
        }

        /* Set code */
        json_object_set_new (root, "code", json_integer (0));
        /* Set body */
        json_object_set_new (root, "body", body);

        out = json_dumps (root, JSON_INDENT (4));
        json_object_clear (root);
        return out;
    } else
        return strdup (SLAVE_HANDLE_SUCCESS_RESPONSE);
}

static int
slaveRegisterHandler (json_t *body) {
    return 0;
}

static int
slaveHeartbeatHandler (json_t *body) {
    return 0;
}

void *
ownershipObserveService (void *args) {
    int ret;
    char *requestMsg;
    void *slaveObserveSock;
    char *cmdStr, *resp;
    json_error_t error;
    json_t *root, *cmd, *body;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Get slave observe sock */
    slaveObserveSock = getSlaveObserveSock ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    while (!SIGUSR1IsInterrupted ()) {
        requestMsg = zstr_recv (slaveObserveSock);
        if (requestMsg == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive slave request with fatal error.\n");
            break;
        }

        root = json_loads (requestMsg, JSON_DISABLE_EOF_CHECK, &error);
        if (root == NULL) {
            LOGE ("Slave request parse error: %s\n", error.text);
            zstr_send (slaveObserveSock, SLAVE_HANDLE_ERROR_RESPONSE);
            free (requestMsg);
            continue;
        }

        cmd = json_object_get (root, "cmd");
        body = json_object_get (root, "body");
        if ((cmd == NULL) || (body == NULL)) {
            LOGE ("Invalid format of slave request: %s.\n", requestMsg);
            zstr_send (slaveObserveSock, SLAVE_HANDLE_ERROR_RESPONSE);
            json_object_clear (root);
            free (requestMsg);
            continue;
        }

        cmdStr = (char *) json_string_value (cmd);
        if (strEqual ("slave_register_request", cmdStr))
            ret = slaveRegisterHandler (body);
        else if (strEqual ("slave_heartbeat", cmdStr))
            ret = slaveHeartbeatHandler (body);
        else {
            LOGE ("Unknown command: %s.\n", cmdStr);
            ret = -1;
        }

        resp = getSlaveHandleResponse (cmdStr, ret);
        if (resp == NULL)
            zstr_send (slaveObserveSock, SLAVE_HANDLE_ERROR_RESPONSE);
        else {
            zstr_send (slaveObserveSock, resp);
            free (resp);
        }
        
        json_object_clear (root);
        free (requestMsg);
    }

    LOGI ("Slave register service will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
