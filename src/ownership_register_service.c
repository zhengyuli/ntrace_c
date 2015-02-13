#include <jansson.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "app_service_manager.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ownership_register_service.h"

#define SLAVE_REGISTER_INIT 0
#define SLAVE_REGISTER_DONE 1

static u_char slaveRegisterServiceState = SLAVE_REGISTER_INIT;

static char *
getSlaveRegisterRequest (u_char state) {
    u_int totalMem, freeMem;
    char *out;
    json_t *root, *body;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    body = json_object ();
    if (body == NULL) {
        LOGE ("Create json object error.\n");
        json_object_clear (root);
        return NULL;
    }

    switch (state) {
        case SLAVE_REGISTER_INIT:
            /* Slave ip */
            json_object_set_new (body, "ip", json_string (getPropertiesSlaveIp ()));
            /* Cpu cores */
            json_object_set_new (body, "cpu_cores", json_integer (getCpuCoresNum ()));
            /* Memory info */
            getMemInfo (&totalMem, &freeMem);
            json_object_set_new (body, "total_mem", json_integer (totalMem));
            json_object_set_new (body, "free_mem", json_integer (freeMem));

            /* Set cmd */
            json_object_set_new (root, "cmd", json_string ("slave_register_request"));
            /* Set body */
            json_object_set_new (root, "body", body);
            break;

        default:
            /* Set Cmd */
            json_object_set_new (root, "cmd", json_string ("slave_heartbeat"));
            /* Set body */
            json_object_set_new (root, "body", body);
            break;
    }

    out = json_dumps (root, JSON_INDENT (4));
    json_object_clear (root);
    return out;
}

static void
slaveRegisterResponseHandler (char *response) {
    int ret;
    json_error_t error;
    json_t *root, *code, *body, *errMsg, *appServices;

    root = json_loads (response, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        LOGE ("Slave register reponse parse error: %s\n", error.text);
        return;
    }

    code = json_object_get (root, "code");
    switch (json_integer_value (code)) {
        /* Handle success response */
        case 0:
            body = json_object_get (root, "body");

            switch (slaveRegisterServiceState) {
                /* Handle slave register response */
                case SLAVE_REGISTER_INIT:
                    appServices = json_object_get (body, "application_services");
                    if ((appServices == NULL) || !json_is_array (appServices))
                        LOGE ("Invalid format body of update profile\n.");
                    else {
                        ret = updateAppServiceManager (body);
                        if (ret < 0)
                            LOGE ("Update application service manager error.\n");
                    }

                    if (ret < 0)
                        slaveRegisterServiceState = SLAVE_REGISTER_INIT;
                    else
                        slaveRegisterServiceState = SLAVE_REGISTER_DONE;
                    break;

                case SLAVE_REGISTER_DONE:
                    LOGD ("Slave heartbeat.\n");
                    break;
            }
            break;

            /* Handle error response */
        default:
            errMsg = json_object_get (root, "error_message");
            LOGE ("Slave register reponse error: %s", json_string_value (errMsg));
            break;
    }

    json_object_clear (root);
}

void *
ownershipRegisterService (void *args) {
    int ret;
    char *request, *response;
    void *slaveRegisterSock;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Get slave register sock */
    slaveRegisterSock = getSlaveRegisterSock ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    while (!SIGUSR1IsInterrupted ()) {
        request = getSlaveRegisterRequest (slaveRegisterServiceState);
        if (request) {
            zstr_send (slaveRegisterSock, request);

            response = zstr_recv (slaveRegisterSock);
            if (response == NULL) {
                if (!SIGUSR1IsInterrupted ())
                    LOGE ("Receive slave response with fatal error.\n");
                break;
            }

            slaveRegisterResponseHandler (response);
            free (response);
        } else
            LOGE ("Get slave register request error.\n");

        sleep (1);
    }

    LOGI ("Slave register service will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
