#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "config.h"
#include "util.h"
#include "logger.h"
#include "indent_level.h"
#include "runtime_context.h"

void
displayRuntimeContextDetail (runtimeContextPtr runtimeContextInstance) {
    int i;
    
    LOGD ("\n%sRuntime context detail:\n", getIndentLevel (0));
    LOGD ("%s{\n", getIndentLevel (0));
    LOGD ("%sAgent state: ", getIndentLevel (1));
    switch (runtimeContextInstance->state) {
        case AGENT_STATE_INIT:
            LOGD ("Init\n");
            break;

        case AGENT_STATE_STOPPED:
            LOGD ("Stopped\n");
            break;

        case AGENT_STATE_RUNNING:
            LOGD ("Running\n");
            break;

        case AGENT_STATE_ERROR:
            LOGD ("Error\n");
            break;

        default:
            LOGD ("Unknown\n");
            return;
    }

    LOGD ("%sagentId: %s\n", getIndentLevel (1),
          runtimeContextInstance->agentId ? runtimeContextInstance->agentId : "Null");
    LOGD ("%spushIp: %s\n", getIndentLevel (1),
          runtimeContextInstance->pushIp ? runtimeContextInstance->pushIp : "Null");
    LOGD ("%spushPort: %u\n\n", getIndentLevel (1),
          runtimeContextInstance->pushPort);
    LOGD ("%sappServices: \n", getIndentLevel (1));
    LOGD ("%s{", getIndentLevel (1));
    if (runtimeContextInstance->appServices && runtimeContextInstance->appServiceCount) {
        for (i = 0; i < runtimeContextInstance->appServiceCount; i++)
            displayAppServiceDetail (runtimeContextInstance->appServices [i], 2);
    }
    LOGD ("%s}\n", getIndentLevel (1));
    LOGD ("%s}\n", getIndentLevel (0));
}

/* Dump runtime context to AGENT_RUNTIME_CONTEXT_CACHE */
int
dumpRuntimeContext (runtimeContextPtr runtimeContextInstance) {
    int fd;
    int ret, i;
    json_t *root;
    char *out;
    json_t *appService, *appServiceArray;

    if (!fileExists (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create directory %s error: %s.\n", AGENT_RUN_DIR, strerror (errno));
        return -1;
    }

    if (runtimeContextInstance->state == AGENT_STATE_INIT) {
        remove (AGENT_RUNTIME_CONTEXT_CACHE);
        return 0;
    }

    fd = open (AGENT_RUNTIME_CONTEXT_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_RUNTIME_CONTEXT_CACHE, strerror (errno));
        return -1;
    }

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json root object error.\n");
        close (fd);
        return -1;
    }

    json_object_set_new (root, RUNTIME_CONTEXT_AGENT_STATE,
                         json_integer (runtimeContextInstance->state));
    json_object_set_new (root, RUNTIME_CONTEXT_AGENT_ID,
                         json_string (runtimeContextInstance->agentId));
    json_object_set_new (root, RUNTIME_CONTEXT_PUSH_IP,
                         json_string (runtimeContextInstance->pushIp));
    json_object_set_new (root, RUNTIME_CONTEXT_PUSH_PORT,
                         json_integer (runtimeContextInstance->pushPort));
    if (runtimeContextInstance->appServices) {
        appServiceArray = json_array ();
        if (appServiceArray == NULL) {
            LOGE ("Create json array for appServices error.\n");
            json_object_clear (root);
            close (fd);
            return -1;
        }

        for (i = 0; i < runtimeContextInstance->appServiceCount; i++) {
            appService = appService2Json (runtimeContextInstance->appServices [i]);
            if (appService == NULL) {
                LOGE ("Convert application service to json error.\n");
                json_object_clear (appServiceArray);
                json_object_clear (root);
                close (fd);
                return -1;
            }

            json_array_append_new (appServiceArray, appService);
        }

        json_object_set_new(root, RUNTIME_CONTEXT_APP_SERVICES, appServiceArray);
    }

    out = json_dumps (root, JSON_INDENT (4));
    if (out == NULL) {
        LOGE ("Dump json object error.\n");
        json_object_clear (root);
        close (fd);
        return -1;
    }

    ret = safeWrite (fd, out, strlen (out));
    if ((ret < 0) || (ret != strlen (out))) {
        LOGE ("Write agent context to %s error: %s", AGENT_RUNTIME_CONTEXT_CACHE, strerror (errno));
        json_object_clear (root);
        close (fd);
        return -1;
    }

    displayRuntimeContextDetail (runtimeContextInstance);
    json_object_clear (root);
    close (fd);
    return 0;
}

static runtimeContextPtr
newRuntimeContext (void) {
    runtimeContextPtr tmp;

    tmp = (runtimeContextPtr) malloc (sizeof (runtimeContext));
    if (tmp == NULL)
        return NULL;

    tmp->state = AGENT_STATE_INIT;
    tmp->agentId = NULL;
    tmp->pushIp = NULL;
    tmp->pushPort = 0;
    tmp->appServices = NULL;
    tmp->appServiceCount = 0;
    return tmp;
}

void
resetRuntimeContext (runtimeContextPtr runtimeContextInstance) {
    int i;

    runtimeContextInstance->state = AGENT_STATE_INIT;
    free (runtimeContextInstance->agentId);
    runtimeContextInstance->agentId = NULL;
    free (runtimeContextInstance->pushIp);
    runtimeContextInstance->pushIp = NULL;
    runtimeContextInstance->pushPort = 0;
    if (runtimeContextInstance->appServices) {
        for (i = 0; i < runtimeContextInstance->appServiceCount; i++)
            freeAppService (runtimeContextInstance->appServices [i]);
        free (runtimeContextInstance->appServices);
        runtimeContextInstance->appServices = NULL;
        runtimeContextInstance->appServiceCount = 0;
    }
}

/*
 * @brief Extract application services from json.
 *
 * @param appServices application services in json
 * @param count variable used to return application service count
 *
 * @return application service array if success, else return NULL
 */
static appServicePtr *
extractAppServicesFromJson (json_t *appServices, u_int *count) {
    u_int i, n;
    json_t *tmp;
    appServicePtr svc, *result;

    result = (appServicePtr *) malloc (sizeof (appServicePtr) * json_array_size (appServices));
    if (result == NULL) {
        LOGE ("Malloc appServicePtr array error: %s\n", strerror (errno));
        *count = 0;
        return NULL;
    }

    for (i = 0; i < json_array_size (appServices); i++) {
        tmp = json_array_get (appServices, i);
        if (tmp == NULL) {
            LOGE ("Get json array item error.\n");
            goto error;
        }

        svc = json2AppService (tmp);
        if (svc == NULL) {
            LOGE ("Convert json to appService error.\n");
            goto error;
        }

        result [i] = svc;
    }
    *count = json_array_size (appServices);
    return result;

error:
    for (n = 0; n < i; n++)
        freeAppService (result [n]);
    free (result);
    result = NULL;
    *count = 0;
    return NULL;
}

int
updateRuntimeContextAppServices (runtimeContextPtr runtimeContextInstance, json_t *appServices) {
    int i;

    if (runtimeContextInstance->appServices) {
        for (i = 0; i < runtimeContextInstance->appServiceCount; i++)
            freeAppService (runtimeContextInstance->appServices [i]);
        free (runtimeContextInstance->appServices);
        runtimeContextInstance->appServices = NULL;
        runtimeContextInstance->appServiceCount = 0;
    }

    runtimeContextInstance->appServices =
            extractAppServicesFromJson (appServices, &runtimeContextInstance->appServiceCount);
    if (runtimeContextInstance->appServices == NULL)
        return -1;
    else
        return 0;
}

/*
 * Runtime context init function
 * Load runtime context from AGENT_RUNTIME_CONTEXT_CACHE.
 */
runtimeContextPtr
loadRuntimeContext (void) {
    int fd;
    json_error_t error;
    json_t *root, *tmp, *appServices;
    runtimeContextPtr runtimeContextInstance;

    runtimeContextInstance = newRuntimeContext ();
    if (runtimeContextInstance == NULL) {
        LOGE ("Create runtime context error.\n");
        return NULL;
    }

    fd = open (AGENT_RUNTIME_CONTEXT_CACHE, O_RDONLY);
    /* If AGENT_RUNTIME_CONTEXT_CACHE doesn't exist, use default
     * runtime context configuration */
    if (fd < 0)
        return runtimeContextInstance;

    root = json_load_file (AGENT_RUNTIME_CONTEXT_CACHE, JSON_DISABLE_EOF_CHECK, &error);
    /* Remove wrong runtime context */
    if ((root == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_AGENT_STATE) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_AGENT_ID) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_PUSH_IP) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_PUSH_PORT) == NULL)) {
        if (root)
            json_object_clear (root);
        close (fd);
        remove (AGENT_RUNTIME_CONTEXT_CACHE);
        return runtimeContextInstance;
    }

    /* Get context cach eagent state */
    tmp = json_object_get (root, RUNTIME_CONTEXT_AGENT_STATE);
    runtimeContextInstance->state = json_integer_value (tmp);
    /* Get runtime context agentId */
    tmp = json_object_get (root, RUNTIME_CONTEXT_AGENT_ID);
    runtimeContextInstance->agentId = strdup (json_string_value (tmp));
    /* Get runtime context push ip */
    tmp = json_object_get (root, RUNTIME_CONTEXT_PUSH_IP);
    runtimeContextInstance->pushIp = strdup (json_string_value (tmp));
    /* Get runtime context push port */
    tmp = json_object_get (root, RUNTIME_CONTEXT_PUSH_PORT);
    runtimeContextInstance->pushPort = json_integer_value (tmp);
    /* Get runtime context services */
    appServices = json_object_get (root, RUNTIME_CONTEXT_APP_SERVICES);
    if (appServices) {
        runtimeContextInstance->appServices =
                extractAppServicesFromJson (appServices, &runtimeContextInstance->appServiceCount);
    }

    if ((runtimeContextInstance->state == AGENT_STATE_INIT) ||
        (runtimeContextInstance->agentId == NULL) ||
        (runtimeContextInstance->pushIp == NULL) ||
        (runtimeContextInstance->pushPort == 0) ||
        (appServices && (runtimeContextInstance->appServices == NULL))) {
        resetRuntimeContext(runtimeContextInstance);
        close (fd);
        remove (AGENT_RUNTIME_CONTEXT_CACHE);
        json_object_clear (root);
        return runtimeContextInstance;
    }

    displayRuntimeContextDetail (runtimeContextInstance);
    close (fd);
    json_object_clear (root);
    return runtimeContextInstance;
}

void
destroyRuntimeContext (runtimeContextPtr runtimeContextInstance) {
    resetRuntimeContext(runtimeContextInstance);
    free (runtimeContextInstance);
}
