#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "config.h"
#include "util.h"
#include "logger.h"
#include "runtime_context.h"

/* Runtime context local instance */
static runtimeContextPtr runtimeContextInstance = NULL;

static runtimeContextPtr
newRuntimeContext (void) {
    runtimeContextPtr tmp;

    tmp = (runtimeContextPtr) malloc (sizeof (runtimeContext));
    if (tmp == NULL)
        return NULL;

    tmp->state = AGENT_STATE_INIT;
    tmp->agentId = NULL;
    tmp->breakdownSinkIp = NULL;
    tmp->breakdownSinkPort = 0;
    tmp->appServices = NULL;
    tmp->appServicesCount = 0;
    return tmp;
}

static void
resetAppServices (void) {
    int i;

    if (runtimeContextInstance->appServices) {
        for (i = 0; i < runtimeContextInstance->appServicesCount; i++)
            freeAppService (runtimeContextInstance->appServices [i]);
        free (runtimeContextInstance->appServices);
    }

    runtimeContextInstance->appServices = NULL;
    runtimeContextInstance->appServicesCount = 0;
}

/*
 * @brief Extract application services from json.
 *
 * @param root application services in json
 * @param count variable used to return application service count
 *
 * @return application service array if success, else return NULL
 */
static appServicePtr *
parseAppServicesFromJson (json_t *root, u_int *count) {
    u_int i, n;
    json_t *tmp;
    appServicePtr svc, *appServices;

    appServices = (appServicePtr *) malloc (sizeof (appServicePtr) * json_array_size (root));
    if (appServices == NULL) {
        LOGE ("Malloc appServicePtr array error: %s\n", strerror (errno));
        *count = 0;
        return NULL;
    }

    for (i = 0; i < json_array_size (root); i++) {
        tmp = json_array_get (root, i);
        if (tmp == NULL) {
            LOGE ("Get json array item error.\n");
            goto error;
        }

        svc = json2AppService (tmp);
        if (svc == NULL) {
            LOGE ("Convert json to appService error.\n");
            goto error;
        }

        appServices [i] = svc;
    }
    *count = json_array_size (root);
    return appServices;

error:
    for (n = 0; n < i; n++)
        freeAppService (appServices [n]);
    free (appServices);
    appServices = NULL;
    *count = 0;
    return NULL;
}

static json_t *
runtimeContext2Json (void) {
    int i;
    json_t *root;
    json_t *appService, *appServiceArray;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json root object error.\n");
        return NULL;
    }

    json_object_set_new (root, RUNTIME_CONTEXT_CACHE_AGENT_STATE,
                         json_integer (runtimeContextInstance->state));
    json_object_set_new (root, RUNTIME_CONTEXT_CACHE_AGENT_ID,
                         json_string (runtimeContextInstance->agentId));
    json_object_set_new (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_IP,
                         json_string (runtimeContextInstance->breakdownSinkIp));
    json_object_set_new (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_PORT,
                         json_integer (runtimeContextInstance->breakdownSinkPort));
    if (runtimeContextInstance->appServices && runtimeContextInstance->appServicesCount) {
        appServiceArray = json_array ();
        if (appServiceArray == NULL) {
            LOGE ("Create json array for appServices error.\n");
            json_object_clear (root);
            return NULL;
        }

        for (i = 0; i < runtimeContextInstance->appServicesCount; i++) {
            appService = appService2Json (runtimeContextInstance->appServices [i]);
            if (appService == NULL) {
                LOGE ("Convert application service to json error.\n");
                json_object_clear (appServiceArray);
                json_object_clear (root);
                return NULL;
            }
            json_array_append_new (appServiceArray, appService);
        }

        json_object_set_new (root, RUNTIME_CONTEXT_CACHE_APP_SERVICES, appServiceArray);
    }

    return root;
}

static runtimeContextPtr
json2RuntimeContext (json_t *root) {
    int i;
    json_t *tmp;
    runtimeContextPtr context;

    context = newRuntimeContext ();
    if (context == NULL) {
        LOGE ("Create runtime context error.\n");
        return NULL;
    }

    /* Return default runtime context if runtime context cache is not valid */
    if ((json_object_get (root, RUNTIME_CONTEXT_CACHE_AGENT_STATE) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_CACHE_AGENT_ID) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_IP) == NULL) ||
        (json_object_get (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_PORT) == NULL))
        return context;

    /* Get agent state */
    tmp = json_object_get (root, RUNTIME_CONTEXT_CACHE_AGENT_STATE);
    context->state = json_integer_value (tmp);
    /* Get agent id */
    tmp = json_object_get (root, RUNTIME_CONTEXT_CACHE_AGENT_ID);
    context->agentId = strdup (json_string_value (tmp));
    /* Get breakdown sink ip */
    tmp = json_object_get (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_IP);
    context->breakdownSinkIp = strdup (json_string_value (tmp));
    /* Get breakdown sink port */
    tmp = json_object_get (root, RUNTIME_CONTEXT_CACHE_BREAKDOWN_SINK_PORT);
    context->breakdownSinkPort = json_integer_value (tmp);
    /* Get application services */
    tmp = json_object_get (root, RUNTIME_CONTEXT_CACHE_APP_SERVICES);
    if (tmp)
        context->appServices = parseAppServicesFromJson (tmp, &context->appServicesCount);

    if ((context->state == AGENT_STATE_INIT) || (context->agentId == NULL) ||
        (context->breakdownSinkIp == NULL) || (context->breakdownSinkPort == 0) ||
        (tmp && (context->appServices == NULL))) {
        context->state = AGENT_STATE_INIT;
        free (context->agentId);
        context->agentId = NULL;
        free (context->breakdownSinkIp);
        context->breakdownSinkIp = NULL;
        context->breakdownSinkPort = 0;
        if (context->appServices) {
            for (i = 0; i < context->appServicesCount; i++)
                freeAppService (context->appServices [i]);
            free (context->appServices);
        }
        context->appServices = NULL;
        context->appServicesCount = 0;
    }

    return context;
}

agentState
getAgentState (void) {
    return runtimeContextInstance->state;
}

int
setAgentState (agentState state) {
    runtimeContextInstance->state = state;
    return 0;
}

char *
getAgentId (void) {
    return runtimeContextInstance->agentId;
}

int
setAgentId (char *agentId) {
    if (agentId == NULL)
        return -1;

    free (runtimeContextInstance->agentId);
    runtimeContextInstance->agentId = agentId;
    return 0;
}

char *
getBreakdownSinkIp (void) {
    return runtimeContextInstance->breakdownSinkIp;
}

int
setBreakdownSinkIp (char *ip) {
    if (ip == NULL)
        return -1;

    free (runtimeContextInstance->breakdownSinkIp);
    runtimeContextInstance->breakdownSinkIp = ip;
    return 0;
}

u_short
getBreakdownSinkPort (void) {
    return runtimeContextInstance->breakdownSinkPort;
}

int
setBreakdownSinkPort (u_short port) {
    runtimeContextInstance->breakdownSinkPort = port;
    return 0;
}

appServicePtr *
getAppServices (void) {
    return runtimeContextInstance->appServices;
}

int
setAppServices (json_t *root) {
    u_int count;
    appServicePtr *tmp;

    tmp = parseAppServicesFromJson (root, &count);
    if (tmp) {
        resetAppServices ();
        runtimeContextInstance->appServices = tmp;
        runtimeContextInstance->appServicesCount = count;
        return 0;
    } else
        return -1;
}

u_int
getAppServicesCount (void) {
    return runtimeContextInstance->appServicesCount;
}

int
setAppServicesCount (u_int count) {
    runtimeContextInstance->appServicesCount = count;
    return 0;
}

/* Reset runtime context */
void
resetRuntimeContext (void) {
    runtimeContextInstance->state = AGENT_STATE_INIT;
    free (runtimeContextInstance->agentId);
    runtimeContextInstance->agentId = NULL;
    free (runtimeContextInstance->breakdownSinkIp);
    runtimeContextInstance->breakdownSinkIp = NULL;
    runtimeContextInstance->breakdownSinkPort = 0;
    resetAppServices ();
}

/* Dump runtime context to AGENT_RUNTIME_CONTEXT_CACHE */
void
dumpRuntimeContext (void) {
    int fd;
    int ret;
    json_t *root;
    char *out;

    if (!fileExists (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create directory %s error: %s.\n", AGENT_RUN_DIR, strerror (errno));
        return;
    }

    if (runtimeContextInstance->state == AGENT_STATE_INIT) {
        remove (AGENT_RUNTIME_CONTEXT_CACHE);
        return;
    }

    fd = open (AGENT_RUNTIME_CONTEXT_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_RUNTIME_CONTEXT_CACHE, strerror (errno));
        return;
    }

    root = runtimeContext2Json ();
    if (root == NULL) {
        LOGE ("Convert runtimeContextInstance to json error.\n");
        close (fd);
        return;
    }

    out = json_dumps (root, JSON_INDENT (4));
    if (out == NULL) {
        LOGE ("Dump json error.\n");
        json_object_clear (root);
        close (fd);
        return;
    }

    ret = safeWrite (fd, out, strlen (out));
    if ((ret < 0) || (ret != strlen (out))) {
        LOGE ("Write agent context to %s error: %s", AGENT_RUNTIME_CONTEXT_CACHE, strerror (errno));
        free (out);
        json_object_clear (root);
        close (fd);
        return;
    }

    LOGD ("\nDump runtimeContext:\n%s\n", out);
    free (out);
    json_object_clear (root);
    close (fd);
    return;
}

/*
 * Runtime context init function
 * Load runtime context from AGENT_RUNTIME_CONTEXT_CACHE.
 */
int
initRuntimeContext (void) {
    json_error_t error;
    json_t *root;
    char *out;

    root = json_load_file (AGENT_RUNTIME_CONTEXT_CACHE, JSON_DISABLE_EOF_CHECK, &error);
    /* If load error return default runtime context cache */
    if (root == NULL)
        runtimeContextInstance = newRuntimeContext ();
    else {
        runtimeContextInstance = json2RuntimeContext (root);
        json_object_clear (root);
    }
    if (runtimeContextInstance == NULL)
        return -1;

    root = runtimeContext2Json ();
    if (root) {
        out = json_dumps (root, JSON_INDENT (4));
        if (out) {
            LOGD ("\nLoad runtimeContext:\n%s\n", out);
            free (out);
        }
        json_object_clear (root);
    }

    return 0;
}

void
destroyRuntimeContext (void) {
    resetRuntimeContext ();
    free (runtimeContextInstance);
    runtimeContextInstance = NULL;
}
