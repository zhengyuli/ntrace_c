#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "config.h"
#include "util.h"
#include "logger.h"
#include "context_cache.h"

void
displayContextCacheState (contextCachePtr contextCacheInstance) {
    LOGD ("Agent state: ");
    switch (contextCacheInstance->state) {
        case CONTEXT_CACHE_STATE_INIT:
            LOGD ("Init\n");
            break;

        case CONTEXT_CACHE_STATE_STOPPED:
            LOGD ("Stopped\n");
            break;

        case CONTEXT_CACHE_STATE_RUNNING:
            LOGD ("Running\n");
            break;

        case CONTEXT_CACHE_STATE_ERROR:
            LOGD ("Error\n");
            break;

        default:
            LOGD ("Unknown\n");
            return;
    }

    LOGD ("      agentId: %s\n", contextCacheInstance->agentId ? contextCacheInstance->agentId : "Null");
    LOGD ("      pushIp: %s\n", contextCacheInstance->pushIp ? contextCacheInstance->pushIp : "Null");
    LOGD ("      pushPort: %u\n", contextCacheInstance->pushPort);
}

int
syncContextCache (contextCachePtr contextCacheInstance) {
    int fd;
    int ret;
    json_t *root;
    char *out;

    if (!fileExists (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create directory %s error: %s.\n", AGENT_RUN_DIR, strerror (errno));
        return -1;
    }

    if (contextCacheInstance->state == CONTEXT_CACHE_STATE_INIT) {
        remove (AGENT_CONTEXT_CACHE_DB);
        return 0;
    }

    fd = open (AGENT_CONTEXT_CACHE_DB, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_CONTEXT_CACHE_DB, strerror (errno));
        return -1;
    }

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json root object error.\n");
        close (fd);
        return -1;
    }

    json_object_set_new (root, CONTEXT_CACHE_SYNC_STATE,
                         json_integer (contextCacheInstance->state));
    json_object_set_new (root, CONTEXT_CACHE_SYNC_AGENT_ID,
                         json_string (contextCacheInstance->agentId));
    json_object_set_new (root, CONTEXT_CACHE_SYNC_PUSH_IP,
                         json_string (contextCacheInstance->pushIp));
    json_object_set_new (root, CONTEXT_CACHE_SYNC_PUSH_PORT,
                         json_integer (contextCacheInstance->pushPort));
    if (contextCacheInstance->services)
        json_object_set_new (root, CONTEXT_CACHE_SYNC_SERVICES,
                             json_deep_copy (contextCacheInstance->services));

    out = json_dumps (root, JSON_INDENT (4));
    if (out == NULL) {
        LOGE ("Dump json object error.\n");
        json_object_clear (root);
        close (fd);
        return -1;
    }

    ret = safeWrite (fd, out, strlen (out));
    if ((ret < 0) || (ret != strlen (out))) {
        LOGE ("Write agent context to %s error: %s", AGENT_CONTEXT_CACHE_DB, strerror (errno));
        json_object_clear (root);
        close (fd);
        return -1;
    }

    json_object_clear (root);
    close (fd);
    return 0;
}

static contextCachePtr
newContextCache (void) {
    contextCachePtr tmp;

    tmp = (contextCachePtr) malloc (sizeof (contextCache));
    if (tmp) {
        tmp->state = CONTEXT_CACHE_STATE_INIT;
        tmp->agentId = NULL;
        tmp->pushIp = NULL;
        tmp->pushPort = 0;
        tmp->services = NULL;
    }

    return tmp;
}

void
resetContextCache (contextCachePtr contextCacheInstance) {
    contextCacheInstance->state = CONTEXT_CACHE_STATE_INIT;
    free (contextCacheInstance->agentId);
    contextCacheInstance->agentId = NULL;
    free (contextCacheInstance->pushIp);
    contextCacheInstance->pushIp = NULL;
    contextCacheInstance->pushPort = 0;
    if (contextCacheInstance->services) {
        json_object_clear (contextCacheInstance->services);
        contextCacheInstance->services = NULL;
    }
}

/*
 * Context cache init function
 * Load context cache from AGENT_CONTEXT_CACHE_DB.
 */
contextCachePtr
loadContextCache (void) {
    int fd;
    json_error_t error;
    json_t *root, *tmp, *svcs;
    contextCachePtr contextCacheInstance;

    contextCacheInstance = newContextCache ();
    if (contextCacheInstance == NULL) {
        LOGE ("Create context cache error.\n");
        return NULL;
    }
    
    fd = open (AGENT_CONTEXT_CACHE_DB, O_RDONLY);
    /* If AGENT_CONTEXT_CACHE_DB doesn't exist, use default
     * context cache configuration */
    if (fd < 0)
        return contextCacheInstance;

    root = json_load_file (AGENT_CONTEXT_CACHE_DB, JSON_DISABLE_EOF_CHECK, &error);
    /* Remove wrong context cache */
    if ((root == NULL) ||
        (json_object_get (root, CONTEXT_CACHE_SYNC_STATE) == NULL) ||
        (json_object_get (root, CONTEXT_CACHE_SYNC_AGENT_ID) == NULL) ||
        (json_object_get (root, CONTEXT_CACHE_SYNC_PUSH_IP) == NULL) ||
        (json_object_get (root, CONTEXT_CACHE_SYNC_PUSH_PORT) == NULL)) {
        if (root)
            json_object_clear (root);
        close (fd);
        remove (AGENT_CONTEXT_CACHE_DB);
        return contextCacheInstance;
    }

    /* Get context cache state */
    tmp = json_object_get (root, CONTEXT_CACHE_SYNC_STATE);
    contextCacheInstance->state = json_integer_value (tmp);
    /* Get context cache agentId */
    tmp = json_object_get (root, CONTEXT_CACHE_SYNC_AGENT_ID);
    contextCacheInstance->agentId = strdup (json_string_value (tmp));
    /* Get context cache push ip */
    tmp = json_object_get (root, CONTEXT_CACHE_SYNC_PUSH_IP);
    contextCacheInstance->pushIp = strdup (json_string_value (tmp));
    /* Get context cache push port */
    tmp = json_object_get (root, CONTEXT_CACHE_SYNC_PUSH_PORT);
    contextCacheInstance->pushPort = json_integer_value (tmp);
    /* Get context cache services */
    svcs = json_object_get (root, CONTEXT_CACHE_SYNC_SERVICES);
    if (svcs)
        contextCacheInstance->services = json_deep_copy (svcs);

    if ((contextCacheInstance->state == CONTEXT_CACHE_STATE_INIT) ||
        (contextCacheInstance->agentId == NULL) ||
        (contextCacheInstance->pushIp == NULL) ||
        (contextCacheInstance->pushPort == 0) ||
        (svcs && (contextCacheInstance->services == NULL))) {
        resetContextCache(contextCacheInstance);
        close (fd);
        remove (AGENT_CONTEXT_CACHE_DB);
        json_object_clear (root);
        return contextCacheInstance;
    }

    close (fd);
    json_object_clear (root);
    return contextCacheInstance;
}

void
destroyContextCache (contextCachePtr contextCacheInstance) {
    resetContextCache(contextCacheInstance);
    free (contextCacheInstance);
}
