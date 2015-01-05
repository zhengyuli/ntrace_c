#include <ini_config.h>
#include "config.h"
#include "logger.h"
#include "properties_manager.h"

/* Properties local instance */
static propertiesPtr propertiesInstance = NULL;

static propertiesPtr
newProperties (void) {
    propertiesPtr tmp;

    tmp = (propertiesPtr) malloc (sizeof (properties));
    if (tmp == NULL)
        return NULL;

    tmp->daemonMode = 0;
    tmp->mirrorInterface = NULL;
    tmp->logLevel = 0;
    return tmp;
}

static void
displayPropertiesDetail (void) {
    logToConsole ("Startup with properties:\n");
    logToConsole ("{\n");
    logToConsole ("    daemonMode: %s\n", propertiesInstance->daemonMode ? "true" : "false");
    logToConsole ("    mirrorInterface: %s\n", propertiesInstance->mirrorInterface);
    logToConsole ("    logLevel: ");
    switch (propertiesInstance->logLevel) {
        case LOG_ERR_LEVEL:
            logToConsole ("ERR\n");
            break;

        case LOG_WARNING_LEVEL:
            logToConsole ("WARNING\n");
            break;
            
        case LOG_INFO_LEVEL:
            logToConsole ("INFO\n");
            break;

        case LOG_DEBUG_LEVEL:
            logToConsole ("DEBUG\n");
            break;
            
        default:
            logToConsole ("Unknown\n");
    }
    logToConsole ("}\n");
}

static propertiesPtr
loadPropertiesFromConfigFile (void) {
    int ret, error;
    struct collection_item *iniConfig = NULL;
    struct collection_item *errorSet = NULL;
    struct collection_item *item;
    propertiesPtr tmp;

    /* Alloc new properties */
    tmp = newProperties ();
    if (tmp == NULL) {
        LOGE ("Alloc new agent config error.\n");
        return NULL;
    }

    /* Load agent properties from AGENT_CONFIG_FILE */
    ret = config_from_file ("Agent", AGENT_CONFIG_FILE,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        logToConsole ("Parse config file: %s error.\n", AGENT_CONFIG_FILE);
        goto freeProperties;
    }

    /* Get daemon mode */
    ret = get_config_item ("MAIN", "daemonMode", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"daemonMode\" error\n");
        goto freeProperties;
    }
    tmp->daemonMode = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"daemonMode\" error.\n");
        goto freeProperties;
    }

    /* Get mirror interface */
    ret = get_config_item ("MAIN", "mirrorInterface", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"mirrorInterface\" error\n");
        goto freeProperties;
    }
    tmp->mirrorInterface = strdup (get_const_string_config_value (item, &error));
    if (tmp->mirrorInterface == NULL) {
        logToConsole ("Get \"mirrorInterface\" error\n");
        goto freeProperties;
    }

    /* Get log level */
    ret = get_config_item ("LOG", "logLevel", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"logLevel\" error\n");
        goto freeProperties;
    }
    tmp->logLevel = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"logLevel\" error.\n");
        goto freeProperties;
    }
    /* Return properties in the last */
    goto exit;

freeProperties:
    free (tmp->mirrorInterface);
    free (tmp);
    tmp = NULL;
exit:
    if (iniConfig)
        free_ini_config (iniConfig);
    if (errorSet)
        free_ini_config_errors (errorSet);
    return tmp;
}

boolean
getPropertiesDaemonMode (void) {
    return propertiesInstance->daemonMode;
}

int
setPropertiesDaemonMode (boolean daemonMode) {
    propertiesInstance->daemonMode = daemonMode;
    return 0;
}

char *
getPropertiesMirrorInterface (void) {
    return propertiesInstance->mirrorInterface;
}

int
setPropertiesMirrorInterface (char *mirrorInterface) {
    if (mirrorInterface == NULL)
        return -1;

    free (propertiesInstance->mirrorInterface);
    propertiesInstance->mirrorInterface = mirrorInterface;
    return 0;
}

u_int
getPropertiesLogLevel (void) {
    return propertiesInstance->logLevel;
}

int
setPropertiesLogLevel (u_int logLevel) {
    propertiesInstance->logLevel = logLevel;
    return 0;
}

int
initPropertiesManager (void) {
    propertiesInstance = loadPropertiesFromConfigFile ();
    if (propertiesInstance == NULL)
        return -1;

    displayPropertiesDetail ();
    return 0;
}

void
destroyPropertiesManager (void) {
    free (propertiesInstance->mirrorInterface);
    free (propertiesInstance);
    propertiesInstance = NULL;
}
