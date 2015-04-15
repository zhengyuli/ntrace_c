#include <stdlib.h>
#include <ini_config.h>
#include "config.h"
#include "log.h"
#include "properties.h"

/* Properties instance */
static propertiesPtr propertiesInstance = NULL;

static propertiesPtr
newProperties (void) {
    propertiesPtr tmp;

    tmp = (propertiesPtr) malloc (sizeof (properties));
    if (tmp == NULL)
        return NULL;

    tmp->daemonMode = 0;
    tmp->managementControlHost = NULL;
    tmp->managementControlPort = 0;
    tmp->mirrorInterface = NULL;
    tmp->pcapOfflineInput = NULL;
    tmp->miningEngineHost = NULL;
    tmp->managementRegisterPort = 0;
    tmp->breakdownRecvPort = 0;
    tmp->logDir = NULL;
    tmp->logFileName = NULL;
    tmp->logLevel = LOG_ERR_LEVEL;
    return tmp;
}

static void
freeProperties (propertiesPtr instance) {
    if (instance == NULL)
        return;

    free (instance->managementControlHost);
    instance->managementControlHost = NULL;
    free (instance->mirrorInterface);
    instance->mirrorInterface = NULL;
    free (instance->pcapOfflineInput);
    instance->pcapOfflineInput = NULL;
    free (instance->miningEngineHost);
    instance->miningEngineHost = NULL;
    free (instance->logDir);
    instance->logDir = NULL;
    free (instance->logFileName);
    instance->logFileName = NULL;

    free (instance);
}

static propertiesPtr
loadPropertiesFromConfigFile (char *configFile) {
    int ret, error;
    struct collection_item *iniConfig = NULL;
    struct collection_item *errorSet = NULL;
    struct collection_item *item;
    propertiesPtr tmp;

    /* Alloc properties */
    tmp = newProperties ();
    if (tmp == NULL) {
        fprintf (stderr, "Alloc properties error.\n");
        return NULL;
    }

    /* Load properties from AGENT_CONFIG_FILE */
    ret = config_from_file ("Main", configFile,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        fprintf (stderr, "Parse config file: %s error.\n", configFile);
        goto freeProperties;
    }

    /* Get daemon mode */
    ret = get_config_item ("Agent", "daemonMode", iniConfig, &item);
    if (ret) {
        fprintf (stderr, "Get_config_item \"daemonMode\" error.\n");
        goto freeProperties;
    }
    ret = get_bool_config_value (item, 0, &error);
    if (error && item) {
        fprintf (stderr, "Parse \"daemonMode\" error.\n");
        goto freeProperties;
    }
    if (ret)
        tmp->daemonMode = True;
    else
        tmp->daemonMode = False;

    /* Get management control host */
    ret = get_config_item ("Agent", "managementControlHost", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"managementControlHost\" error.\n");
        goto freeProperties;
    }
    tmp->managementControlHost = strdup (get_const_string_config_value (item, &error));
    if (tmp->managementControlHost == NULL) {
        fprintf (stderr, "Get \"managementControlHost\" error.\n");
        goto freeProperties;
    }

    /* Get management control port */
    ret = get_config_item ("Agent", "managementControlPort", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"managementControlPort\" error.\n");
        goto freeProperties;
    }
    tmp->managementControlPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"managementControlPort\" error.\n");
        goto freeProperties;
    }

    /* Get mirror interface */
    ret = get_config_item ("Interfaces", "mirrorInterface", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"mirrorInterface\" error.\n");
        goto freeProperties;
    }
    tmp->mirrorInterface = strdup (get_const_string_config_value (item, &error));
    if (tmp->mirrorInterface == NULL) {
        fprintf (stderr, "Get \"mirrorInterface\" error.\n");
        goto freeProperties;
    }

    /* Get pcap offline input */
    ret = get_config_item ("Interfaces", "pcapOfflineInput", iniConfig, &item);
    if (!ret && item) {
        tmp->pcapOfflineInput = strdup (get_const_string_config_value (item, &error));
        if (tmp->pcapOfflineInput == NULL) {
            fprintf (stderr, "Get \"pcapOfflineInput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get mining engine host */
    ret = get_config_item ("MiningEngine", "miningEngineHost", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"miningEngineHost\" error.\n");
        goto freeProperties;
    }
    tmp->miningEngineHost = strdup (get_const_string_config_value (item, &error));
    if (tmp->miningEngineHost == NULL) {
        fprintf (stderr, "Get \"miningEngineHost\" error.\n");
        goto freeProperties;
    }

    /* Get management register port */
    ret = get_config_item ("MiningEngine", "managementRegisterPort", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"managementRegisterPort\" error.\n");
        goto freeProperties;
    }
    tmp->managementRegisterPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"managementRegisterPort\" error.\n");
        goto freeProperties;
    }

    /* Get breakdown receive port */
    ret = get_config_item ("MiningEngine", "breakdownRecvPort", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"breakdownRecvPort\" error.\n");
        goto freeProperties;
    }
    tmp->breakdownRecvPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"breakdownRecvPort\" error.\n");
        goto freeProperties;
    }

    /* Get log dir */
    ret = get_config_item ("LOG", "logDir", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logDir\" error.\n");
        goto freeProperties;
    }
    tmp->logDir = strdup (get_const_string_config_value (item, &error));
    if (error) {
        fprintf (stderr, "Get \"logDir\" error.\n");
        goto freeProperties;
    }

    /* Get log file name */
    ret = get_config_item ("LOG", "logFileName", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logFileName\" error.\n");
        goto freeProperties;
    }
    tmp->logFileName = strdup (get_const_string_config_value (item, &error));
    if (error) {
        fprintf (stderr, "Get \"logFileName\" error.\n");
        goto freeProperties;
    }

    /* Get log level */
    ret = get_config_item ("LOG", "logLevel", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logLevel\" error.\n");
        goto freeProperties;
    }
    tmp->logLevel = get_int_config_value (item, 1, -1, &error);
    if (error) {
        fprintf (stderr, "Parse \"logLevel\" error.\n");
        goto freeProperties;
    }

    goto exit;

freeProperties:
    freeProperties (tmp);
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

void
updatePropertiesDaemonMode (boolean daemonMode) {
    propertiesInstance->daemonMode = daemonMode;
}

char *
getPropertiesManagementControlHost (void) {
    return propertiesInstance->managementControlHost;
}

void
updatePropertiesManagementControlHost (char *ip) {
    free (propertiesInstance->managementControlHost);
    propertiesInstance->managementControlHost = strdup (ip);
}

u_short
getPropertiesManagementControlPort (void) {
    return propertiesInstance->managementControlPort;
}

void
updatePropertiesManagementControlPort (u_short port) {
    propertiesInstance->managementControlPort = port;
}

char *
getPropertiesMirrorInterface (void) {
    return propertiesInstance->mirrorInterface;
}

void
updatePropertiesMirrorInterface (char *mirrorInterface) {
    free (propertiesInstance->mirrorInterface);
    propertiesInstance->mirrorInterface = strdup (mirrorInterface);
}

char *
getPropertiesPcapOfflineInput (void) {
    return propertiesInstance->pcapOfflineInput;
}

void
updatePropertiesPcapOfflineInput (char *fname) {
    free (propertiesInstance->pcapOfflineInput);
    propertiesInstance->pcapOfflineInput = strdup (fname);
}

char *
getPropertiesMiningEngineHost (void) {
    return propertiesInstance->miningEngineHost;
}

void
updatePropertiesMiningEngineHost (char *ip) {
    free (propertiesInstance->miningEngineHost);
    propertiesInstance->miningEngineHost = strdup (ip);
}

u_short
getPropertiesManagementRegisterPort (void) {
    return propertiesInstance->managementRegisterPort;
}

void
updatePropertiesManagementRegisterPort (u_short port) {
    propertiesInstance->managementRegisterPort = port;
}

u_short
getPropertiesBreakdownRecvPort (void) {
    return propertiesInstance->breakdownRecvPort;
}

void
updatePropertiesBreakdownRecvPort (u_short port) {
    propertiesInstance->breakdownRecvPort = port;
}

char *
getPropertiesLogDir (void) {
    return propertiesInstance->logDir;
}

void
updatePropertiesLogDir (char *path) {
    free (propertiesInstance->logDir);
    propertiesInstance->logDir = strdup (path);
}

char *
getPropertiesLogFileName (void) {
    return propertiesInstance->logFileName;
}

void
updatePropertiesLogFileName (char *fileName) {
    free (propertiesInstance->logFileName);
    propertiesInstance->logFileName = strdup (fileName);
}

u_int
getPropertiesLogLevel (void) {
    return propertiesInstance->logLevel;
}

void
updatePropertiesLogLevel (u_int logLevel) {
    propertiesInstance->logLevel = logLevel;
}

void
displayPropertiesDetail (void) {
    fprintf (stdout, "Startup with properties:\n");
    fprintf (stdout, "{\n");
    fprintf (stdout, "    daemonMode: %s\n", propertiesInstance->daemonMode ? "True" : "False");
    fprintf (stdout, "    managementControlHost: %s\n", propertiesInstance->managementControlHost);
    fprintf (stdout, "    managementControlPort: %u\n", propertiesInstance->managementControlPort);
    fprintf (stdout, "    mirrorInterface: %s\n", propertiesInstance->mirrorInterface);
    fprintf (stdout, "    pcapOfflineInput: %s\n", propertiesInstance->pcapOfflineInput);
    fprintf (stdout, "    miningEngineHost: %s\n", propertiesInstance->miningEngineHost);
    fprintf (stdout, "    managementRegisterPort: %u\n", propertiesInstance->managementRegisterPort);
    fprintf (stdout, "    breakdownRecvPort: %u\n", propertiesInstance->breakdownRecvPort);
    fprintf (stdout, "    logDir: %s\n", propertiesInstance->logDir);
    fprintf (stdout, "    logFileName: %s\n", propertiesInstance->logFileName);
    fprintf (stdout, "    logLevel: ");
    switch (propertiesInstance->logLevel) {
        case LOG_ERR_LEVEL:
            fprintf (stdout, "ERROR\n");
            break;

        case LOG_WARN_LEVEL:
            fprintf (stdout, "WARNING\n");
            break;

        case LOG_INFO_LEVEL:
            fprintf (stdout, "INFO\n");
            break;

        case LOG_DEBUG_LEVEL:
            fprintf (stdout, "DEBUG\n");
            break;

        case LOG_TRACE_LEVEL:
            fprintf (stdout, "TRACE\n");
            break;

        default:
            fprintf (stdout, "Unknown\n");
    }
    fprintf (stdout, "}\n");
}

/* Init properties form configFile */
int
initProperties (char *configFile) {
    propertiesInstance = loadPropertiesFromConfigFile (configFile);
    if (propertiesInstance == NULL) {
        fprintf (stderr, "Load properties from config file error.\n");
        return -1;
    }

    return 0;
}

/* Destroy properties */
void
destroyProperties (void) {
    free (propertiesInstance->managementControlHost);
    propertiesInstance->managementControlHost = NULL;
    free (propertiesInstance->mirrorInterface);
    propertiesInstance->mirrorInterface = NULL;
    free (propertiesInstance->pcapOfflineInput);
    propertiesInstance->pcapOfflineInput = NULL;
    free (propertiesInstance->miningEngineHost);
    propertiesInstance->miningEngineHost = NULL;
    free (propertiesInstance->logDir);
    propertiesInstance->logDir = NULL;
    free (propertiesInstance->logFileName);
    propertiesInstance->logFileName = NULL;
    freeProperties (propertiesInstance);
    propertiesInstance = NULL;
}
