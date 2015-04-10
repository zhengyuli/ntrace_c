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
    tmp->mirrorInterface = NULL;
    tmp->pcapOfflineInput = NULL;
    tmp->managementServiceIp = NULL;
    tmp->managementServicePort = 0;
    tmp->serverIp = NULL;
    tmp->agentRegisterPort = 0;
    tmp->breakdownSinkPort = 0;
    tmp->logDir = NULL;
    tmp->logFileName = NULL;
    tmp->logLevel = LOG_ERR_LEVEL;
    return tmp;
}

static void
freeProperties (propertiesPtr instance) {
    if (instance == NULL)
        return;

    free (instance->mirrorInterface);
    instance->mirrorInterface = NULL;
    free (instance->pcapOfflineInput);
    instance->pcapOfflineInput = NULL;
    free (instance->managementServiceIp);
    instance->managementServiceIp = NULL;
    free (instance->serverIp);
    instance->serverIp = NULL;
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
    ret = config_from_file ("Agent", configFile,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        fprintf (stderr, "Parse config file: %s error.\n", configFile);
        goto freeProperties;
    }

    /* Get daemon mode */
    ret = get_config_item ("MAIN", "daemonMode", iniConfig, &item);
    if (ret) {
        fprintf (stderr, "Get_config_item \"daemonMode\" error.\n");
        goto freeProperties;
    }
    ret = get_int_config_value (item, 1, 0, &error);
    if (error && item) {
        fprintf (stderr, "Parse \"daemonMode\" error.\n");
        goto freeProperties;
    }
    if (ret)
        tmp->daemonMode = True;
    else
        tmp->daemonMode = False;

    /* Get mirror interface */
    ret = get_config_item ("MAIN", "mirrorInterface", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"mirrorInterface\" error.\n");
        goto freeProperties;
    }
    tmp->mirrorInterface = strdup (get_const_string_config_value (item, &error));
    if (tmp->mirrorInterface == NULL) {
        fprintf (stderr, "Get \"mirrorInterface\" error.\n");
        goto freeProperties;
    }

    /* Get pcap offline input */
    ret = get_config_item ("MAIN", "pcapOfflineInput", iniConfig, &item);
    if (!ret && item) {
        tmp->pcapOfflineInput = strdup (get_const_string_config_value (item, &error));
        if (tmp->pcapOfflineInput == NULL) {
            fprintf (stderr, "Get \"pcapOfflineInput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get management service ip */
    ret = get_config_item ("MAIN", "managementServiceIp", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"managementServiceIp\" error.\n");
        goto freeProperties;
    }
    tmp->managementServiceIp = strdup (get_const_string_config_value (item, &error));
    if (tmp->managementServiceIp == NULL) {
        fprintf (stderr, "Get \"managementServiceIp\" error.\n");
        goto freeProperties;
    }

    /* Get management service port */
    ret = get_config_item ("MAIN", "managementServicePort", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"managementServicePort\" error.\n");
        goto freeProperties;
    }
    tmp->managementServicePort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"managementServicePort\" error.\n");
        goto freeProperties;
    }

    /* Get server ip */
    ret = get_config_item ("MAIN", "serverIp", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"serverIp\" error.\n");
        goto freeProperties;
    }
    tmp->serverIp = strdup (get_const_string_config_value (item, &error));
    if (tmp->serverIp == NULL) {
        fprintf (stderr, "Get \"serverIp\" error.\n");
        goto freeProperties;
    }

    /* Get agent register port */
    ret = get_config_item ("MAIN", "agentRegisterPort", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"agentRegisterPort\" error.\n");
        goto freeProperties;
    }
    tmp->agentRegisterPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"agentRegisterPort\" error.\n");
        goto freeProperties;
    }

    /* Get breakdown sink port */
    ret = get_config_item ("MAIN", "breakdownSinkPort", iniConfig, &item);
    if (ret || (item == NULL)) {
        fprintf (stderr, "Get_config_item \"breakdownSinkPort\" error.\n");
        goto freeProperties;
    }
    tmp->breakdownSinkPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"breakdownSinkPort\" error.\n");
        goto freeProperties;
    }

    /* Get log dir */
    ret = get_config_item ("LOG", "logDir", iniConfig, &item);
    if (ret || (item == NULL)) {
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
    if (ret || (item == NULL)) {
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
    if (ret || (item == NULL)) {
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
getPropertiesManagementServiceIp (void) {
    return propertiesInstance->managementServiceIp;
}

void
updatePropertiesManagementServiceIp (char *ip) {
    free (propertiesInstance->managementServiceIp);
    propertiesInstance->managementServiceIp = strdup (ip);
}

u_short
getPropertiesManagementServicePort (void) {
    return propertiesInstance->managementServicePort;
}

void
updatePropertiesManagementServicePort (u_short port) {
    propertiesInstance->managementServicePort = port;
}

char *
getPropertiesServerIp (void) {
    return propertiesInstance->serverIp;
}

void
updatePropertiesServerIp (char *ip) {
    free (propertiesInstance->serverIp);
    propertiesInstance->serverIp = strdup (ip);
}

u_short
getPropertiesAgentRegisterPort (void) {
    return propertiesInstance->agentRegisterPort;
}

void
updatePropertiesAgentRegisterPort (u_short port) {
    propertiesInstance->agentRegisterPort = port;
}

u_short
getPropertiesBreakdownSinkPort (void) {
    return propertiesInstance->breakdownSinkPort;
}

void
updatePropertiesBreakdownSinkPort (u_short port) {
    propertiesInstance->breakdownSinkPort = port;
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
    fprintf (stdout, "    mirrorInterface: %s\n", propertiesInstance->mirrorInterface);
    fprintf (stdout, "    pcapOfflineInput: %s\n", propertiesInstance->pcapOfflineInput);
    fprintf (stdout, "    managementServiceIp: %s\n", propertiesInstance->managementServiceIp);
    fprintf (stdout, "    managementServicePort: %u\n", propertiesInstance->managementServicePort);
    fprintf (stdout, "    serverIp: %s\n", propertiesInstance->serverIp);
    fprintf (stdout, "    agentRegisterPort: %u\n", propertiesInstance->agentRegisterPort);
    fprintf (stdout, "    breakdownSinkPort: %u\n", propertiesInstance->breakdownSinkPort);
    fprintf (stdout, "    logDir: %s\n", propertiesInstance->logDir);
    fprintf (stdout, "    logFileName: %s\n", propertiesInstance->logFileName);
    fprintf (stdout, "    logLevel: ");
    switch (propertiesInstance->logLevel) {
        case LOG_ERR_LEVEL:
            fprintf (stdout, "ERR\n");
            break;

        case LOG_WARNING_LEVEL:
            fprintf (stdout, "WARNING\n");
            break;

        case LOG_INFO_LEVEL:
            fprintf (stdout, "INFO\n");
            break;

        case LOG_DEBUG_LEVEL:
            fprintf (stdout, "DEBUG\n");
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
    free (propertiesInstance->mirrorInterface);
    propertiesInstance->mirrorInterface = NULL;
    free (propertiesInstance->pcapOfflineInput);
    propertiesInstance->pcapOfflineInput = NULL;
    free (propertiesInstance->managementServiceIp);
    propertiesInstance->managementServiceIp = NULL;
    free (propertiesInstance->serverIp);
    propertiesInstance->serverIp = NULL;
    free (propertiesInstance->logDir);
    propertiesInstance->logDir = NULL;
    free (propertiesInstance->logFileName);
    propertiesInstance->logFileName = NULL;
    freeProperties (propertiesInstance);
    propertiesInstance = NULL;
}
