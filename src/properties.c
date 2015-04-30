#include <stdlib.h>
#include <sched.h>
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

    tmp->daemonMode = False;
    tmp->schedRealtime = False;
    tmp->schedPriority = 0;
    tmp->managementServicePort = 0;
    tmp->interface = NULL;
    tmp->pcapFile = NULL;
    tmp->loopCount = 0;
    tmp->setFilter = False;
    tmp->outputFile = NULL;
    tmp->packetsToScan = 0;
    tmp->sleepIntervalAfterScan = 0;
    tmp->miningEngineHost = NULL;
    tmp->sessionBreakdownRecvPort = 0;
    tmp->logDir = NULL;
    tmp->logFileName = NULL;
    tmp->logLevel = LOG_ERR_LEVEL;
    return tmp;
}

static void
freeProperties (propertiesPtr instance) {
    if (instance == NULL)
        return;

    free (instance->interface);
    instance->interface = NULL;
    free (instance->pcapFile);
    instance->pcapFile = NULL;
    free (instance->outputFile);
    instance->outputFile = NULL;
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
    int minPriority;
    int maxPriority;
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
    ret = get_config_item ("Basic", "daemonMode", iniConfig, &item);
    if (ret && item == NULL) {
        fprintf (stderr, "Get_config_item \"daemonMode\" error.\n");
        goto freeProperties;
    }
    ret = get_bool_config_value (item, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"daemonMode\" error.\n");
        goto freeProperties;
    }
    if (ret)
        tmp->daemonMode = True;
    else
        tmp->daemonMode = False;

    /* Get schedule priority */
    ret = get_config_item ("SchedulePolicy", "schedPriority", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"schedPriority\" error.\n");
        goto freeProperties;
    }
    tmp->schedPriority = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"schedPriority\" error.\n");
        goto freeProperties;
    }

    minPriority = sched_get_priority_min (SCHED_RR);
    maxPriority = sched_get_priority_max (SCHED_RR);

    if (tmp->schedPriority >= minPriority &&
        tmp->schedPriority <= maxPriority)
        tmp->schedRealtime = True;
    else {
        tmp->schedRealtime = False;
        tmp->schedPriority = 0;
    }

    /* Get management control port */
    ret = get_config_item ("ManagementService", "managementServicePort", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"managementServicePort\" error.\n");
        goto freeProperties;
    }
    tmp->managementServicePort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"managementServicePort\" error.\n");
        goto freeProperties;
    }

    /* Get interface */
    ret = get_config_item ("Input", "interface", iniConfig, &item);
    if (!ret && item) {
        tmp->interface = strdup (get_const_string_config_value (item, &error));
        if (tmp->interface == NULL) {
            fprintf (stderr, "Get \"interface\" error.\n");
            goto freeProperties;
        }
    }

    /* Get pcap file */
    ret = get_config_item ("Input", "pcapFile", iniConfig, &item);
    if (!ret && item) {
        tmp->pcapFile = strdup (get_const_string_config_value (item, &error));
        if (tmp->pcapFile == NULL) {
            fprintf (stderr, "Get \"pcapFile\" error.\n");
            goto freeProperties;
        }
    }

    /* Get loop count */
    ret = get_config_item ("Input", "loopCount", iniConfig, &item);
    if (!ret && item) {
        tmp->loopCount = get_int_config_value (item, 1, 0, &error);
        if (error) {
            fprintf (stderr, "Get \"loopCount\" error.\n");
            goto freeProperties;
        }
    }

    /* Get set filter flag */
    ret = get_config_item ("Input", "setFilter", iniConfig, &item);
    if (!ret && item) {
        ret = get_bool_config_value (item, 0, &error);
        if (error) {
            fprintf (stderr, "Get \"setFilter\" error.\n");
            goto freeProperties;
        }
        if (ret)
            tmp->setFilter = True;
        else
            tmp->setFilter = False;
    }

    /* Get output file */
    ret = get_config_item ("Output", "outputFile", iniConfig, &item);
    if (!ret && item) {
        tmp->outputFile = strdup (get_const_string_config_value (item, &error));
        if (tmp->outputFile == NULL) {
            fprintf (stderr, "Get \"outputFile\" error.\n");
            goto freeProperties;
        }
    }

    /* Get packets to scan for proto detect */
    ret = get_config_item ("ProtoDetect", "packetsToScan", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"packetsToScan\" error.\n");
        goto freeProperties;
    }
    tmp->packetsToScan = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"packetsToScan\" error.\n");
        goto freeProperties;
    }

    /* Get sleep interval after scan for proto detect */
    ret = get_config_item ("ProtoDetect", "sleepIntervalAfterScan", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"sleepIntervalAfterScan\" error.\n");
        goto freeProperties;
    }
    tmp->sleepIntervalAfterScan = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"sleepIntervalAfterScan\" error.\n");
        goto freeProperties;
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

    /* Get breakdown receive port */
    ret = get_config_item ("MiningEngine", "sessionBreakdownRecvPort", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"sessionBreakdownRecvPort\" error.\n");
        goto freeProperties;
    }
    tmp->sessionBreakdownRecvPort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get \"sessionBreakdownRecvPort\" error.\n");
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
        fprintf (stderr, "Get \"logLevel\" error.\n");
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

boolean
getPropertiesSchedRealtime (void) {
    return propertiesInstance->schedRealtime;
}

void
updatePropertiesDaemonMode (boolean daemonMode) {
    propertiesInstance->daemonMode = daemonMode;
}

u_int
getPropertiesSchedPriority (void) {
    return propertiesInstance->schedPriority;
}

void
updatePropertiesSchedPriority (u_int schedPriority) {
    int minPriority;
    int maxPriority;

    minPriority = sched_get_priority_min (SCHED_RR);
    maxPriority = sched_get_priority_max (SCHED_RR);

    if (schedPriority >= minPriority &&
        schedPriority <= maxPriority) {
        propertiesInstance->schedRealtime = True;
        propertiesInstance->schedPriority = schedPriority;
    } else {
        propertiesInstance->schedRealtime = False;
        propertiesInstance->schedPriority = 0;
    }
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
getPropertiesInterface (void) {
    return propertiesInstance->interface;
}

void
updatePropertiesInterface (char *interface) {
    free (propertiesInstance->interface);
    propertiesInstance->interface = strdup (interface);
}

char *
getPropertiesPcapFile (void) {
    return propertiesInstance->pcapFile;
}

void
updatePropertiesPcapFile (char *fname) {
    free (propertiesInstance->pcapFile);
    propertiesInstance->pcapFile = strdup (fname);
}

u_int
getPropertiesLoopCount (void) {
    return propertiesInstance->loopCount;
}

void
updatePropertiesLoopCount (u_int loopCount) {
    propertiesInstance->loopCount = loopCount;
}

boolean
getPropertiesSetFilter (void) {
    return propertiesInstance->setFilter;
}

void
updatePropertiesSetFilter (boolean setFilter) {
    propertiesInstance->setFilter = setFilter;
}

char *
getPropertiesOutputFile (void) {
    return propertiesInstance->outputFile;
}

void
updatePropertiesOutputFile (char *fname) {
    free (propertiesInstance->outputFile);
    propertiesInstance->outputFile = strdup (fname);
}

u_int
getPropertiesPacketsToScan (void) {
    return propertiesInstance->packetsToScan;
}

void
updatePropertiesPacketsToScan (u_int pktsNum) {
    propertiesInstance->packetsToScan = pktsNum;
}

u_int
getPropertiesSleepIntervalAfterScan (void) {
    return propertiesInstance->sleepIntervalAfterScan;
}

void
updatePropertiesSleepIntervalAfterScan (u_int sleepInterval) {
    propertiesInstance->sleepIntervalAfterScan = sleepInterval;
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
getPropertiesSessionBreakdownRecvPort (void) {
    return propertiesInstance->sessionBreakdownRecvPort;
}

void
updatePropertiesSessionBreakdownRecvPort (u_short port) {
    propertiesInstance->sessionBreakdownRecvPort = port;
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
    LOGI ("Startup with properties:{\n");
    LOGI ("    daemonMode: %s\n", propertiesInstance->daemonMode ? "True" : "False");
    LOGI ("    ScheduleRealtime: %s\n", propertiesInstance->schedRealtime ? "True" : "False");
    LOGI ("    SchedulePriority: %u\n", propertiesInstance->schedPriority);
    LOGI ("    managementServicePort: %u\n", propertiesInstance->managementServicePort);
    LOGI ("    interface: %s\n", propertiesInstance->interface);
    LOGI ("    pcapFile: %s\n", propertiesInstance->pcapFile);
    LOGI ("    loopCount: %u\n", propertiesInstance->loopCount);
    LOGI ("    setFilter: %s\n", propertiesInstance->setFilter ? "True" : "False");
    LOGI ("    outputFile: %s\n", propertiesInstance->outputFile);
    LOGI ("    packetsToScan: %u\n", propertiesInstance->packetsToScan);
    LOGI ("    sleepIntervalAfterScan: %u\n", propertiesInstance->sleepIntervalAfterScan);
    LOGI ("    miningEngineHost: %s\n", propertiesInstance->miningEngineHost);
    LOGI ("    sessionBreakdownRecvPort: %u\n", propertiesInstance->sessionBreakdownRecvPort);
    LOGI ("    logDir: %s\n", propertiesInstance->logDir);
    LOGI ("    logFileName: %s\n", propertiesInstance->logFileName);
    LOGI ("    logLevel: ");
    switch (propertiesInstance->logLevel) {
        case LOG_ERR_LEVEL:
            LOGI ("ERROR\n");
            break;

        case LOG_WARN_LEVEL:
            LOGI ("WARNING\n");
            break;

        case LOG_INFO_LEVEL:
            LOGI ("INFO\n");
            break;

        case LOG_DEBUG_LEVEL:
            LOGI ("DEBUG\n");
            break;

        case LOG_TRACE_LEVEL:
            LOGI ("TRACE\n");
            break;

        default:
            LOGI ("Unknown\n");
    }
    LOGI ("}\n");
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
    freeProperties (propertiesInstance);
    propertiesInstance = NULL;
}
