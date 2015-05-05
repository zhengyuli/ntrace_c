#ifndef __PROPERTIES_H__
#define __PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;                 /**< Daemon mode */

    u_int schedPriority;                /**< Schedule priority */

    u_short managementServicePort;      /**< Management service port */

    char *interface;                    /**< Mirror interface */

    char *pcapFile;                     /**< Pcap offline file */
    u_int loopCount;                    /**< Pcap offline file loop read count */

    char *outputFile;                   /**< Session breakdown output file */

    u_int packetsToScan;                /**< Packetes to scan for each proto
                                             detection loop */
    u_int sleepIntervalAfterScan;       /**< Sleep interval after each proto
                                             detection loop */
    boolean autoAddService;             /**< Auto add detected service to sniff */

    char *miningEngineHost;             /**< Mining engine host ip */
    u_short sessionBreakdownRecvPort;   /**< session breakdown receive port of
                                             mining engine */

    char *logDir;                       /**< Log dir */
    char *logFileName;                  /**< Log file name */
    u_int logLevel;                     /**< Log level */
};

/*========================Interfaces definition============================*/
boolean
getPropertiesDaemonMode (void);
void
updatePropertiesDaemonMode (boolean daemonMode);
boolean
getPropertiesSchedRealtime (void);
u_int
getPropertiesSchedPriority (void);
void
updatePropertiesSchedPriority (u_int schedPriority);
u_short
getPropertiesManagementServicePort (void);
void
updatePropertiesManagementServicePort (u_short port);
boolean
getPropertiesSniffLive (void);
char *
getPropertiesInterface (void);
void
updatePropertiesInterface (char *interface);
char *
getPropertiesPcapFile (void);
void
updatePropertiesPcapFile (char *pcapFile);
u_int
getPropertiesLoopCount (void);
void
updatePropertiesLoopCount (u_int loopCount);
char *
getPropertiesOutputFile (void);
void
updatePropertiesOutputFile (char *outputFile);
u_int
getPropertiesPacketsToScan (void);
void
updatePropertiesPacketsToScan (u_int packetsToScan);
u_int
getPropertiesSleepIntervalAfterScan (void);
void
updatePropertiesSleepIntervalAfterScan (u_int sleepInterval);
boolean
getPropertiesAutoAddService (void);
void
updatePropertiesAutoAddService (boolean autoAddService);
char *
getPropertiesMiningEngineHost (void);
void
updatePropertiesMiningEngineHost (char *ip);
u_short
getPropertiesSessionBreakdownRecvPort (void);
void
updatePropertiesSessionBreakdownRecvPort (u_short port);
char *
getPropertiesLogDir (void);
void
updatePropertiesLogDir (char *logDir);
char *
getPropertiesLogFileName (void);
void
updatePropertiesLogFileName (char *logFileName);
u_int
getPropertiesLogLevel (void);
void
updatePropertiesLogLevel (u_int logLevel);
void
displayPropertiesDetail (void);
int
initProperties (char *configFile);
void
destroyProperties (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROPERTIES_H__ */
