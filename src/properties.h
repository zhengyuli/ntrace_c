#ifndef __PROPERTIES_H__
#define __PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;                 /**< Daemon mode */

    boolean schedRealtime;              /**< Realtime schedule flag */
    u_int schedPriority;                /**< Realtime schedule priority */

    u_short managementServicePort;      /**< Management control port */

    char *interface;                    /**< Mirror interface */

    char *pcapFile;                     /**< Pcap file */
    u_int loopCount;                    /**< Pcap file loop read count */

    boolean setFilter;                  /**< BPF filter setting flag */

    char *outputFile;                   /**< Output file */

    u_int packetsToScan;                /**< Proto packetes to scan for each
                                             proto detection loop */
    u_int sleepIntervalAfterScan;       /**< Sleep interval after each proto
                                             detection loop */

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
char *
getPropertiesInterface (void);
void
updatePropertiesInterface (char *interface);
char *
getPropertiesPcapFile (void);
void
updatePropertiesPcapFile (char *fname);
u_int
getPropertiesLoopCount (void);
void
updatePropertiesLoopCount (u_int loopCount);
boolean
getPropertiesSetFilter (void);
void
updatePropertiesSetFilter (boolean setFilter);
char *
getPropertiesOutputFile (void);
u_int
getPropertiesPacketsToScan (void);
void
updatePropertiesPacketsToScan (u_int pktsNum);
u_int
getPropertiesSleepIntervalAfterScan (void);
void
updatePropertiesSleepIntervalAfterScan (u_int sleepInterval);
void
updatePropertiesOutputFile (char *fname);
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
updatePropertiesLogDir (char *path);
char *
getPropertiesLogFileName (void);
void
updatePropertiesLogFileName (char *fileName);
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
