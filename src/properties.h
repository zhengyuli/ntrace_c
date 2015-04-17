#ifndef __PROPERTIES_H__
#define __PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;                 /**< Daemon mode */

    char *managementControlHost;        /**< Management control host ip */
    u_short managementControlPort;      /**< Management control port */

    char *interface;                    /**< Mirror interface */

    char *pcapFile;                     /**< Pcap file */
    u_int loopCount;                    /**< Pcap file loop read count */

    char *miningEngineHost;             /**< Mining engine host ip */
    u_short managementRegisterPort;     /**< Management register port of mining engine */
    u_short breakdownRecvPort;          /**< Breakdown receive port of mining engine */

    char *logDir;                       /**< Log dir */
    char *logFileName;                  /**< Log file name */
    u_int logLevel;                     /**< Log level */
};

/*========================Interfaces definition============================*/
boolean
getPropertiesDaemonMode (void);
void
updatePropertiesDaemonMode (boolean daemonMode);
char *
getPropertiesManagementControlHost (void);
void
updatePropertiesManagementControlHost (char *ip);
u_short
getPropertiesManagementControlPort (void);
void
updatePropertiesManagementControlPort (u_short port);
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
char *
getPropertiesMiningEngineHost (void);
void
updatePropertiesMiningEngineHost (char *ip);
u_short
getPropertiesManagementRegisterPort (void);
void
updatePropertiesManagementRegisterPort (u_short port);
u_short
getPropertiesBreakdownRecvPort (void);
void
updatePropertiesBreakdownRecvPort (u_short port);
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
