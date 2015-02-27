#ifndef __PROPERTIES_H__
#define __PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;                 /**< Daemon mode */

    char *mirrorInterface;              /**< Mirror interface */

    char *pcapOfflineInput;             /**< Pcap offline input file */

    char *breakdownSinkIp;              /**< Breakdown sink ip */
    u_short breakdownSinkPort;          /**< Breakdown sink port */

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
getPropertiesMirrorInterface (void);
void
updatePropertiesMirrorInterface (char *mirrorInterface);
char *
getPropertiesPcapOfflineInput (void);
void
updatePropertiesPcapOfflineInput (char *fname);
char *
getPropertiesBreakdownSinkIp (void);
void
updatePropertiesBreakdownSinkIp (char *ip);
u_short
getPropertiesBreakdownSinkPort (void);
void
updatePropertiesBreakdownSinkPort (u_short port);
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
