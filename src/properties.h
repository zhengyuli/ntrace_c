#ifndef __AGENT_PROPERTIES_H__
#define __AGENT_PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;
    char *mirrorInterface;
    char *breakdownSinkIp;
    u_short breakdownSinkPort;
    u_int logLevel;
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
getPropertiesBreakdownSinkIp (void);
void
updatePropertiesBreakdownSinkIp (char *ip);
u_short
getPropertiesBreakdownSinkPort (void);
void
updatePropertiesBreakdownSinkPort (u_short port);
u_int
getPropertiesLogLevel (void);
void
updatePropertiesLogLevel (u_int logLevel);
int
initProperties (void);
void
destroyProperties (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_PROPERTIES_H__ */

