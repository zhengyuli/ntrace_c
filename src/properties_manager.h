#ifndef __AGENT_PROPERTIES_H__
#define __AGENT_PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

/* Agent config context */
struct _properties {
    boolean daemonMode;                 /**< Daemon flag */
    char *mirrorInterface;              /**< Mirror interface */
    u_int logLevel;                     /**< Log level */
};

/*========================Interfaces definition============================*/
boolean
getPropertiesDaemonMode (void);
int
setPropertiesDaemonMode (boolean daemonMode);
char *
getPropertiesMirrorInterface (void);
int
setPropertiesMirrorInterface (char *mirrorInterface);
u_int
getPropertiesLogLevel (void);
int
setPropertiesLogLevel (u_int logLevel);
int
initPropertiesManager (void);
void
destroyPropertiesManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_PROPERTIES_H__ */

