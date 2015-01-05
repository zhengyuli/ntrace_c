#ifndef __AGENT_VERSION_H__
#define __AGENT_VERSION_H__

#include "config.h"

/*========================Interfaces definition============================*/
int
getMajorVersion (void);
int
getMinorVersion (void);
int
getRevisionVersion (void);
char *
getVersionStr (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_VERSION_H__ */
