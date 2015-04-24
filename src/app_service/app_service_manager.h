#ifndef __APP_SERVICE_MANAGER_H__
#define __APP_SERVICE_MANAGER_H__

#include "proto_analyzer.h"

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *key);
char *
getAppServicesPaddingFilter (void);
char *
getAppServicesFilter (void);
int
addAppService (char *proto, char *ip, u_short port);
int
initAppServiceManager (void);
void
destroyAppServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_MANAGER_H__ */
