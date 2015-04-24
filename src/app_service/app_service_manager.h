#ifndef __APP_SERVICE_MANAGER_H__
#define __APP_SERVICE_MANAGER_H__

#include "proto_analyzer.h"

#define PROFILE_APP_SERVICES "application_services"

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *key);
boolean
appServiceIsDetected (struct in_addr *ip, u_short port);
int
addAppServiceDetected (char *proto, struct in_addr *ip, u_short port);
char *
getAppServicesPaddingFilter (void);
char *
getAppServicesFilter (void);
int
updateAppServiceManager (json_t *updateProfile);
int
initAppServiceManager (void);
void
destroyAppServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_MANAGER_H__ */
