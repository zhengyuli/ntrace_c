#ifndef __APP_SERVICE_MANAGER_H__
#define __APP_SERVICE_MANAGER_H__

#include "proto_analyzer.h"

#define PROFILE_APP_SERVICES "application_services"

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *key);
char *
getAppServicesPaddingFilter (void);
char *
getAppServicesFilter (void);
int
updateAppServiceManager (json_t *root);
int
initAppServiceManager (void);
void
destroyAppServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_MANAGER_H__ */
