#ifndef __APP_SERVICE_MANAGER_H__
#define __APP_SERVICE_MANAGER_H__

#include "proto_analyzer.h"

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getAppServiceProtoAnalyzer (const char *key);
char *
getAppServicesPaddingFilter (void);
char *
getAppServicesFilter (void);
int
updateAppServiceManager (json_t *root);
int
initAppServiceManager (void);
void
destroyAppServiceManager (boolean exitNormally);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_MANAGER_H__ */
