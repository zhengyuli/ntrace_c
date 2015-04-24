#ifndef __APP_SERVICE_CACHE_H__
#define __APP_SERVICE_CACHE_H__

#include <jansson.h>

/*========================Interfaces definition============================*/
json_t *
getAppServicesFromCache (void);
int
syncAppServicesCache (json_t *profile);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_CACHE_H__ */
