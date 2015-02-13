#ifndef __PROFILE_CACHE_H__
#define __PROFILE_CACHE_H__

#include <jansson.h>

/* Profile json key definitions */
#define PROFILE_APP_SERVICES "application_services"

/*========================Interfaces definition============================*/
json_t *
getAppServicesFromProfileCache (void);
json_t *
getAppServicesFromProfile (json_t *profile);
json_t *
getProfileCache (void);
void
syncProfileCache (char *profile);
/*=======================Interfaces definition end=========================*/

#endif /* __PROFILE_CACHE_H__ */
