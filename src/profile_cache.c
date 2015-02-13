#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "util.h"
#include "config.h"
#include "log.h"
#include "profile_cache.h"

/* Get appServices from profile cache if exists */
json_t *
getAppServicesFromProfileCache (void) {
    json_t *profile, *appSvcs, *tmp;
    json_error_t error;

    profile = json_load_file (AGENT_PROFILE_CACHE, JSON_DISABLE_EOF_CHECK, &error);
    if (profile == NULL)
        return NULL;

    tmp = json_object_get (profile, PROFILE_APP_SERVICES);
    if (tmp == NULL) {
        json_object_clear (profile);
        return NULL;
    }
    appSvcs = json_deep_copy (tmp);

    json_object_clear (profile);
    return appSvcs;
}

/* Get appServices from profile */
json_t *
getAppServicesFromProfile (json_t *profile) {
    return json_object_get (profile, PROFILE_APP_SERVICES);
}

/* Get profile cache */
json_t *
getProfileCache (void) {
    json_error_t error;

    return json_load_file (AGENT_PROFILE_CACHE, JSON_DISABLE_EOF_CHECK, &error);
}

/*
 * @brief Sync profile to cache file.
 * 
 * @param profile profile to sync
 */
void
syncProfileCache (char *profile) {
    int fd;
    int ret;

    fd = open (AGENT_PROFILE_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_PROFILE_CACHE, strerror (errno));
        return;
    }

    ret = safeWrite (fd, profile, strlen (profile));
    if ((ret < 0) || (ret != strlen (profile)))
        LOGE ("Sync profile cache error: %s\n", strerror (errno));
    else
        LOGI ("Sync profile success:\n%s\n", profile);

    close (fd);
}
