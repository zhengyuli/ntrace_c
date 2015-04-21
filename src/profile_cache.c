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
        remove (AGENT_PROFILE_CACHE);
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

/**
 * @brief Sync profile to cache file.
 *
 * @param profile profile to sync
 *
 * @return 0 if success else -1
 */
int
syncProfileCache (json_t *profile) {
    int fd;
    char *profileStr;
    int ret;

    profileStr = json_dumps (profile, JSON_INDENT (4) | JSON_PRESERVE_ORDER);
    if (profileStr == NULL) {
        LOGE ("Json dump profile error.\n");
        return -1;
    }

    fd = open (AGENT_PROFILE_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_PROFILE_CACHE, strerror (errno));
        free (profileStr);
        return -1;
    }

    ret = safeWrite (fd, profileStr, strlen (profileStr));
    if (ret < 0 || ret != strlen (profileStr)) {
        LOGE ("Write to profile cache error.\n");
        close (fd);
        free (profileStr);
        return -1;
    }

    LOGI ("Sync profile cache success:\n%s\n", profileStr);
    close (fd);
    free (profileStr);
    return 0;
}
