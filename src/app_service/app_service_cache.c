#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "util.h"
#include "config.h"
#include "log.h"
#include "app_service_cache.h"

/**
 * @brief Get appServices from cache file.
 *        Get appServices from cache file if cache file
 *        exists, it will load json data from cache file.
 *
 * @return appService json array if success, else NULL
 */
json_t *
getAppServicesFromCache (void) {
    json_t *appSvcs, *root;
    json_error_t error;

    root = json_load_file (AGENT_APP_SERVICES_CACHE,
                           JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL)
        return NULL;

    appSvcs = json_deep_copy (root);
    json_object_clear (root);
    return appSvcs;
}

/**
 * @brief Sync appServices to cache file.
 *        Sync appServices json data to cache file.
 *
 * @param appSvcs appServices json data
 *
 * @return 0 if success, else -1
 */
int
syncAppServicesCache (json_t *appSvcs) {
    int fd;
    char *appSvcsStr;
    int ret;

    appSvcsStr = json_dumps (appSvcs, JSON_INDENT (4) | JSON_PRESERVE_ORDER);
    if (appSvcsStr == NULL) {
        LOGE ("Json dump appServices string error.\n");
        return -1;
    }

    fd = open (AGENT_APP_SERVICES_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open appServices cache file %s error: %s\n",
              AGENT_APP_SERVICES_CACHE, strerror (errno));
        free (appSvcsStr);
        return -1;
    }

    ret = safeWrite (fd, appSvcsStr, strlen (appSvcsStr));
    if (ret < 0 || ret != strlen (appSvcsStr)) {
        LOGE ("Write to appServices cache file error.\n");
        close (fd);
        free (appSvcsStr);
        return -1;
    }

    LOGI ("Sync appServices cache success:\n%s\n", appSvcsStr);
    close (fd);
    free (appSvcsStr);
    return 0;
}
