#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <pthread.h>
#include "util.h"
#include "hash.h"
#include "logger.h"
#include "netdev.h"
#include "app_service_manager.h"

#define APP_SERVICES_CACHE_FILE "/tmp/appServices.cache"

/* Application service padding filter */
#define APP_SERVICE_PADDING_BPF_FILTER "icmp"
/* Application service ip fragment filter */
#define APP_SERVICE_IP_FRAGMENT_BPF_FILTER "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
/* Application service filter */
#define APP_SERVICE_BPF_FILTER "(ip host %s and (tcp port %u or %s)) or "
/* Application service filter length */
#define APP_SERVICE_BPF_FILTER_LENGTH 256

static pthread_rwlock_t appServiceHashTableMasterRWLock;
static hashTablePtr appServiceHashTableMaster = NULL;
static hashTablePtr appServiceHashTableSlave = NULL;

protoAnalyzerPtr
getAppServiceProtoAnalyzer (const char *key) {
    appServicePtr svc;
    protoAnalyzerPtr analyzer;

    if (key ==  NULL)
        return NULL;

    pthread_rwlock_rdlock (&appServiceHashTableMasterRWLock);
    svc = (appServicePtr) hashLookup (appServiceHashTableMaster, key);
    if (svc == NULL)
        analyzer = NULL;
    else
        analyzer = svc->analyzer;
    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);

    return analyzer;
}

static int
generateFilterFromEachAppService (void *data, void *args) {
    u_int len;
    appServicePtr svc = (appServicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    snprintf (filter + len, APP_SERVICE_BPF_FILTER_LENGTH, APP_SERVICE_BPF_FILTER,
              svc->ip, svc->port, APP_SERVICE_IP_FRAGMENT_BPF_FILTER);
    return 0;
}

char *
getAppServicesPaddingFilter (void) {
    char *filter;

    filter = strdup (APP_SERVICE_PADDING_BPF_FILTER);
    if (filter == NULL)
        LOGE ("Strdup filter error: %s.\n", strerror (errno));

    return filter;
}

char *
getAppServicesFilter (void) {
    int ret;
    u_int svcNum;
    char *filter;
    u_int filterLen;

    pthread_rwlock_rdlock (&appServiceHashTableMasterRWLock);
    svcNum = hashSize (appServiceHashTableMaster);
    filterLen = APP_SERVICE_BPF_FILTER_LENGTH * (svcNum + 1);
    filter = (char *) malloc (filterLen);
    if (filter == NULL) {
        LOGE ("Alloc filter buffer error: %s.\n", strerror (errno));
        pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
        return NULL;
    }
    memset (filter, 0, filterLen);

    ret = hashForEachItemDo (appServiceHashTableMaster, generateFilterFromEachAppService, filter);
    if (ret < 0) {
        LOGE ("Generate BPF filter from each application service error.\n");
        free (filter);
        pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
        return NULL;
    }
    strcat (filter, APP_SERVICE_PADDING_BPF_FILTER);

    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
    return filter;
}

static void
swapAppServiceMap (void) {
    hashTablePtr tmp;

    tmp = appServiceHashTableMaster;
    pthread_rwlock_wrlock (&appServiceHashTableMasterRWLock);
    appServiceHashTableMaster = appServiceHashTableSlave;
    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
    appServiceHashTableSlave = tmp;
}

static int
addAppServiceToSlave (appServicePtr svc) {
    int ret;
    char key [32];

    snprintf (key, sizeof (key), "%s:%d", svc->ip, svc->port);
    ret = hashInsert (appServiceHashTableSlave, key, svc, freeAppServiceForHash);
    if (ret < 0) {
        LOGE ("Insert new appService: %u error\n", svc->id);
        return -1;
    }

    return 0;
}

/*
 * @brief Extract application services from json.
 *
 * @param root application services in json
 * @param num variable used to return application service number
 *
 * @return application service poinarray if success, else return NULL
 */
static appServicePtr *
getAppServicesFromJson (json_t *root, u_int *num) {
    u_int i, n;
    json_t *tmp;
    appServicePtr svc, *appServices;

    appServices = (appServicePtr *) malloc (sizeof (appServicePtr) * json_array_size (root));
    if (appServices == NULL) {
        LOGE ("Malloc appServicePtr array error: %s\n", strerror (errno));
        *num = 0;
        return NULL;
    }

    for (i = 0; i < json_array_size (root); i++) {
        tmp = json_array_get (root, i);
        if (tmp == NULL) {
            LOGE ("Get json array item error.\n");
            goto error;
        }

        svc = json2AppService (tmp);
        if (svc == NULL) {
            LOGE ("Convert json to appService error.\n");
            goto error;
        }

        appServices [i] = svc;
    }
    *num = json_array_size (root);
    return appServices;

error:
    for (n = 0; n < i; n++)
        freeAppService (appServices [n]);
    free (appServices);
    appServices = NULL;
    *num = 0;
    return NULL;
}

static int
updateAppServicesFromJson (json_t *root) {
    int ret;
    u_int i, n;
    appServicePtr *appServices;
    u_int appServicesNum;

    /* Load appServices from json */
    appServices = getAppServicesFromJson (root, &appServicesNum);
    if (appServices == NULL) {
        LOGE ("Load application services from json error.\n");
        return -1;
    }

    /* Cleanup slave application service hash table */
    hashClean (appServiceHashTableSlave);
    /* Copy and insert application services to slave hash table */
    for (i = 0; i <  appServicesNum; i ++) {
        ret = addAppServiceToSlave (appServices [i]);
        if (ret < 0) {
            LOGE ("Add appService: %u error.\n", appServices [i]->id);
            ret = -1;
            goto freeAppServices;
        }
    }
    swapAppServiceMap ();
    ret = 0;

freeAppServices:
    for (n = i; n < appServicesNum; n++) {
        freeAppService (appServices [n]);
    }
    free (appServices);
    return ret;
}

static int
updateAppServicesFromCache (void) {
    int ret;
    char *out;
    json_t *root;
    json_error_t error;

    root = json_load_file (APP_SERVICES_CACHE_FILE, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL)
        return 0;

    ret = updateAppServicesFromJson (root);
    if (ret < 0) {
        json_object_clear (root);
        return -1;
    } else {
        out = json_dumps (root, JSON_INDENT (4));
        if (out)
            LOGD ("Load appServices cache success:\n%s\n", out);
        json_object_clear (root);
        return 0;
    }
}

static void
syncAppServicesCache (const char *cache) {
    int fd;
    int ret;

    fd = open (APP_SERVICES_CACHE_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", APP_SERVICES_CACHE_FILE, strerror (errno));
        return;
    }

    ret = safeWrite (fd, cache, strlen (cache));
    if ((ret < 0) || (ret != strlen (cache)))
        LOGE ("Sync appServices cache error: %s", strerror (errno));

    close (fd);
    return;
}

/* Update application service manager */
int
updateAppServiceManager (json_t *root) {
    int ret;
    char *out;

    ret = updateAppServicesFromJson (root);
    if (!ret && (out = json_dumps (root, JSON_INDENT (4)))) {
        syncAppServicesCache (out);
        LOGD ("Update appService manager success:\n%s\n", out);
        free (out);
    }

    return ret;
}

/* Init application service manager */
int
initAppServiceManager (void) {
    int ret;

    ret = pthread_rwlock_init (&appServiceHashTableMasterRWLock, NULL);
    if (ret) {
        LOGE ("Init appServiceHashTableMasterRWLock error.\n");
        return -1;
    }

    appServiceHashTableMaster = hashNew (0);
    if (appServiceHashTableMaster == NULL) {
        LOGE ("Create appServiceHashTableMaster error.\n");
        goto destroyAppServiceHashTableMasterRWLock;
    }

    appServiceHashTableSlave = hashNew (0);
    if (appServiceHashTableSlave == NULL) {
        LOGE ("Create appServiceHashTableSlave error.\n");
        goto destroyAppServiceHashTableMaster;
    }

    ret = updateAppServicesFromCache ();
    if (ret < 0) {
        LOGE ("Update appServices from cache error.\n");
        goto destroyAppServiceHashTableSlave;
    }

    return 0;

destroyAppServiceHashTableSlave:
    hashDestroy (appServiceHashTableSlave);
    appServiceHashTableSlave = NULL;
destroyAppServiceHashTableMaster:
    hashDestroy (appServiceHashTableMaster);
    appServiceHashTableMaster = NULL;
destroyAppServiceHashTableMasterRWLock:
    pthread_rwlock_destroy (&appServiceHashTableMasterRWLock);
    return -1;
}

/* Destroy application service manager */
void
destroyAppServiceManager (boolean exitNormally) {
    if (exitNormally)
        remove (APP_SERVICES_CACHE_FILE);
    pthread_rwlock_destroy (&appServiceHashTableMasterRWLock);
    hashDestroy (appServiceHashTableMaster);
    appServiceHashTableMaster = NULL;
    hashDestroy (appServiceHashTableSlave);
    appServiceHashTableSlave = NULL;
}
