#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <pthread.h>
#include "config.h"
#include "util.h"
#include "hash.h"
#include "log.h"
#include "properties.h"
#include "app_service.h"
#include "app_service_manager.h"

/* AppService padding filter */
#define APP_SERVICE_PADDING_BPF_FILTER "icmp"
/* AppService ip fragment filter */
#define APP_SERVICE_IP_FRAGMENT_BPF_FILTER                              \
    "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
/* AppService filter */
#define APP_SERVICE_BPF_FILTER "(ip host %s and (tcp port %u or %s)) or "
/* AppService filter length */
#define APP_SERVICE_BPF_FILTER_LENGTH 256

/* AppService master hash table rwlock */
static pthread_rwlock_t appServiceHashTableMasterRWLock;
/* AppService master hash table */
static hashTablePtr appServiceHashTableMaster = NULL;
/* AppService slave hash table */
static hashTablePtr appServiceHashTableSlave = NULL;

/* AppService detected hash table rwlock */
static pthread_rwlock_t appServiceDetectedHashTableRWLock;
/* AppService detected hash table */
static hashTablePtr appServiceDetectedHashTable = NULL;

/**
 * @brief Get appService proto analyzer.
 *        Get appService proto analyzer from appService map.
 *
 * @param ip -- service ip
 * @param port -- service port
 *
 * @return protoAnalyzerPtr if success, else NULL
 */
protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *ip, u_short port) {
    char key [32];
    appServicePtr svc;
    protoAnalyzerPtr analyzer;

    snprintf (key, sizeof (key), "%s:%u", ip, port);
    pthread_rwlock_rdlock (&appServiceHashTableMasterRWLock);
    svc = (appServicePtr) hashLookup (appServiceHashTableMaster, key);
    if (svc == NULL)
        analyzer = NULL;
    else
        analyzer = svc->analyzer;
    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);

    return analyzer;
}

/**
 * @brief Get appService detected.
 *        Get appService detected from appService detected map.
 *
 * @param ip -- service ip
 * @param port -- service port
 *
 * @return appService detected if success, else NULL
 */
appServicePtr
getAppServiceDetected (char *ip, u_short port) {
    char key [32];
    appServicePtr svc;

    snprintf (key, sizeof (key), "%s:%u", ip, port);
    pthread_rwlock_rdlock (&appServiceDetectedHashTableRWLock);
    svc = (appServicePtr) hashLookup (appServiceDetectedHashTable, key);
    pthread_rwlock_unlock (&appServiceDetectedHashTableRWLock);

    return svc;
}

/**
 * @brief Get appServices padding filter.
 *        Get appServices padding filter to pause packet sniff.
 *
 * @return padding filter
 */
char *
getAppServicesPaddingFilter (void) {
    return strdup (APP_SERVICE_PADDING_BPF_FILTER);
}

static int
getFilterForEachAppService (void *data, void *args) {
    u_int len;
    appServicePtr appSvc = (appServicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    snprintf (filter + len, APP_SERVICE_BPF_FILTER_LENGTH, APP_SERVICE_BPF_FILTER,
              appSvc->ip, appSvc->port, APP_SERVICE_IP_FRAGMENT_BPF_FILTER);
    return 0;
}

/**
 * @brief Get appServices filter.
 *        Get appServices filter from appService map, it will loop
 *        all appServices and generate filter from each.
 *
 * @return appServices filter if success, else NULL
 */
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

    ret = hashLoopDo (appServiceHashTableMaster, getFilterForEachAppService, filter);
    if (ret < 0) {
        pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
        LOGE ("Get BPF filter from each appService error.\n");
        free (filter);
        return NULL;
    }

    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);

    strcat (filter, APP_SERVICE_PADDING_BPF_FILTER);

    return filter;
}

static int
getJsonForEachAppService (void *data, void *args) {
    json_t *root = (json_t *) args;
    json_t *svc;

    svc = appService2Json ((appServicePtr) data);
    if (svc == NULL) {
        LOGE ("Get json from appService error.\n");
        return -1;
    }

    json_array_append_new (root, svc);
    return 0;
}

/**
 * @brief Get json from all appServices.
 *        Get json from appService map, it will loop all
 *        appServices and get json from each.
 *
 * @return json object if success, else NULL
 */
json_t *
getJsonFromAppServices (void) {
    int ret;
    json_t *root;

    root = json_array ();
    if (root == NULL) {
        LOGE ("Create json array object error.\n");
        return NULL;
    }

    pthread_rwlock_rdlock (&appServiceHashTableMasterRWLock);
    ret = hashLoopDo (appServiceHashTableMaster,
                      getJsonForEachAppService,
                      root);
    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);

    if (ret < 0) {
        LOGE ("Get appServices json from each appService error.\n");
        json_object_clear (root);
        return NULL;
    }

    return root;
}

/**
 * @brief Get json from all appServices detected.
 *        Get json from appService detected map, it will
 *        loop all appServices detected and get json from
 *        each.
 *
 * @return json object if success, else NULL
 */
json_t *
getJsonFromAppServicesDetected (void) {
    int ret;
    json_t *root;

    root = json_array ();
    if (root == NULL) {
        LOGE ("Create json array object error.\n");
        return NULL;
    }

    pthread_rwlock_rdlock (&appServiceDetectedHashTableRWLock);
    ret = hashLoopDo (appServiceDetectedHashTable,
                      getJsonForEachAppService,
                      root);
    pthread_rwlock_unlock (&appServiceDetectedHashTableRWLock);

    if (ret < 0) {
        LOGE ("Get appServices detected json from each appService detected error.\n");
        json_object_clear (root);
        return NULL;
    }

    return root;
}

/**
 * @brief Get appServices from json.
 *        Get appServices from json array, it will parse appServices
 *        json array and retrieve each json item, then convert it to
 *        appService.
 *
 * @param root -- json data
 * @param appSvcNum -- pointer to return appServices number
 *
 * @return appServices pointer array if success, else NULL
 */
static appServicePtr *
getAppServicesFromJson (json_t *root, u_int *appSvcNum) {
    u_int i, n;
    json_t *tmp;
    appServicePtr svc, *appServices;

    appServices = (appServicePtr *) malloc (sizeof (appServicePtr) * json_array_size (root));
    if (appServices == NULL) {
        LOGE ("Alloc appServicePtr array error: %s\n", strerror (errno));
        *appSvcNum = 0;
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
    *appSvcNum = json_array_size (root);
    return appServices;

error:
    for (n = 0; n < i; n++)
        freeAppService (appServices [n]);
    free (appServices);
    appServices = NULL;
    *appSvcNum = 0;
    return NULL;
}

static int
addAppServiceToSlave (appServicePtr svc) {
    int ret;
    char key [32];

    snprintf (key, sizeof (key), "%s:%u", svc->ip, svc->port);
    ret = hashInsert (appServiceHashTableSlave, key, svc, freeAppServiceForHash);
    if (ret < 0) {
        LOGE ("Insert appService %s to slave appService map error\n", key);
        return -1;
    }

    return 0;
}

static void
removeAppServiceFromSlave (char *ip, u_short port) {
    char key [32];

    snprintf (key, sizeof (key), "%s:%u", ip, port);
    hashRemove (appServiceHashTableSlave, key);
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

/**
 * @brief Update appService map from json.
 *        Update appService map from appServices retrieved from
 *        json.
 *
 * @param root -- json data
 *
 * @return 0 if success, else -1
 */
static int
updateAppServicesFromJson (json_t *root) {
    int ret;
    u_int i, n;
    appServicePtr svc;
    appServicePtr *appServices;
    appServicePtr *appServicesCopy;
    u_int appServicesNum;

    /* Get appServices from json */
    appServices = getAppServicesFromJson (root, &appServicesNum);
    if (appServices == NULL) {
        LOGE ("Get appServices from json error.\n");
        return -1;
    }

    /* Alloc appServices array copy */
    appServicesCopy = (appServicePtr *) malloc (sizeof (appServicePtr *) * appServicesNum);
    if (appServicesCopy == NULL) {
        LOGE ("Alloc appServicePtr array copy error: %s\n", strerror (errno));

        for (i = 0; i < appServicesNum; i++)
            freeAppService (appServices [i]);
        free (appServices);

        return -1;
    }

    /* Copy appServices to appServicesCopy */
    for (i = 0; i < appServicesNum; i++) {
        svc = copyAppService (appServices [i]);
        if (svc == NULL) {
            LOGE ("Copy appService error.\n");

            for (n = 0; n < appServicesNum; n++)
                freeAppService (appServices [n]);
            free (appServices);

            for (n = 0; n < i; n++)
                freeAppService (appServicesCopy [n]);
            free (appServicesCopy);

            return -1;
        }

        appServicesCopy [i] = svc;
    }

    /* Cleanup slave application service hash table */
    hashClean (appServiceHashTableSlave);
    /* Insert appServices to slave hash table */
    for (i = 0; i < appServicesNum; i++) {
        ret = addAppServiceToSlave (appServices [i]);
        if (ret < 0) {
            for (n = i + 1; n < appServicesNum; n++)
                freeAppService (appServices [n]);
            free (appServices);

            for (n = 0; n < appServicesNum; n++)
                freeAppService (appServicesCopy [n]);
            free (appServicesCopy);

            return -1;
        }
    }

    /* Swap appService map */
    swapAppServiceMap ();

    /* Cleanup slave application service hash table */
    hashClean (appServiceHashTableSlave);
    /* Insert appServices copy to slave hash table */
    for (i = 0; i < appServicesNum; i++) {
        ret = addAppServiceToSlave (appServicesCopy [i]);
        if (ret < 0) {
            for (n = i + 1; n < appServicesNum; n++)
                freeAppService (appServicesCopy [n]);
            free (appServicesCopy);
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Update appService map from cache.
 *        Update appService map from cache file, it will load
 *        appServices from cache file and then update appService
 *        map.
 *
 * @return 0 if success, else -1
 */
static int
updateAppServicesFromCache (void) {
    int ret;
    char *out;
    json_t *appSvcs;
    json_error_t error;

    appSvcs = json_load_file (NTRACE_APP_SERVICES_CACHE,
                              JSON_DISABLE_EOF_CHECK, &error);
    if (appSvcs == NULL)
        return 0;

    ret = updateAppServicesFromJson (appSvcs);
    if (ret < 0) {
        remove (NTRACE_APP_SERVICES_CACHE);
        json_object_clear (appSvcs);
        return -1;
    }

    out = json_dumps (appSvcs, JSON_INDENT (4) | JSON_PRESERVE_ORDER);
    if (out) {
        LOGD ("Update appServices from cache success:\n%s\n", out);
        free (out);
    }

    json_object_clear (appSvcs);
    return 0;
}

/**
 * @brief Sync appServices to cache file.
 *
 * @return 0 if success, else -1
 */
static void
syncAppServicesCache (void) {
    int ret;
    int fd;
    json_t *appSvcs;
    char *appSvcsStr;

    /* Get json from appServices */
    appSvcs = getJsonFromAppServices ();
    if (appSvcs == NULL) {
        LOGE ("Get json from appServices error.\n");
        return;
    }

    appSvcsStr = json_dumps (appSvcs, JSON_INDENT (4) | JSON_PRESERVE_ORDER);
    if (appSvcsStr == NULL) {
        LOGE ("Json dump appServices string error.\n");
        json_object_clear (appSvcs);
        return;
    }

    fd = open (NTRACE_APP_SERVICES_CACHE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open appServices cache file %s error: %s\n",
              NTRACE_APP_SERVICES_CACHE, strerror (errno));
        free (appSvcsStr);
        json_object_clear (appSvcs);
        return;
    }

    ret = safeWrite (fd, appSvcsStr, strlen (appSvcsStr));
    if (ret < 0 || ret != strlen (appSvcsStr))
        LOGE ("Dump to appServices cache file error.\n");
    else
        LOGD ("Sync appServices cache success:\n%s\n", appSvcsStr);

    close (fd);
    free (appSvcsStr);
    json_object_clear (appSvcs);
}

int
updateAppServices (json_t * appServices) {
    int ret;

    if (getPropertiesAutoAddService ()) {
        LOGE ("Can't update appServices for autoAddService mode.\n");
        return -1;
    }

    ret = updateAppServicesFromJson (appServices);
    if (ret < 0) {
        LOGE ("Update appServices error.\n");
        return -1;
    }

    /* Sync appServices cache */
    syncAppServicesCache ();

    return 0;
}

/**
 * @brief Add appService detected to appService detected map.
 *
 * @param ip -- appService detected ip
 * @param port -- appService detected port
 * @param proto -- appService detected proto name
 *
 * @return 0 if success, else -1
 */
int
addAppServiceDetected (char *ip, u_short port, char *proto) {
    int ret;
    appServicePtr svc, svcCopy;
    char key [32];

    /* Add to appService detected map */
    svc = newAppService (ip, port, proto);
    if (svc == NULL) {
        LOGE ("Create detected appService %s:%u proto: %s error\n",
              ip, port, proto);
        return -1;
    }
    snprintf (key, sizeof (key), "%s:%u", ip, port);
    pthread_rwlock_wrlock (&appServiceDetectedHashTableRWLock);
    ret = hashInsert (appServiceDetectedHashTable, key, svc,
                      freeAppServiceForHash);
    pthread_rwlock_unlock (&appServiceDetectedHashTableRWLock);
    if (ret < 0) {
        LOGE ("Insert detected appService: %s proto: %s error\n", key, proto);
        return -1;
    }

    if (getPropertiesAutoAddService ()) {
        pthread_rwlock_rdlock (&appServiceHashTableMasterRWLock);
        svc = (appServicePtr) hashLookup (appServiceHashTableMaster, key);
        pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
        if (svc)
            return 0;

        /* Create new appService */
        svc = newAppService (ip, port, proto);
        if (svc == NULL) {
            LOGE ("Create appService %s:%u proto: %s error\n", ip, port, proto);
            return -1;
        }

        /* Create new appService copy */
        svcCopy = copyAppService (svc);
        if (svcCopy == NULL) {
            LOGE ("Create appService copy %s:%u proto: %s error\n", ip, port, proto);
            freeAppService (svc);
            return -1;
        }

        /* Add appService to slave service map */
        ret = addAppServiceToSlave (svc);
        if (ret < 0) {
            LOGE ("Add appService %s:%u proto: %s to slave service map error.\n",
                  ip, port, proto);
            freeAppService (svcCopy);
            return -1;
        }

        /* Swap service map table */
        swapAppServiceMap ();

        /* Add appService to slave service map */
        ret = addAppServiceToSlave (svcCopy);
        if (ret < 0) {
            swapAppServiceMap ();
            removeAppServiceFromSlave (ip, port);
            return -1;
        }

        /* Sync appServices cache */
        syncAppServicesCache ();
    }

    return 0;
}

/* Init appService manager */
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

    ret = pthread_rwlock_init (&appServiceDetectedHashTableRWLock, NULL);
    if (ret) {
        LOGE ("Init appServiceDetectedHashTableRWLock error.\n");
        goto destroyAppServiceHashTableSlave;
    }

    appServiceDetectedHashTable = hashNew (0);
    if (appServiceDetectedHashTable == NULL) {
        LOGE ("Create appServiceDetectedHashTable error.\n");
        goto destroyAppServiceDetectedHashTableRWLock;
    }

    ret = updateAppServicesFromCache ();
    if (ret < 0) {
        LOGE ("Update appServices from cache error.\n");
        goto destroyAppServiceDetectedHashTable;
    }

    return 0;

destroyAppServiceDetectedHashTable:
    hashDestroy (appServiceDetectedHashTable);
    appServiceDetectedHashTable = NULL;
destroyAppServiceDetectedHashTableRWLock:
    pthread_rwlock_destroy (&appServiceDetectedHashTableRWLock);
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

/* Destroy appService manager */
void
destroyAppServiceManager (void) {
    /* Destroy appService map */
    pthread_rwlock_destroy (&appServiceHashTableMasterRWLock);
    hashDestroy (appServiceHashTableMaster);
    appServiceHashTableMaster = NULL;
    hashDestroy (appServiceHashTableSlave);
    appServiceHashTableSlave = NULL;

    /* Destroy appService detected map */
    pthread_rwlock_destroy (&appServiceDetectedHashTableRWLock);
    hashDestroy (appServiceDetectedHashTable);
    appServiceDetectedHashTable = NULL;

    /* Clean appServices cache */
    remove (NTRACE_APP_SERVICES_CACHE);
}
