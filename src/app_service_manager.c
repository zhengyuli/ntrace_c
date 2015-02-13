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
#include "config.h"
#include "util.h"
#include "hash.h"
#include "log.h"
#include "profile_cache.h"
#include "app_service.h"
#include "app_service_manager.h"

/* Application service padding filter */
#define APP_SERVICE_PADDING_BPF_FILTER "icmp"
/* Application service ip fragment filter */
#define APP_SERVICE_IP_FRAGMENT_BPF_FILTER "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
/* Application service filter */
#define APP_SERVICE_BPF_FILTER "(ip host %s and (tcp port %u or %s)) or "
/* Application service filter length */
#define APP_SERVICE_BPF_FILTER_LENGTH 256

/* Application services master hash table rwlock */
static pthread_rwlock_t appServiceHashTableMasterRWLock;
/* Application services master hash table */
static hashTablePtr appServiceHashTableMaster = NULL;
/* Application services slave hash table */
static hashTablePtr appServiceHashTableSlave = NULL;

protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *key) {
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

char *
getAppServicesPaddingFilter (void) {
    return strdup (APP_SERVICE_PADDING_BPF_FILTER);
}

static int
generateFilterForEachAppService (void *data, void *args) {
    u_int len;
    appServicePtr appSvc = (appServicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    snprintf (filter + len, APP_SERVICE_BPF_FILTER_LENGTH, APP_SERVICE_BPF_FILTER,
              appSvc->ip, appSvc->port, APP_SERVICE_IP_FRAGMENT_BPF_FILTER);
    return 0;
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

    ret = hashLoopDo (appServiceHashTableMaster, generateFilterForEachAppService, filter);
    if (ret < 0) {
        pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);
        LOGE ("Generate BPF filter for each application service error.\n");
        free (filter);
        return NULL;
    }

    pthread_rwlock_unlock (&appServiceHashTableMasterRWLock);

    strcat (filter, APP_SERVICE_PADDING_BPF_FILTER);
    return filter;
}

/*
 * @brief Get application services from json.
 *
 * @param root json object of application services
 * @param appSvcNum pointer to return application service number
 *
 * @return application service pointer array if success, else return NULL
 */
static appServicePtr *
getAppServicesFromJson (json_t *root, u_int *appSvcNum) {
    u_int i, n;
    json_t *tmp;
    appServicePtr svc, *appServices;

    appServices = (appServicePtr *) malloc (sizeof (appServicePtr) * json_array_size (root));
    if (appServices == NULL) {
        LOGE ("Malloc appServicePtr array error: %s\n", strerror (errno));
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

    snprintf (key, sizeof (key), "%s:%d", svc->ip, svc->port);
    ret = hashInsert (appServiceHashTableSlave, key, svc, freeAppServiceForHash);
    if (ret < 0) {
        LOGE ("Insert new appService: %u error\n", svc->id);
        return -1;
    }

    return 0;
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
updateAppServicesFromJson (json_t *root) {
    int ret;
    u_int i, n;
    appServicePtr *appServices;
    u_int appServicesNum;

    /* Get appServices from json */
    appServices = getAppServicesFromJson (root, &appServicesNum);
    if (appServices == NULL) {
        LOGE ("Get application services from json error.\n");
        return -1;
    }

    /* Cleanup slave application service hash table */
    hashClean (appServiceHashTableSlave);
    /* Insert application services to slave hash table */
    for (i = 0; i < appServicesNum; i ++) {
        ret = addAppServiceToSlave (appServices [i]);
        if (ret < 0) {
            LOGE ("Add appService: %u error.\n", appServices [i]->id);
            for (n = i + 1; n < appServicesNum; n++)
                freeAppService (appServices [n]);
            ret = -1;
            goto exit;
        }
    }
    swapAppServiceMap ();
    ret = 0;

exit:
    free (appServices);
    return ret;
}

static int
updateAppServicesFromProfileCache (void) {
    int ret;
    char *out;
    json_t *appSvcs;

    appSvcs = getAppServicesFromProfileCache ();
    if (appSvcs == NULL)
        return 0;
    
    ret = updateAppServicesFromJson (appSvcs);
    if (ret < 0) {
        json_object_clear (appSvcs);
        return -1;
    }

    out = json_dumps (appSvcs, JSON_INDENT (4));
    if (out) {
        LOGI ("Get appServices from profile cache success:\n%s\n", out);
        free (out);
    }

    json_object_clear (appSvcs);    
    return 0;
}

int
updateAppServiceManager (json_t *root) {
    return updateAppServicesFromJson (root);
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

    ret = updateAppServicesFromProfileCache ();
    if (ret < 0) {
        LOGE ("Update appServices from profile cache error.\n");
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
    pthread_rwlock_destroy (&appServiceHashTableMasterRWLock);
    hashDestroy (appServiceHashTableMaster);
    appServiceHashTableMaster = NULL;
    hashDestroy (appServiceHashTableSlave);
    appServiceHashTableSlave = NULL;
}
