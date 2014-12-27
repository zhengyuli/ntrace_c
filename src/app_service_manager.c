#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <pthread.h>
#include "util.h"
#include "logger.h"
#include "hash.h"
#include "runtime_context.h"
#include "app_service_manager.h"

/* Application service BPF ip fragment filter */
#define BPF_IP_FRAGMENT_FILTER "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
/* Application service BPF filter */
#define APP_SERVICE_BPF_FILTER "(ip host %s and (tcp port %u or %s)) or "
/* Application service BPF filter length */
#define APP_SERVICE_BPF_FILTER_LENGTH 256

/* Application service local hash tables */
static hashTablePtr appServiceHashTableMaster = NULL;
static hashTablePtr appServiceHashTableSlave = NULL;
static pthread_rwlock_t appServiceHashTableMasterLock = PTHREAD_RWLOCK_INITIALIZER;

protoType
lookupAppServiceProtoType (const char *key) {
    int proto;
    appServicePtr svc;

    if (key ==  NULL)
        return PROTO_UNKNOWN;

    pthread_rwlock_rdlock (&appServiceHashTableMasterLock);
    svc = (appServicePtr) hashLookup (appServiceHashTableMaster, key);
    if (svc == NULL)
        proto = PROTO_UNKNOWN;
    else
        proto = svc->proto;
    pthread_rwlock_unlock (&appServiceHashTableMasterLock);

    return proto;
}

static int
generateFilterFromEachAppService (void *data, void *args) {
    u_int len;
    appServicePtr svc = (appServicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    snprintf (filter + len, APP_SERVICE_BPF_FILTER_LENGTH, APP_SERVICE_BPF_FILTER, svc->ip, svc->port, BPF_IP_FRAGMENT_FILTER);
    return 0;
}

char *
getAppServicesFilter (void) {
    int ret;
    u_int svcNum;
    char *filter;
    u_int filterLen;

    pthread_rwlock_rdlock (&appServiceHashTableMasterLock);
    svcNum = hashSize (appServiceHashTableMaster);
    filterLen = APP_SERVICE_BPF_FILTER_LENGTH * (svcNum + 1);
    filter = (char *) malloc (filterLen);
    if (filter == NULL) {
        LOGE ("Alloc filter buffer error: %s.\n", strerror (errno));
        pthread_rwlock_unlock (&appServiceHashTableMasterLock);
        return NULL;
    }
    memset(filter, 0, filterLen);

    ret = hashForEachItemDo (appServiceHashTableMaster, generateFilterFromEachAppService, filter);
    if (ret < 0) {
        LOGE ("Generate BPF filter from each application service error.\n");
        free (filter);
        pthread_rwlock_unlock (&appServiceHashTableMasterLock);
        return NULL;
    }

    strcat (filter, "icmp");
    pthread_rwlock_unlock (&appServiceHashTableMasterLock);
    return filter;
}

static void
swapAppServiceMap (void) {
    hashTablePtr tmp;

    tmp = appServiceHashTableMaster;
    pthread_rwlock_wrlock (&appServiceHashTableMasterLock);
    appServiceHashTableMaster = appServiceHashTableSlave;
    pthread_rwlock_unlock (&appServiceHashTableMasterLock);
    appServiceHashTableSlave = tmp;
}

static int
addAppService (appServicePtr svc) {
    int ret;
    char key [32] = {0};

    snprintf (key, sizeof (key) - 1, "%s:%d", svc->ip, svc->port);
    ret = hashInsert (appServiceHashTableSlave, key, svc, freeAppServiceForHash);
    if (ret < 0) {
        LOGE ("Insert new appService: %u error\n", svc->id);
        return -1;
    }

    return 0;
}

/* Update application service manager from runtime context */
int
updateAppServiceManager (void) {
    int ret;
    u_int i, appServicesCount;
    appServicePtr tmp, svc, *appServiceArray;

    /* Cleanup slave application service hash table */
    hashClean (appServiceHashTableSlave);

    appServiceArray = getRuntimeContextAppServices ();
    appServicesCount = getRuntimeContextAppServicesCount ();
    for (i = 0; i <  appServicesCount; i ++) {
        tmp = appServiceArray [i];
        svc = copyAppService (tmp);
        if (svc == NULL) {
            LOGE ("Copy appService error.\n");
            return -1;
        }

        ret = addAppService (svc);
        if (ret < 0) {
            LOGE ("Add appService error.\n");
            return -1;
        }
    }
    swapAppServiceMap ();

    return 0;
}

void
cleanAppServiceManager (void) {
    hashClean (appServiceHashTableSlave);
    swapAppServiceMap ();
    hashClean (appServiceHashTableSlave);
}

int
initAppServiceManager (void) {
    int ret;

    appServiceHashTableMaster = hashNew (0);
    if (appServiceHashTableMaster == NULL) {
        LOGE ("Create appServiceHashTableMaster error.\n");
        return -1;
    }

    appServiceHashTableSlave = hashNew (0);
    if (appServiceHashTableSlave == NULL) {
        LOGE ("Create appServiceHashTableSlave error.\n");
        hashDestroy (appServiceHashTableMaster);
        appServiceHashTableMaster = NULL;
        return -1;
    }

    ret = updateAppServiceManager ();
    if (ret < 0) {
        LOGE ("Update application service manager error.\n");
        hashDestroy (appServiceHashTableSlave);
        appServiceHashTableSlave = NULL;
        hashDestroy (appServiceHashTableMaster);
        appServiceHashTableMaster = NULL;
        return -1;
    }

    return 0;
}

void
destroyAppServiceManager (void) {
    hashDestroy (appServiceHashTableSlave);
    appServiceHashTableSlave = NULL;
    hashDestroy (appServiceHashTableMaster);
    appServiceHashTableMaster = NULL;
}
