#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <pthread.h>
#include "util.h"
#include "logger.h"
#include "hash.h"
#include "service_manager.h"

/* BPF ip fragment filter */
#define BPF_IP_FRAGMENT_FILTER "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
/* BPF service filter */
#define BPF_SERVICE_FILTER "(ip host %s and (tcp port %u or %s)) or "
/* BPF service filter length */
#define BPF_SERVICE_FILTER_LENGTH 256

static hashTablePtr serviceHashTableMaster = NULL;
static hashTablePtr serviceHashTableSlave = NULL;
static pthread_rwlock_t serviceHashTableMasterLock = PTHREAD_RWLOCK_INITIALIZER;

protoType
lookupServiceProtoType (const char *key) {
    int proto;
    servicePtr svc;

    if (key ==  NULL)
        return PROTO_UNKNOWN;

    pthread_rwlock_rdlock (&serviceHashTableMasterLock);
    svc = (servicePtr) hashLookup (serviceHashTableMaster, key);
    if (svc == NULL)
        proto = PROTO_UNKNOWN;
    else
        proto = svc->proto;
    pthread_rwlock_unlock (&serviceHashTableMasterLock);

    return proto;
}

static int
generateFilterFromEachService (void *data, void *args) {
    u_int len;
    servicePtr svc = (servicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    snprintf (filter + len, BPF_SERVICE_FILTER_LENGTH, BPF_SERVICE_FILTER, svc->ip, svc->port, BPF_IP_FRAGMENT_FILTER);
    return 0;
}

char *
getServicesFilter (void) {
    int ret;
    u_int svcNum;
    char *filter;
    u_int filterLen;

    pthread_rwlock_rdlock (&serviceHashTableMasterLock);
    svcNum = hashSize (serviceHashTableMaster);
    filterLen = BPF_SERVICE_FILTER_LENGTH * (svcNum + 1);
    filter = (char *) malloc (filterLen);
    if (filter == NULL) {
        LOGE ("Alloc filter buffer error: %s.\n", strerror (errno));
        pthread_rwlock_unlock (&serviceHashTableMasterLock);
        return NULL;
    }
    memset(filter, 0, filterLen);

    ret = hashForEachItemDo (serviceHashTableMaster, generateFilterFromEachService, filter);
    if (ret < 0) {
        LOGE ("Generate BPF filter from service error.\n");
        free (filter);
        pthread_rwlock_unlock (&serviceHashTableMasterLock);
        return NULL;
    }

    strcat (filter, "icmp");
    pthread_rwlock_unlock (&serviceHashTableMasterLock);
    return filter;
}

static void
serviceMapSwap (void) {
    hashTablePtr tmp;

    tmp = serviceHashTableMaster;
    pthread_rwlock_wrlock (&serviceHashTableMasterLock);
    serviceHashTableMaster = serviceHashTableSlave;
    pthread_rwlock_unlock (&serviceHashTableMasterLock);
    serviceHashTableSlave = tmp;
}

static int
addService (servicePtr svc) {
    int ret;
    char key [32] = {0};

    snprintf (key, sizeof (key) - 1, "%s:%d", svc->ip, svc->port);
    ret = hashInsert (serviceHashTableSlave, key, svc, freeService);
    if (ret < 0) {
        LOGE ("Insert new service: %u error\n", svc->id);
        return -1;
    }

    displayServiceDetail (svc);
    return 0;
}

int
updateServiceManager (json_t *services) {
    int ret;
    u_int i;
    json_t *tmp;
    servicePtr svc;

    /* Cleanup slave service hash table */
    hashClean (serviceHashTableSlave);

    for (i = 0; i < json_array_size (services); i ++) {
        tmp = json_array_get (services, i);
        if (tmp == NULL) {
            LOGE ("Get json array item error.\n");
            return -1;
        }

        svc = json2Service (tmp);
        if (svc == NULL) {
            LOGE ("Convert json to service error.\n");
            return -1;
        }

        ret = addService (svc);
        if (ret < 0) {
            LOGE ("Add service error.\n");
            return -1;
        }
    }
    /* Swap service map */
    serviceMapSwap ();

    return 0;
}

void
cleanServiceManager (void) {
    hashClean (serviceHashTableSlave);
    serviceMapSwap ();
    hashClean (serviceHashTableSlave);
}

int
initServiceManager (void) {
    serviceHashTableMaster = hashNew (0);
    if (serviceHashTableMaster == NULL) {
        LOGE ("Create serviceHashTableMaster error.\n");
        return -1;
    }

    serviceHashTableSlave = hashNew (0);
    if (serviceHashTableSlave == NULL) {
        LOGE ("Create serviceHashTableSlave error.\n");
        hashDestroy (serviceHashTableMaster);
        serviceHashTableMaster = NULL;
        return -1;
    }

    return 0;
}

void
destroyServiceManager (void) {
    hashDestroy (serviceHashTableSlave);
    serviceHashTableSlave = NULL;
    hashDestroy (serviceHashTableMaster);
    serviceHashTableMaster = NULL;
}
