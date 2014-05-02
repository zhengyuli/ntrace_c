#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <jansson.h>
#include "log.h"
#include "util.h"
#include "service.h"

#define SVC_MAP_INIT_SIZE 133

/*
 * The master service hash map will be used by parsing sub-threads.
 * When there is a service update, serviceUpdateMonitor will update
 * svcMapSlave first and try to get svcMapMasterLock's rw lock, if
 * success then swap svcMapMaster and svcMapSlave.
 */
static hashTablePtr svcMapMaster;
static hashTablePtr svcMapSlave;
static pthread_rwlock_t svcMapMasterLock = PTHREAD_RWLOCK_INITIALIZER;

int
serviceNum (void) {
    return hashSize (svcMapSlave);
}

int
serviceLoopDo (hashForEachItemDoFun fun, void *args) {
    return hashForEachItemDo (svcMapSlave, fun, args);
}

static servicePtr
newService (void) {
    servicePtr svc;

    svc = malloc (sizeof (service));
    if (svc)
        memset (svc, 0, sizeof (service));

    return svc;
}

static void
freeService (void *data) {
    servicePtr svc;

    svc = (servicePtr) data;
    free (svc->ip);
    free (data);
}

static servicePtr
copyService (servicePtr svcFrom) {
    servicePtr svcTo;

    svcTo = newService ();
    if (svcTo) {
        svcTo->id = svcFrom->id;
        svcTo->proto = svcFrom->proto;
        svcTo->ip = strdup (svcFrom->ip);
        if (svcTo->ip == NULL) {
            free (svcTo);
            return NULL;
        }
        svcTo->port = svcFrom->port;
    }

    return svcTo;
}

/*
 * @brief Add service to slave service hash map
 *
 * @param svc service to add
 *
 * @return 0 if success else -1
 */
static int
addService (servicePtr svc) {
    int ret;
    char key [32];
    servicePtr newSvc;

    newSvc = copyService (svc);
    if (newSvc == NULL) {
        LOGE ("CopyService error.\n");
        return -1;
    }

    snprintf (key, sizeof (key), "%s:%d", newSvc->ip, newSvc->port);
    ret = hashInsert (svcMapSlave, key, newSvc, freeService);
    if (ret < 0) {
        LOGE ("Insert new service: %u error\n", svc->id);
        return -1;
    }

    return 0;
}

/*
 * @brief Delete service from slave service hash map.
 *
 * @param svc service to delete
 *
 * @return 0 if success else -1
 */
static int
deleteService (servicePtr svc) {
    int ret;
    char key [32];

    snprintf (key, sizeof (key), "%s:%d", svc->ip, svc->port);
    ret = hashDel (svcMapSlave, key);
    if (ret < 0) {
        LOGE ("Service: %u doesn't exist.\n", svc->id);
        return -1;
    }

    return 0;
}

/*
 * @brief To modify service, first, we need to remove the old service
 *        and then add the new service.
 *
 * @param oldSvc old service to delete
 * @param newSvc new service to add
 *
 * @return 0 if success else -1
 */
static int
modifyService (servicePtr oldSvc, servicePtr newSvc) {
    int ret;

    ret = deleteService (oldSvc);
    if (ret < 0) {
        LOGE ("Delete service error.\n");
        return -1;
    }

    ret = addService (newSvc);
    if (ret < 0) {
        LOGE ("Add service error.\n");
        return -1;
    }

    return 0;
}

static void
serviceMapSwap (void) {
    hashTablePtr tmp;

    /* Switch master and slave service hash table and
     * update slave service hash table
     */
    tmp = svcMapMaster;
    pthread_rwlock_wrlock (&svcMapMasterLock);
    svcMapMaster = svcMapSlave;
    pthread_rwlock_unlock (&svcMapMasterLock);
    svcMapSlave = tmp;
}

/*
 * @brief display service update info
 *
 * @param svcUpdateType service update type
 * @param svc service to update
 */
static void
displayServiceUpdateDetail (svcUpdateType updateType, servicePtr svc) {
    switch (updateType) {
        case SVC_UPDATE_ADD:
            LOGI ("\nService add:\n");
            break;

        case SVC_UPDATE_MOD:
            LOGI ("Service modify:\n");
            break;

        case SVC_UPDATE_DEL:
            LOGI ("Service delete:\n");
            break;

        default:
            LOGI ("Unknown service update type\n");
            return;
    }

    LOGI ("--id: %u\n", svc->id);

    switch (svc->proto) {
        case PROTO_DEFAULT:
            LOGI ("--proto: %s\n", "default");
            break;

        case PROTO_MYSQL:
            LOGI ("--proto: %s\n", "mysql");
            break;

        case PROTO_HTTP:
            LOGI ("--proto: %s\n", "http");
            break;

        default:
            LOGI ("Unsupported protocol\n");
            return;
    }

    LOGI ("--ip: %s\n", svc->ip);
    LOGI ("--port: %u\n", svc->port);
}

static void *
lookupServiceBySvcId (void *data, void *args) {
    servicePtr tmp = (servicePtr) data;
    servicePtr svc = (servicePtr) args;

    if (tmp->id == svc->id)
        return (void *) tmp;
    else
        return NULL;
}

static void *
lookupServiceBySvcIdStub (void *data, void *args) {
    servicePtr oldSvc = (servicePtr) data;
    servicePtr svc = (servicePtr) args;

    if (oldSvc->id == svc->id)
        return (void *) oldSvc;
    else
        return NULL;
}

/*
 * @brief Update service
 *
 * @param updateType service update type
 * @param svc service to update
 *
 * @return 0 if success else -1
 */
int
updateService (svcUpdateType updateType, servicePtr svc) {
    int ret;
    servicePtr oldSvc;
    servicePtr oldSvcBackup;

    oldSvc = (servicePtr) hashForEachItemCheck (svcMapSlave, lookupServiceBySvcIdStub, (void *) svc);
    switch (updateType) {
        case SVC_UPDATE_ADD:
            if (oldSvc) {
                LOGE ("Service: %d  has been registered.\n", svc->id);
                freeService (svc);
                return -1;
            }
            ret = addService (svc);
            if (ret < 0) {
                LOGE ("addService error.\n");
                freeService (svc);
                return -1;
            }
            break;

        case SVC_UPDATE_MOD:
            if (oldSvc == NULL) {
                LOGE ("Service modify error, service not exists.\n");
                freeService (svc);
                return -1;
            }
            oldSvcBackup = copyService (oldSvc);
            if (oldSvcBackup == NULL) {
                LOGE ("CopyService error.\n");
                freeService (svc);
                return -1;
            }
            ret = modifyService (oldSvcBackup, svc);
            /* Free old service backup if update fail */
            if (ret < 0) {
                LOGE ("modifyService error.\n");
                freeService (oldSvcBackup);
                freeService (svc);
                return -1;
            }
            break;

        case SVC_UPDATE_DEL:
            if (oldSvc == NULL) {
                LOGE ("Service Delete error, service not exists.\n");
                freeService (svc);
                return -1;
            }
            ret = deleteService (svc);
            if (ret < 0) {
                LOGE ("deleteService error.\n");
                freeService (svc);
                return -1;
            }
            break;

        default:
            LOGE ("Unknown service update type.\n");
            freeService (svc);
            return -1;
    }

    /* Swap service master and slave hash map */
    serviceMapSwap ();

    switch (updateType) {
        case SVC_UPDATE_ADD:
            ret = addService (svc);
            if (ret < 0) {
                LOGE ("addService error.\n");
                freeService (svc);
                return -1;
            }
            break;

        case SVC_UPDATE_MOD:
            ret = modifyService (oldSvcBackup, svc);
            /* Free old service backup if update fail */
            if (ret < 0) {
                LOGE ("modifyService error.\n");
                freeService (oldSvcBackup);
                freeService (svc);
                return -1;
            }
            break;

        case SVC_UPDATE_DEL:
            ret = deleteService (svc);
            if (ret < 0) {
                LOGE ("deleteService error.\n");
                freeService (svc);
                return -1;
            }
            break;

        default:
            LOGE ("Unknown service update type.\n");
            freeService (svc);
            return -1;
    }

    displayServiceUpdateDetail (updateType, svc);
    if (updateType == SVC_UPDATE_MOD)
        freeService (oldSvcBackup);
    freeService (svc);
    return 0;
}

/*
 * @brief Lookup service proto type from svcMapMaster.
 *
 * @param key hash key to search
 *
 * @return service proto
 */
protoType
lookupServiceProtoType (const char *key) {
    int proto;
    servicePtr svc;

    if (key ==  NULL)
        return PROTO_UNKNOWN;

    pthread_rwlock_rdlock (&svcMapMasterLock);
    svc = (servicePtr) hashLookup (svcMapMaster, key);
    if (svc == NULL)
        proto = PROTO_UNKNOWN;
    else
        proto = svc->proto;
    pthread_rwlock_unlock (&svcMapMasterLock);

    return proto;
}

/*
 * @brief Convert json string to service structure,
 *
 * @param jsonData Json format for service
 *
 * @return Service pointer if success else NULL
 */
servicePtr
json2Service (const char *jsonData) {
    servicePtr svc;
    json_error_t error;
    json_t *root, *tmp;
    struct in_addr sa;

    svc = newService ();
    if (svc == NULL) {
        LOGE ("Alloc service error.\n");
        return NULL;
    }

    root = json_loads (jsonData, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        LOGE ("json parse error: %s.\n", error.text);
        free (svc);
        return NULL;
    }

    /* Get service id */
    tmp = json_object_get (root, "service_id");
    if (tmp == NULL) {
        LOGE ("Has no service_id item.\n");
        json_object_clear (root);
        free (svc);
        return NULL;
    }
    svc->id = json_integer_value (tmp);

    /* Get service proto */
    tmp = json_object_get (root, "service_proto");
    if (tmp == NULL) {
        LOGE ("Has no service_proto item.\n");
        json_object_clear (root);
        free (svc);
        return NULL;
    }
    svc->proto = getProtoType (json_string_value (tmp));
    if (svc->proto == PROTO_UNKNOWN) {
        LOGE ("Unknown proto type: %s.\n", (json_string_value (tmp)));
        json_object_clear (root);
        free (svc);
        return NULL;
    }

    /* Get service ip */
    tmp = json_object_get (root, "service_ip");
    if (tmp == NULL) {
        LOGE ("Has no service_ip item.\n");
        json_object_clear (root);
        free (svc);
        return NULL;
    }
    if (!inet_aton (json_string_value (tmp), &sa)) {
        LOGE ("Wrong ip format: %s.\n", (json_string_value (tmp)));
        json_object_clear (root);
        free (svc);
        return NULL;
    }
    svc->ip = strdup (json_string_value (tmp));
    if (svc->ip == NULL) {
        LOGE ("Alloc memory for service ip error: %s.\n", strerror (errno));
        json_object_clear (root);
        free (svc);
        return NULL;
    }

    /* Get service port */
    tmp = json_object_get (root, "service_port");
    if (tmp == NULL) {
        LOGE ("Has no service_port item.\n");
        json_object_clear (root);
        free (svc->ip);
        free (svc);
        return NULL;
    }
    svc->port = json_integer_value (tmp);

    json_object_clear (root);
    return svc;
}

/* Servcie context init */
int
initServiceContext (void) {
    svcMapMaster = hashNew (SVC_MAP_INIT_SIZE);
    if (svcMapMaster == NULL) {
        LOGE ("Create master service hash map error.\n");
        return -1;
    }

    svcMapSlave = hashNew (SVC_MAP_INIT_SIZE);
    if (svcMapSlave == NULL) {
        LOGE ("Create slave service hash map error.\n");
        hashDestroy (&svcMapMaster);
        return -1;
    }

    return 0;
}

void
destroyServiceContext (void) {
    hashDestroy (&svcMapSlave);
    hashDestroy (&svcMapMaster);
}
