#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <jansson.h>
#include "util.h"
#include "log.h"
#include "service.h"

static hashTablePtr svcMapMaster = NULL;
static hashTablePtr svcMapSlave = NULL;
static pthread_rwlock_t svcMapMasterLock = PTHREAD_RWLOCK_INITIALIZER;

inline u_int
serviceNum (void) {
    u_int size;

    pthread_rwlock_rdlock (&svcMapMasterLock);
    size = hashSize (svcMapMaster);
    pthread_rwlock_unlock (&svcMapMasterLock);

    return size;
}

inline int
serviceLoopDo (hashForEachItemDoCB fun, void *args) {
    int ret;
    
    pthread_rwlock_rdlock (&svcMapMasterLock);
    ret = hashForEachItemDo (svcMapMaster, fun, args);
    pthread_rwlock_unlock (&svcMapMasterLock);

    return ret;
}

static void
freeService (void *data) {
    servicePtr svc;

    if (data == NULL)
        return;
    svc = (servicePtr) data;
    free (svc->ip);
    free (svc);
}

static int
addService (servicePtr svc) {
    int ret;
    char key [32] = {0};

    snprintf (key, sizeof (key) - 1, "%s:%d", svc->ip, svc->port);
    ret = hashInsert (svcMapSlave, key, svc, freeService);
    if (ret < 0) {
        LOGE ("Insert new service: %u error\n", svc->id);
        return -1;
    }

    return 0;
}

static void
serviceMapSwap (void) {
    hashTablePtr tmp;

    tmp = svcMapMaster;
    pthread_rwlock_wrlock (&svcMapMasterLock);
    svcMapMaster = svcMapSlave;
    pthread_rwlock_unlock (&svcMapMasterLock);
    svcMapSlave = tmp;
}

static void
displayServiceUpdateDetail (servicePtr svc) {
    LOGI ("\nAdd service:\n");
    LOGI ("--id: %u\n", svc->id);
    LOGI ("--proto: %s\n", getProtoName (svc->proto) ? getProtoName (svc->proto) : "Unknown protoType");
    LOGI ("--ip: %s\n", svc->ip);
    LOGI ("--port: %u\n", svc->port);
}

static servicePtr
json2Service (json_t *json) {
    json_t *tmp;
    servicePtr svc;
    struct in_addr sa;

    svc = (servicePtr) malloc (sizeof (service));
    if (svc == NULL) {
        LOGE ("Alloc service error: %s.\n", strerror (errno));
        return NULL;
    }

    /* Get service id */
    tmp = json_object_get (json, "service_id");
    if (tmp == NULL) {
        LOGE ("Has no service_id item.\n");
        free (svc);
        return NULL;
    }
    svc->id = (u_int) json_integer_value (tmp);

    /* Get service proto */
    tmp = json_object_get (json, "service_proto");
    if (tmp == NULL) {
        LOGE ("Has no service_proto item.\n");
        free (svc);
        return NULL;
    }
    svc->proto = getProtoType (json_string_value (tmp));
    if (svc->proto == PROTO_UNKNOWN) {
        LOGE ("Unknown proto type: %s.\n", (json_string_value (tmp)));
        free (svc);
        return NULL;
    }

    /* Get service ip */
    tmp = json_object_get (json, "service_ip");
    if (tmp == NULL) {
        LOGE ("Has no service_ip item.\n");
        free (svc);
        return NULL;
    }
    if (!inet_aton (json_string_value (tmp), &sa)) {
        LOGE ("Wrong ip address: %s.\n", (json_string_value (tmp)));
        free (svc);
        return NULL;
    }
    svc->ip = strdup (json_string_value (tmp));
    if (svc->ip == NULL) {
        LOGE ("Strdup service ip error: %s.\n", strerror (errno));
        free (svc);
        return NULL;
    }

    /* Get service port */
    tmp = json_object_get (json, "service_port");
    if (tmp == NULL) {
        LOGE ("Has no service_port item.\n");
        free (svc->ip);
        free (svc);
        return NULL;
    }
    svc->port = (u_short) json_integer_value (tmp);

    return svc;
}

int
updateService (const char *svcJson) {
    u_int i;
    json_error_t error;
    json_t *root, *tmp;
    servicePtr svc;

    /* Cleanup svcMapSlave */
    hashClen (svcMapSlave);

    /* Parse services */
    root = json_loads (jsonData, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        LOGE ("Json parse error: %s.\n", error.text);
        return -1;
    }

    if (!json_is_array (root)) {
        LOGE ("Wrong json format.\n");
        json_object_clear (root);
        return -1;
    }

    for (i = 0; i < json_array_size (root); i ++) {
        tmp = json_array_get (root, i);
        if (tmp == NULL) {
            LOGE ("Get json array item error.\n");
            json_object_clear (root);
            return -1;
        }

        svc = json2Service (tmp);
        if (svc == NULL) {
            LOGE ("Convert json to service error.\n");
            json_object_clear (root);
            return -1;
        }
        ret = addService (svc);
        if (ret < 0) {
            LOGE ("Add service error.\n");
            json_object_clear (root);
            return -1;
        }
    }
    serviceMapSwap ();
    return 0;
}

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

int
initServiceContext (void) {
    svcMapMaster = hashNew (0);
    if (svcMapMaster == NULL) {
        LOGE ("Create master service hash map error.\n");
        return -1;
    }

    svcMapSlave = hashNew (0);
    if (svcMapSlave == NULL) {
        LOGE ("Create slave service hash map error.\n");
        hashDestroy (svcMapMaster);
        svcMapMaster = NULL;
        return -1;
    }

    return 0;
}

void
destroyServiceContext (void) {
    hashDestroy (svcMapSlave);
    svcMapSlave = NULL;
    hashDestroy (svcMapMaster);
    svcMapMaster = NULL;
}
