#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include "logger.h"
#include "service.h"

servicePtr
newService (void) {
    servicePtr svc;

    svc = (servicePtr) malloc (sizeof (service));
    if (svc == NULL)
        return NULL;

    svc->id = 0;
    svc->proto = PROTO_UNKNOWN;
    svc->ip = NULL;
    svc->port = 0;
    return svc;
}

void
freeService (void *data) {
    servicePtr svc;

    if (data == NULL)
        return;
    svc = (servicePtr) data;
    free (svc->ip);
    free (svc);
}

void
displayServiceDetail (servicePtr svc) {
    LOGI ("\nService detail info:\n");
    LOGI ("--id: %u\n", svc->id);
    LOGI ("--proto: %s\n", getProtoName (svc->proto) ? getProtoName (svc->proto) : "Unknown protoType");
    LOGI ("--ip: %s\n", svc->ip);
    LOGI ("--port: %u\n", svc->port);
}

servicePtr
json2Service (json_t *json) {
    json_t *tmp;
    servicePtr svc;
    struct in_addr sa;

    svc = newService ();
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
    svc->id = json_integer_value (tmp);

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
