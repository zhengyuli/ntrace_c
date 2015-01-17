#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <jansson.h>
#include "log.h"
#include "app_service.h"

appServicePtr
newAppService (void) {
    appServicePtr svc;

    svc = (appServicePtr) malloc (sizeof (appService));
    if (svc == NULL)
        return NULL;

    svc->id = 0;
    svc->proto = NULL;
    svc->ip = NULL;
    svc->port = 0;
    svc->analyzer = NULL;
    return svc;
}

appServicePtr
copyAppService (appServicePtr appService) {
    appServicePtr tmp;

    tmp = newAppService ();
    if (tmp == NULL)
        return NULL;

    tmp->id = appService->id;
    tmp->proto = appService->proto;
    tmp->ip = strdup (appService->ip);
    if (tmp->ip == NULL) {
        free (tmp);
        return NULL;
    }
    tmp->port = appService->port;
    tmp->analyzer = appService->analyzer;

    return tmp;
}

void
freeAppService (appServicePtr svc) {
    if (svc == NULL)
        return;
    free (svc->ip);
    free (svc);
}

void
freeAppServiceForHash (void *data) {
    return freeAppService ((appServicePtr) data);
}

json_t *
appService2Json (appServicePtr svc) {
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Application service id */
    json_object_set_new (root, APP_SERVICE_ID, json_integer (svc->id));
    /* Application service proto */
    json_object_set_new (root, APP_SERVICE_PROTO, json_string (svc->proto));
    /* Application service ip */
    json_object_set_new (root, APP_SERVICE_IP, json_string (svc->ip));
    /* Application service port */
    json_object_set_new (root, APP_SERVICE_PORT, json_integer (svc->port));

    return root;
}

appServicePtr
json2AppService (json_t *json) {
    json_t *tmp;
    appServicePtr svc;
    protoAnalyzerPtr analyzer;
    struct in_addr sa;

    svc = newAppService ();
    if (svc == NULL) {
        LOGE ("Alloc appService error: %s.\n", strerror (errno));
        return NULL;
    }

    /* Get application service id */
    tmp = json_object_get (json, APP_SERVICE_ID);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_ID);
        free (svc);
        return NULL;
    }
    svc->id = json_integer_value (tmp);

    /* Get application service proto */
    tmp = json_object_get (json, APP_SERVICE_PROTO);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PROTO);
        free (svc);
        return NULL;
    }
    analyzer = getProtoAnalyzer (json_string_value (tmp));
    if (analyzer == NULL) {
        LOGE ("Unsupported application service proto type: %s.\n", (json_string_value (tmp)));
        free (svc);
        return NULL;
    }
    svc->proto = analyzer->proto;
    svc->analyzer = analyzer;
    
    /* Get application service ip */
    tmp = json_object_get (json, APP_SERVICE_IP);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_IP);
        free (svc);
        return NULL;
    }
    if (!inet_aton (json_string_value (tmp), &sa)) {
        LOGE ("Wrong application service ip address: %s.\n", (json_string_value (tmp)));
        free (svc);
        return NULL;
    }
    svc->ip = strdup (json_string_value (tmp));
    if (svc->ip == NULL) {
        LOGE ("Strdup application service ip error: %s.\n", strerror (errno));
        free (svc);
        return NULL;
    }

    /* Get application service port */
    tmp = json_object_get (json, APP_SERVICE_PORT);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PORT);
        free (svc->ip);
        free (svc);
        return NULL;
    }
    svc->port = (u_short) json_integer_value (tmp);

    return svc;
}
