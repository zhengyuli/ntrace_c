#include <stdlib.h>
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

    svc->proto = NULL;
    svc->analyzer = NULL;
    svc->ip = NULL;
    svc->port = 0;

    return svc;
}

void
freeAppService (appServicePtr svc) {
    if (svc == NULL)
        return;

    free (svc->ip);
    free (svc);
}

appServicePtr
copyAppService (appServicePtr appService) {
    appServicePtr tmp;

    tmp = newAppService ();
    if (tmp == NULL)
        return NULL;

    tmp->proto = appService->proto;
    tmp->analyzer = appService->analyzer;
    tmp->ip = strdup (appService->ip);
    if (tmp->ip == NULL) {
        freeAppService (tmp);
        return NULL;
    }
    tmp->port = appService->port;

    return tmp;
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
        LOGE ("Alloc appService error.\n");
        return NULL;
    }

    /* Get application service proto and analyzer */
    tmp = json_object_get (json, APP_SERVICE_PROTO);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PROTO);
        freeAppService (svc);
        return NULL;
    }
    analyzer = getProtoAnalyzer ((char *) json_string_value (tmp));
    if (analyzer == NULL) {
        LOGE ("Unsupported application service proto type: %s.\n", (json_string_value (tmp)));
        freeAppService (svc);
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
        freeAppService (svc);
        return NULL;
    }
    svc->ip = strdup (json_string_value (tmp));
    if (svc->ip == NULL) {
        LOGE ("Strdup application service ip error: %s.\n", strerror (errno));
        freeAppService (svc);
        return NULL;
    }

    /* Get application service port */
    tmp = json_object_get (json, APP_SERVICE_PORT);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PORT);
        freeAppService (svc);
        return NULL;
    }
    svc->port = (u_short) json_integer_value (tmp);

    return svc;
}
