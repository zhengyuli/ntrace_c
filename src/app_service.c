#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include "logger.h"
#include "indent_level.h"
#include "app_service.h"

void
displayAppServiceDetail (appServicePtr svc, u_int indentLevel) {
    LOGD ("\n%sappService-%d:\n", getIndentLevel (indentLevel), svc->id);
    LOGD ("%s{\n", getIndentLevel (indentLevel));
    LOGD ("%sid: %d\n", getIndentLevel (indentLevel + 1), svc->id);
    LOGD ("%sproto: %s\n", getIndentLevel (indentLevel + 1),
          getProtoName (svc->proto) ? getProtoName (svc->proto) : "Unknown protoType");
    LOGD ("%sip: %s\n", getIndentLevel (indentLevel + 1), svc->ip);
    LOGD ("%sport: %u\n", getIndentLevel (indentLevel + 1), svc->port);
    LOGD ("%s}\n", getIndentLevel (indentLevel));
}

appServicePtr
newAppService (void) {
    appServicePtr svc;

    svc = (appServicePtr) malloc (sizeof (appService));
    if (svc == NULL)
        return NULL;

    svc->id = 0;
    svc->proto = PROTO_UNKNOWN;
    svc->ip = NULL;
    svc->port = 0;
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
    tmp->port = appService->port;

    if (tmp->ip == NULL) {
        free (tmp);
        return NULL;
    }

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
    /* Application service proto type */
    json_object_set_new (root, APP_SERVICE_PROTO, json_string (getProtoName (svc->proto)));
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

    /* Get application service proto type */
    tmp = json_object_get (json, APP_SERVICE_PROTO);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PROTO);
        free (svc);
        return NULL;
    }
    svc->proto = getProtoType (json_string_value (tmp));
    if (svc->proto == PROTO_UNKNOWN) {
        LOGE ("Unknown application service proto type: %s.\n", (json_string_value (tmp)));
        free (svc);
        return NULL;
    }

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
