#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <json/json.h>
#include "util.h"
#include "log.h"
#include "byte-order.h"
#include "http-analyzer.h"

/* Current timestamp */
static __thread timeValPtr currTime;
/* Current session done indicator */
static __thread int currSessionDone;
/* Current http header type */
static __thread httpHeaderType currHeaderType;
/* Current http session detail */
static __thread httpSessionDetailPtr currSessionDetail;

static httpSessionDetailNodePtr
newHttpSessionDetailNode (void);

static void
freeHttpSessionDetailNode (httpSessionDetailNodePtr hsdn);

/* Http_parser callback */
/* Resquest callback */
static int
onReqMessageBegin (http_parser *parser) {
    httpSessionDetailNodePtr hsdn;

    hsdn = newHttpSessionDetailNode ();
    if (hsdn == NULL)
        LOGE ("NewHttpSessionDetailNode error.\n");
    else {
        hsdn->state = HTTP_REQUEST_HEADER;
        hsdn->reqTime = timeVal2MilliSecond (currTime);
        listAddTail (&hsdn->node, &currSessionDetail->head);
    }

    return 0;
}

static int
onReqUrl (http_parser *parser, const char *from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->method = strdup (http_method_str (parser->method));
    currNode->url = strndup (from, length);
    if (currNode->url == NULL)
        LOGE ("Get http request url error.\n");

    return 0;
}

static int
onReqHeaderField (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    if (strncmp (HTTP_HEADER_HOST_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_HOST;
    else if (strncmp (HTTP_HEADER_USER_AGENT_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_USER_AGENT;
    else if (strncmp (HTTP_HEADER_REFERER_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_REFERER;
    else if (strncmp (HTTP_HEADER_ACCEPT_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT;
    else if (strncmp (HTTP_HEADER_ACCEPT_LANGUAGE_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT_LANGUAGE;
    else if (strncmp (HTTP_HEADER_ACCEPT_ENCODING_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT_ENCODING;
    else if (strncmp (HTTP_HEADER_X_FORWARDED_FOR_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_X_FORWARDED_FOR;
    else if (strncmp (HTTP_HEADER_CONNECTION_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_CONNECTION;

    return 0;
}

static int
onReqHeaderValue (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    switch (currHeaderType) {
        case HTTP_HEADER_HOST:
            currNode->host = strndup (from, length);
            if (currNode->host == NULL)
                LOGE ("Get Host field error.\n");
            break;

        case HTTP_HEADER_USER_AGENT:
            currNode->userAgent = strndup (from, length);
            if (currNode->userAgent == NULL)
                LOGE ("Get User-Agent field error.\n");
            break;

        case HTTP_HEADER_REFERER:
            currNode->referer = strndup (from, length);
            if (currNode->referer == NULL)
                LOGE ("Get Referer field error.\n");
            break;

        case HTTP_HEADER_ACCEPT_LANGUAGE:
            currNode->acceptLanguage = strndup (from, length);
            if (currNode->acceptLanguage == NULL)
                LOGE ("Get Accept-Language field error.\n");
            break;

        case HTTP_HEADER_ACCEPT_ENCODING:
            currNode->acceptEncoding = strndup (from, length);
            if (currNode->acceptEncoding == NULL)
                LOGE ("Get Accept-Encoding field error.\n");
            break;

        case HTTP_HEADER_X_FORWARDED_FOR:
            currNode->xForwardedFor = strndup (from, length);
            if (currNode->xForwardedFor == NULL)
                LOGE ("Get X-Forwarded-For field error.\n");
            break;

        case HTTP_HEADER_CONNECTION:
            currNode->reqConnection = strndup (from, length);
            if (currNode->reqConnection == NULL)
                LOGE ("Get Connection field error.\n");
            break;

        default:
            break;
    }
    currHeaderType = HTTP_HEADER_IGNORE;

    return 0;
}

static int
onReqHeadersComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_HEADER_COMPLETE;
    snprintf (currNode->reqVer, HTTP_VERSION_LENGTH - 1, "HTTP/%d.%d",
              parser->http_major, parser->http_minor);
    currNode->reqHeaderSize = parser->nread;

    return 0;
}

static int
onReqBody (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_BODY;
    currNode->reqBodySize += length;

    return 0;
}

static int
onReqMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_BODY_COMPLETE;

    return 0;
}

/* Response callback */
static int
onRespMessageBegin (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_HEADER;
    currNode->respTimeBegin = timeVal2MilliSecond (currTime);

    return 0;
}

static int
onRespUrl (http_parser *parser, const char *from, size_t length) {
    return 0;
}

static int
onRespHeaderField (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    if (strncmp (HTTP_HEADER_CONTENT_TYPE_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_CONTENT_TYPE;
    else if (strncmp (HTTP_HEADER_CONNECTION_STRING, from, length) == 0)
        currHeaderType = HTTP_HEADER_CONNECTION;

    return 0;
}

static int
onRespHeaderValue (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    switch (currHeaderType) {
        case HTTP_HEADER_CONTENT_TYPE:
            currNode->contentType = strndup (from, length);
            if (currNode->contentType == NULL)
                LOGE ("Get Content-Type field error.\n");
            break;

        case HTTP_HEADER_CONNECTION:
            currNode->respConnection = strndup (from, length);
            if (currNode->respConnection == NULL)
                LOGE ("Get Connection field error.\n");
            break;

        default:
            break;
    }
    currHeaderType = HTTP_HEADER_IGNORE;

    return 0;
}

static int
onRespHeadersComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    snprintf(currNode->respVer, HTTP_VERSION_LENGTH - 1, "HTTP/%d.%d",
             parser->http_major, parser->http_minor);
    currNode->state = HTTP_RESPONSE_HEADER_COMPLETE;
    currNode->statusCode = parser->status_code;
    currNode->respHeaderSize = parser->nread;

    return 0;
}

static int
onRespBody (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_BODY;
    currNode->respBodySize += length;
    currNode->respTimeEnd = timeVal2MilliSecond (currTime);

    return 0;
}

static int
onRespMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_BODY_COMPLETE;
    currSessionDone = 1;

    return 0;
}
/* Http_parser callback end */

static int
initHttpProto (void) {
    return 0;
}

static void
destroyHttpProto (void) {
    return;
}

static httpSessionDetailNodePtr
newHttpSessionDetailNode (void) {
    httpSessionDetailNodePtr hsdn;

    hsdn = (httpSessionDetailNodePtr) malloc (sizeof (httpSessionDetailNode));
    if (hsdn) {
        memset (hsdn->reqVer, 0, HTTP_VERSION_LENGTH);
        hsdn->method = NULL;
        hsdn->url = NULL;
        hsdn->host = NULL;
        hsdn->userAgent = NULL;
        hsdn->referer = NULL;
        hsdn->accept = NULL;
        hsdn->acceptLanguage = NULL;
        hsdn->acceptEncoding = NULL;
        hsdn->xForwardedFor = NULL;
        hsdn->reqConnection = NULL;
        memset (hsdn->respVer, 0, HTTP_VERSION_LENGTH);
        hsdn->contentType = NULL;
        hsdn->respConnection = NULL;
        hsdn->state = HTTP_REQUEST_HEADER;
        hsdn->statusCode = 0;
        hsdn->reqTime = 0;
        hsdn->reqHeaderSize = 0;
        hsdn->reqBodySize = 0;
        hsdn->respTimeBegin = 0;
        hsdn->respHeaderSize = 0;
        hsdn->respBodySize = 0;
        hsdn->respTimeEnd = 0;
        initListHead (&hsdn->node);
        return hsdn;
    } else
        return NULL;
}

static void
freeHttpSessionDetailNode (httpSessionDetailNodePtr hsdn) {
    if (hsdn == NULL)
        return;

    if (hsdn->method) {
        free (hsdn->method);
        hsdn->method = NULL;
    }

    if (hsdn->url) {
        free (hsdn->url);
        hsdn->url = NULL;
    }

    if (hsdn->host) {
        free (hsdn->host);
        hsdn->host = NULL;
    }

    if (hsdn->userAgent) {
        free (hsdn->userAgent);
        hsdn->userAgent = NULL;
    }

    if (hsdn->referer) {
        free (hsdn->referer);
        hsdn->referer = NULL;
    }

    if (hsdn->accept) {
        free (hsdn->accept);
        hsdn->accept = NULL;
    }

    if (hsdn->acceptLanguage) {
        free (hsdn->acceptLanguage);
        hsdn->acceptLanguage = NULL;
    }

    if (hsdn->acceptEncoding) {
        free (hsdn->acceptEncoding);
        hsdn->acceptEncoding = NULL;
    }

    if (hsdn->xForwardedFor) {
        free (hsdn->xForwardedFor);
        hsdn->xForwardedFor = NULL;
    }

    if (hsdn->reqConnection) {
        free (hsdn->reqConnection);
        hsdn->reqConnection = NULL;
    }

    if (hsdn->contentType) {
        free (hsdn->contentType);
        hsdn->contentType = NULL;
    }

    if (hsdn->respConnection) {
        free (hsdn->respConnection);
        hsdn->respConnection = NULL;
    }

    free (hsdn);
}

static void *
newHttpSessionDetail (void) {
    httpSessionDetailPtr hsd;
    http_parser *reqParser;
    http_parser_settings *reqParserSettings;
    http_parser *resParser;
    http_parser_settings *resParserSettings;

    hsd = (httpSessionDetailPtr) malloc (sizeof (httpSessionDetail));
    if (hsd) {
        /* Init http session detail */
        reqParser = &hsd->reqParser;
        reqParserSettings = &hsd->reqParserSettings;
        memset (reqParserSettings, 0, sizeof (*reqParserSettings));
        reqParserSettings->on_message_begin = onReqMessageBegin;
        reqParserSettings->on_url = onReqUrl;
        reqParserSettings->on_header_field = onReqHeaderField;
        reqParserSettings->on_header_value = onReqHeaderValue;
        reqParserSettings->on_headers_complete = onReqHeadersComplete;
        reqParserSettings->on_body = onReqBody;
        reqParserSettings->on_message_complete = onReqMessageComplete;
        http_parser_init (reqParser, HTTP_REQUEST);

        resParser = &hsd->resParser;
        resParserSettings = &hsd->resParserSettings;
        memset (resParserSettings, 0, sizeof (*resParserSettings));
        resParserSettings->on_message_begin = onRespMessageBegin;
        resParserSettings->on_url = onRespUrl;
        resParserSettings->on_header_field = onRespHeaderField;
        resParserSettings->on_header_value = onRespHeaderValue;
        resParserSettings->on_headers_complete = onRespHeadersComplete;
        resParserSettings->on_body = onRespBody;
        resParserSettings->on_message_complete = onRespMessageComplete;
        http_parser_init (resParser, HTTP_RESPONSE);

        initListHead (&hsd->head);
        return hsd;
    } else
        return NULL;
}

static void
freeHttpSessionDetail (void *sd) {
    httpSessionDetailNodePtr pos, tmp;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    if (hsd == NULL)
        return;

    listForEachEntrySafe (pos, tmp, &hsd->head, node) {
        listDel (&pos->node);
        freeHttpSessionDetailNode (pos);
    }

    free (sd);
}

static void *
newHttpSessionBreakdown (void) {
    httpSessionBreakdownPtr hsbd;

    hsbd = (httpSessionBreakdownPtr) malloc (sizeof (httpSessionBreakdown));
    if (hsbd) {
        hsbd->reqVer = NULL;
        hsbd->method = NULL;
        hsbd->url = NULL;
        hsbd->host = NULL;
        hsbd->userAgent = NULL;
        hsbd->referer = NULL;
        hsbd->accept = NULL;
        hsbd->acceptLanguage = NULL;
        hsbd->acceptEncoding = NULL;
        hsbd->xForwardedFor = NULL;
        hsbd->reqConnection = NULL;
        hsbd->respVer = NULL;
        hsbd->contentType = NULL;
        hsbd->respConnection = NULL;
        hsbd->state = HTTP_BREAKDOWN_ERROR;
        hsbd->statusCode = 0;
        hsbd->reqHeaderSize = 0;
        hsbd->reqBodySize = 0;
        hsbd->respHeaderSize = 0;
        hsbd->respBodySize = 0;
        hsbd->serverLatency = 0;
        hsbd->responseLatency = 0;
        return hsbd;
    } else
        return NULL;
}

static void
freeHttpSessionBreakdown (void *sbd) {
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    if (hsbd == NULL)
        return;

    if (hsbd->reqVer) {
        free (hsbd->reqVer);
        hsbd->reqVer = NULL;
    }

    if (hsbd->method) {
        free (hsbd->method);
        hsbd->method = NULL;
    }

    if (hsbd->url) {
        free (hsbd->url);
        hsbd->url = NULL;
    }

    if (hsbd->host) {
        free (hsbd->host);
        hsbd->host = NULL;
    }

    if (hsbd->userAgent) {
        free (hsbd->userAgent);
        hsbd->userAgent = NULL;
    }

    if (hsbd->referer) {
        free (hsbd->referer);
        hsbd->referer = NULL;
    }

    if (hsbd->accept) {
        free (hsbd->accept);
        hsbd->accept = NULL;
    }

    if (hsbd->acceptLanguage) {
        free (hsbd->acceptLanguage);
        hsbd->acceptLanguage = NULL;
    }

    if (hsbd->acceptEncoding) {
        free (hsbd->acceptEncoding);
        hsbd->acceptEncoding = NULL;
    }

    if (hsbd->xForwardedFor) {
        free (hsbd->xForwardedFor);
        hsbd->xForwardedFor = NULL;
    }

    if (hsbd->reqConnection) {
        free (hsbd->reqConnection);
        hsbd->reqConnection = NULL;
    }

    if (hsbd->respVer) {
        free (hsbd->respVer);
        hsbd->respVer = NULL;
    }

    if (hsbd->contentType) {
        free (hsbd->contentType);
        hsbd->contentType = NULL;
    }

    if (hsbd->respConnection) {
        free (hsbd->respConnection);
        hsbd->respConnection = NULL;
    }

    free (sbd);
}

static inline int
genHttpBreakdownState (uint16_t statusCode) {
    int st = statusCode / 100;
    if (st == 1 || st == 2 || st == 3)
        return HTTP_BREAKDOWN_OK;
    else
        return HTTP_BREAKDOWN_ERROR;
}

static int
generateHttpSessionBreakdown (void *sd, void *sbd) {
    httpSessionDetailNodePtr hsdn;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    listFirstEntry (hsdn, &hsd->head, node);
    if (hsdn == NULL)
        return -1;
    /* Remove from httpSessionDetailNode list */
    listDel (&hsdn->node);

    if (hsdn->reqVer) {
        hsbd->reqVer = strdup (hsdn->reqVer);
        if (hsbd->reqVer == NULL) {
            LOGE ("Strdup httpSessionBreakdown reqVer error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->method) {
        hsbd->method = strdup (hsdn->method);
        if (hsbd->method == NULL) {
            LOGE ("Strdup httpSessionBreakdown method error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->url) {
        hsbd->url = strdup (hsdn->url);
        if (hsbd->url == NULL) {
            LOGE ("Strdup httpSessionBreakdown request url error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->host) {
        hsbd->host = strdup (hsdn->host);
        if (hsbd->host == NULL) {
            LOGE ("Strdup http host error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->userAgent) {
        hsbd->userAgent = strdup (hsdn->userAgent);
        if (hsbd->userAgent == NULL) {
            LOGE ("Strdup http User-Agent error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->referer) {
        hsbd->referer = strdup (hsdn->referer);
        if (hsbd->referer == NULL) {
            LOGE ("Strdup httpSessionBreakdown referer url error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->accept) {
        hsbd->accept = strdup (hsdn->accept);
        if (hsbd->accept == NULL) {
            LOGE ("Strdup httpSessionBreakdown accept error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->acceptLanguage) {
        hsbd->acceptLanguage = strdup (hsdn->acceptLanguage);
        if (hsbd->acceptLanguage == NULL) {
            LOGE ("Strdup httpSessionBreakdown acceptLanguage error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->acceptEncoding) {
        hsbd->acceptEncoding = strdup (hsdn->acceptEncoding);
        if (hsbd->acceptEncoding == NULL) {
            LOGE ("Strdup httpSessionBreakdown acceptEncoding error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->xForwardedFor) {
        hsbd->xForwardedFor = strdup (hsdn->xForwardedFor);
        if (hsbd->xForwardedFor == NULL) {
            LOGE ("Strdup httpSessionBreakdown xForwardedFor error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->reqConnection) {
        hsbd->reqConnection = strdup (hsdn->reqConnection);
        if (hsbd->reqConnection == NULL) {
            LOGE ("Strdup httpSessionBreakdown reqConnection error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->respVer) {
        hsbd->respVer = strdup (hsdn->respVer);
        if (hsbd->respVer == NULL) {
            LOGE ("Strdup httpSessionBreakdown respVer error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->contentType) {
        hsbd->contentType = strdup (hsdn->contentType);
        if (hsbd->contentType == NULL) {
            LOGE ("Strdup httpSessionBreakdown Content-Type error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->respConnection) {
        hsbd->respConnection = strdup (hsdn->respConnection);
        if (hsbd->respConnection == NULL) {
            LOGE ("Strdup httpSessionBreakdown respConnection error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    switch (hsdn->state) {
        /* Reset before http request */
        case HTTP_RESPONSE_BODY_COMPLETE:
            hsbd->state = genHttpBreakdownState (hsdn->statusCode);
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = hsdn->respHeaderSize;
            hsbd->respBodySize = hsdn->respBodySize;
            hsbd->serverLatency = hsdn->respTimeBegin - hsdn->reqTime;
            hsbd->responseLatency = hsdn->respTimeEnd - hsdn->respTimeBegin;
            break;

        case HTTP_RESET_TYPE1:
        case HTTP_RESET_TYPE2:
            if (hsdn->state == HTTP_RESET_TYPE1)
                hsbd->state = HTTP_BREAKDOWN_RESET_TYPE1;
            else
                hsbd->state = HTTP_BREAKDOWN_RESET_TYPE2;
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = 0;
            hsbd->respBodySize = 0;
            hsbd->serverLatency = 0;
            hsbd->responseLatency = 0;

        case HTTP_RESET_TYPE3:
            hsbd->state = HTTP_BREAKDOWN_RESET_TYPE3;
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = hsdn->respHeaderSize;
            hsbd->respBodySize = hsdn->respBodySize;
            hsbd->serverLatency = hsdn->respTimeBegin - hsdn->reqTime;
            hsbd->responseLatency = 0;

        default:
            LOGE ("Wrong http state for breakdown.\n");
            freeHttpSessionDetailNode (hsdn);
            return -1;
    }

    /* Free session detail node */
    freeHttpSessionDetailNode (hsdn);

    return 0;
}

static void
httpSessionBreakdown2Json (struct json_object *root, void *sd, void *sbd) {
    int st;
    char buf [64];
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    if (hsbd->reqVer)
        json_object_object_add (root, HTTP_SBKD_REQUEST_VERSION, json_object_new_string (hsbd->reqVer));
    else
        json_object_object_add (root, HTTP_SBKD_REQUEST_VERSION, NULL);

    if (hsbd->method)
        json_object_object_add (root, HTTP_SBKD_METHOD, json_object_new_string (hsbd->method));
    else
        json_object_object_add (root, HTTP_SBKD_METHOD, NULL);

    if (hsbd->url)
        json_object_object_add (root, HTTP_SBKD_URL, json_object_new_string (hsbd->url));
    else
        json_object_object_add (root, HTTP_SBKD_URL, NULL);

    if (hsbd->host)
        json_object_object_add (root, HTTP_SBKD_HOST, json_object_new_string (hsbd->host));
    else
        json_object_object_add (root, HTTP_SBKD_HOST, NULL);

    if (hsbd->userAgent)
        json_object_object_add (root, HTTP_SBKD_USER_AGENT, json_object_new_string (hsbd->userAgent));
    else
        json_object_object_add (root, HTTP_SBKD_USER_AGENT, NULL);

    if (hsbd->referer)
        json_object_object_add (root, HTTP_SBKD_REFERER, json_object_new_string (hsbd->referer));
    else
        json_object_object_add (root, HTTP_SBKD_REFERER, NULL);

    if (hsbd->accept)
        json_object_object_add (root, HTTP_SBKD_ACCEPT, json_object_new_string (hsbd->accept));
    else
        json_object_object_add (root, HTTP_SBKD_ACCEPT, NULL);

    if (hsbd->acceptLanguage)
        json_object_object_add (root, HTTP_SBKD_ACCEPT_LANGUAGE, json_object_new_string (hsbd->acceptLanguage));
    else
        json_object_object_add (root, HTTP_SBKD_ACCEPT_LANGUAGE, NULL);

    if (hsbd->acceptEncoding)
        json_object_object_add (root, HTTP_SBKD_ACCEPT_ENCODING, json_object_new_string (hsbd->acceptEncoding));
    else
        json_object_object_add (root, HTTP_SBKD_ACCEPT_ENCODING, NULL);

    if (hsbd->xForwardedFor)
        json_object_object_add (root, HTTP_SBKD_X_FORWARDED_FOR, json_object_new_string (hsbd->xForwardedFor));
    else
        json_object_object_add (root, HTTP_SBKD_X_FORWARDED_FOR, NULL);

    if (hsbd->reqConnection)
        json_object_object_add (root, HTTP_SBKD_REQUEST_CONNECTION, json_object_new_string (hsbd->reqConnection));
    else
        json_object_object_add (root, HTTP_SBKD_REQUEST_CONNECTION, NULL);

    if (hsbd->respVer)
        json_object_object_add (root, HTTP_SBKD_RESPONSE_VERSION, json_object_new_string (hsbd->respVer));
    else
        json_object_object_add (root, HTTP_SBKD_RESPONSE_VERSION, NULL);

    if (hsbd->contentType)
        json_object_object_add (root, HTTP_SBKD_CONTENT_TYPE, json_object_new_string (hsbd->contentType));
    else
        json_object_object_add (root, HTTP_SBKD_CONTENT_TYPE, NULL);

    if (hsbd->respConnection)
        json_object_object_add (root, HTTP_SBKD_RESPONSE_CONNECTION, json_object_new_string (hsbd->respConnection));
    else
        json_object_object_add (root, HTTP_SBKD_RESPONSE_CONNECTION, NULL);

    UINT32_TO_STRING (buf, hsbd->state);
    json_object_object_add (root, HTTP_SBKD_STATE, json_object_new_string (buf));

    UINT16_TO_STRING (buf, hsbd->statusCode);
    json_object_object_add (root, HTTP_SBKD_STATUS_CODE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->reqHeaderSize);
    json_object_object_add (root, HTTP_SBKD_REQUEST_HEADER_SIZE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->reqBodySize);
    json_object_object_add (root, HTTP_SBKD_REQUEST_BODY_SIZE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->respHeaderSize);
    json_object_object_add (root, HTTP_SBKD_RESPONSE_HEADER_SIZE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->respBodySize);
    json_object_object_add (root, HTTP_SBKD_RESPONSE_BODY_SIZE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->serverLatency);
    json_object_object_add (root, HTTP_SBKD_SERVER_LATENCY, json_object_new_string (buf));
    
    UINT64_TO_STRING (buf, hsbd->responseLatency);
    json_object_object_add (root, HTTP_SBKD_RESPONSE_LATENCY, json_object_new_string (buf));
}

static void
httpSessionProcessEstb (void *sd, timeValPtr tm) {
    return;
}

static void
httpSessionProcessUrgData (int fromClient, char urgData, void *sd, timeValPtr tm) {
    return;
}

static int
httpSessionProcessData (int fromClient, const u_char *data, int dataLen, void *sd, timeValPtr tm, int *sessionDone) {
    int parseCount;

    currTime = tm;
    currSessionDone = 0;
    currHeaderType = HTTP_HEADER_IGNORE;
    currSessionDetail = (httpSessionDetailPtr) sd;

    if (fromClient)
        parseCount = http_parser_execute (&currSessionDetail->reqParser, &currSessionDetail->reqParserSettings,
                                          (const char *) data, dataLen);
    else
        parseCount = http_parser_execute (&currSessionDetail->resParser, &currSessionDetail->resParserSettings,
                                          (const char *) data, dataLen);

    *sessionDone = currSessionDone;
    return parseCount;
}

static void
httpSessionProcessReset (int fromClient, void *sd, timeValPtr tm) {
    httpSessionDetailNodePtr currNode;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    listFirstEntry (currNode, &hsd->head, node);
    if (currNode == NULL)
        return;

    if (currNode->state == HTTP_REQUEST_HEADER ||
        currNode->state == HTTP_REQUEST_HEADER_COMPLETE ||
        currNode->state == HTTP_REQUEST_BODY)
        currNode->state = HTTP_RESET_TYPE1;
    else if (currNode->state == HTTP_REQUEST_BODY_COMPLETE)
        currNode->state = HTTP_RESET_TYPE2;
    else
        currNode->state = HTTP_RESET_TYPE3;
}

static void
httpSessionProcessFin (int fromClient, void *sd, timeValPtr tm, int *sessionDone) {
    httpSessionDetailNodePtr currNode;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    if (!fromClient) {
        listFirstEntry (currNode, &hsd->head, node);
        if (currNode == NULL)
            return;

        if (currNode->state == HTTP_RESPONSE_BODY) {
            currNode->state = HTTP_RESPONSE_BODY_COMPLETE;
            *sessionDone = 1;
        }
    }
}

protoParser httpParser = {
    .initProto = initHttpProto,
    .destroyProto = destroyHttpProto,
    .newSessionDetail = newHttpSessionDetail,
    .freeSessionDetail = freeHttpSessionDetail,
    .newSessionBreakdown = newHttpSessionBreakdown,
    .freeSessionBreakdown = freeHttpSessionBreakdown,
    .generateSessionBreakdown = generateHttpSessionBreakdown,
    .sessionBreakdown2Json = httpSessionBreakdown2Json,
    .sessionProcessEstb = httpSessionProcessEstb,
    .sessionProcessUrgData = httpSessionProcessUrgData,
    .sessionProcessData = httpSessionProcessData,
    .sessionProcessReset = httpSessionProcessReset,
    .sessionProcessFin = httpSessionProcessFin
};
