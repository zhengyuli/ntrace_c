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

typedef enum {
    HTTP_HEADER_HOST = 1,
    HTTP_HEADER_USER_AGENT,
    HTTP_HEADER_REFER_URL,
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_ACCEPT_LANGUAGE,
    HTTP_HEADER_ACCEPT_ENCODING,
    HTTP_HEADER_X_FORWARDED_FOR,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_CONNECTION,
    HTTP_HEADER_IGNORE
} httpHeaderType;

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
        hsdn->requestTime = timeVal2MilliSecond (currTime);
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

    if (strncmp ("Host", from, length) == 0)
        currHeaderType = HTTP_HEADER_HOST;
    else if (strncmp ("User-Agent", from, length) == 0)
        currHeaderType = HTTP_HEADER_USER_AGENT;
    else if (strncmp ("Referer", from, length) == 0)
        currHeaderType = HTTP_HEADER_REFER;
    else if (strncmp ("Accept", from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT;
    else if (strncmp ("Accept-Language", from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT_LANGUAGE;
    else if (strncmp ("Accept-Encoding", from, length) == 0)
        currHeaderType = HTTP_HEADER_ACCEPT_ENCODING;
    else if (strncmp ("X-Forwarded-For", from, length) == 0)
        currHeaderType = HTTP_HEADER_X_FORWARDED_FOR;
    else if (strncmp ("Connection", from, length) == 0)
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

        case HTTP_HEADER_REFER:
            currNode->referUrl = strndup (from, length);
            if (currNode->referUrl == NULL)
                LOGE ("Get Refer field error.\n");
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

    currNode->reqBodySize += length;

    return 0;
}

static int
onReqMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listTailEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->reqComplete = 1;

    return 0;
}

/* Response callback */
static int
onRespMessageBegin (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->downloadTimeBegin = timeVal2MilliSecond (currTime);

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

    if (strncmp ("Content-Type", from, length) == 0)
        currHeaderType = HTTP_HEADER_CONTENT_TYPE;
    else if (strncmp ("Connection", from, length) == 0)
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
    currNode->respHeaderSize = parser->nread;

    return 0;
}

static int
onRespBody (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->pageSize += length;
    currNode->downloadTimeEnd = timeVal2MilliSecond (currTime);

    return 0;
}

static int
onRespMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    listFirstEntry (currNode, &currSessionDetail->head, node);
    if (currNode == NULL)
        return 0;

    currNode->statusCode = parser->status_code;
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
        hsdn->referUrl = NULL;
        hsdn->accept = NULL;
        hsdn->acceptLanguage = NULL;
        hsdn->acceptEncoding = NULL;
        hsdn->xForwardedFor = NULL;
        hsdn->reqConnection = NULL;
        hsdn->reqComplete = 0;
        memset (hsdn->respVer, 0, HTTP_VERSION_LENGTH);
        hsdn->contentType = NULL;
        hsdn->respConnection = NULL;
        hsdn->state = 0;
        hsdn->statusCode = 0;
        hsdn->requestTime = 0;
        hsdn->requestAckTime = 0;
        hsdn->downloadTimeBegin = 0;
        hsdn->downloadTimeEnd = 0;
        hsdn->downloadSize = 0;
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

    if (hsdn->reqUrl) {
        free (hsdn->reqUrl);
        hsdn->reqUrl = NULL;
    }

    if (hsdn->host) {
        free (hsdn->host);
        hsdn->host = NULL;
    }

    if (hsdn->userAgent) {
        free (hsdn->userAgent);
        hsdn->userAgent = NULL;
    }

    if (hsdn->referUrl) {
        free (hsdn->referUrl);
        hsdn->referUrl = NULL;
    }

    if (hsdn->contentType) {
        free (hsdn->contentType);
        hsdn->contentType = NULL;
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
        memset (&hsd->misc, 0, sizeof (tcpMisc));

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
        hsbd->method = NULL;
        hsbd->reqUrl = NULL;
        hsbd->host = NULL;
        hsbd->userAgent = NULL;
        hsbd->referUrl = NULL;
        hsbd->contentType = NULL;
        hsbd->statusCode = 0;
        hsbd->networkTime = 0;
        hsbd->serverTime = 0;
        hsbd->downloadTime = 0;
        hsbd->downloadSize = 0;
        return hsbd;
    } else
        return NULL;
}

static void
freeHttpSessionBreakdown (void *sbd) {
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    if (hsbd == NULL)
        return;

    if (hsbd->method) {
        free (hsbd->method);
        hsbd->method = NULL;
    }

    if (hsbd->reqUrl) {
        free (hsbd->reqUrl);
        hsbd->reqUrl = NULL;
    }

    if (hsbd->host) {
        free (hsbd->host);
        hsbd->host = NULL;
    }

    if (hsbd->userAgent) {
        free (hsbd->userAgent);
        hsbd->userAgent = NULL;
    }

    if (hsbd->referUrl) {
        free (hsbd->referUrl);
        hsbd->referUrl = NULL;
    }

    if (hsbd->contentType) {
        free (hsbd->contentType);
        hsbd->contentType = NULL;
    }

    free (sbd);
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

    if (hsdn->method) {
        hsbd->method = strdup (hsdn->method);
        if (hsbd->method == NULL) {
            LOGE ("Strdup httpSessionBreakdown method error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    } else {
        LOGE ("Http method is NULL.\n");
        freeHttpSessionDetailNode (hsdn);
        return -1;
    }

    if (hsdn->reqUrl) {
        hsbd->reqUrl = strdup (hsdn->reqUrl);
        if (hsbd->reqUrl == NULL) {
            LOGE ("Strdup httpSessionBreakdown request url error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    } else {
        LOGE ("Http request url is NULL.\n");
        freeHttpSessionDetailNode (hsdn);
        return -1;
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

    if (hsdn->referUrl) {
        hsbd->referUrl = strdup (hsdn->referUrl);
        if (hsbd->referUrl == NULL) {
            LOGE ("Strdup httpSessionBreakdown refer url error: %s.\n", strerror (errno));
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

    switch (hsdn->statusCode) {
        case HTTP_ACTIVE_CLOSE:
            hsbd->statusCode = HTTP_ACTIVE_CLOSE;
            hsbd->networkTime = 0;
            hsbd->serverTime = 0;
            hsbd->downloadTime = 0;
            hsbd->downloadSize = 0;
            break;

        case HTTP_RESET_CLOSE:
            hsbd->statusCode = HTTP_RESET_CLOSE;
            hsbd->networkTime = 0;
            hsbd->serverTime = 0;
            hsbd->downloadTime = 0;
            hsbd->downloadSize = 0;
            break;

        default:
            if (!hsdn->requestTime || !hsdn->requestAckTime || !hsdn->downloadTimeBegin) {
                hsbd->statusCode = HTTP_ACTIVE_CLOSE;
                hsbd->networkTime = 0;
                hsbd->serverTime = 0;
                hsbd->downloadTime = 0;
                hsbd->downloadSize = 0;
                break;
            }

            hsbd->statusCode = hsdn->statusCode;

            if (hsdn->requestAckTime >= hsdn->downloadTimeBegin) {
                hsbd->networkTime = 0;
                hsbd->serverTime = hsdn->downloadTimeBegin - hsdn->requestTime;
            } else {
                hsbd->networkTime = hsdn->requestAckTime - hsdn->requestTime;
                hsbd->serverTime = hsdn->downloadTimeBegin - hsdn->requestAckTime;
            }

            if (hsdn->downloadTimeEnd == 0) {
                hsbd->downloadTime = 0;
                hsbd->downloadSize = 0;
            } else {
                hsbd->downloadTime = hsdn->downloadTimeEnd -hsdn->downloadTimeBegin;
                hsbd->downloadSize = hsdn->downloadSize;
            }
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

    json_object_object_add (root, HTTP_SBKD_REQUEST_METHOD, json_object_new_string (hsbd->method));
    json_object_object_add (root, HTTP_SBKD_REQUEST_URL, json_object_new_string (hsbd->reqUrl));

    if (hsbd->host)
        json_object_object_add (root, HTTP_SBKD_HOST, json_object_new_string (hsbd->host));

    if (hsbd->userAgent)
        json_object_object_add (root, HTTP_SBKD_USER_AGENT, json_object_new_string (hsbd->userAgent));

    if (hsbd->referUrl)
        json_object_object_add (root, HTTP_SBKD_REFER_URL, json_object_new_string (hsbd->referUrl));

    if (hsbd->contentType)
        json_object_object_add (root, HTTP_SBKD_CONTENT_TYPE, json_object_new_string (hsbd->contentType));

    /* If http response code is 1xx, 2xx or 3xx, request success */
    st = hsbd->statusCode / 100;
    if (st == 1 || st == 2 || st == 3)
        UINT32_TO_STRING (buf, 1);
    else
        UINT32_TO_STRING (buf, 0);
    json_object_object_add (root, HTTP_SBKD_REQUEST_SUCCESS, json_object_new_string (buf));

    UINT16_TO_STRING (buf, hsbd->statusCode);
    json_object_object_add (root, HTTP_SBKD_STATUS_CODE, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->networkTime);
    json_object_object_add (root, HTTP_SBKD_NETWORK_TIME, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->serverTime);
    json_object_object_add (root, HTTP_SBKD_SERVER_TIME, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->downloadTime);
    json_object_object_add (root, HTTP_SBKD_DOWNLOAD_TIME, json_object_new_string (buf));

    UINT64_TO_STRING (buf, hsbd->downloadSize);
    json_object_object_add (root, HTTP_SBKD_DOWNLOAD_SIZE, json_object_new_string (buf));
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

    currNode->statusCode = HTTP_RESET_CLOSE;
    *sessionDone = 1;
}

static void
httpSessionProcessFin (int fromClient, void *sd, timeValPtr tm, int *sessionDone) {
    httpSessionDetailNodePtr currNode;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    if (!fromClient) {
        listFirstEntry (currNode, &hsd->head, node);
        if (currNode == NULL)
            return;

        if (hsd->resParser.status_code == 0)
            currNode->statusCode = HTTP_ACTIVE_CLOSE;
        else
            currNode->statusCode = hsd->resParser.status_code;
        *sessionDone = 1;
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
