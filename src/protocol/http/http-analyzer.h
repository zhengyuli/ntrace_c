#ifndef __WDM_AGENT_HTTP_ANALYZER_H__
#define __WDM_AGENT_HTTP_ANALYZER_H__

#include <stdint.h>
#include "util.h"
#include "list.h"
#include "http_parser.h"
#include "protocol.h"

#define HTTP_VERSION_LENGTH 16

typedef enum {
    HTTP_OK = 0,                        /**< Http request ok */
    HTTP_ERROR,                         /**< Http request error */
    HTTP_RESET_TYPE1,                   /**< reset during request */
    HTTP_RESET_TYPE2,                   /**< reset after request and before response */
    HTTP_RESET_TYPE3                    /**< reset during response */
} httpBreakdownState;

typedef struct _httpSessionDetailNode httpSessionDetailNode;
typedef httpSessionDetailNode *httpSessionDetailNodePtr;

struct _httpSessionDetailNode {
    char reqVer [HTTP_VERSION_LENGTH];  /**< Http protocol request version */
    char *method;                       /**< Http request method */
    char *url;                          /**< Http request url */
    char *host;                         /**< Http server host */
    char *userAgent;                    /**< Http request user agent */
    char *referUrl;                     /**< Http request refer url */
    char *accept;                       /**< Http request accept sources */
    char *acceptLanguage;               /**< Http request accept language */
    char *acceptEncoding;               /**< Http request accept encoding */
    char *xForwardedFor;                /**< Http request x forwarded for */
    char *reqConnection;                /**< Http request connection */
    char respVer [HTTP_VERSION_LENGTH]; /**< Http protocol response version */
    char *contentType;                  /**< Http content type */
    char *respConnection;               /**< Http response connection */
    uint8_t state;                      /**< Http state */
    uint16_t statusCode;                /**< Http status code */
    uint64_t reqHeaderSize;             /**< Http request header size */
    uint64_t reqBodySize;               /**< Http request body size */
    uint64_t respHeaderSize;            /**< Http response header size */
    uint64_t pageSize;                  /**< Http page size */
    uint64_t requestTime;               /**< Http request time */
    uint64_t downloadTimeBegin;         /**< Http download begin time */
    uint64_t downloadTimeEnd;           /**< Http download end time */
    listHead node;                      /**< Http session detail node */
};

typedef struct _httpSessionDetail httpSessionDetail;
typedef httpSessionDetail *httpSessionDetailPtr;

/* Http session detail */
struct _httpSessionDetail {
    http_parser reqParser;                   /**< Http request parser */
    http_parser_settings reqParserSettings;  /**< Http request parser settings */
    http_parser resParser;                   /**< Http response parser */
    http_parser_settings resParserSettings;  /**< Http response parser settings */
    listHead head;                           /**< HttpSessionDetailNode list */
};

typedef struct _httpSessionBreakdown httpSessionBreakdown;
typedef httpSessionBreakdown *httpSessionBreakdownPtr;

/* Http session time breakdown */
struct _httpSessionBreakdown {
    char *reqVer;                       /**< Http protocol request version */
    char *method;                       /**< Http request method */
    char *url;                          /**< Http request url */
    char *host;                         /**< Http server host */
    char *userAgent;                    /**< Http request user agent */
    char *referUrl;                     /**< Http request refer url */
    char *accept;                       /**< Http request accept sources */
    char *acceptLanguage;               /**< Http request accept language */
    char *acceptEncoding;               /**< Http request accept encoding */
    char *xForwardedFor;                /**< Http request x forwarded for */
    char *reqConnection;                /**< Http request connection */
    char *respVer;                      /**< Http protocol response version */
    char *contentType;                  /**< Http response content type */
    char *respConnection;               /**< Http response connection */
    uint8_t state;                      /**< Http state */
    uint16_t statusCode;                /**< Http status code */
    uint64_t reqHeaderSize;             /**< Http request size */
    uint64_t reqBodySize;               /**< Http request size */
    uint64_t respHeaderSize;            /**< Http response size */
    uint64_t pageSize;                  /**< Http page size */
    uint64_t serverLatency;             /**< Http Server latency to first buffer */
    uint64_t downloadLatency;           /**<  Http download latency */
};

/* Http session breakdown json key definitions */
#define HTTP_REQUEST_VERSION           "http_request_version"
#define HTTP_SBKD_METHOD               "http_method"
#define HTTP_SBKD_URL                  "http_url"
#define HTTP_SBKD_HOST                 "http_host"
#define HTTP_SBKD_USER_AGENT           "http_user_agent"
#define HTTP_SBKD_REFER_URL            "http_refer_url"
#define HTTP_SBKD_ACCEPT               "http_accept"
#define HTTP_SBKD_ACCEPT_LANGUAGE      "http_accept_language"
#define HTTP_SBKD_ACCEPT_ENCODING      "http_accept_encoding"
#define HTTP_SBKD_X_FORWARDED_FOR      "http_x_forwarded_for"
#define HTTP_SBKD_REQUEST_CONNECTION   "http_request_connection"
#define HTTP_RESPONSE_VERSION          "http_response_version"
#define HTTP_SBKD_CONTENT_TYPE         "http_content_type"
#define HTTP_SBKD_RESPONSE_CONNECTION  "http_response_connection"
#define HTTP_SBKD_STATE                "http_state"
#define HTTP_SBKD_STATUS_CODE          "http_status_code"
#define HTTP_SBKD_REQUEST_HEADER_SIZE  "http_request_header_size"
#define HTTP_SBKD_REQUEST_BODY_SIZE    "http_request_body_size"
#define HTTP_SBKD_RESPONSE_HEADER_SIZE "http_response_header_size"
#define HTTP_SBKD_PAGE_SIZE            "http_page_size"
#define HTTP_SBKD_SERVER_LATENCY       "http_server_latency"
#define HTTP_SBKD_DOWNLOAD_LATENCY     "http_download_latency"

/*========================Interfaces definition============================*/
extern protoParser httpParser;
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_HTTP_ANALYZER_H__ */
