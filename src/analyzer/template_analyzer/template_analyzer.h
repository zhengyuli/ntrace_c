#ifndef __AGENT_CAT_ANALYZER_H__
#define __AGENT_CAT_ANALYZER_H__

typedef struct _templateSessionDetail templateSessionDetail;
typedef templateSessionDetail *templateSessionDetailPtr;

struct _templateSessionDetail {
    u_int exchangeSize;                 /**< Template data size exchanged between client and server */
    u_long_long serverTimeBegin;        /**< Template server time begin */
    u_long_long serverTimeEnd;          /**< Template server time end */
};

typedef struct _templateSessionBreakdown templateSessionBreakdown;
typedef templateSessionBreakdown *templateSessionBreakdownPtr;

struct _templateSessionBreakdown {
    u_int exchangeSize;                 /**< Template data size exchanged */
    u_int serverLatency;                /**< Template server latency */
};

/* Template session breakdown json key definitions */
#define TEMPLATE_SBKD_EXCHANGE_SIZE     "template_exchange_size"
#define TEMPLATE_SBKD_SERVER_LATENCY    "template_server_latency"

#endif /* __AGENT_TEMPLATE_ANALYZER_H__ */
