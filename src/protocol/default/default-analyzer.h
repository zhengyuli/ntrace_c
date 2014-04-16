#ifndef __WDM_AGENT_DEFAULT_ANALYZER_H__
#define __WDM_AGENT_DEFAULT_ANALYZER_H__

#include <stdint.h>
#include "protocol.h"

typedef struct _defaultSessionDetail defaultSessionDetail;
typedef defaultSessionDetail *defaultSessionDetailPtr;

struct _defaultSessionDetail {
    uint64_t serverTimeBegin;           /**< Default server time begin */
    uint64_t serverTimeEnd;             /**< Default server time end */
    uint64_t exchangeSize;              /**< Default data size exchanged between client and server */
};

typedef struct _defaultSessionBreakdown defaultSessionBreakdown;
typedef defaultSessionBreakdown *defaultSessionBreakdownPtr;

struct _defaultSessionBreakdown {
    uint64_t serverLatency;             /**< Default server latency */
    uint64_t exchangeSize;              /**< Default data size exchanged */
};

/* Default session breakdown json key definitions */
#define DEFAULT_SBKD_SERVER_LATENCY    "default_server_latency"
#define DEFAULT_SBKD_EXCHANGE_SIZE     "default_exchange_size"

/*========================Interfaces definition============================*/
extern protoParser defaultParser;
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_DEFAULT_ANALYZER_H__ */
