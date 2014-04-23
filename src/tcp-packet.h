#ifndef __WDM_AGENT_TCP_PACKET_H__
#define __WDM_AGENT_TCP_PACKET_H__

#include <stdint.h>
#include "list.h"
#include "protocol.h"

#define TCP_FIN_SENT 15
#define TCP_FIN_CONFIRMED 16

typedef struct _skbuff skbuff;
typedef skbuff *skbuffPtr;

struct _skbuff {
    u_char *data;                       /**< Skbuff data */
    u_int len;                          /**< Skbuff length */
    u_int truesize;                     /**< Skbuff true size */
    u_int seq;                          /**< Skbuff sequence number */
    u_int ack;                          /**< Skbuff ack number */
    char urg;                           /**< Skbuff urgency data flag */
    u_int urgPtr;                       /**< Skbuff urgency pointer */
    char psh;                           /**< Skbuff push flag */
    char fin;                           /**< Skbuff fin flag */
    listHead node;                      /**< Skbuff list node */
};

typedef struct _halfStream halfStream;
typedef halfStream *halfStreamPtr;

struct _halfStream {
    int state;                          /**< Half stream state */
    u_char *rcvBuf;                     /**< Half stream receive buffer */
    u_int bufSize;                      /**< Half stream receive buffer size */
    u_int offset;                       /**< Half stream read offset */
    u_int count;                        /**< Half stream total data received */
    u_int countNew;                     /**< Half stream new data received */
    u_int seq;                          /**< Half stream send sequence number */
    u_int ackSeq;                       /**< Half stream ack sequence number */
    u_int firstDataSeq;                 /**< Half stream first data send sequence number */
    u_int urgCount;                     /**< Half stream urg data received */
    u_int urgCountNew;                  /**< Half stream new urg data count received */
    u_char urgData;                     /**< Half stream new urg data received */
    u_char urgSeen;                     /**< Half stream has new urg data flag */
    u_int urgPtr;                       /**< Half stream urg data pointer */
    u_short window;                     /**< Half stream current window size */
    u_char tsOn;                        /**< Half stream timestamp options on flag */
    u_char wscaleOn;                    /**< Half stream window scale options on flag */
    u_int currTs;                       /**< Half stream current timestamp */
    u_int wscale;                       /**< Half stream window scale size */
    u_int mss;                          /**< Half stream MSS (Maxium Segment Size) */
    listHead head;                      /**< Half stream skbuff list head */
    u_int rmemAlloc;                    /**< Half stream memory allocated for skbuff */
};

typedef struct _tuple4 tuple4;
typedef tuple4 *tuple4Ptr;

struct _tuple4 {
    struct in_addr saddr;               /**< source ip */
    uint16_t source;                    /**< source tcp port */
    struct in_addr daddr;               /**< dest ip */
    uint16_t dest;                      /**< dest tcp port */
};

/* Tcp stream state */
typedef enum {
    STREAM_INIT,
    STREAM_CONNECTED,
    STREAM_DATA_EXCHANGING,
    STREAM_CLOSING,
    STREAM_TIME_OUT,
    STREAM_CLOSED,
    STREAM_RESET_TYPE1,                 /**< Tcp connection reset type1 (from client and before connected) */
    STREAM_RESET_TYPE2,                 /**< Tcp connection reset type2 (from server and before connected) */
    STREAM_RESET_TYPE3,                 /**< Tcp connection reset type3 (from client and after connected) */ 
    STREAM_RESET_TYPE4,                 /**< Tcp connection reset type4 (from server and after connected) */ 
} streamState;

typedef struct _tcpStream tcpStream;
typedef tcpStream *tcpStreamPtr;

/* Tcp stream */
struct _tcpStream {
    protoType proto;                    /**< Service protocol type */
    protoParserPtr parser;              /**< Protocol parser */
    tuple4 addr;                        /**< Tcp stream 4-tuple address */
    uint64_t connId;                    /**< Global tcp connection id */
    streamState state;                  /**< Tcp stream state */
    halfStream client;                  /**< Tcp stream client halfStream */
    halfStream server;                  /**< Tcp stream server halfStream */
    uint64_t synTime;                   /**< Syn timestamp of three handshake */
    uint64_t retries;                   /**< Retries count */
    uint64_t retriesTime;               /**< The last retry timestamp */
    uint64_t dupSynAcks;                /**< Duplicate syn/acks of three handshake */
    uint64_t synAckTime;                /**< Syn/ack timestamp of three handshake */
    uint64_t estbTime;                  /**< Tcp connection success timestamp */
    uint64_t rtt;                       /**< Tcp round trip latency */
    uint64_t mss;                       /**< Tcp MSS */
    uint64_t totalPkts;                 /**< Tcp total packets */
    uint64_t tinyPkts;                  /**< Tcp tiny packets */
    uint64_t pawsPkts;                  /**< Tcp PAWS packets */
    uint64_t retransmittedPkts;         /**< Tcp retransmitted packets */
    uint64_t outOfOrderPkts;            /**< Tcp out of order packets */
    uint64_t zeroWindows;               /**< Tcp zero windows */
    uint64_t dupAcks;                   /**< Tcp duplicate acks */
    void *sessionDetail;                /**< Appliction session detail */
    int inClosingTimeout;               /**< In closing timeout list */
    uint64_t closeTime;                 /**< Tcp close time */
    listHead node;                      /**< Tcp stream list node */
};

typedef struct _tcpTimeout tcpTimeout;
typedef tcpTimeout *tcpTimeoutPtr;

/* Tcp closing timeout */
struct _tcpTimeout {
    tcpStreamPtr stream;                /**< Tcp stream to close */
    uint64_t timeout;                   /**< Tcp stream close timeout */
    listHead node;                      /**< Tcp stream timeout list node */
};

/* Tcp state for tcp breakdown */
typedef enum {
    TCP_CONNECTED = 0,                  /**< Tcp connection connected */
    TCP_DATA_EXCHANGING,                /**< Tcp connection data exchanging */
    TCP_CLOSED,                         /**< Tcp connection closed */
    TCP_RESET_TYPE1,                    /**< Tcp connection reset type1 (from client and before connected) */
    TCP_RESET_TYPE2,                    /**< Tcp connection reset type2 (from server and before connected) */
    TCP_RESET_TYPE3,                    /**< Tcp connection reset type3 (from client and after connected) */
    TCP_RESET_TYPE4                     /**< Tcp connection reset type4 (from server and after connected) */
} tcpBreakdownState;

typedef struct _tcpBreakdown tcpBreakdown;
typedef tcpBreakdown *tcpBreakdownPtr;

struct _tcpBreakdown {
    uint64_t bkdId;                     /**< Global breakdown id */
    uint64_t timestamp;                 /**< Timestamp in seconds */
    uint16_t proto;                     /**< Tcp application level protocol type */
    struct in_addr srcIp;               /**< Source ip */
    uint16_t srcPort;                   /**< Source port */
    struct in_addr svcIp;               /**< Service ip */
    uint16_t svcPort;                   /**< Service port */
    uint64_t connId;                    /**< Global tcp connection id */
    tcpBreakdownState state;            /**< Tcp state */
    uint64_t retries;                   /**< Tcp retries */
    uint64_t retriesLatency;            /**< Tcp retries latency in milliseconds */
    uint64_t dupSynAcks;                /**< Tcp duplicate syn/ack packages */
    uint64_t rtt;                       /**< Tcp round trip latency */
    uint64_t mss;                       /**< Tcp mss (maxium segment size) */
    uint64_t connLatency;               /**< Tcp connection latency in milliseconds */
    uint64_t totalPkts;                 /**< Tcp total packets */
    uint64_t tinyPkts;                  /**< Tcp tiny packets */
    uint64_t pawsPkts;                  /**< Tcp PAWS (Protect Against Wrapped Sequence numbers) packets */
    uint64_t retransmittedPkts;         /**< Tcp retransmitted packets */
    uint64_t outOfOrderPkts;            /**< Tcp out of order packets */
    uint64_t zeroWindows;               /**< Tcp zero windows */
    uint64_t dupAcks;                   /**< Tcp duplicate acks */
    void *sessionBreakdown;             /**< Application level session breakdown */
};

/* Common session breakdown json key definitions */
#define COMMON_SKBD_BREAKDOWN_ID                 "breakdown_id"
#define COMMON_SKBD_TIMESTAMP                    "timestamp"
#define COMMON_SKBD_PROTOCOL                     "protocol"
#define COMMON_SKBD_SOURCE_IP                    "source_ip"
#define COMMON_SKBD_SOURCE_PORT                  "source_port"
#define COMMON_SKBD_SERVICE_IP                   "service_ip"
#define COMMON_SKBD_SERVICE_PORT                 "service_port"
#define COMMON_SKBD_TCP_CONNECTION_ID            "tcp_connection_id"
#define COMMON_SKBD_TCP_STATE                    "tcp_state"
#define COMMON_SKBD_TCP_RETRIES                  "tcp_retries"
#define COMMON_SKBD_TCP_RETRIES_LATENCY          "tcp_retries_latency"
#define COMMON_SKBD_TCP_DUPLICATE_SYNACKS        "tcp_duplicate_synacks"
#define COMMON_SKBD_TCP_RTT                      "tcp_rtt"
#define COMMON_SKBD_TCP_MSS                      "tcp_mss"
#define COMMON_SKBD_TCP_CONNECTION_LATENCY       "tcp_connection_latency"
#define COMMON_SKBD_TCP_TOTAL_PACKETS            "tcp_total_packets"
#define COMMON_SKBD_TCP_TINY_PACKETS             "tcp_tiny_packets"
#define COMMON_SKBD_TCP_PAWS_PACKETS             "tcp_paws_packets"
#define COMMON_SKBD_TCP_RETRANSMITTED_PACKETS    "tcp_retransmitted_packets"
#define COMMON_SKBD_TCP_OUT_OF_ORDER_PACKETS     "tcp_out_of_order_packets"
#define COMMON_SKBD_TCP_ZERO_WINDOWS             "tcp_zero_windows"
#define COMMON_SKBD_TCP_DUPLICATE_ACKS           "tcp_duplicate_acks"

/* Tcp session breakdown callback */
typedef void * (*publishTcpBreakdownCB) (const char *tcpBreakdown, void *args);

/*========================Interfaces definition============================*/
void
tcpProcess (u_char *data, int skbLen, timeValPtr tm);
int
initTcp (publishTcpBreakdownCB publishTcpBreakdown, void *args);
void
destroyTcp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_TCP_PACKET_H__ */
