#ifndef __PROTO_DETECTION_PACKET_H__
#define __PROTO_DETECTION_PACKET_H__

#include <stdlib.h>
#include "util.h"
#include "list.h"
#include "ip.h"

typedef enum {
  TCP_SYN_PKT_SENT,
  TCP_SYN_PKT_RECV,
  TCP_CONN_ESTABLISHED,
  TCP_FIN_PKT_SENT,
  TCP_FIN_PKT_CONFIRMED,
  TCP_CONN_CLOSING,
  TCP_CONN_CLOSED
} tcpState;

typedef struct _skbuff skbuff;
typedef skbuff *skbuffPtr;

struct _skbuff {
    u_char *data;                       /**< Skbuff data */
    u_int len;                          /**< Skbuff length */
    u_int seq;                          /**< Skbuff sequence number */
    u_int ack;                          /**< Skbuff ack number */
    u_char urg;                         /**< Skbuff urgency data flag */
    u_short urgPtr;                     /**< Skbuff urgency pointer */
    u_char psh;                         /**< Skbuff push flag */
    u_char fin;                         /**< Skbuff fin flag */
    listHead node;                      /**< Skbuff list node */
};

typedef struct _halfStream halfStream;
typedef halfStream *halfStreamPtr;

struct _halfStream {
    tcpState state;                     /**< Tcp half stream state */
    u_char *rcvBuf;                     /**< Tcp half stream receive buffer */
    u_int bufSize;                      /**< Tcp half stream receive buffer size */
    u_int offset;                       /**< Tcp half stream read offset */
    u_int count;                        /**< Tcp half stream total data received */
    u_int countNew;                     /**< Tcp half stream new data received */
    u_int seq;                          /**< Tcp half stream send sequence number */
    u_int ackSeq;                       /**< Tcp half stream ack sequence number */
    u_int firstDataSeq;                 /**< Tcp half stream first data send sequence number */
    u_int urgCount;                     /**< Tcp half stream urg data received */
    u_int urgCountNew;                  /**< Tcp half stream new urg data count received */
    u_char urgData;                     /**< Tcp half stream new urg data received */
    u_char urgSeen;                     /**< Tcp half stream has new urg data flag */
    u_short urgPtr;                     /**< Tcp half stream urg data pointer */
    u_short window;                     /**< Tcp half stream current window size */
    boolean tsOn;                       /**< Tcp half stream timestamp options on flag */
    boolean wscaleOn;                   /**< Tcp half stream window scale options on flag */
    u_int currTs;                       /**< Tcp half stream current timestamp */
    u_short wscale;                     /**< Tcp half stream window scale size */
    u_short mss;                        /**< Tcp half stream MSS (Maxium Segment Size) */
    listHead head;                      /**< Tcp half stream skbuff list head */
    u_int rmemAlloc;                    /**< Tcp half stream memory allocated for skbuff */
};

typedef struct _tuple4 tuple4;
typedef tuple4 *tuple4Ptr;

struct _tuple4 {
    struct in_addr saddr;               /**< Source ip */
    u_short source;                     /**< Source tcp port */
    struct in_addr daddr;               /**< Dest ip */
    u_short dest;                       /**< Dest tcp port */
};

typedef enum {
    STREAM_INIT,
    STREAM_CONNECTED,
    STREAM_DATA_EXCHANGING,
    STREAM_CLOSING,
    STREAM_TIME_OUT,
    STREAM_CLOSED,
    STREAM_RESET
} tcpStreamState;

typedef struct _tcpStream tcpStream;
typedef tcpStream *tcpStreamPtr;

/* Tcp stream */
struct _tcpStream {
    char *proto;                        /**< Tcp application level proto name */
    tuple4 addr;                        /**< Tcp stream 4-tuple address */
    tcpStreamState state;               /**< Tcp stream state */
    halfStream client;                  /**< Tcp stream client halfStream */
    halfStream server;                  /**< Tcp stream server halfStream */
    u_int mss;                          /**< Tcp MSS */
    boolean inClosingTimeout;           /**< In closing timeout list flag */
    listHead node;                      /**< Tcp stream list node */
};

typedef struct _tcpStreamTimeout tcpStreamTimeout;
typedef tcpStreamTimeout *tcpStreamTimeoutPtr;

/* Tcp closing timeout */
struct _tcpStreamTimeout {
    tcpStreamPtr stream;                /**< Tcp stream to close */
    u_long_long timeout;                /**< Tcp stream timeout to close */
    listHead node;                      /**< Tcp stream timeout list node */
};

/*========================Interfaces definition============================*/
void
protoDetectionProcess (iphdrPtr iph, timeValPtr tm);
void
resetProtoDetectionContext (void);
int
initProtoDetectionContext (void);
void
destroyProtoDetectionContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROTO_DETECTION_PACKET_H__ */
