#ifndef __TCP_PACKET_H__
#define __TCP_PACKET_H__

#include <stdlib.h>
#include <uuid/uuid.h>
#include <time.h>
#include "util.h"
#include "list.h"
#include "ip.h"

typedef enum {
    TCP_SYN_PKT_SENT,
    TCP_SYN_PKT_RECV,
    TCP_CONN_ESTABLISHED,
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
    u_int seq;                          /**< Tcp half stream send sequence number */
    u_int ackSeq;                       /**< Tcp half stream ack sequence number */
    u_int firstDataSeq;                 /**< Tcp half stream first data send sequence number */
    u_int urgCount;                     /**< Tcp half stream urg data received */
    u_char urgSeen;                     /**< Tcp half stream has new urg data flag */
    u_short urgPtr;                     /**< Tcp half stream urg data pointer */
    listHead head;                      /**< Tcp half stream skbuff list head */
};

typedef enum {
    STREAM_INIT,
    STREAM_CONNECTED,
    STREAM_CLOSED,
    STREAM_RESET
} tcpStreamState;

typedef struct _tuple4 tuple4;
typedef tuple4 *tuple4Ptr;

struct _tuple4 {
    struct in_addr saddr;               /**< Source ip */
    u_short source;                     /**< Source tcp port */
    struct in_addr daddr;               /**< Dest ip */
    u_short dest;                       /**< Dest tcp port */
};

typedef struct _tcpStream tcpStream;
typedef tcpStream *tcpStreamPtr;

/* Tcp stream */
struct _tcpStream {
    tuple4 addr;                        /**< Tcp stream 4-tuple address */
    tcpStreamState state;               /**< Tcp stream state */
    halfStream client;                  /**< Tcp stream client halfStream */
    halfStream server;                  /**< Tcp stream server halfStream */
    listHead node;                      /**< Tcp stream list node */
};

/*========================Interfaces definition============================*/
void
tcpProcess (iphdrPtr iph, timeValPtr tm);
int
initTcp (void *sock);
void
destroyTcp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __TCP_PACKET_H__ */
