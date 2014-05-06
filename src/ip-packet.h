#ifndef __AGENT_IP_PACKET_H__
#define __AGENT_IP_PACKET_H__

#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include "list.h"

#define IPF_NOTF 1
#define IPF_ISF 2
#define IPF_NEW 3
#define IPF_ERROR 4

typedef void (*timerExpireFunc) (void *data);

typedef struct _expireTimer expireTimer;
typedef expireTimer *expireTimerPtr;

struct _expireTimer {
    time_t expires;
    timerExpireFunc fun;
    void *data;
    listHead node;
};

typedef struct _skbBuf skbBuf;
typedef skbBuf *skbBufPtr;

struct _skbBuf {
    u_char *data;
    u_int truesize;
};

typedef struct _ipFrag ipFrag;
typedef ipFrag *ipFragPtr;

struct _ipFrag {
    u_short offset;                     /**< Offset of fragment in IP datagram */
    u_short end;                        /**< Last byte of data in datagram */
    u_short len;                        /**< Length of this fragment */
    u_char *ptr;                        /**< Pointer into real fragment data */
    skbBufPtr skb;                      /**< Complete received fragment */
    listHead node;                      /**< Ipqueue list node */
};

typedef struct _hostFrag hostFrag;
typedef hostFrag *hostFragPtr;

struct _hostFrag {
    struct in_addr ip;
    listHead ipqueue;
    u_int ipFragMem;
    expireTimer timer;
};

typedef struct _ipq ipq;
typedef ipq *ipqPtr;

/* Describe an entry in the "incomplete datagrams" queue. */
struct _ipq {
    u_short ihlen;                      /**< Length of the IP header */
    struct ip *iph;                     /**< Pointer to IP header */
    u_short len;                        /**< Total length of original datagram */
    expireTimer timer;                  /**< When will this queue expire? */
    hostFragPtr hf;                     /**< HostFrag belongs to */
    listHead fragments;                 /**< Linked list of received fragments */
    listHead node;                      /**< Ipqueue list node */
};

/*========================Interfaces definition============================*/
int
ipDefragProcess (struct ip *iph, u_int ipCaptureLen, struct ip **new);
int
initIp (void);
void
destroyIp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_IP_PACKET_H__ */
