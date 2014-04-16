#ifndef __WDM_AGENT_IP_PACKET_H__
#define __WDM_AGENT_IP_PACKET_H__

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
    int expires;
    timerExpireFunc fun;
    void *data;
    listHead node;
};

typedef struct _skbBuf skbBuf;
typedef skbBuf *skbBufPtr;

struct _skbBuf {
    int truesize;
    u_char *data;
};

typedef struct _ipFrag ipFrag;
typedef ipFrag *ipFragPtr;

struct _ipFrag {
    int offset;                 /**< offset of fragment in IP datagram */
    int end;                    /**< last byte of data in datagram */
    int len;                    /**< length of this fragment */
    u_char *ptr;                /**< pointer into real fragment data */
    skbBufPtr skb;              /**< complete received fragment */
    listHead node;              /**< ipqueue list node */
};

typedef struct _hostFrag hostFrag;
typedef hostFrag *hostFragPtr;

struct _hostFrag {
    struct in_addr ip;
    listHead ipqueue;
    int ipFragMem;
};

typedef struct _ipq ipq;
typedef ipq *ipqPtr;

/* Describe an entry in the "incomplete datagrams" queue. */
struct _ipq {
    short ihlen;                /**< Length of the IP header */
    struct ip *iph;             /**< Pointer to IP header */
    int len;                    /**< Total length of original datagram */
    expireTimer timer;          /**< When will this queue expire? */
    hostFragPtr hf;             /**< HostFrag belongs to */
    listHead fragments;         /**< Linked list of received fragments */
    listHead node;              /**< Ipqueue list node */
};

/*========================Interfaces definition============================*/
int
ipDefragProcess (void *frame, int ipCaptureLen, struct ip **new);
int
initIp (void);
void
destroyIp (void);
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_IP_PACKET_H__ */
