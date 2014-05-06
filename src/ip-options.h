#ifndef __AGENT_IP_OPTIONS_H__
#define __AGENT_IP_OPTIONS_H__

#include <sys/types.h>

#define ipCheckAddr(x) 0

struct ip_options {
    uint32_t faddr;                     /**< Saved first hop address */
    uint8_t optlen;
    uint8_t srr;
    uint8_t rr;
    uint8_t ts;
    uint8_t isSetbyuser:1,              /**< Set by setsockopt?                   */
            isData:1,                   /**< Options in __data, rather than skb   */
            isStrictroute:1,            /**< Strict source route                  */
            srrIsHit:1,                 /**< Packet destination addr was our one  */
            isChanged:1,                /**< IP checksum more not valid           */
            rrNeedaddr:1,               /**< Need to record addr of outgoing dev  */
            tsNeedtime:1,               /**< Need to record timestamp             */
            tsNeedaddr:1;               /**< Need to record addr of outgoing dev  */
    uint8_t routerAlert;
    uint8_t __pad1;
    uint8_t __pad2;
    uint8_t __data [0];
};

/*========================Interfaces definition============================*/
int
ipOptionsCompile (const u_char *iph);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_IP_OPTIONS_H__ */
