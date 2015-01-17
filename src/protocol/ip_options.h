#ifndef __IP_OPTIONS_H__
#define __IP_OPTIONS_H__

#define ipCheckAddr(x) 0

struct ip_options {
    u_int faddr;                        /**< Saved first hop address */
    u_char optlen;
    u_char srr;
    u_char rr;
    u_char ts;
    u_char isSetbyuser:1,               /**< Set by setsockopt? */
           isData:1,                    /**< Options in __data, rather than skb */
           isStrictroute:1,             /**< Strict source route */
           srrIsHit:1,                  /**< Packet destination addr was our one */
           isChanged:1,                 /**< IP checksum more not valid */
           rrNeedaddr:1,                /**< Need to record addr of outgoing dev */
           tsNeedtime:1,                /**< Need to record timestamp */
           tsNeedaddr:1;                /**< Need to record addr of outgoing dev */
    u_char routerAlert;
    u_char __pad1;
    u_char __pad2;
    u_char __data [0];
};

/*========================Interfaces definition============================*/
int
ipOptionsCompile (u_char *iph);
/*=======================Interfaces definition end=========================*/

#endif /* __IP_OPTIONS_H__ */
