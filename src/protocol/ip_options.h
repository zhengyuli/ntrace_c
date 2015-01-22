#ifndef __IP_OPTIONS_H__
#define __IP_OPTIONS_H__

#define ipCheckAddr(x) 0

struct ip_options {
    u_int faddr;                        /**< Saved first hop address */
    u_char optlen;
    u_char srr;
    u_char rr;
    u_char ts;
    u_char isSetbyuser:1;               /**< Set by setsockopt? */
    u_char isData:1;                    /**< Options in __data, rather than skb */
    u_char isStrictroute:1;             /**< Strict source route */
    u_char srrIsHit:1;                  /**< Packet destination addr was our one */
    u_char isChanged:1;                 /**< IP checksum more not valid */
    u_char rrNeedaddr:1;                /**< Need to record addr of outgoing dev */
    u_char tsNeedtime:1;                /**< Need to record timestamp */
    u_char tsNeedaddr:1;                /**< Need to record addr of outgoing dev */
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
