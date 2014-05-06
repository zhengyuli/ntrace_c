#ifndef __AGENT_BYTE_ORDER_H__
#define __AGENT_BYTE_ORDER_H__

#include "typedef.h"

static inline u_long_long
ntohll (u_long_long src) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_long_long dst;
    u_char *dbytep = (u_char *) &dst;
    u_char *sbytep = (u_char *) &src;

    dbytep [0] = sbytep [7];
    dbytep [1] = sbytep [6];
    dbytep [2] = sbytep [5];
    dbytep [3] = sbytep [4];
    dbytep [4] = sbytep [3];
    dbytep [5] = sbytep [2];
    dbytep [6] = sbytep [1];
    dbytep [7] = sbytep [0];
    return dst;
#elif __BYTE_ORDER == __BIG_EDIAN
    return src;
#endif
}

static inline u_long_long
htonll (u_long_long src) {
    return ntohll (src);
}

#endif /* __AGENT_BYTE_ORDER_H__ */
