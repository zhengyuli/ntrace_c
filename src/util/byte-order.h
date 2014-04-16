#ifndef __WDM_AGENT_BYTE_ORDER_H__
#define __WDM_AGENT_BYTE_ORDER_H__

#include <stdint.h>

static inline uint64_t
ntoh64 (uint64_t src) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_t dst;
    uint8_t *dbytep = (uint8_t *) &dst;
    uint8_t *sbytep = (uint8_t *) &src;

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

static inline uint64_t
hton64 (uint64_t src) {
    return ntoh64 (src);
}

#endif /* __WDM_AGENT_BYTE_ORDER_H__ */
