#include <string.h>
#include <netinet/ip.h>
#include "util.h"
#include "ip_options.h"

/*
 * @brief Check ip header options
 *
 * @param iph ip header
 *
 * @return 0 if success, else -1
 */
int
ipOptionsCompile (u_char *iph) {
    int l;
    u_char optHolder [16];
    struct ip_options *opt;
    u_int optlen;
    u_char *optPtr;
    u_char *ppPtr = 0;
    u_int skb = 1;
    u_int skbPaAddr = 314159;
    u_int midtime;
    u_int addr;
    struct timestamp *ts;
    u_int *timeptr;

    opt = (struct ip_options *) optHolder;
    memset (opt, 0, sizeof (struct ip_options));
    opt->optlen = ((struct ip *) iph)->ip_hl * 4 - sizeof (struct ip);
    optPtr = iph + sizeof (struct ip);
    opt->isData = 0;

    for (l = opt->optlen; l > 0;) {
        switch (*optPtr) {
            case IPOPT_END:
                for (optPtr++, l--; l > 0; l--) {
                    if (*optPtr != IPOPT_END) {
                        *optPtr = IPOPT_END;
                        opt->isChanged = 1;
                    }
                }
                goto endOfLine;

            case IPOPT_NOOP:
                l--;
                optPtr++;
                continue;
        }

        optlen = optPtr [1];
        if (optlen < 2 || optlen > l) {
            ppPtr = optPtr;
            goto error;
        }

        switch (*optPtr) {
            case IPOPT_SSRR:
            case IPOPT_LSRR:
                if (optlen < 3) {
                    ppPtr = optPtr + 1;
                    goto error;
                }
                if (optPtr [2] < 4) {
                    ppPtr = optPtr + 2;
                    goto error;
                }
                /* NB: cf RFC-1812 5.2.4.1 */
                if (opt->srr) {
                    ppPtr = optPtr;
                    goto error;
                }
                if (!skb) {
                    if (optPtr [2] != 4 || optlen < 7 || ((optlen - 3) & 3)) {
                        ppPtr = optPtr + 1;
                        goto error;
                    }
                    memcpy (&opt->faddr, &optPtr [3], 4);
                    if (optlen > 7)
                        memmove (&optPtr [3], &optPtr [7], optlen - 7);
                }
                opt->isStrictroute = (optPtr [0] == IPOPT_SSRR);
                opt->srr = optPtr - iph;
                break;

            case IPOPT_RR:
                if (opt->rr) {
                    ppPtr = optPtr;
                    goto error;
                }
                if (optlen < 3) {
                    ppPtr = optPtr + 1;
                    goto error;
                }
                if (optPtr [2] < 4) {
                    ppPtr = optPtr + 2;
                    goto error;
                }
                if (optPtr [2] <= optlen) {
                    if (optPtr [2] + 3 > optlen) {
                        ppPtr = optPtr + 2;
                        goto error;
                    }
                    if (skb) {
                        memcpy (&optPtr [optPtr [2] - 1], &skbPaAddr, 4);
                        opt->isChanged = 1;
                    }
                    optPtr [2] += 4;
                    opt->rrNeedaddr = 1;
                }
                opt->rr = optPtr - iph;
                break;

            case IPOPT_TIMESTAMP:
                if (opt->ts) {
                    ppPtr = optPtr;
                    goto error;
                }
                if (optlen < 4) {
                    ppPtr = optPtr + 1;
                    goto error;
                }
                if (optPtr [2] < 5) {
                    ppPtr = optPtr + 2;
                    goto error;
                }
                if (optPtr [2] <= optlen) {
                    ts = (struct timestamp *) (optPtr + 1);
                    timeptr = 0;

                    if (ts->ptr + 3 > ts->len) {
                        ppPtr = optPtr + 2;
                        goto error;
                    }

                    switch (ts->flags) {
                        case IPOPT_TS_TSONLY:
                            opt->ts = optPtr - iph;
                            if (skb)
                                timeptr = (u_int *) &optPtr [ts->ptr - 1];
                            opt->tsNeedtime = 1;
                            ts->ptr += 4;
                            break;

                        case IPOPT_TS_TSANDADDR:
                            if (ts->ptr + 7 > ts->len) {
                                ppPtr = optPtr + 2;
                                goto error;
                            }
                            opt->ts = optPtr - iph;
                            if (skb) {
                                memcpy (&optPtr [ts->ptr - 1], &skbPaAddr, 4);
                                timeptr = (u_int *) & optPtr [ts->ptr + 3];
                            }
                            opt->tsNeedaddr = 1;
                            opt->tsNeedtime = 1;
                            ts->ptr += 8;
                            break;

                        case IPOPT_TS_PRESPEC:
                            if (ts->ptr + 7 > ts->len) {
                                ppPtr = optPtr + 2;
                                goto error;
                            }
                            opt->ts = optPtr - iph;
                            {
                                memcpy (&addr, &optPtr [ts->ptr - 1], 4);
                                if (ipCheckAddr (addr) == 0)
                                    break;
                                if (skb)
                                    timeptr = (u_int *) & optPtr [ts->ptr + 3];
                            }
                            opt->tsNeedaddr = 1;
                            opt->tsNeedtime = 1;
                            ts->ptr += 8;
                            break;

                        default:
                            ppPtr = optPtr + 3;
                            goto error;
                    }

                    if (timeptr) {
                        midtime = 1;
                        memcpy (timeptr, &midtime, sizeof (u_int));
                        opt->isChanged = 1;
                    }
                } else {
                    ts = (struct timestamp *) (optPtr + 1);
                    if (ts->overflow == 15) {
                        ppPtr = optPtr + 3;
                        goto error;
                    }
                    opt->ts = optPtr - iph;
                    if (skb) {
                        ts->overflow++;
                        opt->isChanged = 1;
                    }
                }
                break;

            case IPOPT_SEC:
            case IPOPT_SID:
            default:
                if (!skb) {
                    ppPtr = optPtr;
                    goto error;
                }
                break;
        }

        l -= optlen;
        optPtr += optlen;
    }

endOfLine:
    opt = (struct ip_options *) optHolder;
    if (!ppPtr)
        if (!opt->srr)
            return 0;

error:
    return -1;
}
