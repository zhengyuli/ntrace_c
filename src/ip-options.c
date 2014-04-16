#include <string.h>
#include <netinet/ip.h>
#include "ip-options.h"

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
    int optlen;
    u_char *optptr;
    u_char *ppPtr = 0;
    char optholder [16];
    struct ip_options *opt;
    int skb = 1;
    int skbPaAddr = 314159;
    uint32_t midtime;
    uint32_t addr;
    struct timestamp *ts;
    uint32_t *timeptr;

    opt = (struct ip_options *) optholder;
    memset (opt, 0, sizeof (struct ip_options));
    opt->optlen = ((struct ip *) iph)->ip_hl * 4 - sizeof (struct ip);
    optptr = iph + sizeof (struct ip);
    opt->isData = 0;

    for (l = opt->optlen; l > 0;) {
        switch (*optptr) {
            case IPOPT_END:
                for (optptr++, l--; l > 0; l--) {
                    if (*optptr != IPOPT_END) {
                        *optptr = IPOPT_END;
                        opt->isChanged = 1;
                    }
                }
                goto eol;

            case IPOPT_NOOP:
                l--;
                optptr++;
                continue;
        }

        optlen = optptr [1];
        if (optlen < 2 || optlen > l) {
            ppPtr = optptr;
            goto error;
        }

        switch (*optptr) {
            case IPOPT_SSRR:
            case IPOPT_LSRR:
                if (optlen < 3) {
                    ppPtr = optptr + 1;
                    goto error;
                }
                if (optptr [2] < 4) {
                    ppPtr = optptr + 2;
                    goto error;
                }
                /* NB: cf RFC-1812 5.2.4.1 */
                if (opt->srr) {
                    ppPtr = optptr;
                    goto error;
                }
                if (!skb) {
                    if (optptr [2] != 4 || optlen < 7 || ((optlen - 3) & 3)) {
                        ppPtr = optptr + 1;
                        goto error;
                    }
                    memcpy (&opt->faddr, &optptr [3], 4);
                    if (optlen > 7)
                        memmove (&optptr [3], &optptr [7], optlen - 7);
                }
                opt->isStrictroute = (optptr [0] == IPOPT_SSRR);
                opt->srr = optptr - iph;
                break;

            case IPOPT_RR:
                if (opt->rr) {
                    ppPtr = optptr;
                    goto error;
                }
                if (optlen < 3) {
                    ppPtr = optptr + 1;
                    goto error;
                }
                if (optptr [2] < 4) {
                    ppPtr = optptr + 2;
                    goto error;
                }
                if (optptr [2] <= optlen) {
                    if (optptr [2] + 3 > optlen) {
                        ppPtr = optptr + 2;
                        goto error;
                    }
                    if (skb) {
                        memcpy (&optptr [optptr [2] - 1], &skbPaAddr, 4);
                        opt->isChanged = 1;
                    }
                    optptr [2] += 4;
                    opt->rrNeedaddr = 1;
                }
                opt->rr = optptr - iph;
                break;

            case IPOPT_TIMESTAMP:
                if (opt->ts) {
                    ppPtr = optptr;
                    goto error;
                }
                if (optlen < 4) {
                    ppPtr = optptr + 1;
                    goto error;
                }
                if (optptr [2] < 5) {
                    ppPtr = optptr + 2;
                    goto error;
                }
                if (optptr [2] <= optlen) {
                    ts = (struct timestamp *) (optptr + 1);
                    timeptr = 0;

                    if (ts->ptr + 3 > ts->len) {
                        ppPtr = optptr + 2;
                        goto error;
                    }

                    switch (ts->flags) {
                        case IPOPT_TS_TSONLY:
                            opt->ts = optptr - iph;
                            if (skb)
                                timeptr = (uint32_t *) &optptr [ts->ptr - 1];
                            opt->tsNeedtime = 1;
                            ts->ptr += 4;
                            break;

                        case IPOPT_TS_TSANDADDR:
                            if (ts->ptr + 7 > ts->len) {
                                ppPtr = optptr + 2;
                                goto error;
                            }
                            opt->ts = optptr - iph;
                            if (skb) {
                                memcpy (&optptr [ts->ptr - 1], &skbPaAddr, 4);
                                timeptr = (uint32_t *) & optptr [ts->ptr + 3];
                            }
                            opt->tsNeedaddr = 1;
                            opt->tsNeedtime = 1;
                            ts->ptr += 8;
                            break;

                        case IPOPT_TS_PRESPEC:
                            if (ts->ptr + 7 > ts->len) {
                                ppPtr = optptr + 2;
                                goto error;
                            }
                            opt->ts = optptr - iph;
                            {
                                memcpy (&addr, &optptr [ts->ptr - 1], 4);
                                if (ipCheckAddr (addr) == 0)
                                    break;
                                if (skb)
                                    timeptr = (uint32_t *) & optptr [ts->ptr + 3];
                            }
                            opt->tsNeedaddr = 1;
                            opt->tsNeedtime = 1;
                            ts->ptr += 8;
                            break;

                        default:
                            ppPtr = optptr + 3;
                            goto error;
                    }

                    if (timeptr) {
                        midtime = 1;
                        memcpy (timeptr, &midtime, sizeof (uint32_t));
                        opt->isChanged = 1;
                    }
                } else {
                    ts = (struct timestamp *) (optptr + 1);
                    if (ts->overflow == 15) {
                        ppPtr = optptr + 3;
                        goto error;
                    }
                    opt->ts = optptr - iph;
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
                    ppPtr = optptr;
                    goto error;
                }
                break;
        }

        l -= optlen;
        optptr += optlen;
    }

eol:
    opt = (struct ip_options *) optholder;
    if (!ppPtr)
        if (!opt->srr)
            return 0;

error:
    return -1;
}
