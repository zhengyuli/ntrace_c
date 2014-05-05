#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "util.h"
#include "tcp-options.h"

/*
 * @brief Get tcp timestamp option
 *
 * @param tcph tcp header
 * @param ts pointer to return time stamp
 *
 * @return 1 if time stamp option on else 0
 */
int
getTimeStampOption (struct tcphdr *tcph, uint32_t *ts) {
    int len;
    uint32_t timeStamp;
    u_char *options;
    int index = 0;

    len = tcph->doff * 4;
    options = (u_char *) (tcph + 1);

    while (index <=  len - (int) sizeof (struct tcphdr) - 10 ) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return 0;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 8: /* TCPOPT_TIMESTAMP */
                memcpy ((char *) &timeStamp, options + index + 2, 4);
                *ts = ntohl (timeStamp);
                return 1;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return 0;
                index += options [index + 1];
        }
    }

    return 0;
}

/*
 * @brief Get tcp window scale option
 *
 * @param tcph tcp header
 * @param ws pointer to return window scale
 *
 * @return 1 if window scale option on else 0
 */
int
getTcpWindowScaleOption (struct tcphdr *tcph, uint16_t *ws) {
    int len;
    uint8_t wscale;
    u_char *options;
    int index = 0;

    *ws = 1;
    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <=  len - (int) sizeof (struct tcphdr) - 3) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return 0;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 3: /* TCPOPT_WSCALE */
                memcpy ((char *) &wscale, options + index + 2, 1);
                if (wscale > 14)
                    wscale = 14;
                *ws = (1 << wscale);
                return 1;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return 0;
                index += options [index + 1];
        }
    }

    return 0;
}

/*
 * @brief Get tcp MSS option
 *
 * @param tcph tcp header
 * @param mss pointer to return mss
 *
 * @return 1 if MSS option on else 0
 */
int
getTcpMssOption (struct tcphdr *tcph, uint16_t *mss) {
    int len;
    uint16_t maxiumSegSize;
    u_char *options;
    int index = 0;

    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <=  len - (int) sizeof (struct tcphdr) - 4 ) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return 0;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 2: /* TCPOPT_MSS */
                memcpy ((char *) &maxiumSegSize, options + index + 2, 2);
                *mss = ntohs (maxiumSegSize);
                return 1;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return 0;
                index += options [index + 1];
        }
    }

    return 0;
}
