#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "tcp-options.h"

/*
 * @brief Get tcp timestamp option
 *
 * @param tcph tcp header
 * @param ts time stamp receive pointer
 *
 * @return 1 if time stamp option on else 0
 */
int
getTimeStampOption (struct tcphdr *tcph, u_int *ts) {
    int len;
    u_int timeStamp;
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
 * @param ws window scale return pointer
 *
 * @return 1 if window scale option on else 0
 */
int
getTcpWindowScaleOption (struct tcphdr *tcph, u_int *ws) {
    int len;
    u_int wscale;
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
                wscale = options [index + 2];
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
