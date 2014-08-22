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
 * @return true if time stamp option on else false
 */
bool
getTimeStampOption (struct tcphdr *tcph, u_int *ts) {
    u_int len;
    u_int timeStamp;
    u_char *options;
    u_int index = 0;

    len = tcph->doff * 4;
    options = (u_char *) (tcph + 1);

    while (index <=  len - sizeof (struct tcphdr) - 10 ) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return false;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 8: /* TCPOPT_TIMESTAMP */
                memcpy ((char *) &timeStamp, options + index + 2, 4);
                *ts = ntohl (timeStamp);
                return true;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return false;
                index += options [index + 1];
        }
    }

    return false;
}

/*
 * @brief Get tcp window scale option
 *
 * @param tcph tcp header
 * @param ws pointer to return window scale
 *
 * @return true if window scale option on else false
 */
bool
getTcpWindowScaleOption (struct tcphdr *tcph, u_short *ws) {
    u_int len;
    u_char wscale;
    u_char *options;
    u_int index = 0;

    *ws = 1;
    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <=  len - sizeof (struct tcphdr) - 3) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return false;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 3: /* TCPOPT_WSCALE */
                memcpy ((char *) &wscale, options + index + 2, 1);
                if (wscale > 14)
                    wscale = 14;
                *ws = (1 << wscale);
                return true;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return false;
                index += options [index + 1];
        }
    }

    return false;
}

/*
 * @brief Get tcp MSS option
 *
 * @param tcph tcp header
 * @param mss pointer to return mss
 *
 * @return true if MSS option on else false
 */
bool
getTcpMssOption (struct tcphdr *tcph, u_short *mss) {
    u_int len;
    u_short maxiumSegSize;
    u_char *options;
    u_int index = 0;

    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <=  len - sizeof (struct tcphdr) - 4 ) {
        switch (options [index]) {
            case 0: /* TCPOPT_EOL */
                return false;

            case 1: /* TCPOPT_NOP */
                index++;
                continue;

            case 2: /* TCPOPT_MSS */
                memcpy ((char *) &maxiumSegSize, options + index + 2, 2);
                *mss = ntohs (maxiumSegSize);
                return true;

            default:
                if (options [index + 1] < 2 ) /* "silly option" */
                    return false;
                index += options [index + 1];
        }
    }

    return false;
}
