#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "util.h"

inline u_long_long
timeVal2Second (timeValPtr tm) {
    u_long_long second;

    second = tm->tvSec + (tm->tvUsec / 1000000);
    return second;
}

inline u_long_long
timeVal2MilliSecond (timeValPtr tm) {
    u_long_long milli;

    milli = (tm->tvSec * 1000) + (tm->tvUsec / 1000);
    return milli;
}

inline u_long_long
timeVal2MicoSecond (timeValPtr tm) {
    u_long_long micro;

    micro = (tm->tvSec * 1000000) + tm->tvUsec;
    return micro;
}

inline u_long_long
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

inline u_long_long
htonll (u_long_long src) {
    return ntohll (src);
}

BOOL
strEqualIgnoreCase (const char *str1, const char *str2) {
    if (strlen (str1) != strlen (str2))
        return FALSE;
    else {
        while (*str1) {
            if (tolower (*str1) != tolower (*str2))
                return FALSE;
            str1++;
            str2++;
        }
        return TRUE;
    }
}

BOOL
strEqual (const char *str1, const char *str2) {
    if (strlen (str1) != strlen (str2))
        return FALSE;

    if (!strcmp (str1, str2))
        return TRUE;
    else
        return FALSE;
}

ssize_t
safeRead (int fd, void *buf, size_t count) {
    size_t nread = 0;
    while (count > 0) {
        ssize_t r = read (fd, buf, count);
        if ((r < 0) && (errno == EINTR))
            continue;
        if (r < 0)
            return r;
        if (r == 0)
            return nread;
        buf = (char *) buf + r;
        count -= r;
        nread += r;
    }
    return nread;
}

ssize_t
safeWrite (int fd, const void *buf, size_t count) {
    size_t nwritten = 0;
    while (count > 0) {
        ssize_t r = write (fd, buf, count);

        if ((r < 0) && (errno == EINTR))
            continue;
        if (r < 0)
            return r;
        if (r == 0)
            return nwritten;
        buf = (const char *) buf + r;
        count -= r;
        nwritten += r;
    }
    return nwritten;
}

BOOL
fileExist (const char *path) {
    if (access (path, F_OK))
        return FALSE;
    else
        return TRUE;
}

BOOL
fileIsEmpty (const char *path) {
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0)
        return TRUE;

    if (!st.st_size)
        return TRUE;
    else
        return FALSE;
}

/*
 * @brief Get ip address of interface
 *
 * @param interface interface name, like eth0
 *
 * @return Ip address if exists else NULL
 */
char *
getIpAddrOfInterface (const char *interface) {
    int sockfd;
    size_t ifNameLen;
    struct ifreq ifr;
    char *ipAddr = NULL;
    struct sockaddr_in *sockAddr;

    ifNameLen = strlen (interface);
    if (ifNameLen < sizeof (ifr.ifr_name)) {
        strncpy (ifr.ifr_name, interface, ifNameLen);
        ifr.ifr_name [ifNameLen] = 0;
    } else
        return NULL;

    if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
        return NULL;
    if (ioctl (sockfd, SIOCGIFADDR, &ifr) < 0) {
        close (sockfd);
        return NULL;
    }

    sockAddr = (struct sockaddr_in *) &ifr.ifr_addr;
    ipAddr = strdup (inet_ntoa (sockAddr->sin_addr));

    close (sockfd);
    return ipAddr;
}

inline u_int
getCpuCores (void) {
    return sysconf (_SC_NPROCESSORS_CONF);
}
