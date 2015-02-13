#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include "util.h"

/* ========================================================================== */
u_long_long
timeVal2Second (timeValPtr tm) {
    u_long_long second;

    second = tm->tvSec + (tm->tvUsec / 1000000);
    return second;
}

u_long_long
timeVal2MilliSecond (timeValPtr tm) {
    u_long_long milli;

    milli = (tm->tvSec * 1000) + (tm->tvUsec / 1000);
    return milli;
}

u_long_long
timeVal2MicoSecond (timeValPtr tm) {
    u_long_long micro;

    micro = (tm->tvSec * 1000000) + tm->tvUsec;
    return micro;
}

/* ========================================================================== */
u_long_long
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

u_long_long
htonll (u_long_long src) {
    return ntohll (src);
}

/* ========================================================================== */
boolean
strEqualIgnoreCase (char *str1, char *str2) {
    if (strlen (str1) != strlen (str2))
        return false;

    while (*str1) {
        if (tolower (*str1) != tolower (*str2))
            return false;
        str1++;
        str2++;
    }
    return true;
}

boolean
strEqual (char *str1, char *str2) {
    if (strlen (str1) != strlen (str2))
        return false;

    if (!strcmp (str1, str2))
        return true;
    else
        return false;
}

/* ========================================================================== */
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
safeWrite (int fd, void *buf, size_t count) {
    size_t nwritten = 0;

    while (count > 0) {
        ssize_t r = write (fd, buf, count);
        if ((r < 0) && (errno == EINTR))
            continue;

        if (r < 0)
            return r;

        if (r == 0)
            return nwritten;

        buf = (char *) buf + r;
        count -= r;
        nwritten += r;
    }
    
    return nwritten;
}

boolean
fileExist (char *path) {
    if (access (path, F_OK))
        return false;
    else
        return true;
}

boolean
fileIsEmpty (char *path) {
    int ret;
    struct stat st;

    ret = stat (path, &st);
    if (ret < 0)
        return true;

    if (!st.st_size)
        return true;
    else
        return false;
}

/* ========================================================================== */
inline pid_t
gettid () {
    return syscall (SYS_gettid);
}

/*
 * @brief Get ip address of interface.
 *
 * @param interface interface name, like eth0
 *
 * @return Ip address if exists else NULL
 */
char *
getIpAddrOfInterface (char *interface) {
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

u_int
getCpuCoresNum (void) {
    return sysconf (_SC_NPROCESSORS_ONLN);
}

/*
 * @brief Get memory info
 * 
 * @param totalMem total memory in MB
 * @param freeMem free memory in MB
 */
void
getMemInfo (u_int *totalMem, u_int *freeMem) {
    *totalMem = sysconf (_SC_PHYS_PAGES) / 256;
    *freeMem = sysconf (_SC_AVPHYS_PAGES) / 256;
}

/* ========================================================================== */
