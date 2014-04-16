#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "util.h"

inline uint64_t
timeVal2MilliSecond (timeValPtr tm) {
    uint64_t milli;

    milli = (tm->tv_sec * 1000) + (tm->tv_usec / 1000);
    return milli;
}

int
strEqualIgnoreCase (const char *str1, const char *str2) {
    if (strlen (str1) != strlen (str2))
        return 0;
    else {
        while (*str1) {
            if (tolower (*str1) != tolower (*str2))
                return 0;
            str1++;
            str2++;
        }
        return 1;
    }
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

/*
 * Check whether file is existed, if existed return 1
 * else return 0.
 */
int
fileExist (const char *path, int amode)
{
    if (access (path, amode))
        return 0;
    else
        return 1;
}

/* Check remote service status, if is running then return 1
 * else return 0 */
int
remoteServiceRun (const char *svcIp, uint16_t svcPort) {
    int ret;
    int sockfd;
    struct sockaddr_in srvAddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        return 0;

    memset (&srvAddr, 0, sizeof (srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons (svcPort);
    ret = inet_pton (AF_INET, svcIp ? svcIp : "127.0.0.1", &srvAddr.sin_addr);
    if (ret <= 0)
        return 0;

    ret = connect (sockfd, (const struct sockaddr *) &srvAddr, sizeof (srvAddr));
    if(ret < 0) {
        close (sockfd);
        return 0;
    } else {
        close (sockfd);
        return 1;
    }
}
