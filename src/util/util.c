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
timeVal2Second (timeValPtr tm) {
    uint64_t second;

    second = tm->tv_sec + (tm->tv_usec / 1000000);
    return second;
}

inline uint64_t
timeVal2MilliSecond (timeValPtr tm) {
    uint64_t milli;

    milli = (tm->tv_sec * 1000) + (tm->tv_usec / 1000);
    return milli;
}

inline uint64_t
timeVal2MicoSecond (timeValPtr tm) {
    uint64_t micro;

    micro = (tm->tv_sec * 1000000) + tm->tv_usec;
    return micro;
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
