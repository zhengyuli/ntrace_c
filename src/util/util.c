#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "typedef.h"
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

BOOL
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

BOOL
strEqual (const char *str1, const char *str2) {
    if (strlen (str1) != strlen (str2))
        return 0;

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

/*
 * Check whether file is existed, if existed return 1
 * else return 0.
 */
BOOL
fileExist (const char *path)
{
    if (access (path, F_OK))
        return FALSE;
    else
        return TRUE;
}
