/** 
 * @file util.h -*- c -*-
 * 
 * @brief agent utils interface
 * 
 * Time-stamp: <2015-01-07 13:35:06 Wednesday by lzy>
 * 
 * Copyright (c) 2011-2012, zhengyu li <lizhengyu419@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without" 
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __AGENT_UTIL_H__
#define __AGENT_UTIL_H__

#include <string.h>
#include <stdlib.h>

typedef long long int long_long;
typedef unsigned long long int u_long_long;

typedef enum {
    false = 0,
    true = 1
} boolean;

typedef struct _timeVal timeVal;
typedef timeVal *timeValPtr;

struct _timeVal {
    u_long_long tvSec;
    u_long_long tvUsec;
};

#define TABLE_SIZE(x) (sizeof (x) / sizeof ((x) [0]))

#define STRPREFIX(s1, s2) (!strncmp (s1, s2, strlen (s2)))

#define MAX_NUM(n1, n2) ((n1) > (n2) ? (n1) : (n2))
#define MIN_NUM(n1, n2) ((n1) > (n2) ? (n2) : (n1))

/* Number to string interfaces */
#define CHAR_TO_STRING(dst, val) sprintf (dst, "%d", val)
#define UCHAR_TO_STRING(dst, val) sprintf (dst, "%u", val)

#define SHORT_TO_STRING(dst, val) sprintf (dst, "%d", val)
#define USHORT_TO_STRING(dst, val) sprintf (dst, "%u", val)

#define INT_TO_STRING(dst, val) sprintf (dst, "%d", val)
#define UINT_TO_STRING(dst, val) sprintf (dst, "%u", val)

#define LONGLONG_TO_STRING(dst, val) sprintf (dst, "%lld", val)
#define ULONGLONG_TO_STRING(dst, val) sprintf (dst, "%llu", val)

#define FLOAT_TO_STRING(dst, val) sprintf (dst, "%f", val)

#define DOUBLE_TO_STRING(dst, val) sprintf (dst, "%lf", val)

/* String to number interfaces */
#define STRING_TO_CHAR(dst, str) sscanf (str, "%d", (int *) dst)
#define STRING_TO_UCHAR(dst, str) sscanf (str, "%u", (u_int *) dst)

#define STRING_TO_SHORT(dst, str) sscanf (str, "%d", (int *) dst)
#define STRING_TO_USHORT(dst, str) sscanf (str, "%u", (u_int *) dst)

#define STRING_TO_INT(dst, str) sscanf (str, "%d", (int *) dst)
#define STRING_TO_UINT(dst, str) sscanf (str, "%u", (u_int *) dst)

#define STRING_TO_LONGLONG(dst, str) sscanf (str, "%lld", (long_long *) dst)
#define STRING_TO_ULONGLONG(dst, str) sscanf (str, "%llu", (u_long_long *) dst)

#define STRING_TO_FLOAT(dst, str) sscanf (str, "%f", (float *) dst)

#define STRING_TO_DOUBLE(dst, str) sscanf (str, "%lf", (double *) dst)

/*========================Interfaces definition============================*/
pid_t
gettid ();
u_long_long
timeVal2Second (timeValPtr tm);
u_long_long
timeVal2MilliSecond (timeValPtr tm);
u_long_long
timeVal2MicoSecond (timeValPtr tm);
u_long_long
ntohll (u_long_long src);
u_long_long
htonll (u_long_long src);
boolean
strEqualIgnoreCase (const char *str1, const char *str2);
boolean
strEqual (const char *str1, const char *str2);
ssize_t
safeRead (int fd, void *buf, size_t count);
ssize_t
safeWrite (int fd, const void *buf, size_t count);
boolean
fileExists (const char *path);
boolean
fileIsEmpty (const char *path);
char *
getIpAddrOfInterface (const char *interface);
u_int
getCpuCores (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_UTIL_H__ */
