#ifndef __AGENT_UTIL_H__
#define __AGENT_UTIL_H__

#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <ctype.h>
#include "typedef.h"

#define TABLE_SIZE(x) (sizeof (x) / sizeof ((x) [0]))

#define STRPREFIX(s1, s2) (strncmp (s1, s2, strlen (s2)) == 0)

#define MAX_NUM(n1, n2) ((n1) > (n2) ? (n1) : (n2))
#define MIN_NUM(n1, n2) ((n1) > (n2) ? (n2) : (n1))

/* Number to string interfaces */
#define INT8_TO_STRING(dst, val) sprintf (dst, "%"PRId8, val)
#define UINT8_TO_STRING(dst, val) sprintf (dst, "%"PRIu8, val)

#define INT16_TO_STRING(dst, val) sprintf (dst, "%"PRId16, val)
#define UINT16_TO_STRING(dst, val) sprintf (dst, "%"PRIu16, val)

#define INT32_TO_STRING(dst, val) sprintf (dst, "%"PRId32, val)
#define UINT32_TO_STRING(dst, val) sprintf (dst, "%"PRIu32, val)

#define INT_TO_STRING(dst, val) sprintf (dst, "%d", val)
#define UINT_TO_STRING(dst, val) sprintf (dst, "%u", val)

#define INT64_TO_STRING(dst, val) sprintf (dst, "%"PRId64, val)
#define UINT64_TO_STRING(dst, val) sprintf (dst, "%"PRIu64, val)

#define FLOAT_TO_STRING(dst, val) sprintf (dst, "%f", val)

#define DOUBLE_TO_STRING(dst, val) sprintf (dst, "%lf", val)

/* String to number interfaces */
#define STRING_TO_INT8(dst, str) sscanf (str, "%"PRId8, (int32_t *) dst)
#define STRING_TO_UINT8(dst, str) sscanf (str, "%"PRIu8, (uint32_t *) dst)

#define STRING_TO_INT16(dst, str) sscanf (str, "%"PRId16, (int32_t *) dst)
#define STRING_TO_UINT16(dst, str) sscanf (str, "%"PRIu16, (uint32_t *) dst)

#define STRING_TO_INT32(dst, str) sscanf (str, "%"PRId32, (int32_t *) dst)
#define STRING_TO_UINT32(dst, str) sscanf (str, "%"PRIu32, (uint32_t *) dst)

#define STRING_TO_INT(dst, str) sscanf (str, "%d", (int *) dst)
#define STRING_TO_UINT(dst, str) sscanf (str, "%u", (uint *) dst)

#define STRING_TO_INT64(dst, str) sscanf (str, "%"PRId64, (int64_t *) dst)
#define STRING_TO_UINT64(dst, str) sscanf (str, "%"PRIu64, (uint64_t *) dst)

#define STRING_TO_FLOAT(dst, str) sscanf (str, "%f", (float *) dst)

#define STRING_TO_DOUBLE(dst, str) sscanf (str, "%lf", (double *) dst)

typedef struct _timeVal timeVal;
typedef timeVal *timeValPtr;

struct _timeVal {
    u_long_long tvSec;
    u_long_long tvUsec;
};

/*========================Interfaces definition============================*/
u_long_long
timeVal2Second (timeValPtr tm);
u_long_long
timeVal2MilliSecond (timeValPtr tm);
u_long_long
timeVal2MicoSecond (timeValPtr tm);
BOOL
strEqualIgnoreCase (const char *str1, const char *str2);
BOOL
strEqual (const char *str1, const char *str2);
ssize_t
safeRead (int fd, void *buf, size_t count);
ssize_t
safeWrite (int fd, const void *buf, size_t count);
BOOL
fileExist (const char *path);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_UTIL_H__ */
