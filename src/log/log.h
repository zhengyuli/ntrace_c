#ifndef __WDM_AGENT_LOG_H__
#define __WDM_AGENT_LOG_H__

#include <stdio.h>

/* Log level for SYS_LOG*/
#define MSG_ERR "<0>"       /* error message */
#define MSG_WARNING "<1>"   /* warning message */
#define MSG_INFO "<2>"      /* normal information */
#define MSG_DEBUG "<3>"     /* debug information */

/* Log level for initLogContext */
#define LOG_ERR_LEVEL 0
#define LOG_WARNING_LEVEL 1
#define LOG_INFO_LEVEL 2
#define LOG_DEBUG_LEVEL 3

#define MINIMUM_LOGLEVEL 0
#define MAXMUM_LOGLEVEL 3
#define DEFAULT_LOGLEVEL 2
#define DEFAULT_MSG_LEVEL 3
#define MAX_LOG_MSG_LENGTH 4096

/* Logd service port */
#define LOGD_SOCK_PORT 59001
/* Logd service log publish port */
#define LOG_NET_SOCK_PORT 59002

/*========================Interfaces definition============================*/
int
initLog (const char *ip, int level);
void
destroyLog (void);
void
logToConsole (const char *msg, ...);
void
doLog (char *file, int line, const char *func, const char *msg, ...);

#define LOGE(...)                                                   \
    doLog (__FILE__, __LINE__, __FUNCTION__, MSG_ERR __VA_ARGS__)

#define LOGW(...)                                                       \
    doLog (__FILE__, __LINE__, __FUNCTION__, MSG_WARNING __VA_ARGS__)

#define LOGI(...)                                                   \
    doLog (__FILE__, __LINE__, __FUNCTION__, MSG_INFO __VA_ARGS__)

#ifdef NDEBUG
#define LOGD(...)
#else
#define LOGD(...)                                                   \
    doLog (__FILE__, __LINE__, __FUNCTION__, MSG_DEBUG __VA_ARGS__)
#endif
/*=======================Interfaces definition end=========================*/

#endif /* __WDM_AGENT_LOG_H__ */
