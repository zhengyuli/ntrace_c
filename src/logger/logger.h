#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdlib.h>

/* Log level tag */
#define LOG_ERR_TAG "<0>"       /* Error message */
#define LOG_WARNING_TAG "<1>"   /* Warning message */
#define LOG_INFO_TAG "<2>"      /* Normal information */
#define LOG_DEBUG_TAG "<3>"     /* Debug information */

/* Log backend tag  */
#define LOG_TO_ALL_TAG 'a'      /* Log to all backend */
#define LOG_TO_NET_TAG 'n'      /* Log to net backend */

/* Log level for initLogContext */
#define LOG_ERR_LEVEL 0
#define LOG_WARNING_LEVEL 1
#define LOG_INFO_LEVEL 2
#define LOG_DEBUG_LEVEL 3

#define MINIMUM_LOGLEVEL 0
#define MAXMUM_LOGLEVEL 3
#define DEFAULT_LOGLEVEL 2
#define MAX_LOG_LENGTH 4096

#define LOG_MESSAGE_INDICATOR_1 "@#>"
#define LOG_MESSAGE_INDICATOR_2 "&#>"

/* Log service log message sink port */
#define LOG_SERVICE_SINK_PORT 59001
/* Log service log message publish port */
#define LOG_SERVICE_PUBLISH_PORT 59002

/*========================Interfaces definition============================*/
void
logToConsole (const char *msg, ...);
void
doLog (char *filePath, u_int line, const char *func, const char *msg, ...);
int
initLog (u_int logLevel);
void
destroyLog (void);

#define LOGE(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_ERR_TAG __VA_ARGS__)
#define LOGW(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_WARNING_TAG __VA_ARGS__)
#define LOGI(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_INFO_TAG __VA_ARGS__)
#ifdef NDEBUG
#define LOGD(...)
#else
#define LOGD(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_DEBUG_TAG __VA_ARGS__)
#endif
/*=======================Interfaces definition end=========================*/

#endif /* __LOGGER_H__ */
