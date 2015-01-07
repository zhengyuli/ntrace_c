#ifndef __AGENT_LOGGER_H__
#define __AGENT_LOGGER_H__

#include <stdlib.h>

/* Log level tag */
#define LOG_ERR_TAG "<0>"       /* Error message */
#define LOG_WARNING_TAG "<1>"   /* Warning message */
#define LOG_INFO_TAG "<2>"      /* Normal information */
#define LOG_DEBUG_TAG "<3>"     /* Debug information */

/*========================Interfaces definition============================*/
void
logToConsole (const char *msg, ...);
void
doLog (char *filePath, u_int line, const char *func, const char *msg, ...);

#define LOGE(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_ERR_TAG __VA_ARGS__)
#define LOGW(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_WARNING_TAG __VA_ARGS__)
#define LOGI(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_INFO_TAG __VA_ARGS__)
#ifdef NDEBUG
#define LOGD(...)
#else
#define LOGD(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_DEBUG_TAG __VA_ARGS__)
#endif
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_LOGGER_H__ */
