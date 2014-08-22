#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <czmq.h>
#include "log.h"

typedef struct _logContext logContext;
typedef logContext *logContextPtr;

struct _logContext {
    zctx_t *ctxt;                       /**< Zmq context */
    void *logSock;                      /**< Log zmq sock */
    u_int logLevel;                     /**< Log level */
};

/* Thread local log context */
static __thread logContextPtr logCtxt = NULL;

/*
 * @brief Get log level from log message.
 * 
 * @param msg log message
 * @param level pointer to return log level
 * 
 * @return 0 if success else -1
 */
static int
getLogLevel (const char *msg, u_int *level) {
    int ret;

    ret = sscanf (msg, "<%u>", level);
    if (ret == 1)
        return 0;
    else
        return -1;
}

/*
 * @brief Write log message to console.
 * 
 * @param msg log message to write
 */
void
logToConsole (const char *msg, ...) {
    va_list va;
    char tmp [MAX_LOG_LENGTH] = {0};

    va_start (va, msg);
    vsnprintf (tmp, sizeof (tmp) - 1, msg, va);
    va_end (va);
    fprintf (stdout, "%s", tmp);
}

/*
 * @brief Format log message and push log message to log service.
 *
 * @param file Source file name info
 * @param line Line number info
 * @param func Function name info
 * @param msg Real log message
 */
void
doLog (char *file, u_int line, const char *func, const char *msg, ...) {
    int ret;
    u_int level;
    u_int flag;
    va_list va;
    const char *message;
    time_t seconds;
    struct tm *localTime;
    char timeStr [32] = {0};
    char logLevel [10] = {0};
    /* Thread local message buffer */
    static __thread char tmp [MAX_LOG_LENGTH] = {0};
    static __thread char buf [MAX_LOG_LENGTH] = {0};
    zframe_t *frame;

    if (logCtxt == NULL) {
        fprintf (stderr, "Log context has not been initialized.\n");
        return;
    }

    seconds = time (NULL);
    localTime = localtime (&seconds);
    snprintf (timeStr, sizeof (timeStr) - 1, "%02d:%02d:%02d %02d/%02d/%04d",
              localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
              localTime->tm_mon + 1, localTime->tm_mday, (localTime->tm_year + 1900));

    ret = getLogLevel (msg, &level);
    if (ret < 0) {
        fprintf (stderr, "Get log level error.\n");
        return;
    }
    else
        /* Drop log level info and get real log message */
        message = msg + 3;

    va_start (va, msg);
    vsnprintf (tmp, sizeof (tmp) - 1, message, va);
    tmp [sizeof (tmp) - 1] = 0;
    va_end (va);

    switch (level) {
        case LOG_ERR_LEVEL:
            snprintf (logLevel, sizeof (logLevel) - 1, "ERROR");
            break;

        case LOG_WARNING_LEVEL:
            snprintf (logLevel, sizeof (logLevel) - 1, "WARNING");
            break;

        case LOG_INFO_LEVEL:
            snprintf (logLevel, sizeof (logLevel) - 1, "INFO");
            break;

        case LOG_DEBUG_LEVEL:
            snprintf (logLevel, sizeof (logLevel) - 1, "DEBUG");
            break;

        default:
            fprintf (stderr, "Unknow log level!\n");
            return;
    }

    if (level <= logCtxt->logLevel)
        flag = LOG_TO_ALL_TAG;
    else
        flag = LOG_TO_NET_TAG;

    snprintf (buf, sizeof (buf) - 1, "%u[pid:%u %s]:[%s] <file=%s:line=%u:func_name=%s>:%s",
              flag, getpid (), logLevel, timeStr, file, line, func, tmp);
    buf [sizeof (buf) - 1] = 0;

    frame = zframe_new ((void *) buf, strlen (buf));
    if (frame == NULL) {
        fprintf (stderr, "Create zframe for log message error.\n");
        return;
    }
    ret = zframe_send (&frame, logCtxt->logSock, 0);
    if (ret < 0) {
        fprintf (stderr, "Send log message error.\n");
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Init thread local log context.
 *        It will create a thread local log context, every thread want to
 *        use log function must init log context before do logging.
 * @param logLevel Log level used to do logging 
 *
 * @return 0 if success else -1
 */
int
initLog (u_int logLevel) {
    int ret;

    /* Init log context */
    logCtxt = (logContextPtr) malloc (sizeof (logContext));
    if (logCtxt == NULL)
        return -1;

    logCtxt->ctxt = zctx_new ();
    if (logCtxt->ctxt == NULL) {
        free (logCtxt);
        return -1;
    }
    zctx_set_linger (logCtxt->ctxt, 0);

    logCtxt->logSock = zsocket_new (logCtxt->ctxt, ZMQ_PUSH);
    if (logCtxt->logSock == NULL) {
        zctx_destroy (&logCtxt->ctxt);
        free (logCtxt);
        return -1;
    }

    ret = zsocket_connect (logCtxt->logSock, "tcp://%s:%d", "127.0.0.1", LOG_SERVICE_SINK_PORT);
    if (ret < 0) {
        zctx_destroy (&logCtxt->ctxt);
        free (logCtxt);
        return -1;
    }

    if (logLevel > MAXMUM_LOGLEVEL || logLevel < MINIMUM_LOGLEVEL)
        logCtxt->logLevel = DEFAULT_LOGLEVEL;
    else
        logCtxt->logLevel = logLevel;

    return 0;
}

/* Destroy thread local log context */
void
destroyLog (void) {
    zctx_destroy (&logCtxt->ctxt);
    free (logCtxt);
    logCtxt = NULL;
}
