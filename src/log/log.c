#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <czmq.h>
#include "util.h"
#include "zmq_hub.h"
#include "log.h"
#include "log_service.h"

#define MAX_LOG_LENGTH 4096

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
 * @brief Format log message and push log message to log service.
 *
 * @param file Source file name info
 * @param line Line number info
 * @param func Function name info
 * @param msg Real log message
 */
void
doLog (u_char logLevel, char *filePath, u_int line, const char *func, const char *msg, ...) {
    int ret;
    char flag;
    va_list va;
    char *fileName;
    time_t seconds;
    struct tm *localTime;
    char timeStr [32];
    /* Thread local message buffer */
    static __thread char tmp [MAX_LOG_LENGTH];
    static __thread char buf [MAX_LOG_LENGTH];
    static __thread char logLevelMsg [16];
    zframe_t *frame;

    if (logCtxt == NULL) {
        fprintf (stderr, "Log context has not been initialized.\n");
        return;
    }

    seconds = time (NULL);
    localTime = localtime (&seconds);
    snprintf (timeStr, sizeof (timeStr), "%04d-%02d-%02d %02d:%02d:%02d",
              (localTime->tm_year + 1900), localTime->tm_mon + 1, localTime->tm_mday,
              localTime->tm_hour, localTime->tm_min, localTime->tm_sec);

    va_start (va, msg);
    vsnprintf (tmp, sizeof (tmp), msg, va);
    va_end (va);

    switch (logLevel) {
        case LOG_ERR_LEVEL:
            snprintf (logLevelMsg, sizeof (logLevelMsg), "ERROR");
            break;

        case LOG_WARNING_LEVEL:
            snprintf (logLevelMsg, sizeof (logLevelMsg), "WARNING");
            break;

        case LOG_INFO_LEVEL:
            snprintf (logLevelMsg, sizeof (logLevelMsg), "INFO");
            break;

        case LOG_DEBUG_LEVEL:
            snprintf (logLevelMsg, sizeof (logLevelMsg), "DEBUG");
            break;

        default:
            fprintf (stderr, "Unknown log level!\n");
            return;
    }

    if (logLevel <= logCtxt->logLevel)
        flag = 'a';
    else
        flag = 'n';

    fileName = strrchr (filePath, '/') + 1;
    snprintf (buf, sizeof (buf), "%c%s [thread:%u] %s file=%s (line=%u, func=%s): %s",
              flag, timeStr, gettid (), logLevelMsg, fileName, line, func, tmp);
    buf [MAX_LOG_LENGTH - 1] = 0;

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
 * @brief Init log context.
 *        It will create a thread local log context, every thread want to
 *        use log function must init log context before do logging.
 * @param logLevel Log level used to do logging
 *
 * @return 0 if success else -1
 */
int
initLogContext (u_int logLevel) {
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

    ret = zsocket_connect (logCtxt->logSock, "tcp://localhost:%u", LOG_SERVICE_LOG_RECV_PORT);
    if (ret < 0) {
        zctx_destroy (&logCtxt->ctxt);
        free (logCtxt);
        return -1;
    }

    if (logLevel > LOG_DEBUG_LEVEL || logLevel < LOG_ERR_LEVEL)
        logCtxt->logLevel = LOG_DEBUG_LEVEL;
    else
        logCtxt->logLevel = logLevel;

    return 0;
}

/* Destroy log context */
void
destroyLog (void) {
    zctx_destroy (&logCtxt->ctxt);
    free (logCtxt);
    logCtxt = NULL;
}
