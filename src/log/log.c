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
    int logLevel;                       /**< Log level */
};

/* Thread local log context */
static __thread logContextPtr logCtxt = NULL;

static int
getMsgLevel (const char *msg) {
    int ret;
    int level;

    ret = sscanf (msg, "<%d>", &level);
    if (ret == 1)
        return level;
    else
        return -1;
}

void
logToConsole (const char *msg, ...) {
    va_list va;
    char tmp [MAX_LOG_LENGTH] = {0};

    va_start (va, msg);
    vsnprintf (tmp, MAX_LOG_LENGTH - 1, msg, va);
    va_end (va);
    fprintf (stdout, "%s", tmp);
}

/*
 * @brief Format log message and send log to log service.
 *
 * @param file File name info
 * @param line Line number info
 * @param func Function name info
 * @param msg Real log message
 */
void
doLog (char *file, int line, const char *func, const char *msg, ...) {
    int ret;
    int level;
    char flag;
    va_list va;
    const char *message;
    time_t seconds;
    struct tm *localTime;
    char timeStr [32] = {0};
    char logLevel [10] = {0};
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

    level = getMsgLevel (msg);
    if (level < 0)
        return;
    else
        message = msg + 3;

    va_start (va, msg);
    vsnprintf (tmp, MAX_LOG_LENGTH - 1, message, va);
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

    /*
     * Send log message to log service, if message level less or equal than
     * log level then add flag 'a' at the head of message, else add 'n'. For
     * 'a' log service will log message both to local file and net, else
     * only publish message to net.
     */
    if (level <= logCtxt->logLevel)
        flag = 'a';
    else
        flag = 'n';

    /* format output message */
    snprintf (buf, MAX_LOG_LENGTH - 1, "%c[pid:%d %s]:[%s] <file=%s:line=%d:func_name=%s>:%s",
              flag, getpid (), logLevel, timeStr, file, line, func, tmp);

    frame = zframe_new ((void *) buf, strlen (buf));
    if (frame == NULL)
        return;
    ret = zframe_send (&frame, logCtxt->logSock, 0);
    if (ret < 0) {
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Init log context
 *
 * @param logLevel Log level
 *
 * @return 0 if success else -1
 */
int
initLog (int logLevel) {
    int ret;

    /* Init log context */
    logCtxt = malloc (sizeof (logContext));
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

/* Destroy log context */
void
destroyLog (void) {
    zctx_destroy (&logCtxt->ctxt);
    free (logCtxt);
    logCtxt = NULL;
}
