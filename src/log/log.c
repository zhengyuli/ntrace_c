#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <signal.h>
#include <czmq.h>
#include "log.h"
#include "util.h"

typedef struct _logContext logContext;
typedef logContext *logContextPtr;

struct _logContext {
    zctx_t *ctxt;
    void *logSock;
    int logLevel;
};

/* Thread local log context */
static __thread logContextPtr logCtxt = NULL;

/*
 * @brief Init log context
 *
 * @param logdIp ip of logd to connect
 * @param logLevel log level
 *
 * @return 0 if success else -1
 */
int
initLog (const char *logdIp, int logLevel) {
    int ret;
    int sockfd;
    struct sockaddr_in logdAddr;

    /* Check logd service is running */
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf (stderr, "Create socket error.\n");
        return -1;
    }
    
    memset (&logdAddr, 0, sizeof (logdAddr));
    logdAddr.sin_family = AF_INET;
    logdAddr.sin_port = htons (LOGD_SOCK_PORT);
    ret = inet_pton (AF_INET, logdIp ? logdIp : "127.0.0.1", &logdAddr.sin_addr);
    if (ret < 0) {
        fprintf (stderr, "Ivalid logd ip address.\n");
        return -1;
    }

    ret = connect (sockfd, (const struct sockaddr *) &logdAddr, sizeof (logdAddr));
    close (sockfd);
    if (ret < 0) {
        fprintf (stderr, "Logd is not running.\n");
        close (sockfd);
        return -1;
    }
        
    /* init log context */
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

    ret = zsocket_connect (logCtxt->logSock, "tcp://%s:%d",
                           logdIp ? logdIp : "127.0.0.1",
                           LOGD_SOCK_PORT);
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

/* Free thread local log context */
void
destroyLog (void) {
    zctx_destroy (&logCtxt->ctxt);
    free (logCtxt);
    logCtxt = NULL;
}

/*
 * @brief Get msg level from log message.
 *
 * @param msg log message
 *
 * @return Return msg level if success, else return -1
 */
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

/* Log to console if log context has not been initialized. */
void
logToConsole (const char *msg, ...) {
    va_list va;
    char tmp [MAX_LOG_MSG_LENGTH] = {0};

    va_start (va, msg);
    vsnprintf (tmp, MAX_LOG_MSG_LENGTH - 1, msg, va);
    va_end (va);
    fprintf (stdout, "%s", tmp);
}

/*
 * @brief Recored log message to log file and console
 *
 * @param file file name
 * @param line line number
 * @param func function name
 * @param msg message to log
 */
void
doLog (char *file, int line, const char *func, const char *msg, ...) {
    int ret;
    int level;
    char flag;
    va_list va;
    char const *message;
    time_t seconds;
    struct tm *localTime;
    char timeStr [100] = {0};
    char logLevel [10] = {0};
    char tmp [MAX_LOG_MSG_LENGTH] = {0};
    char buf [MAX_LOG_MSG_LENGTH] = {0};
    zframe_t *frame;

    if (logCtxt == NULL) {
        fprintf (stderr, "Log context has not been initialized.\n");
        return;
    }

    /* get system time */
    seconds = time (NULL);
    localTime = localtime (&seconds);
    snprintf (timeStr, sizeof (timeStr) - 1, "%02d:%02d:%02d %02d/%02d/%04d",
              localTime->tm_hour, localTime->tm_min,
              localTime->tm_sec, localTime->tm_mon + 1,
              localTime->tm_mday, (localTime->tm_year + 1900));

    level = getMsgLevel (msg);
    if (level < 0) {
        level = DEFAULT_MSG_LEVEL;
        message = msg;
    } else
        /*
         * in normal case, message level occupys first three characters
         * of msg, so, the actual message need to display should start
         * from (msg + 3)
         */
        message = msg + 3;

    va_start (va, msg);
    vsnprintf (tmp, MAX_LOG_MSG_LENGTH - 1, message, va);
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
     * Write log message to logd, if message level less or equal than
     * log level then add flag 'a' at the head of message, else add 'n'.
     * For 'a' logd will log message both to local file and net, else
     * only publish message to net.
     */
    if (level <= logCtxt->logLevel)
        flag = 'a';
    else
        flag = 'n';

    /* format output message */
    snprintf (buf, MAX_LOG_MSG_LENGTH - 1, "%c[pid:%d %s]:[%s] <file=%s:line=%d:func_name=%s>:%s",
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
