#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <czmq.h>
#include <locale.h>
#include "util.h"
#include "list.h"
#include "properties.h"
#include "signals.h"
#include "zmq_hub.h"
#include "log.h"
#include "log_service.h"

#define LOG_TO_FILE_MASK (1 << 0)
#define LOG_TO_NET_MASK (1 << 1)

#define LOG_SERVICE_RESTART_MAX_RETRIES 3

#define LOG_SERVICE_STATUS_EXCHANGE_CHANNEL "inproc://logServiceStatusExchangeChannel"

static zctx_t *logServiceZmqCtxt = NULL;
static void *logServiceStatusSendSock = NULL;
static void *logServiceStatusRecvSock = NULL;
static void *logServiceLogRecvSock = NULL;
static pthread_t logServiceThreadId;

/* Log devices list */
static listHead logDevices;

typedef struct _logDev logDev;
typedef logDev *logDevPtr;
/*
 * Log service backend dev, every dev has three interfaces,
 * you can add new log dev into log service with log_dev_add
 */
struct _logDev {
    listHead node;                      /**< Log dev list node of global log devices */
    void *data;                         /**< Log dev private data */
    int (*init) (logDevPtr dev);        /**< Log dev init operation */
    void (*destroy) (logDevPtr dev);    /**< Log dev destroy operation */
    void (*write) (const char *msg, logDevPtr dev, u_int flag); /**< Log dev write operation */
};

/* Flag check */
static inline boolean
flagOn (u_int flag, u_int bitMask) {
    if (flag & bitMask)
        return true;
    else
        return false;
}

/*===========================Log file dev=================================*/

#define LOG_FILE_MAX_SIZE (512 << 20)
#define LOG_FILE_ROTATION_COUNT 16
#define LOG_FILE_SIZE_CHECK_THRESHOLD 500
#define LOG_FILE_PATH_MAX_LEN 512

typedef struct _logFile logFile;
typedef logFile *logFilePtr;

struct _logFile {
    int fd;                             /**< Log file fd */
    char *filePath;                     /**< Log file path */
    u_int checkCount;                   /**< Log file size check count */
};

/*
 * @brief Check whether log file is oversize
 *
 * @param filePath log file path to check
 *
 * @return true if oversize else FALE
 */
static boolean
logFileOversize (const char *filePath) {
    int ret;
    struct stat fileStat;

    ret = stat (filePath, &fileStat);
    if (ret < 0)
        return true;

    if (fileStat.st_size >= LOG_FILE_MAX_SIZE)
        return true;
    else
        return false;
}

/*
 * @brief Rotate log file.
 *
 * @param logFileName log file name to ratate
 *
 * @return 0 if success else -1
 */
static int
logFileRotate (const char *logFileName) {
    int ret;
    int index;
    char fileNameBuf1 [LOG_FILE_PATH_MAX_LEN];
    char fileNameBuf2 [LOG_FILE_PATH_MAX_LEN];

    for (index = (LOG_FILE_ROTATION_COUNT - 1); index > 0; index--) {
        if (index == (LOG_FILE_ROTATION_COUNT - 1)) {
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index);
            if (fileExists (fileNameBuf2)) {
                ret = remove (fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file rotate error.\n");
                    return -1;
                }
            }
        } else {
            snprintf (fileNameBuf1, sizeof (fileNameBuf1), "%s_%d", logFileName, index);
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index + 1);
            if (fileExists (fileNameBuf1)) {
                ret = rename (fileNameBuf1, fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file rotate error.\n");
                    return -1;
                }
            }
        }
    }

    if (LOG_FILE_ROTATION_COUNT == 1) {
        ret = remove (logFileName);
        if (ret < 0) {
            fprintf (stderr, "Log file rotate error.\n");
            return -1;
        }
    } else {
        snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, 1);
        ret = rename (logFileName, fileNameBuf2);
        if (ret < 0) {
            fprintf (stderr, "Log file rotate error.\n");
            return -1;
        }
    }

    return 0;
}

/* Update log file when log file is oversize. */
static int
logFileUpdate (logDevPtr dev) {
    int ret;
    logFilePtr logfile = (logFilePtr) dev->data;

    close (logfile->fd);
    ret = logFileRotate (logfile->filePath);
    if (ret < 0)
        return -1;

    logfile->fd = open (logfile->filePath, O_WRONLY | O_APPEND | O_CREAT, 0755);
    if (logfile->fd < 0)
        return -1;

    logfile->checkCount = 0;
    return 0;
}

static int
initLogFile (logDevPtr dev) {
    char logFilePath [LOG_FILE_PATH_MAX_LEN];
    logFilePtr logfile;

    if (!fileExists (getPropertiesLogDir ()) &&
        (mkdir (getPropertiesLogDir (), 0755) < 0))
        return -1;

    logfile = (logFilePtr) malloc (sizeof (logFile));
    if (logfile == NULL)
        return -1;

    snprintf (logFilePath, sizeof (logFilePath), "%s/%s",
              getPropertiesLogDir (), getPropertiesLogFileName ());
    logfile->filePath = strdup (logFilePath);
    if (logfile->filePath == NULL) {
        free (logfile);
        return -1;
    }

    logfile->fd = open (logfile->filePath, O_WRONLY | O_APPEND | O_CREAT, 0755);
    if (logfile->fd < 0) {
        free (logfile->filePath);
        free (logfile);
        return -1;
    }

    /* Update log file context */
    logfile->checkCount = 0;
    dev->data = logfile;

    return 0;
}

static void
destroyLogFile (logDevPtr dev) {
    logFilePtr logfile = (logFilePtr) dev->data;

    close (logfile->fd);
    free (logfile->filePath);
    free (logfile);
}

static int
resetLogFile (logDevPtr dev) {
    destroyLogFile (dev);
    return initLogFile (dev);
}

static void
writeLogFile (const char *msg, logDevPtr dev, u_int flag) {
    int ret;
    logFilePtr logfile;

    if (!flagOn (flag, LOG_TO_FILE_MASK))
        return;

    logfile = (logFilePtr) dev->data;
    ret = safeWrite (logfile->fd, msg, strlen (msg));
    if ((ret < 0) || (ret != strlen (msg))) {
        ret = resetLogFile (dev);
        if (ret < 0) {
            zctx_interrupted = 1;
            fprintf (stderr, "Reset log file error.\n");
        }
        return;
    }
    logfile->checkCount++;
    /* Check whether log file is oversize after checkCount writing */
    if ((logfile->checkCount >= LOG_FILE_SIZE_CHECK_THRESHOLD) &&
        logFileOversize (logfile->filePath)) {
        ret = logFileUpdate (dev);
        if (ret < 0)
            zctx_interrupted = 1;
        fprintf (stderr, "Log file update error.\n");
    }
    sync ();
}

/*===========================Log net dev=================================*/

typedef struct _logNet logNet;
typedef logNet *logNetPtr;

struct _logNet {
    zctx_t *context;
    void *sock;
};

static int
initLogNet (logDevPtr dev) {
    int ret;
    logNetPtr lognet;

    if ((dev->data = malloc (sizeof (logNet))) == NULL)
        return -1;

    lognet = (logNetPtr) dev->data;
    lognet->context = zctx_new ();
    if (lognet->context == NULL) {
        free (dev->data);
        return -1;
    }

    lognet->sock = zsocket_new (lognet->context, ZMQ_PUB);
    if (lognet->sock == NULL) {
        zctx_destroy (&lognet->context);
        return -1;
    }

    ret = zsocket_bind (lognet->sock, "tcp://*:%u", LOG_SERVICE_LOG_PUBLISH_PORT);
    if (ret < 0) {
        zctx_destroy (&lognet->context);
        return -1;
    }

    return 0;
}

static void
writeLogNet (const char *msg, logDevPtr dev, u_int flag) {
    int ret;
    logNetPtr lognet;
    zframe_t *frame = NULL;

    if (!flagOn (flag, LOG_TO_NET_MASK))
        return;

    lognet = (logNetPtr) dev->data;

    frame = zframe_new ((void *) msg, strlen (msg));
    if (frame == NULL)
        return;

    ret = zframe_send (&frame, lognet->sock, 0);
    if (ret < 0) {
        zframe_destroy (&frame);
        return;
    }
}

static void
destroyLogNet (logDevPtr dev) {
    logNetPtr lognet = (logNetPtr) dev->data;

    zctx_destroy (&lognet->context);
    free (lognet);
}

/*============================log dev================================*/

static int
logDevAdd (logDevPtr dev) {
    int ret;

    ret = dev->init (dev);
    if (ret < 0)
        return -1;

    listAdd (&dev->node, &logDevices);

    return 0;
}

static void
logDevWrite (listHeadPtr logDevices, const char *msg) {
    u_int flag;
    logDevPtr dev;

    switch (*msg) {
        case 'a':
            flag = LOG_TO_FILE_MASK | LOG_TO_NET_MASK;
            break;

        case 'n':
            flag = LOG_TO_NET_MASK;
            break;

        default:
            return;
    }

    listForEachEntry (dev, logDevices, node) {
        dev->write (msg + 1, dev, flag);
    }
}

static void
logDevDestroy (void) {
    logDevPtr dev, ndev;

    listForEachEntrySafe (dev, ndev, &logDevices, node) {
        dev->destroy (dev);
        listDel (&dev->node);
    }
}

static void *
logService (void *args) {
    int ret;
    char *msg;
    char exitMsg [128];

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log file backend dev */
    logDev logFileDev = {
        .init = initLogFile,
        .destroy = destroyLogFile,
        .write = writeLogFile,
    };

    /* Init log net backend dev */
    logDev logNetDev = {
        .init = initLogNet,
        .destroy = destroyLogNet,
        .write = writeLogNet,
    };

    /* Init file log dev */
    initListHead (&logDevices);
    ret = logDevAdd (&logFileDev);
    if (ret < 0)
        goto exit;

    /* Init net log dev */
    ret = logDevAdd (&logNetDev);
    if (ret < 0)
        goto destroyDev;

    while (!sigusr1IsInterrupted ()) {
        msg = zstr_recv (logServiceLogRecvSock);
        if (msg == NULL)
            break;
        logDevWrite (&logDevices, msg);
        free (msg);
    }

destroyDev:
    logDevDestroy ();
exit:
    if (!sigusr1IsInterrupted ()) {
        snprintf (exitMsg, sizeof (exitMsg), "%u:%lu", LOG_SERVICE_STATUS_EXIT, pthread_self ());
        zstr_send (logServiceStatusSendSock, exitMsg);
    }

    return NULL;
}

void *
getLogServiceStatusRecvSock (void) {
    return logServiceStatusRecvSock;
}

int
logServiceStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret, retries;
    char *statusMsg;
    u_int status;
    pthread_t tid;

    statusMsg =  zstr_recv_nowait (logServiceStatusRecvSock);
    if (statusMsg == NULL)
        return 0;

    sscanf (statusMsg, "%u:%lu", &status, &tid);
    switch (status) {
        case LOG_SERVICE_STATUS_EXIT:
            fprintf (stderr, "Task %lu exit abnormally.\n", tid);
            retries = LOG_SERVICE_RESTART_MAX_RETRIES;
            while (retries) {
                fprintf (stdout, "Try to restart logService... .. .\n");
                ret = pthread_create (&logServiceThreadId, NULL, logService, NULL);
                if (ret < 0)
                    retries--;
                else
                    break;
            }
            if (ret < 0) {
                fprintf (stderr, "Restart logService failed.\n");
                ret = -1;
            } else {
                fprintf (stdout, "Restart logService successfully.\n");
                ret = 0;
            }
            break;

        default:
            fprintf (stderr, "Unknown logService status.\n");
            ret = 0;
            break;
    }

    free (statusMsg);
    return ret;
}

int
initLogService (void) {
    int ret;

    logServiceZmqCtxt = zctx_new ();
    if (logServiceZmqCtxt == NULL) {
        fprintf (stderr, "Create logServiceZmqCtxt error");
        goto destroyLogServiceZmqCtxt;
    }
    zctx_set_linger (logServiceZmqCtxt, 0);

    /* Create logServiceStatusSendSock */
    logServiceStatusSendSock = zsocket_new (logServiceZmqCtxt, ZMQ_PUSH);
    if (logServiceStatusSendSock == NULL) {
        fprintf (stderr, "Create logServiceStatusSendSock error.\n");
        goto destroyLogServiceZmqCtxt;
    }
    ret = zsocket_bind (logServiceStatusSendSock, LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        fprintf (stderr, "Bind to %s error.\n", LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
        goto destroyLogServiceZmqCtxt;
    }

    /* Create logServiceStatusRecvSock */
    logServiceStatusRecvSock = zsocket_new (logServiceZmqCtxt, ZMQ_PULL);
    if (logServiceStatusRecvSock == NULL) {
        fprintf (stderr, "Create logServiceStatusRecvSock error.\n");
        goto destroyLogServiceZmqCtxt;
    }
    ret = zsocket_connect (logServiceStatusRecvSock, LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        fprintf (stderr, "Connect to %s error.\n", LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
        goto destroyLogServiceZmqCtxt;
    }

    /* Create logServiceLogRecvSock */
    logServiceLogRecvSock = zsocket_new (logServiceZmqCtxt, ZMQ_PULL);
    if (logServiceLogRecvSock == NULL) {
        fprintf (stderr, "Create logServiceLogRecvSock error.\n");
        goto destroyLogServiceZmqCtxt;
    }
    ret = zsocket_bind (logServiceLogRecvSock, "tcp://*:%u", LOG_SERVICE_LOG_RECV_PORT);
    if (ret < 0) {
        fprintf (stderr, "Bind to \"tcp://*:%u\" error.\n", LOG_SERVICE_LOG_RECV_PORT);
        goto destroyLogServiceZmqCtxt;
    }

    ret = pthread_create (&logServiceThreadId, NULL, logService, NULL);
    if (ret < 0) {
        fprintf (stderr, "Start logService error.\n");
        goto destroyLogServiceZmqCtxt;
    }

    return 0;

destroyLogServiceZmqCtxt:
    zctx_destroy (&logServiceZmqCtxt);
    return -1;
}

void
destroyLogService (void) {
    pthread_kill (logServiceThreadId, SIGUSR1);
    zctx_destroy (&logServiceZmqCtxt);
}
