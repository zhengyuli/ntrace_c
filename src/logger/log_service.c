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
#include "log.h"
#include "zmq_hub.h"
#include "log_service.h"

#define LOG_TO_FILE_MASK (1 << 0)
#define LOG_TO_NET_MASK (1 << 1)

#define LOG_SERVICE_RESTART_MAX_RETRIES 3

#define LOG_SERVICE_STATUS_EXCHANGE_CHANNEL "inproc://logServiceStatusExchangeChannel"

/* Log service instance */
static logServiceCtxtPtr logServiceCtxtInstance = NULL;

/* Log devices list */
static listHead logDevices;

typedef struct _logDev logDev;
typedef logDev *logDevPtr;
/*
 * Log service append dev, every dev has three interfaces,
 * you can add new log dev into log service with log_dev_add
 */
struct _logDev {
    void *data;                         /**< Log dev private data */
    int (*init) (logDevPtr dev);        /**< Log dev init operation */
    void (*destroy) (logDevPtr dev);    /**< Log dev destroy operation */
    void (*write) (char *msg, logDevPtr dev, u_int flag); /**< Log dev write operation */
    listHead node;                      /**< Log dev list node of global log devices */
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

static boolean
logFileOversize (char *filePath) {
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

static int
logFileRotate (char *logFileName) {
    int ret;
    int index;
    char fileNameBuf1 [LOG_FILE_PATH_MAX_LEN];
    char fileNameBuf2 [LOG_FILE_PATH_MAX_LEN];

    for (index = (LOG_FILE_ROTATION_COUNT - 1); index > 0; index--) {
        if (index == (LOG_FILE_ROTATION_COUNT - 1)) {
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index);
            if (fileExist (fileNameBuf2)) {
                ret = remove (fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file rotate error.\n");
                    return -1;
                }
            }
        } else {
            snprintf (fileNameBuf1, sizeof (fileNameBuf1), "%s_%d", logFileName, index);
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index + 1);
            if (fileExist (fileNameBuf1)) {
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

    if (!fileExist (getPropertiesLogDir ()) &&
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
writeLogFile (char *msg, logDevPtr dev, u_int flag) {
    int ret;
    logFilePtr logfile;

    if (!flagOn (flag, LOG_TO_FILE_MASK))
        return;

    logfile = (logFilePtr) dev->data;
    ret = safeWrite (logfile->fd, msg, strlen (msg));
    if ((ret < 0) || (ret != strlen (msg))) {
        ret = resetLogFile (dev);
        if (ret < 0)
            fprintf (stderr, "Reset log file error.\n");
        return;
    }

    logfile->checkCount++;
    if ((logfile->checkCount >= LOG_FILE_SIZE_CHECK_THRESHOLD) &&
        logFileOversize (logfile->filePath)) {
        ret = logFileUpdate (dev);
        if (ret < 0)
            fprintf (stderr, "Log file update error.\n");
    }
    sync ();
}
/*===========================Log file dev=================================*/

/*===========================Log net dev==================================*/

typedef struct _logNet logNet;
typedef logNet *logNetPtr;

struct _logNet {
    zctx_t *zmqCtxt;
    void *sock;
};

static int
initLogNet (logDevPtr dev) {
    int ret;
    logNetPtr lognet;

    lognet = (logNetPtr) malloc (sizeof (logNet));
    if (lognet == NULL)
        return -1;

    lognet->zmqCtxt = zctx_new ();
    if (lognet->zmqCtxt == NULL) {
        free (lognet);
        return -1;
    }

    lognet->sock = zsocket_new (lognet->zmqCtxt, ZMQ_PUB);
    if (lognet->sock == NULL) {
        zctx_destroy (&lognet->zmqCtxt);
        free (lognet);
        return -1;
    }

    ret = zsocket_bind (lognet->sock, "tcp://*:%u", LOG_SERVICE_LOG_PUBLISH_PORT);
    if (ret < 0) {
        zctx_destroy (&lognet->zmqCtxt);
        free (lognet);
        return -1;
    }

    dev->data = lognet;
    return 0;
}

static void
writeLogNet (char *msg, logDevPtr dev, u_int flag) {
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
        fprintf (stderr, "Send log message error.\n");
        return;
    }
}

static void
destroyLogNet (logDevPtr dev) {
    logNetPtr lognet = (logNetPtr) dev->data;

    zctx_destroy (&lognet->zmqCtxt);
    free (lognet);
}

/*============================log dev=================================*/

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
logDevWrite (listHeadPtr logDevices, char *msg) {
    u_int flag;
    logDevPtr dev;
    listHeadPtr pos;

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

    listForEachEntry (dev, pos, logDevices, node) {
        dev->write (msg + 1, dev, flag);
    }
}

static void
logDevDestroy (void) {
    logDevPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &logDevices, node) {
        entry->destroy (entry);
        listDel (&entry->node);
    }
}

static void *
logService (void *args) {
    int ret;
    u_int retries = 3;
    char *logMsg;
    char exitMsg [128];

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log file dev */
    logDev logFileDev = {
        .data = NULL,
        .init = initLogFile,
        .destroy = destroyLogFile,
        .write = writeLogFile,
    };

    /* Init log net dev */
    logDev logNetDev = {
        .data = NULL,
        .init = initLogNet,
        .destroy = destroyLogNet,
        .write = writeLogNet,
    };

    initListHead (&logDevices);
    /* Add file log dev */
    ret = logDevAdd (&logFileDev);
    if (ret < 0)
        goto exit;

    /* Add net log dev */
    ret = logDevAdd (&logNetDev);
    if (ret < 0)
        goto destroyDev;

    while (!SIGUSR1IsInterrupted ()) {
        logMsg = zstr_recv (logServiceCtxtInstance->logRecvSock);
        if (logMsg == NULL)
            break;
        logDevWrite (&logDevices, logMsg);
        free (logMsg);
    }

destroyDev:
    logDevDestroy ();
exit:
    if (!SIGUSR1IsInterrupted ()) {
        snprintf (exitMsg, sizeof (exitMsg), "%u:%lu", LOG_SERVICE_STATUS_EXIT, pthread_self ());
        do {
            ret = zstr_send (logServiceCtxtInstance->statusSendSock, exitMsg);
            retries -= 1;
        } while ((ret < 0) && retries);

        if (ret < 0)
            fprintf (stderr, "Send log service state error.\n");
    }

    return NULL;
}

void *
getLogServiceStatusRecvSock (void) {
    return logServiceCtxtInstance->statusRecvSock;
}

int
logServiceStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    u_int retries;
    char *statusMsg;
    u_int status;
    pthread_t tid;

    statusMsg =  zstr_recv_nowait (logServiceCtxtInstance->statusRecvSock);
    if (statusMsg == NULL)
        return 0;

    sscanf (statusMsg, "%u:%lu", &status, &tid);
    switch (status) {
        case LOG_SERVICE_STATUS_EXIT:
            fprintf (stderr, "Task %lu exit abnormally.\n", tid);
            retries = 0;
            while (retries < LOG_SERVICE_RESTART_MAX_RETRIES) {
                fprintf (stdout, "Try to restart logService with retries: %u.\n", retries);
                ret = pthread_create (&logServiceCtxtInstance->tid, NULL, logService, NULL);
                if (!ret)
                    break;

                retries++;
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

/* Init log service */
int
initLogService (void) {
    int ret;

    logServiceCtxtInstance = (logServiceCtxtPtr) malloc (sizeof (logServiceCtxt));
    if (logServiceCtxtInstance == NULL) {
        fprintf (stderr, "Alloc logServiceCtxtInstance error.\n");
        return -1;
    }

    logServiceCtxtInstance->zmqCtxt = zctx_new ();
    if (logServiceCtxtInstance->zmqCtxt == NULL) {
        fprintf (stderr, "Create zmq context error");
        goto freeLogServiceCtxtInstance;
    }
    zctx_set_linger (logServiceCtxtInstance->zmqCtxt, 0);

    /* Create statusSendSock */
    logServiceCtxtInstance->statusSendSock = zsocket_new (logServiceCtxtInstance->zmqCtxt, ZMQ_PUSH);
    if (logServiceCtxtInstance->statusSendSock == NULL) {
        fprintf (stderr, "Create statusSendSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (logServiceCtxtInstance->statusSendSock, LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        fprintf (stderr, "Bind to %s error.\n", LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create statusRecvSock */
    logServiceCtxtInstance->statusRecvSock = zsocket_new (logServiceCtxtInstance->zmqCtxt, ZMQ_PULL);
    if (logServiceCtxtInstance->statusRecvSock == NULL) {
        fprintf (stderr, "Create statusRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_connect (logServiceCtxtInstance->statusRecvSock, LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
    if (ret < 0) {
        fprintf (stderr, "Connect to %s error.\n", LOG_SERVICE_STATUS_EXCHANGE_CHANNEL);
        goto destroyZmqCtxt;
    }

    /* Create logRecvSock */
    logServiceCtxtInstance->logRecvSock = zsocket_new (logServiceCtxtInstance->zmqCtxt, ZMQ_PULL);
    if (logServiceCtxtInstance->logRecvSock == NULL) {
        fprintf (stderr, "Create logRecvSock error.\n");
        goto destroyZmqCtxt;
    }
    ret = zsocket_bind (logServiceCtxtInstance->logRecvSock, "tcp://*:%u", LOG_SERVICE_LOG_RECV_PORT);
    if (ret < 0) {
        fprintf (stderr, "Bind to \"tcp://*:%u\" error.\n", LOG_SERVICE_LOG_RECV_PORT);
        goto destroyZmqCtxt;
    }

    ret = pthread_create (&logServiceCtxtInstance->tid, NULL, logService, NULL);
    if (ret < 0) {
        fprintf (stderr, "Start logService error.\n");
        goto destroyZmqCtxt;
    }

    return 0;

destroyZmqCtxt:
    zctx_destroy (&logServiceCtxtInstance->zmqCtxt);
freeLogServiceCtxtInstance:
    free (logServiceCtxtInstance);
    logServiceCtxtInstance = NULL;
    return -1;
}

/* Destroy log service */
void
destroyLogService (void) {
    pthread_kill (logServiceCtxtInstance->tid, SIGUSR1);
    usleep (100000);
    zctx_destroy (&logServiceCtxtInstance->zmqCtxt);
    free (logServiceCtxtInstance);
    logServiceCtxtInstance = NULL;
}
