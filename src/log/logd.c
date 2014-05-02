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
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include "list.h"
#include "log.h"
#include "util.h"

#define LOGD_DEFAULT_PID_FILE "/var/run/logd.pid"
#define LOG_FILE_DIR "/var/log/wdm/"
#define LOG_FILE_NAME "agent.log"
/* Number of log files to rotate */
#define LOG_FILE_ROTATE_NUM 4

/* Log file max size is 512MB */
#define LOG_FILE_MAX_SIZE (512 << 20)
/* Log file size check count */
#define LOG_FILE_NEED_CHECK 200
#define LOG_FILE_PATH_MAX_LEN 200
#define LOG_TO_FILE_MASK (1 << 0)
#define LOG_TO_NET_MASK (1 << 1)

/* Logd status */
static int logdExit = 0;
/* Logd pid file */
static char *logdPidFile = NULL;
/* Logd pid file fd */
static int logdPidFileFd = -1;

/* Logd options */
static struct option logdOptions [] = {
    {"pid-file", required_argument, NULL, 'f'},
    {"daemon", no_argument, NULL, 'd'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0},
};

typedef struct _logDev logDev;
typedef logDev *logDevPtr;
/*
 * Log backend dev, every dev has three interfaces,
 * you can add new log dev into log system with log_dev_add
 */
struct _logDev {
    listHead node;
    void *data;

    /* operations for log dev */
    int (*init) (logDevPtr dev);
    void (*destroy) (logDevPtr dev);
    void (*write) (const char *msg, logDevPtr dev, int flag);
};

/* Bit test */
static inline int
testBit (int flag, int bitMask) {
    return flag & bitMask;
}

/*===========================log file dev=================================*/

typedef struct _logFile logFile;
typedef logFile *logFilePtr;

struct _logFile {
    int fd;
    char *filePath;
    int checkCount;
    int maxSize;
};

/*
 * @brief Check whether current log file has over the max log file
 *        size, if so, return 1 else return 0.
 *
 * @param filePath current log file path
 *
 * @return 1 oversized, 0 no oversized, -1 for other cases
 */
static int
logFileOversize (const char *filePath) {
    int ret;
    struct stat fileStat;

    ret = stat (filePath, &fileStat);
    if (ret < 0)
        return -1;

    if (fileStat.st_size >= LOG_FILE_MAX_SIZE)
        return 1;
    else
        return 0;
}

/*
 * @brief Rotate log file name
 *
 * @param logFileName base file to rotate
 *
 * @return 0 if success, else -1
 */
static int
logFileNameRotate (const char *logFileName) {
    int ret;
    int i;
    char fileNameBuf1 [512];
    char fileNameBuf2 [512];

    for (i = (LOG_FILE_ROTATE_NUM - 1); i > 0; i--) {
        if (i == (LOG_FILE_ROTATE_NUM - 1)) {
            snprintf (fileNameBuf2, sizeof (fileNameBuf2) - 1, "%s_%d", logFileName, i);
            if (fileExist (fileNameBuf2, F_OK)) {
                ret = remove (fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file name rotate error.\n");
                    return -1;
                }
            }
        } else {
            snprintf (fileNameBuf1, sizeof (fileNameBuf1) - 1, "%s_%d", logFileName, i);
            snprintf (fileNameBuf2, sizeof (fileNameBuf2) - 1, "%s_%d", logFileName, i + 1);
            if (fileExist (fileNameBuf1, F_OK)) {
                ret = rename (fileNameBuf1, fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file name rotate error.\n");
                    return -1;
                }
            }
        }
    }

    if (LOG_FILE_ROTATE_NUM == 1) {
        ret = remove (logFileName);
        if (ret < 0) {
            fprintf (stderr, "Log file name rotate error.\n");
            return -1;
        }
    } else {
        snprintf (fileNameBuf2, sizeof (fileNameBuf2) - 1, "%s_%d", logFileName, 1);
        ret = rename (logFileName, fileNameBuf2);
        if (ret < 0) {
            fprintf (stderr, "Log file name rotate error.\n");
            return -1;
        }
    }

    return 0;
}

/* Update log file when exceeding max log file size limit */
static int
logFileUpdate (logDevPtr dev) {
    int ret;
    char logFilePath [128];
    logFilePtr logfile = (logFilePtr) dev->data;

    /* Close current log file */
    close (logfile->fd);
    /* Rotate log file name */
    ret = logFileNameRotate (logfile->filePath);
    if (ret < 0)
        return -1;
    /* Reopen new log file */
    logfile->fd = open (logfile->filePath, O_WRONLY | O_APPEND | O_CREAT, 0755);
    if (logfile->fd < 0)
        return -1;

    logfile->checkCount = 0;
    return 0;
}

static int
logFileInit (logDevPtr dev) {
    char logFilePath [128];
    logFilePtr logfile;

    if (!fileExist (LOG_FILE_DIR, F_OK) &&
        (mkdir (LOG_FILE_DIR, 0755) < 0))
        return -1;

    logfile = malloc (sizeof (logFile));
    if (logfile == NULL)
        return -1;

    snprintf (logFilePath, sizeof (logFilePath), "%s/%s", LOG_FILE_DIR, LOG_FILE_NAME);
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
    logfile->maxSize = LOG_FILE_MAX_SIZE;
    dev->data = logfile;

    return 0;
}

static void
logFileDestroy (logDevPtr dev) {
    logFilePtr logfile = (logFilePtr) dev->data;
    if (logfile) {
        if (logfile->filePath)
            free (logfile->filePath);
        if (logfile->fd != -1)
            close (logfile->fd);
        free (logfile);
    }
}

static void
logFileWrite (const char *msg, logDevPtr dev, int flag) {
    int ret;
    logFilePtr logfile;

    if (!testBit (flag, LOG_TO_FILE_MASK))
        return;

    logfile = (logFilePtr) dev->data;
    ret = safeWrite (logfile->fd, msg, strlen (msg));
    logfile->checkCount++;
    if (ret < 0) {
        logdExit = 1;
        fprintf (stderr, "log file write error.\n");
        return;
    }
    if (logfile->checkCount >= LOG_FILE_NEED_CHECK) {
        ret = logFileOversize (logfile->filePath);
        if (ret < 0) {
            logdExit = 1;
            fprintf (stderr, "check log file oversize error.\n");
            return;
        }
        if (ret == 1) {
            ret = logFileUpdate (dev);
            if (ret < 0)
                logdExit = 1;
            fprintf (stderr, "log file update error.\n");
        }
    }
}

/*===========================log net dev=================================*/

typedef struct _logNet logNet;
typedef logNet *logNetPtr;

struct _logNet {
    zctx_t *context;
    void *sock;
    int type;
};

static int
logNetInit (logDevPtr dev) {
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

    lognet->type = ZMQ_PUB;
    lognet->sock = zsocket_new (lognet->context, lognet->type);
    if (lognet->sock == NULL) {
        zctx_destroy (&lognet->context);
        return -1;
    }

    ret = zsocket_bind (lognet->sock, "tcp://*:%d", LOG_SERVICE_PUBLISH_PORT);
    if (ret != LOG_SERVICE_PUBLISH_PORT) {
        zctx_destroy (&lognet->context);
        return -1;
    }

    return 0;
}

static void
logNetWrite (const char *msg, logDevPtr dev, int flag) {
    int ret;
    logNetPtr lognet;
    zframe_t *frame = NULL;

    if (!testBit (flag, LOG_TO_NET_MASK))
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
logNetDestroy (logDevPtr dev) {
    logNetPtr lognet = (logNetPtr) dev->data;
    if (lognet) {
        zctx_destroy (&lognet->context);
        free (lognet);
    }
}

/*============================log dev================================*/

static int
logDevAdd (listHeadPtr logDevices, logDevPtr dev) {
    int ret;

    ret = dev->init (dev);
    if (ret < 0)
        return -1;

    listAdd (&dev->node, logDevices);

    return 0;
}

static void
logDevWrite (listHeadPtr logDevices, const char *msg) {
    int flag;
    logDevPtr dev;
    const char *message = msg + 1;

    switch (msg [0]) {
        case 'f':
            flag = LOG_TO_FILE_MASK;
            break;
        case 'n':
            flag = LOG_TO_NET_MASK;
            break;
        case 'a':
            flag = LOG_TO_FILE_MASK | LOG_TO_NET_MASK;
            break;
        default:
            flag = 0;
            break;
    }

    listForEachEntry (dev, logDevices, node) {
        dev->write (message, dev, flag);
    }
}

static void
logDevDestroy (listHeadPtr logDevices) {
    logDevPtr dev, ndev;

    listForEachEntrySafe (dev, ndev, logDevices, node) {
        dev->destroy (dev);
        listDel (&dev->node);
    }
}

static int
lockPidFile (void) {
    pid_t pid;
    ssize_t n;
    char buf [16];

    pid = getpid ();

    logdPidFileFd = open (logdPidFile, O_CREAT | O_RDWR, 0666);
    if (logdPidFileFd < 0) {
        fprintf(stderr, "Open pid file %s error: %s.\n", logdPidFile, strerror (errno));
        return -1;
    }

    if (flock (logdPidFileFd, LOCK_EX | LOCK_NB) == 0) {
        snprintf (buf, sizeof (buf), "%d", pid);
        n = write (logdPidFileFd, buf, strlen (buf));
        if (n != strlen (buf)) {
            fprintf(stderr, "Write pid to pid file error: %s.\n", strerror (errno));
            close (logdPidFileFd);
            remove (logdPidFile);
            return -1;
        }
        sync ();
    } else {
        fprintf (stderr, "Logd service is running.\n");
        close (logdPidFileFd);
        return -1;
    }

    return 0;
}

static void
freePidFile (void) {
    int ret;

    if (logdPidFileFd != -1) {
        flock (logdPidFileFd, LOCK_UN);
        close (logdPidFileFd);
        remove (logdPidFile);
    }
}

static void
logd (void) {
    int ret;
    char *msg;
    zctx_t *context;
    void *logdRcvSock;

    logDev logFileDev = {
        .init = logFileInit,
        .destroy = logFileDestroy,
        .write = logFileWrite,
    };

    logDev logNetDev = {
        .init = logNetInit,
        .destroy = logNetDestroy,
        .write = logNetWrite,
    };

    listHead logDevices;

    /* Lock pid file */
    if (lockPidFile () != 0)
        return;

    /* init logd front end to receive msg from clients */
    context = zctx_new ();
    if (context == NULL)
        return;
    logdRcvSock = zsocket_new (context, ZMQ_PULL);
    if (logdRcvSock == NULL) {
        zctx_destroy (&context);
        return;
    }
    ret = zsocket_bind (logdRcvSock, "tcp://*:%d", LOG_SERVICE_SINK_PORT);
    if (ret != LOG_SERVICE_SINK_PORT) {
        zctx_destroy (&context);
        return;
    }

    /* add log dev */
    initListHead (&logDevices);
    ret = logDevAdd (&logDevices, &logFileDev);
    if (ret < 0) {
        zctx_destroy (&context);
        return;
    }
    ret = logDevAdd (&logDevices, &logNetDev);
    if (ret < 0) {
        logDevDestroy (&logDevices);
        zctx_destroy (&context);
        return;
    }

    while (!logdExit && !zctx_interrupted) {
        msg = zstr_recv (logdRcvSock);
        if (msg) {
            logDevWrite (&logDevices, msg);
            free (msg);
        }
    }

exit:
    freePidFile ();
    /* release log devices */
    logDevDestroy (&logDevices);
    zctx_destroy (&context);
}

static void
logdDaemon (void) {
    pid_t pid, next_pid;
    int stdinfd = -1;
    int stdoutfd = -1;

    if (chdir("/") < 0) {
        fprintf (stderr, "Chdir error: %s.\n", strerror (errno));
        exit (-1);
    }

    pid = fork ();
    switch (pid) {
        case 0: /* Child process 1 */
            if ((stdinfd = open ("/dev/null", O_RDONLY)) < 0)
                exit (-1);
            if ((stdoutfd = open ("/dev/null", O_WRONLY)) < 0) {
                close (stdinfd);
                free (logdPidFile);
                exit (-1);
            }
            if (dup2 (stdinfd, STDIN_FILENO) != STDIN_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                free (logdPidFile);
                exit (-1);
            }
            if (dup2 (stdoutfd, STDOUT_FILENO) != STDOUT_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                free (logdPidFile);
                exit (-1);
            }
            if (dup2 (stdoutfd, STDERR_FILENO) != STDERR_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                free (logdPidFile);
                exit (-1);
            }
            if (stdinfd > STDERR_FILENO)
                close (stdoutfd);
            if (stdoutfd > STDERR_FILENO)
                close (stdinfd);
            /* Set session id */
            if (setsid () < 0) {
                close (stdoutfd);
                close (stdinfd);
                free (logdPidFile);
                exit (-1);
            }

            next_pid = fork ();
            switch (next_pid) {
                case 0: /* Child process 2 */
                    logd ();
                    free (logdPidFile);
                    exit (0);

                case -1: /* Father 2 process exit abnormally */
                    free (logdPidFile);
                    exit (-1);

                default: /* Father 2 process exit normally */
                    free (logdPidFile);
                    exit (0);
            }

        case -1: /* Father 1 process exit abnormally */
            free (logdPidFile);
            exit (-1);

        default: /* Father 1 process exit normally */
            free (logdPidFile);
            exit (0);
    }
}

static void
showHelpInfo (const char *cmd) {
    const char *cmdName;

    cmdName = strrchr (cmd, '/') ? (strrchr (cmd, '/') + 1) : cmd;
    fprintf (stdout,
             "Usage: %s -f <pid-file> [-d]\n"
             "Basic options: \n"
             "  -d|--daemon run as daemon\n"
             "  -f|--pid-file <pid-file> pid file to write\n"
             "  -h|--help show help message\n",
             cmdName);
}

int
main (int argc, char *argv []) {
    char option;
    /* Whether run as daemon service */
    int runDaemon = 0;

    if (getuid () != 0) {
        fprintf (stderr, "Error: permission denied.\n");
        return -1;
    }

    /* Set locale */
    setlocale(LC_COLLATE,"");
    while ((option = getopt_long (argc, argv, "f:dh?", logdOptions, NULL)) != -1) {
        switch (option) {
            case 'f':
                logdPidFile = strdup (optarg);
                if (logdPidFile == NULL) {
                    fprintf(stderr, "Strdup logd pid file name error: %s.\n", strerror (errno));
                    return -1;
                }
                break;

            case 'd':
                runDaemon = 1;
                break;

            case 'h':
                showHelpInfo (argv [0]);
                return 0;

            case '?':
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (logdPidFile == NULL)
        logdPidFile = strdup (LOGD_DEFAULT_PID_FILE);
    if (logdPidFile == NULL) {
        fprintf(stderr, "Strdup logd pid file name error: %s.\n", strerror (errno));
        return -1;
    }

    if (runDaemon)
        logdDaemon ();
    else {
        logd ();
        free (logdPidFile);
    }

    return 0;
}
