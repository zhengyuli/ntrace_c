#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <czmq.h>
#include <locale.h>
#include "config.h"
#include "util.h"
#include "properties.h"
#include "args_parser.h"
#include "signals.h"
#include "log_service.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "proto_analyzer.h"
#include "app_service_manager.h"
#include "netdev.h"
#include "management_service.h"
#include "raw_packet_capture_service.h"
#include "ip_packet_process_service.h"
#include "tcp_packet_process_service.h"

/* Agent pid file fd */
static int agentPidFd = -1;

static int
lockPidFile (void) {
    int ret;
    pid_t pid;
    ssize_t n;
    char buf [16];

    pid = getpid ();

    agentPidFd = open (AGENT_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (agentPidFd < 0)
        return -1;

    ret = flock (agentPidFd, LOCK_EX | LOCK_NB);
    if (ret < 0) {
        close (agentPidFd);
        return -1;
    } else {
        snprintf (buf, sizeof (buf), "%d", pid);
        n = safeWrite (agentPidFd, buf, strlen (buf));
        if (n != strlen (buf)) {
            close (agentPidFd);
            remove (AGENT_PID_FILE);
            return -1;
        }
        sync ();
    }

    return 0;
}

static void
unlockPidFile (void) {
    if (agentPidFd >= 0) {
        flock (agentPidFd, LOCK_UN);
        close (agentPidFd);
        agentPidFd = -1;
    }
    remove (AGENT_PID_FILE);
}

static int
startTasks (void) {
    int ret;
    u_int i;

    ret = newTask (managementService, NULL);
    if (ret < 0) {
        LOGE ("Create managementService task error.\n");
        goto stopAllTask;
    }

    ret = newTask (rawPktCaptureService, NULL);
    if (ret < 0) {
        LOGE ("Create rawPktCaptureService task error.\n");
        goto stopAllTask;
    }

    ret = newTask (ipPktProcessService, NULL);
    if (ret < 0) {
        LOGE ("Create ipPktParsingService task error.\n");
        goto stopAllTask;
    }

    for (i = 0; i < getTcpPktParsingThreadsNum (); i++) {
        ret = newTask (tcpPktProcessService, getTcpPktParsingThreadIDHolder (i));
        if (ret < 0) {
            LOGE ("Create tcpPktParsingService %u task error.\n", i);
            goto stopAllTask;
        }
    }

    return 0;

stopAllTask:
    stopAllTask ();
    return -1;
}

static int
agentService (void) {
    int ret;
    boolean exitNormally = false;
    zloop_t *loop;
    zmq_pollitem_t pollItems [2];

    /* Lock agent pid file */
    ret = lockPidFile ();
    if (ret < 0) {
        fprintf (stderr, "Lock pid file error.\n");
        return -1;
    }

    /* Setup signal */
    setupSignals ();

    /* Init log service */
    ret = initLogService ();
    if (ret < 0) {
        fprintf (stderr, "Init log service error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        ret = -1;
        goto destroyLogService;
    }

    /* Init zmq hub */
    ret = initZmqHub ();
    if (ret < 0) {
        LOGE ("Init zmq hub error.\n");
        ret = -1;
        goto destroyLog;
    }

    /* Init task manager */
    ret = initTaskManager ();
    if (ret < 0) {
        LOGE ("Init task manager error.\n");
        ret = -1;
        goto destroyZmqHub;
    }

    /* Init proto analyzer */
    ret = initProtoAnalyzer ();
    if (ret < 0) {
        LOGE ("Init proto context error.\n");
        goto destroyTaskManager;
    }

    /* Init application service manager */
    ret = initAppServiceManager ();
    if (ret < 0) {
        LOGE ("Init application service manager error.\n");
        ret = -1;
        goto destroyProtoAnalyzer;
    }

    ret = initNetDev ();
    if (ret < 0) {
        LOGE ("Init net device error.\n");
        ret = -1;
        goto destroyAppServiceManager;
    }

    ret = startTasks ();
    if (ret < 0) {
        LOGE ("Start tasks error.\n");
        ret = -1;
        goto destroyNetDev;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto stopAllTask;
    }

    /* Init poll item 0*/
    pollItems [0].socket = getLogServiceStatusRecvSock ();
    pollItems [0].fd = 0;
    pollItems [0].events = ZMQ_POLLIN;
    /* Register poll item 0 */
    ret = zloop_poller (loop, &pollItems [0], logServiceStatusHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [0] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Init poll item 1*/
    pollItems [1].socket = getTaskStatusRecvSock ();
    pollItems [1].fd = 0;
    pollItems [1].events = ZMQ_POLLIN;
    /* Register poll item 1 */
    ret = zloop_poller (loop, &pollItems [1], taskStatusHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [1] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Start zloop */
    ret = zloop_start (loop);
    if (ret < 0) {
        exitNormally = false;
        LOGE ("Agent exit abnormally.\n");
    } else {
        exitNormally = true;
        LOGD ("Agent exit normally.\n");
    }

destroyZloop:
    zloop_destroy (&loop);
stopAllTask:
    stopAllTask ();
destroyNetDev:
    destroyNetDev();
destroyAppServiceManager:
    destroyAppServiceManager (exitNormally);
destroyProtoAnalyzer:
    destroyProtoAnalyzer ();
destroyTaskManager:
    destroyTaskManager ();
destroyZmqHub:
    destroyZmqHub ();
destroyLog:
    destroyLog ();
destroyLogService:
    destroyLogService ();
unlockPidFile:
    unlockPidFile ();
    return ret;
}

static int
agentDaemon (void) {
    pid_t pid, next_pid;
    int stdinfd;
    int stdoutfd;

    if (chdir ("/") < 0) {
        fprintf (stderr, "Chdir error: %s.\n", strerror (errno));
        return -1;
    }

    pid = fork ();
    switch (pid) {
        case 0:
            if ((stdinfd = open ("/dev/null", O_RDONLY)) < 0)
                return -1;

            if ((stdoutfd = open ("/dev/null", O_WRONLY)) < 0) {
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdinfd, STDIN_FILENO) != STDIN_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdoutfd, STDOUT_FILENO) != STDOUT_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdoutfd, STDERR_FILENO) != STDERR_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (stdinfd > STDERR_FILENO)
                close (stdoutfd);

            if (stdoutfd > STDERR_FILENO)
                close (stdinfd);

            /* Set session id */
            if (setsid () < 0) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            next_pid = fork ();
            switch (next_pid) {
                case 0:
                    return agentService ();

                case -1:
                    return -1;

                default:
                    return 0;
            }

        case -1:
            return -1;

        default:
            return 0;
    }
}

int
main (int argc, char *argv []) {
    int ret;

    if (getuid () != 0) {
        fprintf (stderr, "Permission denied, please run as root.\n");
        return -1;
    }

    /* Set locale */
    setlocale (LC_COLLATE,"");

    /* Init properties */
    ret = initProperties ();
    if (ret < 0) {
        fprintf (stderr, "Init properties error.\n");
        return -1;
    }

    /* Parse command line arguments */
    ret = parseArgs (argc, argv);
    if (ret < 0) {
        fprintf (stderr, "Parse command line arguments error.\n");
        ret = -1;
        goto destroyProperties;
    }

    /* Run as daemon process */
    if (getPropertiesDaemonMode ())
        ret = agentDaemon ();
    else
        ret = agentService ();

destroyProperties:
    destroyProperties ();
    return ret;
}
