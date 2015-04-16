#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <czmq.h>
#include <locale.h>
#include "config.h"
#include "util.h"
#include "properties.h"
#include "option_parser.h"
#include "signals.h"
#include "log_service.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "proto_analyzer.h"
#include "app_service_manager.h"
#include "ownership_manager.h"
#include "netdev.h"
#include "management_service.h"
#include "mining_service.h"
#include "raw_capture_service.h"
#include "ip_process_service.h"
#include "icmp_process_service.h"
#include "tcp_dispatch_service.h"
#include "tcp_process_service.h"

/* Agent pid file fd */
static int agentPidFd = -1;

static int
lockPidFile (void) {
    int ret;
    ssize_t n;
    char buf [16];

    if (!getPropertiesDaemonMode ())
        return 0;

    agentPidFd = open (AGENT_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (agentPidFd < 0)
        return -1;

    ret = flock (agentPidFd, LOCK_EX | LOCK_NB);
    if (ret < 0) {
        close (agentPidFd);
        return -1;
    }

    snprintf (buf, sizeof (buf), "%d", getpid ());
    n = safeWrite (agentPidFd, buf, strlen (buf));
    if (n != strlen (buf)) {
        close (agentPidFd);
        remove (AGENT_PID_FILE);
        return -1;
    }
    sync ();

    return 0;
}

static void
unlockPidFile (void) {
    if (!getPropertiesDaemonMode ())
        return;

    if (agentPidFd >= 0) {
        flock (agentPidFd, LOCK_UN);
        close (agentPidFd);
        agentPidFd = -1;
    }
    remove (AGENT_PID_FILE);
}

static int
startServices (void) {
    int ret;
    u_int i;

    ret = newTask (managementService, NULL);
    if (ret < 0) {
        LOGE ("Create managementService error.\n");
        goto stopAllTask;
    }

    ret = newTask (miningService, NULL);
    if (ret < 0) {
        LOGE ("Create miningService error.\n");
        goto stopAllTask;
    }

    ret = newTask (rawCaptureService, NULL);
    if (ret < 0) {
        LOGE ("Create rawCaptureService error.\n");
        goto stopAllTask;
    }

    ret = newTask (ipProcessService, NULL);
    if (ret < 0) {
        LOGE ("Create ipProcessService error.\n");
        goto stopAllTask;
    }

    ret = newTask (icmpProcessService, NULL);
    if (ret < 0) {
        LOGE ("Create icmpProcessService error.\n");
        goto stopAllTask;
    }

    ret = newTask (tcpDispatchService, NULL);
    if (ret < 0) {
        LOGE ("Create tcpDispatchService error.\n");
        goto stopAllTask;
    }

    for (i = 0; i < getTcpProcessThreadsNum (); i++) {
        ret = newTask (tcpProcessService, getTcpProcessThreadIDHolder (i));
        if (ret < 0) {
            LOGE ("Create tcpProcessService:%u error.\n", i);
            goto stopAllTask;
        }
    }

    return 0;

stopAllTask:
    stopAllTask ();
    return -1;
}

static void
stopServices (void) {
    stopAllTask ();
}

static int
agentService (void) {
    int ret;
    zloop_t *loop;
    zmq_pollitem_t pollItems [2];

    /* Check Permission */
    if (getuid () != 0) {
        fprintf (stderr, "Permission denied, please run as root.\n");
        return -1;
    }

    /* Lock pid file */
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
        goto destroyLogContext;
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

    ret = initOwnershipManager ();
    if (ret < 0) {
        LOGE ("Init packetOwnership error.\n");
        ret = -1;
        goto destroyAppServiceManager;
    }

    ret = initNetDev ();
    if (ret < 0) {
        LOGE ("Init net device error.\n");
        ret = -1;
        goto destroyOwnershipManager;
    }

    ret = startServices ();
    if (ret < 0) {
        LOGE ("Start services error.\n");
        ret = -1;
        goto destroyNetDev;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto stopServices;
    }

    /* Init poll item 0 */
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

    /* Init poll item 1 */
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
    if (ret < 0)
        LOGE ("Agent exit abnormally.\n");
    else
        LOGI ("Agent exit normally.\n");

destroyZloop:
    zloop_destroy (&loop);
stopServices:
    stopServices ();
destroyNetDev:
    destroyNetDev ();
destroyOwnershipManager:
    destroyOwnershipManager ();
destroyAppServiceManager:
    destroyAppServiceManager ();
destroyProtoAnalyzer:
    destroyProtoAnalyzer ();
destroyTaskManager:
    destroyTaskManager ();
destroyZmqHub:
    destroyZmqHub ();
destroyLogContext:
    destroyLogContext ();
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
        fprintf (stderr, "Change dir error: %s.\n", strerror (errno));
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
    char *configFile;

    /* Set locale */
    setlocale (LC_COLLATE,"");

    /* Get config file */
    configFile = getConfigFile (argc, argv);
    if (configFile == NULL) {
        fprintf (stderr, "Get config file error.\n");
        return -1;
    }

    /* Init properties */
    ret = initProperties (configFile);
    if (ret < 0) {
        fprintf (stderr, "Init properties error.\n");
        return -1;
    }

    /* Parse command line options */
    ret = parseOptions (argc, argv);
    if (ret < 0) {
        fprintf (stderr, "Parse command line options error.\n");
        ret = -1;
        goto destroyProperties;
    }

    /* Run as daemon or normal process */
    if (getPropertiesDaemonMode ())
        ret = agentDaemon ();
    else {
        displayPropertiesDetail ();
        ret = agentService ();
    }

destroyProperties:
    destroyProperties ();
    return ret;
}
