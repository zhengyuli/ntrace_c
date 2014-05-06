#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <czmq.h>
#include <string.h>
#include "typedef.h"
#include "log.h"
#include "util.h"

#define MAX_PID_TABLE_SIZE 100

/* Log service ip */
static char *logServiceIp = NULL;
/* Display log with detail info */
static BOOL showInDetail  = FALSE;
/* Process name to filter */
static char *procName = NULL;
/* Log level to filter */
static char *logLevel = NULL;
/* PIDs to filter */
static pid_t pidTable [MAX_PID_TABLE_SIZE] = {0};
/* Count of PIDs to filter */
static u_int pidTableCount = 0;

static zctx_t *zmqContext = NULL;
static void *subSock = NULL;

/* Check log level is valid */
static BOOL
checkLogLevel (const char *logLevel) {
    if (strEqual ("ERR", logLevel) ||
        strEqual ("WARNING", logLevel) ||
        strEqual ("INFO", logLevel) ||
        strEqual ("DEBUG", logLevel))
        return TRUE;
    else
        return FALSE;
}

static BOOL
pidTableIsEqual (pid_t pidTable1 [], pid_t pidTable2 [], u_int size) {
    u_int i;

    for (i = 0; i < size; i++) {
        if (pidTable1 [i] != pidTable2 [i])
            return FALSE;
    }

    return TRUE;
}

static inline void
copyPidTable (pid_t pidTableDst [], pid_t pidTableSrc [], u_int size) {
    u_int i;

    for (i = 0; i < size; i++)
        pidTableDst [i] = pidTableSrc [i];
}

static void
subLog (void) {
    u_int index;
    char filter [50] = {0};

    if (subSock == NULL)
        return;

    if (procName) {
        if (pidTableCount) {
            for (index = 0; index < pidTableCount; index++) {
                snprintf (filter, sizeof (filter) - 1, "[pid:%d", pidTable [index]);
                zsocket_set_subscribe (subSock, filter);
            }
        } else {
            snprintf (filter, sizeof (filter) - 1, "magic");
            zsocket_set_subscribe (subSock, filter);
        }
    } else {
        filter [0] = 0;
        zsocket_set_subscribe (subSock, filter);
    }
}

static void
unsubLog (void) {
    u_int index;
    char filter[50] = {0};

    if (subSock == NULL)
        return;

    if (procName) {
        if (pidTableCount) {
            for (index = 0; index < pidTableCount; index++) {
                snprintf (filter, sizeof (filter) - 1, "[pid:%d", pidTable [index]);
                zsocket_set_unsubscribe (subSock, filter);
            }
        } else {
            snprintf (filter, sizeof (filter) - 1, "magic");
            zsocket_set_unsubscribe (subSock, filter);
        }
    }
}

static void
updateSubRules (void) {
    char cmd [128];
    char buf [128];
    pid_t newPidTable [MAX_PID_TABLE_SIZE] = {0};
    u_int newPidTableCount = 0;
    FILE *fp;

    if (procName) {
        /* Get pids of procName */
        snprintf (cmd, sizeof (cmd) - 1, "ps -fLC %s|tr -s ' '|cut -d' ' -f2", procName);
        fp = popen (cmd, "r");
        if (fp == NULL)
            return;
        while (fgets (buf, sizeof (buf), fp) && (newPidTableCount <= MAX_PID_TABLE_SIZE)) {
            if (!strncmp (buf, "PID", 3))
                continue;
            else
                newPidTable [newPidTableCount ++] = atoi (buf);
        }
        pclose (fp);

        if ((pidTableCount != newPidTableCount) || !pidTableIsEqual (pidTable, newPidTable, newPidTableCount)) {
            unsubLog ();
            pidTableCount = newPidTableCount;
            copyPidTable (pidTable, newPidTable, newPidTableCount);
            subLog ();
        }
    } else
        subLog ();
}

/* Logview options */
static struct option logviewOptions [] = {
    {"address", required_argument, NULL, 'i'},
    {"proc", required_argument, NULL, 'p'},
    {"level", required_argument, NULL, 'l'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0}
};

static void
showHelp (const char *cmd) {
    const char *cmdName, *tmp;

    tmp = strrchr (cmd, '/');
    if (tmp)
        cmdName = tmp + 1;
    else
        cmdName = cmd;

    printf ("Usage: %s [options]\n"
            "       %s [-h]\n"
            "Options:\n"
            "  -i|--address <ip>, ip addr of log service\n"
            "  -p|--proc <procName>, process name\n"
            "  -l|--level <logLevel>, optional log level: ERR, WARNING, INFO, DEBUG\n"
            "  -v|--verbose, display log in detail\n"
            "  -h|--help, help info\n",
            cmdName, cmdName);
}

/* Parse command line */
static int
parseCmdline (int argc, char *argv []) {
    int ret = 0;
    char option;

    while ((option = getopt_long (argc, argv, "i:p:l:vh?", logviewOptions, NULL)) != -1) {
        switch (option) {
            case 'i':
                logServiceIp = strdup (optarg);
                if (logServiceIp == NULL)
                    return -1;
                break;

            case 'p':
                procName = strdup (optarg);
                if (procName == NULL)
                    return -1;
                break;

            case 'l':
                logLevel = strdup (optarg);
                if (logLevel == NULL)
                    return -1;
                ret = checkLogLevel (logLevel);
                if (ret < 0) {
                    fprintf (stderr, "Wrong log level.\n");
                    ret = -1;
                }
                break;

            case 'v':
                showInDetail = 1;
                break;

            case 'h':
            default:
                showHelp (argv [0]);
                ret = -1;
        }
    }

    return ret;
}

/* Thread to update subscribe filter */
static void *
subUpdateMonitor (void *args) {
    while (1)
    {
        updateSubRules ();
        usleep (500000);
    }

    return ((void *) 0);
}

static int
logSvcIsRunning (const char *ip) {
    int ret;
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf (stderr, "Create socket error.\n");
        return 0;
    }

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    ret = inet_pton (AF_INET, ip ? ip : "127.0.0.1", &addr.sin_addr);
    if (ret < 0) {
        fprintf (stderr, "Ivalid log service ip.\n");
        return 0;
    }
    addr.sin_port = htons (LOG_SERVICE_PUBLISH_PORT);

    ret = connect (sockfd, (const struct sockaddr *) &addr, sizeof (addr));
    if (ret < 0)
        ret = 0;
    else
        ret = 1;
    close (sockfd);

    return ret;
}

int
main (int argc, char *argv []) {
    int ret;
    char *logMsg, *tmp;

    /* Parse command line */
    ret = parseCmdline (argc, argv);
    if (ret < 0) {
        showHelp (argv [0]);
        return -1;
    }

    /* Check log service state */
    if (!logSvcIsRunning (logServiceIp)) {
        fprintf (stderr, "The log service on %s is not running.\n", logServiceIp ? logServiceIp : "127.0.0.1");
        return -1;
    }

    /* Init zmq context */
    zmqContext = zctx_new ();
    if (zmqContext == NULL)
        return -1;
    subSock = zsocket_new (zmqContext, ZMQ_SUB);
    if (subSock == NULL) {
        zctx_destroy (&zmqContext);
        return -1;
    }
    ret = zsocket_connect (subSock, "tcp://%s:%d", logServiceIp ? logServiceIp : "localhost", LOG_SERVICE_PUBLISH_PORT);
    if (ret < 0) {
        zctx_destroy (&zmqContext);
        return -1;
    }

    /* Create sub-thread to check update rule periodically */
    ret = zthread_new (subUpdateMonitor, NULL);
    if (ret < 0) {
        fprintf (stderr, "Create subUpdateMonitor thread error.\n");
        zctx_destroy (&zmqContext);
        return -1;
    }

    while (!zctx_interrupted) {
        logMsg = zstr_recv (subSock);
        if (logMsg) {
            if (logLevel) {
                if (strstr (logMsg, logLevel)) {
                    if (showInDetail)
                        printf ("%s", logMsg);
                    else {
                        tmp = strstr (logMsg, ">:");
                        printf ("%s", (tmp + 2));
                    }
                }
            } else {
                if (showInDetail)
                    printf ("%s", logMsg);
                else {
                    tmp = strstr (logMsg, ">:");
                    printf ("%s", (tmp + 2));
                }
            }
            free (logMsg);
        }
    }

    zctx_destroy (&zmqContext);
    return 0;
}
