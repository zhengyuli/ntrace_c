#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <czmq.h>
#include <string.h>
#include "log.h"
#include "util.h"

/* Process name to filter */
static char *procName = NULL;
/* Logd service ip */
static char *srvIp = NULL;
/* Log level to filter */
static char *msgLevel = NULL;
/* PIDs to filter */
static uint pidTable [100] = {0};
/* Number of PIDs to filter */
static uint pidTableItems = 0;
/* Display log with detail info */
static uint showDetails  = 0;

static zctx_t *zmqContext = NULL;
static void *subSock = NULL;

/* Logview options */
static struct option logviewOptions [] = {
    {"server", required_argument, NULL, 's'},
    {"proc",   required_argument, NULL, 'p'},
    {"level",  required_argument, NULL, 'l'},
    {"verbose",no_argument,       NULL, 'v'},
    {"help",   no_argument,       NULL, 'h'},
    {NULL,     no_argument,       NULL, 0}
};

static int
checkMsgLevel (const char *msgLevel) {
    if (!strcmp ("ERR", msgLevel) ||
        !strcmp ("WARNING", msgLevel) ||
        !strcmp ("INFO", msgLevel) ||
        !strcmp ("DEBUG", msgLevel))
        return 0;
    else
        return -1;
}

static int
pidTableEqual (uint pidTable1 [], uint pidTable2 [], uint size) {
    int i;

    for (i = 0; i < size; i++) {
        if (pidTable1 [i] != pidTable2 [i])
            return 0;
    }

    return 1;
}

static inline void
pidTableCopy (uint pidTableDst [], uint pidTableSrc [], uint size) {
    int i;

    for (i = 0; i < size; i++)
        pidTableDst [i] = pidTableSrc [i];
}

static void
subMsg (void) {
    int index;
    char filter [50];

    if (subSock == NULL)
        return;

    if (procName) {
        if (pidTableItems) {
            for (index = 0; index < pidTableItems; index++) {
                snprintf (filter, sizeof (filter), "[pid:%d", pidTable [index]);
                zsocket_set_subscribe (subSock, filter);
            }
        } else {
            snprintf (filter, sizeof (filter), "magic");
            zsocket_set_subscribe (subSock, filter);
        }
    } else {
        filter [0] = 0;
        zsocket_set_subscribe (subSock, filter);
    }
}

static void
unsubMsg (void) {
    int index;
    char filter[50];

    if (subSock == NULL)
        return;

    if (procName) {
        if (pidTableItems) {
            for (index = 0; index < pidTableItems; index++) {
                snprintf (filter, sizeof (filter), "[pid:%d", pidTable [index]);
                zsocket_set_unsubscribe (subSock, filter);
            }
        } else {
            snprintf (filter, sizeof (filter), "magic");
            zsocket_set_unsubscribe (subSock, filter);
        }
    }
}

static void
updateSubRules () {
    static int init = 1;
    char cmd [100];
    char buf [100];
    uint newPidTable [100] = {0};
    uint newPidTableItems = 0;
    FILE *fp;

    if (!procName) {
        if (init) {
            subMsg ();
            init = 0;
        }
        return;
    }

    snprintf (cmd, sizeof (cmd), "ps -fLC %s|tr -s ' '|cut -d' ' -f2", procName);
    fp = popen (cmd, "r");
    if (fp == NULL)
        return;

    while (fgets (buf, sizeof (buf), fp) && (newPidTableItems <= TABLE_SIZE (newPidTable))) {
        if (!strncmp (buf, "PID", 3))
            continue;
        else
            newPidTable [newPidTableItems ++] = atoi (buf);
    }

    if (init) {
        pidTableItems = newPidTableItems;
        pidTableCopy (pidTable, newPidTable, newPidTableItems);
        subMsg ();
        init = 0;
    } else {
        if ((pidTableItems != newPidTableItems) ||
            (!pidTableEqual (pidTable, newPidTable, newPidTableItems))) {
            unsubMsg ();
            pidTableItems = newPidTableItems;
            pidTableCopy (pidTable, newPidTable, newPidTableItems);
            subMsg();
        }
    }

    pclose (fp);
}

static void
showHelp (const char *cmd) {
    const char *cmdName, *tmp;

    tmp = strrchr(cmd, '/');
    if (tmp)
        cmdName = tmp + 1;
    else
        cmdName = cmd;

    printf ("Usage: %s [options]\n"
            "       %s [-h]\n"
            "Options:\n"
            "  -s|--server   ip addr of logd server\n"
            "  -p|--proc     process name\n"
            "  -l|--level    optional log level: ERR, WARNING, INFO, DEBUG\n"
            "  -v|--verbose  display log in detail\n"
            "  -h|--help     help info\n", cmdName, cmdName);
}

static int
parseCmdline (int argc, char *argv []) {
    int ret = 0;
    char option;

    while ((option = getopt_long (argc, argv, "s:p:l:vh?", logviewOptions, NULL)) != -1) {
        switch (option) {
            case 's':
                srvIp = strdup (optarg);
                if (srvIp == NULL)
                    return -1;
                break;

            case 'p':
                procName = strdup (optarg);
                if (procName == NULL)
                    return -1;
                break;

            case 'l':
                msgLevel = strdup (optarg);
                if (msgLevel == NULL)
                    return -1;
                ret = checkMsgLevel (msgLevel);
                if (ret < 0)
                    ret = -1;
                break;

            case 'v':
                showDetails = 1;
                break;

            case 'h':
            default:
                showHelp (argv [0]);
                ret = -1;
        }
    }

    return ret;
}

static void *
subUpdateMonitor (void *args) {
    while (1)
    {
        updateSubRules ();
        usleep (500000);
    }

    return ((void *) 0);
}

int
main (int argc, char *argv []) {
    int ret;
    char *msg, *tmp;

    ret = parseCmdline (argc, argv);
    if (ret < 0)
        return -1;

    ret = remoteServiceRun (srvIp, LOG_NET_SOCK_PORT);
    if (!ret) {
        printf ("Logd is not running.\n");
        return -1;
    }

    zmqContext = zctx_new ();
    if (zmqContext == NULL)
        return -1;
    subSock = zsocket_new (zmqContext, ZMQ_SUB);
    if (subSock == NULL) {
        zctx_destroy (&zmqContext);
        return -1;
    }
    ret = zsocket_connect (subSock, "tcp://%s:%d",
                           srvIp ? srvIp : "localhost",
                           LOG_NET_SOCK_PORT);
    if (ret < 0) {
        zctx_destroy (&zmqContext);
        return -1;
    }

    /* create sub-thread to monitor service update */
    ret = zthread_new (subUpdateMonitor, NULL);
    if (ret < 0) {
        printf ("Create subUpdateMonitor thread error.\n");
        zctx_destroy (&zmqContext);
        return -1;
    }

    while (!zctx_interrupted) {
        msg = zstr_recv (subSock);
        if (msg) {
            if (msgLevel) {
                if (strstr (msg, msgLevel)) {
                    if (showDetails)
                        printf ("%s", msg);
                    else {
                        tmp = strstr (msg, ">:");
                        printf ("%s", (tmp + 2));
                    }
                }
            } else {
                if (showDetails)
                    printf ("%s", msg);
                else {
                    tmp = strstr (msg, ">:");
                    printf ("%s", (tmp + 2));
                }
            }
            free (msg);
        }
    }

    zctx_destroy (&zmqContext);
    return 0;
}
