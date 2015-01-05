#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <czmq.h>
#include <jansson.h>
#include <locale.h>
#include "config.h"
#include "version.h"
#include "util.h"
#include "logger.h"
#include "zmq_hub.h"
#include "properties_manager.h"
#include "runtime_context.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "raw_packet_service.h"
#include "ip_packet_service.h"
#include "tcp_packet_service.h"
#include "agent.h"

/* Agent pid file fd */
static int agentPidFd = -1;

/*
 * Check agent id.
 * If agent id is valid return 0 else return -1
 */
static int
checkAgentId (json_t *profile) {
    json_t *tmp;

    tmp = json_object_get (profile, "agent_id");
    if (tmp == NULL)
        return -1;

    if (!strEqual (getAgentId (), json_string_value (tmp)))
        return -1;

    return 0;
}

/*
 * @brief Add and init agent runtime context
 *
 * @param profile add agent profile
 *
 * @return 0 if success else -1
 */
static int
addAgent (json_t *profile) {
    int ret;
    json_t *tmp;

    if (getAgentState () != AGENT_STATE_INIT) {
        LOGE ("Add agent error: agent already added.\n");
        return -1;
    }

    if ((json_object_get (profile, "agent_id") == NULL) ||
        (json_object_get (profile, "breakdown_sink_ip") == NULL) ||
        (json_object_get (profile, "breakdown_sink_port") == NULL)) {
        LOGE ("Add agent profile parse error.\n");
        return -1;
    }

    /* Update agent state */
    setAgentState (AGENT_STATE_STOPPED);

    /* Update agent id */
    tmp = json_object_get (profile, "agent_id");
    ret = setAgentId (strdup (json_string_value (tmp)));
    if (ret < 0) {
        LOGE ("Update agent id error.\n");
        resetRuntimeContext ();
        return -1;
    }

    /* Update breakdown sink ip */
    tmp = json_object_get (profile, "breakdown_sink_ip");
    ret = setBreakdownSinkIp (strdup (json_string_value (tmp)));
    if (ret < 0) {
        LOGE ("Update breakdown sink ip error.\n");
        resetRuntimeContext ();
        return -1;
    }

    /* Update breakdown sink port */
    tmp = json_object_get (profile, "breakdown_sink_port");
    setBreakdownSinkPort (json_integer_value (tmp));

    /* Dump runtime context */
    dumpRuntimeContext ();

    return 0;
}

/*
 * @brief Remove agent if agent is not running and reset agent
 *        runtime context.
 *
 * @param profile remove agent profile
 *
 * @return 0 if success else -1
 */
static int
removeAgent (json_t *profile) {
    int ret;

    if (getAgentState () == AGENT_STATE_RUNNING) {
        LOGE ("Agent is running, please stop it before removing.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    /* Reset application service manager */
    resetAppServiceManager ();
    /* Reset runtime context */
    resetRuntimeContext ();
    /* Dump runtime context */
    dumpRuntimeContext ();

    return 0;
}

static int
agentRun (void) {
    u_int i;
    taskId tid;

    tid = newTask (rawPktCaptureService, NULL);
    if (tid < 0) {
        LOGE ("Create rawPktCaptureService task error.\n");
        goto stopAllTask;
    }

    tid = newTask (ipPktParsingService, NULL);
    if (tid < 0) {
        LOGE ("Create ipPktParsingService task error.\n");
        goto stopAllTask;
    }

    for (i = 0; i < getTcpPktParsingThreadsNum (); i++) {
        tid = newTask (tcpPktParsingService, getTcpPktParsingThreadIDHolder (i));
        if (tid < 0) {
            LOGE ("Create tcpPktParsingService %u task error.\n", i);
            goto stopAllTask;
        }
    }

    return 0;

stopAllTask:
    stopAllTask ();
    return -1;
}

/*
 * @brief Start agent if agent state is AGENT_STATE_STOPPED
 *
 * @param profile start agent profile
 *
 * @return 0 if success else -1
 */
static int
startAgent (json_t *profile) {
    int ret;

    if (getAgentState () == AGENT_STATE_INIT) {
        LOGE ("Agent is not ready now.\n");
        return -1;
    }

    if (getAgentState () == AGENT_STATE_RUNNING) {
        LOGW ("Agent is already running now.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    ret = agentRun ();
    if (ret < 0) {
        LOGE ("Start agent task error.\n");
        return -1;
    }

    /* Update agent state */
    setAgentState (AGENT_STATE_RUNNING);
    /* Dump runtime context */
    dumpRuntimeContext ();
    LOGD ("Start agent: [Success]\n");

    return 0;
}

/*
 * @brief Stop agent if agent is running
 *
 * @param profile stop agent profile
 *
 * @return 0 if success else -1
 */
static int
stopAgent (json_t *profile) {
    int ret;

    if (getAgentState () != AGENT_STATE_RUNNING) {
        LOGE ("Agent is not running.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    stopAllTask ();

    /* Update agent state */
    setAgentState (AGENT_STATE_STOPPED);
    /* Dump runtime context */
    dumpRuntimeContext ();

    return 0;
}

/*
 * @brief Agent Heartbeat handler
 *
 * @param profile Heartbeat profile
 *
 * @return 0 if success else -1
 */
static int
heartbeat (json_t *profile) {
    int ret;

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    return 0;
}

/*
 * @brief Agent push profile handler
 *
 * @param profile pushProfile profile
 *
 * @return 0 if success else -1
 */
static int
pushProfile (json_t *profile) {
    int ret;
    char *filter;
    json_t *appServices;

    if (getAgentState () == AGENT_STATE_INIT) {
        LOGE ("Agent has not been added.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    appServices = json_object_get (profile, "app_services");
    if ((appServices == NULL) || !json_is_array (appServices)) {
        LOGE ("Get application services error.\n");
        return -1;
    }

    /* Update application services*/
    ret = setAppServices (appServices);
    if (ret < 0) {
        LOGE ("Update application services error.\n");
        return -1;
    }

    /* Update application service manager */
    ret = updateAppServiceManager ();
    if (ret < 0) {
        LOGE ("Update application service manager error.\n");
        return -1;
    }

    /* Update application services filter */
    if (getAgentState () == AGENT_STATE_RUNNING) {
        filter = getAppServicesFilter ();
        if (filter == NULL) {
            LOGE ("Get application services filter error.\n");
            return -1;
        }

        ret = updateFilter (filter);
        if (ret < 0) {
            LOGE ("Update application services filter error.\n");
            free (filter);
            return -1;
        }
        LOGD ("Update application services filter: %s\n", filter);
        free (filter);
    }

    /* Dump runtime context */
    dumpRuntimeContext ();

    return 0;
}

/*
 * @brief Build agent management response message
 *
 * @param code response code
 * @param status response status
 *
 * @return response message if success else NULL
 */
static char *
buildAgentManagementResponse (int code, int status) {
    char *json;
    json_t *root, *tmp;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json root object error.\n");
        return  NULL;
    }

    /* Set response code */
    json_object_set_new (root, "code", json_integer (code));

    /* Set response body:status */
    if (status != AGENT_STATE_INIT) {
        tmp = json_object ();
        if (tmp == NULL) {
            LOGE ("Create json tmp object error.\n");
            json_object_clear (root);
            return NULL;
        }
        json_object_set_new (tmp, "status", json_integer (status));
        json_object_set_new (root, "body", tmp);
    }

    json = json_dumps (root, JSON_INDENT (4));
    json_object_clear (root);

    return json;
}

static int
managementRequestHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    char *msg;
    const char *cmd;
    char *resp;
    json_error_t error;
    json_t *root, *tmp, *body;

    msg = zstr_recv_nowait (getManagementRespSock ());
    if (msg == NULL)
        return 0;

    LOGD ("Management message: %s\n", msg);
    root = json_loads (msg, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, AGENT_MANAGEMENT_CMD_KEY) == NULL) ||
        (json_object_get (root, AGENT_MANAGEMENT_BODY_KEY) == NULL)) {
        LOGE ("Agent management message parse error: %s\n", error.text);
        ret = -1;
    } else {
        tmp = json_object_get (root, AGENT_MANAGEMENT_CMD_KEY);
        cmd = json_string_value (tmp);
        body = json_object_get (root, AGENT_MANAGEMENT_BODY_KEY);

        if (strEqual (AGENT_MANAGEMENT_CMD_ADD_AGENT, cmd))
            ret = addAgent (body);
        else if (strEqual (AGENT_MANAGEMENT_CMD_REMOVE_AGENT, cmd))
            ret = removeAgent (body);
        else if (strEqual (AGENT_MANAGEMENT_CMD_START_AGENT, cmd))
            ret = startAgent (body);
        else if (strEqual (AGENT_MANAGEMENT_CMD_STOP_AGENT, cmd))
            ret = stopAgent (body);
        else if (strEqual (AGENT_MANAGEMENT_CMD_HEARTBEAT, cmd))
            ret = heartbeat (body);
        else if (strEqual (AGENT_MANAGEMENT_CMD_PUSH_PROFILE, cmd))
            ret = pushProfile (body);
        else
            ret = -1;
    }

    if (ret < 0)
        resp = buildAgentManagementResponse (AGENT_MANAGEMENT_RESPONSE_ERROR,
                                             AGENT_STATE_ERROR);
    else
        resp = buildAgentManagementResponse (AGENT_MANAGEMENT_RESPONSE_SUCCESS,
                                             getAgentState ());

    if (resp) {
        zstr_send (getManagementRespSock (), resp);
        free (resp);
    } else {
        if (ret < 0)
            zstr_send (getManagementRespSock (),
                       AGENT_MANAGEMENT_RESPONSE_ERROR_MESSAGE);
        else
            zstr_send (getManagementRespSock (),
                       AGENT_MANAGEMENT_RESPONSE_SUCCESS_MESSAGE);
    }

    json_object_clear (root);
    free (msg);
    return 0;
}

static int
lockPidFile (void) {
    int ret;
    pid_t pid;
    ssize_t n;
    char buf [16] = {0};

    pid = getpid ();

    agentPidFd = open (AGENT_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (agentPidFd < 0)
        return -1;

    ret = flock (agentPidFd, LOCK_EX | LOCK_NB);
    if (ret < 0) {
        close (agentPidFd);
        return -1;
    } else {
        snprintf (buf, sizeof (buf) - 1, "%d", pid);
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
agentService (void) {
    int ret;
    zloop_t *loop;
    zmq_pollitem_t pollItems [2];

    /* Lock agent pid file */
    ret = lockPidFile ();
    if (ret < 0) {
        logToConsole ("Lock pid file error.\n");
        return -1;
    }

    /* Init log context */
    ret = initLog (getPropertiesLogLevel ());
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    /* Init runtime context */
    ret = initRuntimeContext ();
    if (ret < 0) {
        LOGE ("Init runtime context error.\n");
        ret = -1;
        goto destroyLog;
    }

    /* Init zmq hub */
    ret = initZmqHub ();
    if (ret < 0) {
        LOGE ("Init zmq hub error.\n");
        ret = -1;
        goto destroyRuntimeContext;
    }

    /* Init task manager */
    ret = initTaskManager ();
    if (ret < 0) {
        LOGE ("Init task manager error.\n");
        ret = -1;
        goto destroyZmqHub;
    }

    /* Init application service manager */
    ret = initAppServiceManager ();
    if (ret < 0) {
        LOGE ("Init application service manager error.\n");
        ret = -1;
        goto destroyTaskManager;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto destroyAppServiceManager;
    }

    /* Init poll item 0*/
    pollItems [0].socket = getManagementRespSock ();
    pollItems [0].fd = 0;
    pollItems [0].events = ZMQ_POLLIN;

    /* Init poll item 1*/
    pollItems [1].socket = getTaskStatusPullSock ();
    pollItems [1].fd = 0;
    pollItems [1].events = ZMQ_POLLIN;

    /* Register poll item 0 */
    ret = zloop_poller (loop, &pollItems [0], managementRequestHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [0] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Register poll item 1 */
    ret = zloop_poller (loop, &pollItems [1], taskStatusHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [1] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    if (getAgentState () == AGENT_STATE_RUNNING) {
        ret = agentRun ();
        if (ret < 0) {
            LOGE ("Restore agent to run error.\n");
            ret = -1;
            goto destroyZloop;
        }
    }

    /* Start zloop */
    ret = zloop_start (loop);

    if (ret < 0)
        LOGE ("Agent exit abnormally.\n");
    else
        LOGD ("Agent exit normally.\n");
    stopAllTask ();
destroyZloop:
    zloop_destroy (&loop);
destroyAppServiceManager:
    destroyAppServiceManager ();
destroyTaskManager:
    destroyTaskManager ();
destroyZmqHub:
    destroyZmqHub ();
destroyRuntimeContext:
    destroyRuntimeContext ();
destroyLog:
    destroyLog ();
unlockPidFile:
    unlockPidFile ();
    return ret;
}

/* Agent cmd options */
static struct option agentOptions [] = {
    {"daemonMode", no_argument, NULL, 'D'},
    {"mirrorInterface", required_argument, NULL, 'm'},
    {"logLevel", required_argument, NULL, 'l'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0},
};

static void
showHelpInfo (const char *cmd) {
    const char *cmdName;

    cmdName = strrchr (cmd, '/') ? (strrchr (cmd, '/') + 1) : cmd;
    logToConsole ("Usage: %s -m <eth*> [options]\n"
                  "       %s [-vh]\n"
                  "Basic options: \n"
                  "  -D|--daemonMode, run as daemon\n"
                  "  -m|--mirrorInterface <eth*> interface to collect packets\n"
                  "  -l|--logLevel <level> log level\n"
                  "       Optional level: 0-ERR 1-WARNING 2-INFO 3-DEBUG\n"
                  "  -v|--version, version of %s\n"
                  "  -h|--help, help information\n",
                  cmdName, cmdName, cmdName);
}

/* Cmd line parser */
static int
parseCmdline (int argc, char *argv []) {
    int ret;
    char option;
    boolean showVersion = false;
    boolean showHelp = false;

    while ((option = getopt_long (argc, argv, "Dm:l:vh?", agentOptions, NULL)) != -1) {
        switch (option) {
            case 'D':
                setPropertiesDaemonMode (true);
                break;

            case 'm':
                ret = setPropertiesMirrorInterface (strdup (optarg));
                if (ret < 0) {
                    logToConsole ("Parse mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'l':
                setPropertiesLogLevel (atoi (optarg));
                break;

            case 'v':
                showVersion = true;
                break;

            case 'h':
                showHelp = true;
                break;

            case '?':
                logToConsole ("Unknown options.\n");
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            logToConsole ("Current version: %s\n", getVersionStr ());
        if (showHelp)
            showHelpInfo (argv [0]);
        exit (0);
    }

    return 0;
}

static int
agentDaemon (void) {
    pid_t pid, next_pid;
    int stdinfd;
    int stdoutfd;

    if (chdir("/") < 0) {
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

    ret = initPropertiesManager ();
    if (ret < 0) {
        logToConsole ("Init properties manager error.\n");
        return -1;
    }

    /* Parse command */
    ret = parseCmdline (argc, argv);
    if (ret < 0) {
        logToConsole ("Parse command line error.\n");
        ret = -1;
        goto destroyPropertiesManager;
    }

    if (getPropertiesDaemonMode ())
        ret = agentDaemon ();
    else
        ret = agentService ();

destroyPropertiesManager:
    destroyPropertiesManager ();
    return ret;
}
