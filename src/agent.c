#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <czmq.h>
#include <ini_config.h>
#include <jansson.h>
#include <locale.h>
#include "config.h"
#include "list.h"
#include "hash.h"
#include "log.h"
#include "util.h"
#include "service-manager.h.h"
#include "router.h"
#include "ip-packet.h"
#include "tcp-packet.h"
#include "agent.h"

/* Global agent parameters */
static agentParams agentParameters = {
    .daemonMode = 0,
    .mirrorInterface = NULL,
    .logLevel = 0,
};

/* Agent run instance */
static agentRun agentRunInstance = {
    .state = AGENT_STATE_INIT,
    .agentId = NULL,
    .srvIp = NULL,
    .srvPort = 0,
    .services = NULL
};

static int agentPidFd = -1;
/* Mirror interface pcap descriptor */
static pcap_t *mirrorPcapDev = NULL;

static inline void
freeAgentParameters (void) {
    free (agentParameters.mirrorInterface);
}

static void
dumpAgentRunInstance (void);

static int
initAgentRunInstance (void) {
    int fd;
    json_error_t error;
    json_t *root, *tmp;

    if (!fileExist (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create agent run directory error: %s.\n", strerror (errno));
        return -1;
    }

    if (!fileExist (AGENT_DB_FILE) || fileIsEmpty (AGENT_DB_FILE))
        dumpAgentRunInstance ();
    
    fd = open (AGENT_DB_FILE, O_RDONLY);
    if (fd < 0) {
        LOGE ("Open agent DB file error: %s\n", strerror (errno));
        return -1;
    }
    
    root = json_load_file (AGENT_DB_FILE, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "state") == NULL) ||
        (json_object_get (root, "agent-id") == NULL) ||
        (json_object_get (root, "server-ip") == NULL) ||
        (json_object_get (root, "server-port") == NULL)) {
        agentRunInstance.state = AGENT_STATE_INIT;
        agentRunInstance.agentId = NULL;
        agentRunInstance.srvIp = NULL;
        agentRunInstance.srvPort = 0;
        agentRunInstance.services = NULL;
        close (fd);
        return 0;
    }

    tmp = json_object_get (root, "state");
    agentRunInstance.state = json_integer_value (tmp);
    tmp = json_object_get (root, "agent-id");
    agentRunInstance.agentId = strdup (json_string_value (tmp));
    tmp = json_object_get (root, "server-ip");
    agentRunInstance.srvIp = strdup (json_string_value (tmp));
    tmp = json_object_get (root, "server-port");
    agentRunInstance.srvPort = json_integer_value (tmp);
    tmp = json_object_get (root, "services");
    agentRunInstance.services = strdup (json_string_value (tmp));

    if ((agentRunInstance.state == AGENT_STATE_INIT) || (agentRunInstance.agentId == NULL) ||
        (agentRunInstance.srvIp == NULL) || (agentRunInstance.srvPort == 0)) {
        /* Free */
        free (agentRunInstance.agentId);
        free (agentRunInstance.srvIp);
        free (agentRunInstance.services);
        /* Reset */
        agentRunInstance.state = AGENT_STATE_INIT;
        agentRunInstance.agentId = NULL;
        agentRunInstance.srvIp = NULL;
        agentRunInstance.srvPort = 0;
        agentRunInstance.services = NULL;
    }

    close (fd);
    return 0;
}

static inline void
freeAgentRunInstance (void) {
    free (agentRunInstance.agentId);
    free (agentRunInstance.srvIp);
    free (agentRunInstance.services);
}

static void
dumpAgentRunInstance (void) {
    int fd;
    json_t *root;
    char *dumpOut;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Dump agent run instance error.\n");
        return;
    }

    fd = open (AGENT_DB_FILE, O_RDWR | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open agent DB file error: %s\n", strerror (errno));
        return;
    }

    json_object_set_new (root, "state", json_integer (agentRunInstance.state));
    json_object_set_new (root, "agent-id", json_string (agentRunInstance.agentId));
    json_object_set_new (root, "server-ip", json_string (agentRunInstance.srvIp));
    json_object_set_new (root, "server-port", json_integer (agentRunInstance.srvPort));
    json_object_set_new (root, "services", json_string (agentRunInstance.services));
    dumpOut = json_dumps(root, JSON_INDENT (4));
    json_object_clear (root);

    safeWrite (fd, dumpOut, strlen (dumpOut));
    close (fd);
}

static int
lockPidFile (void) {
    pid_t pid;
    ssize_t n;
    char buf [16] = {0};

    pid = getpid ();

    agentPidFd = open (AGENT_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (agentPidFd < 0) {
        fprintf(stderr, "Open pid file %s error: %s.\n", AGENT_PID_FILE, strerror (errno));
        return -1;
    }

    if (flock (agentPidFd, LOCK_EX | LOCK_NB) == 0) {
        snprintf (buf, sizeof (buf) - 1, "%d", pid);
        n = write (agentPidFd, buf, strlen (buf));
        if (n != strlen (buf)) {
            fprintf(stderr, "Write pid to pid file error: %s.\n", strerror (errno));
            close (agentPidFd);
            remove (AGENT_PID_FILE);
            return -1;
        }
        sync ();
    } else {
        fprintf (stderr, "Agent is running.\n");
        close (agentPidFd);
        return -1;
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
agentRun (void) {
    int ret;

    if (lockPidFile () < 0)
        return -1;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

unlockPidFile:
    unlockPidFile ();
    return ret;
}

/* Parse configuration of agent */
static int
parseConf (void) {
    int ret, error;
    const char *tmp;
    struct collection_item *iniConfig = NULL;
    struct collection_item *errorSet = NULL;
    struct collection_item *item;

    ret = config_from_file ("Agent", AGENT_CONFIG_FILE,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        logToConsole ("Parse config file: %s error.\n", AGENT_CONFIG_FILE);
        return -1;
    }

    /* Get daemon mode */
    ret = get_config_item ("MAIN", "daemon_mode", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"daemon_mode\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.daemonMode = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"daemon_mode\" error.\n");
        ret = -1;
        goto exit;
    }

    /* Get mirror interface */
    ret = get_config_item ("MAIN", "mirror_interface", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"mirror_interface\" error\n");
        ret = -1;
        goto exit;
    }
    tmp = get_const_string_config_value (item, &error);
    if (error) {
        logToConsole ("Parse \"mirror_interface\" error.\n");
        ret = -1;
        goto exit;
    }
    agentParameters.mirrorInterface = strdup (tmp);
    if (agentParameters.mirrorInterface == NULL) {
        logToConsole ("Get \"mirror_interface\" error\n");
        ret = -1;
        goto exit;
    }

    /* Get default log level */
    ret = get_config_item ("LOG", "log_level", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"log_level\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.logLevel = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"log_level\" error.\n");
        ret = -1;
        goto exit;
    }

exit:
    if (iniConfig)
        free_ini_config (iniConfig);
    if (errorSet)
        free_ini_config_errors (errorSet);
    return ret;
}

/* Agent cmd options */
static struct option agentOptions [] = {
    {"daemon-mode", no_argument, NULL, 'D'},
    {"mirror-interface", required_argument, NULL, 'm'},
    {"log-level", required_argument, NULL, 'l'},
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
                  "  -D|--daemon-mode, run as daemon\n"
                  "  -m|--mirror-interface <eth*> interface to collect packets\n"
                  "  -l|--log-level <level> log level\n"
                  "       Optional level: 0-ERR 1-WARNING 2-INFO 3-DEBUG\n"
                  "  -v|--version, version of %s\n"
                  "  -h|--help, help information\n",
                  cmdName, cmdName, cmdName);
}

/* Cmd line parser */
static int
parseCmdline (int argc, char *argv []) {
    char option;
    BOOL showVersion = FALSE;
    BOOL showHelp = FALSE;

    while ((option = getopt_long (argc, argv, "Dm:l:vh?", agentOptions, NULL)) != -1) {
        switch (option) {
            case 'D':
                agentParameters.daemonMode = 1;
                break;

            case 'm':
                agentParameters.mirrorInterface = strdup (optarg);
                if (agentParameters.mirrorInterface == NULL) {
                    logToConsole ("Get mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'l':
                agentParameters.logLevel = atoi (optarg);
                break;

            case 'v':
                showVersion = TRUE;
                break;

            case 'h':
                showHelp = TRUE;
                break;

            case '?':
                logToConsole ("Unknown options.\n");
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            logToConsole ("Current version: %d.%d\n", AGENT_VERSION_MAJOR, AGENT_VERSION_MINOR);
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
                    return agentRun ();

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
    /* Parse configuration file */
    ret = parseConf ();
    if (ret < 0) {
        fprintf (stderr, "Parse configuration file error.\n");
        ret = -1;
        goto exit;
    }

    /* Parse command */
    ret = parseCmdline (argc, argv);
    if (ret < 0) {
        fprintf (stderr, "Parse command line error.\n");
        ret = -1;
        goto exit;
    }

    if (agentParameters.daemonMode)
        ret = agentDaemon ();
    else
        ret = agentRun ();
exit:
    freeAgentParameters ();
    return ret;
}
