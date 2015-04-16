#include <stdio.h>
#include <getopt.h>
#include "config.h"
#include "properties.h"
#include "version.h"
#include "option_parser.h"

static struct option options [] = {
    {"config", required_argument, NULL, 'C'},
    {"daemonMode", no_argument, NULL, 'D'},
    {"managementControlHost", required_argument, NULL, 'I'},
    {"managementControlPort", required_argument, NULL, 'P'},
    {"interface", required_argument, NULL, 'm'},
    {"pcapFile", required_argument, NULL, 'o'},
    {"loopCount", required_argument, NULL, 'n'},
    {"miningEngineHost", required_argument, NULL, 'i'},
    {"managementRegisterPort", required_argument, NULL, 'r'},
    {"breakdownRecvPort", required_argument, NULL, 'p'},
    {"logDir", required_argument, NULL, 'd'},
    {"logFileName", required_argument, NULL, 'f'},
    {"logLevel", required_argument, NULL, 'l'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0},
};

static void
showHelpInfo (const char *cmd) {
    const char *cmdName;

    cmdName = strrchr (cmd, '/') ? (strrchr (cmd, '/') + 1) : cmd;
    fprintf (stdout,
             "Usage: %s -m <eth*> [options]\n"
             "       %s [-vh]\n"
             "Basic options: \n"
             "  -C|--config, config file\n"
             "  -D|--daemonMode, run as daemon\n"
             "  -I|--managementControlHost <ip> management control host ip\n"
             "  -P|--managementControlPort <port> management control port\n"
             "  -m|--interface <eth*> interface to monitor\n"
             "  -o|--pcapFile <fname> pcap offline input file\n"
             "  -n|--loopCount <count> Loop read pcap file some times, 0 for loop forever\n"
             "  -i|--miningEngineHost <ip> mining engine host ip\n"
             "  -r|--managementRegisterPort <port> management register port\n"
             "  -p|--breakdownRecvPort <port> breakdown receive port\n"
             "  -d|--logDir <path>, log file directory\n"
             "  -f|--logFileName <name>, log file name\n"
             "  -l|--logLevel <level> log level\n"
             "       Optional level: 0-ERROR 1-WARNING 2-INFO 3-DEBUG 4-TRACE\n"
             "  -v|--version, version of %s\n"
             "  -h|--help, help information\n",
             cmdName, cmdName, cmdName);
}

char *
getConfigFile (int argc, char *argv []) {
    char option;

    optind = 1;
    while ((option = getopt_long (argc, argv, ":C:?", options, NULL)) != -1) {
        switch (option) {
            case 'C':
                return optarg;

            case ':':
                fprintf (stderr, "Miss option argument.\n");
                showHelpInfo (argv [0]);
                return NULL;

            case '?':
                break;
        }
    }

    return AGENT_CONFIG_FILE;
}

/* Command line options parser */
int
parseOptions (int argc, char *argv []) {
    char option;
    boolean showVersion = False;
    boolean showHelp = False;

    optind = 1;
    while ((option = getopt_long (argc, argv, ":C:DI:P:m:o:n:i:r:p:d:f:l:vh?", options, NULL)) != -1) {
        switch (option) {
            case 'C':
                break;

            case 'D':
                updatePropertiesDaemonMode (True);
                break;

            case 'I':
                updatePropertiesManagementControlHost (optarg);
                if (getPropertiesManagementControlHost () == NULL) {
                    fprintf (stderr, "Parse management control host error!\n");
                    return -1;
                }
                break;

            case 'P':
                updatePropertiesManagementControlPort (atoi (optarg));
                break;

            case 'm':
                updatePropertiesInterface (optarg);
                if (getPropertiesInterface () == NULL) {
                    fprintf (stderr, "Parse mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'o':
                updatePropertiesPcapFile (optarg);
                if (getPropertiesPcapFile () == NULL) {
                    fprintf (stderr, "Parse pcap offline input error!\n");
                    return -1;
                }
                break;

            case 'n':
                updatePropertiesLoopCount (atoi (optarg));
                break;

            case 'i':
                updatePropertiesMiningEngineHost (optarg);
                if (getPropertiesMiningEngineHost () == NULL) {
                    fprintf (stderr, "Parse mining engine host error!\n");
                    return -1;
                }
                break;

            case 'r':
                updatePropertiesManagementRegisterPort (atoi (optarg));
                break;

            case 'p':
                updatePropertiesBreakdownRecvPort (atoi (optarg));
                break;

            case 'd':
                updatePropertiesLogDir (optarg);
                if (getPropertiesLogDir () == NULL) {
                    fprintf (stderr, "Parse log dir error!\n");
                    return -1;
                }
                break;

            case 'f':
                updatePropertiesLogFileName (optarg);
                if (getPropertiesLogFileName () == NULL) {
                    fprintf (stderr, "Parse log file name error!\n");
                    return -1;
                }
                break;

            case 'l':
                updatePropertiesLogLevel (atoi (optarg));
                break;

            case 'v':
                showVersion = True;
                break;

            case 'h':
                showHelp = True;
                break;

            case ':':
                fprintf (stderr, "Miss option argument.\n");
                showHelpInfo (argv [0]);
                return -1;

            case '?':
                fprintf (stderr, "Unknown option.\n");
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            fprintf (stdout, "Current version: %s\n", VERSION_STRING);
        if (showHelp)
            showHelpInfo (argv [0]);
        exit (0);
    }

    return 0;
}
