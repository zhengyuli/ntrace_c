#include <stdio.h>
#include <getopt.h>
#include "config.h"
#include "util.h"
#include "properties.h"
#include "version.h"
#include "option_parser.h"

static struct option options [] = {
    {"config", required_argument, NULL, 'C'},
    {"daemonMode", no_argument, NULL, 'D'},
    {"schedPriority", required_argument, NULL, 'S'},
    {"managementServicePort", required_argument, NULL, 'P'},
    {"interface", required_argument, NULL, 'm'},
    {"pcapFile", required_argument, NULL, 'F'},
    {"loopCount", required_argument, NULL, 'n'},
    {"setFlag", no_argument, NULL, 'B'},
    {"outputFile", required_argument, NULL, 'O'},
    {"packetsToScan", required_argument, NULL, 'N'},
    {"sleepIntervalAfterScan", required_argument, NULL, 'T'},
    {"autoAddService", no_argument, NULL, 'A'},
    {"miningEngineHost", required_argument, NULL, 'i'},
    {"sessionBreakdownRecvPort", required_argument, NULL, 'p'},
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
             "Options: \n"
             "  -C|--config, config file\n"
             "  -D|--daemonMode, run as daemon\n"
             "  -S|--schedPriority <priority> schedule priority\n"
             "  -P|--managementServicePort <port> management control port\n"
             "  -m|--interface <eth*> interface to monitor\n"
             "  -F|--pcapFile <fname> pcap file\n"
             "  -n|--loopCount <count> Loop read pcap file some times, 0 for loop forever\n"
             "  -O|--outputFile <fname> output file\n"
             "  -N|--packetsToScan, packets to scan for each proto detect loop\n"
             "  -T|--sleepIntervalAfterScan, sleep interval after each proto detect loop\n"
             "  -A|--autoAddService, auto add detected service for sniff\n"
             "  -i|--miningEngineHost <ip> mining engine host ip\n"
             "  -p|--sessionBreakdownRecvPort <port> session breakdown receive port\n"
             "  -d|--logDir <path>, log file directory\n"
             "  -f|--logFileName <name>, log file name\n"
             "  -l|--logLevel <level> log level\n"
             "       Optional level: 0-ERROR 1-WARNING 2-INFO 3-DEBUG 4-TRACE\n"
             "  -v|--version, version of %s\n"
             "  -h|--help, help information\n",
             cmdName, cmdName, cmdName);
}

/* Get config file */
char *
getConfigFile (int argc, char *argv []) {
    u_int i;
    char option;
    char *argvCopy [128];

    for (i = 0; i < argc && i < sizeof (argvCopy); i++)
        argvCopy [i] = argv [i];

    optind = 1;
    while ((option = getopt_long (argc, argvCopy, ":C:?", options, NULL)) != -1) {
        switch (option) {
            case 'C':
                return optarg;

            case ':':
                fprintf (stderr, "Miss option argument.\n");
                showHelpInfo (argvCopy [0]);
                return NULL;

            case '?':
                break;
        }
    }

    return NTRACE_CONFIG_FILE;
}

/* Command line options parser */
int
parseOptions (int argc, char *argv []) {
    u_int i;
    char option;
    char *argvCopy [128];
    boolean showVersion = False;
    boolean showHelp = False;

    for (i = 0; i < argc && i < sizeof (argvCopy); i++)
        argvCopy [i] = argv [i];

    optind = 1;
    while ((option = getopt_long (argc, argvCopy,
                                  ":C:DS:P:m:F:n:O:N:T:Ai:p:d:f:l:vh?",
                                  options, NULL)) != -1) {
        switch (option) {
            case 'C':
                break;

            case 'D':
                updatePropertiesDaemonMode (True);
                break;

            case 'S':
                updatePropertiesSchedPriority (atoi (optarg));
                break;

            case 'P':
                updatePropertiesManagementServicePort (atoi (optarg));
                break;

            case 'm':
                updatePropertiesInterface (optarg);
                if (getPropertiesInterface () == NULL) {
                    fprintf (stderr, "Parse mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'F':
                updatePropertiesPcapFile (optarg);
                if (getPropertiesPcapFile () == NULL) {
                    fprintf (stderr, "Parse pcap file error!\n");
                    return -1;
                }
                break;

            case 'n':
                updatePropertiesLoopCount (atoi (optarg));
                break;

            case 'O':
                updatePropertiesOutputFile (optarg);
                if (getPropertiesOutputFile () == NULL) {
                    fprintf (stderr, "Parse output file error!\n");
                    return -1;
                }
                break;

            case 'N':
                updatePropertiesPacketsToScan (atoi (optarg));
                break;

            case 'T':
                updatePropertiesSleepIntervalAfterScan (atoi (optarg));
                break;

            case 'A':
                updatePropertiesAutoAddService (True);
                break;

            case 'i':
                updatePropertiesMiningEngineHost (optarg);
                if (getPropertiesMiningEngineHost () == NULL) {
                    fprintf (stderr, "Parse mining engine host error!\n");
                    return -1;
                }
                break;

            case 'p':
                updatePropertiesSessionBreakdownRecvPort (atoi (optarg));
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
                showHelpInfo (argvCopy [0]);
                return -1;

            case '?':
                fprintf (stderr, "Unknown option.\n");
                showHelpInfo (argvCopy [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            fprintf (stdout, "Current version: %s\n", VERSION_STRING);
        if (showHelp)
            showHelpInfo (argvCopy [0]);
        exit (0);
    }

    return 0;
}
