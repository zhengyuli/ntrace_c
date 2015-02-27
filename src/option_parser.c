#include <stdio.h>
#include <getopt.h>
#include "config.h"
#include "properties.h"
#include "version.h"
#include "option_parser.h"

static struct option options [] = {
    {"config", required_argument, NULL, 'C'},
    {"daemonMode", no_argument, NULL, 'D'},
    {"mirrorInterface", required_argument, NULL, 'm'},
    {"pcapOfflineInput", required_argument, NULL, 'I'},
    {"breakdownSinkIp", required_argument, NULL, 'i'},
    {"breakdownSinkPort", required_argument, NULL, 'p'},
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
             "  -m|--mirrorInterface <eth*> interface to collect packets\n"
             "  -I|--pcapOfflineInput <fname> pcap offline input file\n"
             "  -i|--breakdownSinkIp <ip> breakdown sink ip\n"
             "  -p|--breakdownSinkPort <port> breakdown sink port\n"
             "  -d|--logDir <path>, log file directory\n"
             "  -f|--logFileName <name>, log file name\n"
             "  -l|--logLevel <level> log level\n"
             "       Optional level: 0-ERR 1-WARNING 2-INFO 3-DEBUG\n"
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
    boolean showVersion = false;
    boolean showHelp = false;

    optind = 1;
    while ((option = getopt_long (argc, argv, ":C:Dm:I:i:p:d:f:l:vh?", options, NULL)) != -1) {
        switch (option) {
            case 'C':
                break;
            
            case 'D':
                updatePropertiesDaemonMode (true);
                break;
                
            case 'm':
                updatePropertiesMirrorInterface (optarg);
                if (getPropertiesMirrorInterface () == NULL) {
                    fprintf (stderr, "Parse mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'I':
                updatePropertiesPcapOfflineInput (optarg);
                if (getPropertiesPcapOfflineInput () == NULL) {
                    fprintf (stderr, "Parse pcap offline input error!\n");
                    return -1;
                }
                break;

            case 'i':
                updatePropertiesBreakdownSinkIp (optarg);
                if (getPropertiesBreakdownSinkIp () == NULL) {
                    fprintf (stderr, "Parse breakdown sink ip error!\n");
                    return -1;
                }
                break;

            case 'p':
                updatePropertiesBreakdownSinkPort (atoi (optarg));
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
                showVersion = true;
                break;

            case 'h':
                showHelp = true;
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
