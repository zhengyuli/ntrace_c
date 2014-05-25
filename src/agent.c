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
#include "util.h"
#include "atomic.h"
#include "log.h"
#include "zmqhub.h"
#include "task-manager.h"
#include "service-manager.h"
#include "dispatch-router.h"
#include "raw-packet.h"
#include "ip-packet.h"
#include "tcp-packet.h"
#include "protocol/protocol.h"
#include "agent.h"

/* Agent zmq inproc address */
#define SHARED_STATUS_PUSH_CHANNEL "inproc://sharedStatusPushChannel"
#define IP_PACKET_PUSH_CHANNEL "inproc://ipPacketPushChannel"
#define TCP_PACKET_PUSH_CHANNEL "inproc://tcpPacketPushChannel"
#define SESSION_BREAKDOWN_PUSH_CHANNEL "inproc://sessionBreakdownPushChannel"

#define SHARED_STATUS_EXIT "Exit"

/* Agent SIGUSR1 interrupt flag */
static BOOL agentInterrupted = FALSE;
/* Agent pid file fd */
static int agentPidFd = -1;
/* Agent packet parsing threads number */
static u_int pktParsingThreads = 0;
/* Shared status push socket */
static void *sharedStatusPushSock = NULL;
/* Shared status push socket mutex lock */
static pthread_mutex_t sharedStatusPushSockLock = PTHREAD_MUTEX_INITIALIZER;
/* Shared status pull socket */
static void *sharedStatusPullSock = NULL;
/* Agent management response socket */
static void *agentManagementRespSock = NULL;

#ifndef NDEBUG
/* Session breakdown count */
static u_int sessionBreakdownCount = 0;
#endif

/* Agent configuration instance */
static agentConfig agentConfigInstance = {
    .daemonMode = 0,
    .mirrorInterface = NULL,
    .logLevel = 0,
};

/* Agent state cache instance */
static agentStateCache agentStateCacheInstance = {
    .state = AGENT_STATE_INIT,
    .agentId = NULL,
    .pubIp = NULL,
    .pubPort = 0,
    .services = NULL
};

/* Agent mirror interface */
static netInterface mirrorNic = {
    .name = NULL,
    .pcapDesc = NULL,
    .linkType = 0
};

static void
sigUser1Handler (int signo) {
    agentInterrupted = TRUE;
}

static void
freeAgentConfiguration (void) {
    agentConfigInstance.daemonMode = 0;

    free (agentConfigInstance.mirrorInterface);
    agentConfigInstance.mirrorInterface = NULL;

    agentConfigInstance.logLevel = 0;
}

static void
resetAgentStateCache (void) {
    agentStateCacheInstance.state = AGENT_STATE_INIT;

    free (agentStateCacheInstance.agentId);
    agentStateCacheInstance.agentId = NULL;

    free (agentStateCacheInstance.pubIp);
    agentStateCacheInstance.pubIp = NULL;

    agentStateCacheInstance.pubPort = 0;

    json_object_clear (agentStateCacheInstance.services);
    agentStateCacheInstance.services = NULL;
}

static void
resetMirrorNic (void) {
    free (mirrorNic.name);
    mirrorNic.name = NULL;

    if (mirrorNic.pcapDesc) {
        pcap_close (mirrorNic.pcapDesc);
        mirrorNic.pcapDesc = NULL;
    }

    mirrorNic.linkType = 0;
}

static void
pushSharedStatus (const char *msg) {
    pthread_mutex_lock (&sharedStatusPushSockLock);
    zstr_send (sharedStatusPushSock, msg);
    pthread_mutex_unlock (&sharedStatusPushSockLock);
}

static char *
readSharedStatusNonBlock (void) {
    return zstr_recv_nowait (sharedStatusPullSock);
}

/*
 * Agent state cache init function
 * Load agent state cache from AGENT_STATE_CACHE_FILE, if AGENT_STATE_CACHE_FILE
 * doesn't exist then use default state cache.
 */
void
initAgentStateCache (void) {
    int fd;
    json_error_t error;
    json_t *root, *tmp;

    if (!fileExist (AGENT_STATE_CACHE_FILE))
        return;

    fd = open (AGENT_STATE_CACHE_FILE, O_RDONLY);
    if (fd < 0) {
        LOGE ("Open %s error: %s.\n", AGENT_STATE_CACHE_FILE, strerror (errno));
        return;
    }

    root = json_load_file (AGENT_STATE_CACHE_FILE, JSON_DISABLE_EOF_CHECK, &error);
    /* Rmove wrong state cache file */
    if ((root == NULL) ||
        (json_object_get (root, "state") == NULL) || (json_object_get (root, "agentId") == NULL) ||
        (json_object_get (root, "pubIp") == NULL) || (json_object_get (root, "pubPort") == NULL)) {
        if (root)
            json_object_clear (root);
        close (fd);
        remove (AGENT_STATE_CACHE_FILE);
        return;
    }

    /* Get agent state */
    tmp = json_object_get (root, "state");
    agentStateCacheInstance.state = json_integer_value (tmp);
    /* Get agent id */
    tmp = json_object_get (root, "agentId");
    agentStateCacheInstance.agentId = strdup (json_string_value (tmp));
    /* Get pub ip */
    tmp = json_object_get (root, "pubIp");
    agentStateCacheInstance.pubIp = strdup (json_string_value (tmp));
    /* Get pub port */
    tmp = json_object_get (root, "pubPort");
    agentStateCacheInstance.pubPort = json_integer_value (tmp);
    /* Get services */
    tmp = json_object_get (root, "services");
    if (tmp)
        agentStateCacheInstance.services = json_deep_copy (tmp);

    if ((agentStateCacheInstance.state == AGENT_STATE_INIT) || (agentStateCacheInstance.agentId == NULL) ||
        (agentStateCacheInstance.pubIp == NULL) || (agentStateCacheInstance.pubPort == 0)) {
        json_object_clear (root);
        /* Reset Agent cache */
        resetAgentStateCache ();
        close (fd);
        remove (AGENT_STATE_CACHE_FILE);
        return;
    }

    /* Update service */
    if (agentStateCacheInstance.services && updateService (agentStateCacheInstance.services))
        LOGE ("Update service error.\n");

    json_object_clear (root);
    close (fd);
}

/*
 * Agent state cache dump function
 * Dump current agent state cache to AGENT_STATE_CACHE_FILE, if current
 * state is AGENT_STATE_INIT then remove AGENT_STATE_CACHE_FILE else dump
 * all state cache to it.
 */
void
dumpAgentStateCache (void) {
    int fd;
    json_t *root;
    char *out;

    if (!fileExist (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create directory %s error: %s.\n", AGENT_RUN_DIR, strerror (errno));
        return;
    }

    if (agentStateCacheInstance.state == AGENT_STATE_INIT) {
        remove (AGENT_STATE_CACHE_FILE);
        return;
    }

    fd = open (AGENT_STATE_CACHE_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open file %s error: %s\n", AGENT_STATE_CACHE_FILE, strerror (errno));
        return;
    }

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json root object error.\n");
        close (fd);
        return;
    }

    json_object_set_new (root, "state", json_integer (agentStateCacheInstance.state));
    json_object_set_new (root, "agentId", json_string (agentStateCacheInstance.agentId));
    json_object_set_new (root, "pubIp", json_string (agentStateCacheInstance.pubIp));
    json_object_set_new (root, "pubPort", json_integer (agentStateCacheInstance.pubPort));
    if (agentStateCacheInstance.services)
        json_object_set_new (root, "services", json_deep_copy (agentStateCacheInstance.services));

    out = json_dumps (root, JSON_INDENT (4));
    safeWrite (fd, out, strlen (out));

    json_object_clear (root);
    close (fd);
}

/*
 * @brief Create a new pcap descriptor
 *
 * @param interface net interface bind to pcap descriptor
 *
 * @return pcap descriptor if success else NULL
 */
static pcap_t *
newPcapDev (const char *interface) {
    int ret;
    pcap_t *pcapDev;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("No network devices found.\n");
        return NULL;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (strEqual (devptr->name, interface))
            break;
    }
    if (devptr == NULL)
        return NULL;

    /* Create pcap descriptor */
    pcapDev = pcap_create (interface, errBuf);
    if (pcapDev == NULL) {
        LOGE ("Create pcap device error: %s.\n", errBuf);
        return NULL;
    }

    /* Set pcap max capture length */
    ret = pcap_set_snaplen (pcapDev, PCAP_MAX_CAPTURE_LENGTH);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (pcapDev, PCAP_CAPTURE_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set capture timeout error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (pcapDev, PCAP_CAPTURE_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDev, PCAP_CAPTURE_IN_PROMISC);
    if (ret < 0) {
        LOGE ("Set pcap promisc mode error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Activate pcap device */
    ret = pcap_activate (pcapDev);
    if (ret < 0) {
        LOGE ("Activate pcap device error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    return pcapDev;
}

/* Update BPF filter */
static int
updateFilter (const char *filter) {
    int ret;
    struct bpf_program pcapFilter;

    ret = pcap_compile (mirrorNic.pcapDesc, &pcapFilter, filter, 1, 0);
    if (ret < 0) {
        pcap_freecode (&pcapFilter);
        return -1;
    }

    ret = pcap_setfilter (mirrorNic.pcapDesc, &pcapFilter);
    pcap_freecode (&pcapFilter);
    return ret;
}

static int
initMirrorNic (void) {
    int ret;
    int linkType;
    char *filter;

    /* Set mirrorNic name */
    mirrorNic.name = strdup (agentConfigInstance.mirrorInterface);
    if (mirrorNic.name == NULL) {
        LOGE ("Strdup mirrorNic name error: %s.\n", strerror (errno));
        return -1;
    }

    /* Create pcap descriptor */
    mirrorNic.pcapDesc = newPcapDev (mirrorNic.name);
    if (mirrorNic.pcapDesc == NULL) {
        LOGE ("Create pcap descriptor for %s error.\n", mirrorNic.name);
        resetMirrorNic ();
        return -1;
    }

    /* Get link type */
    linkType = pcap_datalink (mirrorNic.pcapDesc);
    if (linkType < 0) {
        LOGE ("Get datalink type error.\n");
        resetMirrorNic ();
        return -1;
    }
    mirrorNic.linkType = linkType;

    /* Get service filter */
    filter = getServiceFilter ();
    if (filter == NULL) {
        LOGE ("Get service filter error.\n");
        resetMirrorNic ();
        return -1;
    }

    /* Set service filter */
    ret = updateFilter (filter);
    if (ret < 0) {
        LOGE ("Update filter error.\n");
        free (filter);
        resetMirrorNic ();
        return -1;
    }

    LOGD ("Update filter: %s\n", filter);
    free (filter);
    return 0;
}

/*
 * Raw packet capture service.
 * Capture raw packet from mirror interface, then get ip packet
 * from raw packet and push it to ip packet parsing service.
 */
static void *
rawPktCaptureService (void *args) {
    int ret;
    BOOL exitNormally = TRUE;
    struct pcap_pkthdr *capPkthdr;
    u_char *rawPkt;
    struct ip *ipPkt;
    timeVal capTime;
    zframe_t *frame;
    void *ipPktPushSock;

    /* Init log context */
    ret = initLog (agentConfigInstance.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        exitNormally = FALSE;
        goto exit;
    }

    /* Init mirror interface */
    ret = initMirrorNic ();
    if (ret < 0) {
        LOGE ("Init mirror NIC error.\n");
        exitNormally = FALSE;
        goto destroyLog;
    }

    ipPktPushSock = zsocket_new (zmqHubContext (), ZMQ_PUSH);
    if (ipPktPushSock == NULL) {
        LOGE ("Create ipPktPushSock error.\n");
        exitNormally = FALSE;
        goto resetMirrorNic;
    }
    /* Set ipPktPushSock sndhwm to 500,000 */
    zsocket_set_sndhwm (ipPktPushSock, 500000);
    ret = zsocket_bind (ipPktPushSock, IP_PACKET_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", IP_PACKET_PUSH_CHANNEL);
        exitNormally = FALSE;
        goto destroyIpPktPushSock;
    }

    while (!agentInterrupted)
    {
        ret = pcap_next_ex (mirrorNic.pcapDesc, &capPkthdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter incomplete packet */
            if (capPkthdr->caplen != capPkthdr->len)
                continue;

            /* Get ip packet */
            ipPkt = (struct ip *) getIpPacket (rawPkt, mirrorNic.linkType);
            if (ipPkt == NULL)
                continue;

            /* Get packet capture timestamp */
            capTime.tvSec = htonll (capPkthdr->ts.tv_sec);
            capTime.tvUsec = htonll (capPkthdr->ts.tv_usec);

            /* Push capture timestamp zframe */
            frame = zframe_new (&capTime, sizeof (timeVal));
            if (frame == NULL) {
                LOGE ("Create packet timestamp zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktPushSock, ZFRAME_MORE);
            if (ret < 0) {
                LOGE ("Push packet timestamp zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }

            /* Push ip packet zframe */
            frame = zframe_new (ipPkt, ntohs (ipPkt->ip_len));
            if (frame == NULL) {
                LOGE ("Create ip packet zframe error.\n");
                continue;
            }
            ret = zframe_send (&frame, ipPktPushSock, 0);
            if (ret < 0) {
                LOGE ("Push ip packet zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }
        } else if (ret == -1) {
            LOGE ("Capture packet fatal error, rawPktCaptureService will exit...\n");
            exitNormally = FALSE;
            break;
        }
    }

    LOGD ("RawPktCaptureService will exit...\n");
destroyIpPktPushSock:
    zsocket_destroy (zmqHubContext (), ipPktPushSock);
resetMirrorNic:
    resetMirrorNic ();
destroyLog:
    destroyLog ();
exit:
    if (!exitNormally)
        pushSharedStatus (SHARED_STATUS_EXIT);

    return NULL;
}

/* Session breakdown publish callback */
static void
publishSessionBreakdown (const char *sessionBreakdown, void *args) {
    void *pushSock = args;

    zstr_send (pushSock, sessionBreakdown);
}

/*
 * Tcp packet parsing service.
 * Pull ip packet pushed from ipPktParsingService, then do tcp parsing and
 * publish session breakdown in the end.
 */
static void *
tcpPktParsingService (void *args) {
    int ret;
    BOOL exitNormally = TRUE;
    u_int retries;
    taskId tid;
    timeValPtr tm;
    struct ip *iphdr;
    zframe_t *tmFrame;
    zframe_t *pktFrame;
    void *tcpPktPullSock;
    void *sessionBreakdownPushSock;

    /* Get task id */
    tid = * (taskId *) args;

    /* Init log context */
    ret = initLog (agentConfigInstance.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        exitNormally = FALSE;
        goto exit;
    }

    tcpPktPullSock = zsocket_new (zmqHubContext (), ZMQ_PULL);
    if (tcpPktPullSock == NULL) {
        LOGE ("Create tcpPktPullSock error.\n");
        exitNormally = FALSE;
        goto destroyLog;
    }
    /* Set tcpPktPullSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (tcpPktPullSock, 500000);
    retries = 3;
    while (retries --)
    {
        ret = zsocket_connect (tcpPktPullSock, "%s%u", TCP_PACKET_PUSH_CHANNEL, tid);
        if (ret < 0) {
            if (retries)
                sleep (1);
            else {
                LOGE ("Connect to %s%u error.\n", TCP_PACKET_PUSH_CHANNEL, tid);
                exitNormally = FALSE;
                goto destroyTcpPktPullSock;
            }
        }
    }

    sessionBreakdownPushSock = zsocket_new (zmqHubContext (), ZMQ_PUSH);
    if (sessionBreakdownPushSock == NULL) {
        LOGE ("Create sessionBreakdownPushSock error.\n");
        exitNormally = FALSE;
        goto destroyTcpPktPullSock;
    }
    /* Set sessionBreakdownPushSock sndhwm to 50,000 */
    zsocket_set_sndhwm (sessionBreakdownPushSock, 50000);
    retries = 3;
    while (retries --)
    {
        ret = zsocket_connect (sessionBreakdownPushSock, SESSION_BREAKDOWN_PUSH_CHANNEL);
        if (ret < 0) {
            if (retries)
                sleep (1);
            else {
                LOGE ("Connect to %s error.\n", SESSION_BREAKDOWN_PUSH_CHANNEL);
                exitNormally = FALSE;
                goto destroySessionBreakdownPushSock;
            }
        }
    }

    /* Init tcp context */
    ret = initTcp (publishSessionBreakdown, sessionBreakdownPushSock);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        exitNormally = FALSE;
        goto destroySessionBreakdownPushSock;
    }

    /* Init proto context */
    ret = initProto ();
    if (ret < 0) {
        LOGE ("Init proto context error.\n");
        exitNormally = FALSE;
        goto destroyTcp;
    }

    while (!agentInterrupted) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktPullSock);
            if (tmFrame == NULL) {
                if (!agentInterrupted) {
                    exitNormally = FALSE;
                    LOGE ("Receive timestamp zframe fatal error.\n");
                }
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (tcpPktPullSock);
        if (pktFrame == NULL) {
            if (!agentInterrupted) {
                exitNormally = FALSE;
                LOGE ("Receive ip packet zframe fatal error.\n");
            }
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iphdr = (struct ip *) zframe_data (pktFrame);
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcpProcess (iphdr, tm);
                break;

            default:
                break;
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("TcpPktParsingService will exit...\n");
    destroyProto ();
destroyTcp:
    destroyTcp ();
destroySessionBreakdownPushSock:
    zsocket_destroy (zmqHubContext (), sessionBreakdownPushSock);
destroyTcpPktPullSock:
    zsocket_destroy (zmqHubContext (), tcpPktPullSock);
destroyLog:
    destroyLog ();
exit:
    if (!exitNormally)
        pushSharedStatus (SHARED_STATUS_EXIT);

    return NULL;
}

/*
 * Ip packet parsing service.
 * Pull ip packet pushed from rawPktCaptureService, then do ip parsing and
 * dispatch defragment ip packet to specific tcpPktParsingService thread in
 * the end.
 */
void *
ipPktParsingService (void *args) {
    int ret;
    BOOL exitNormally = TRUE;
    u_int retries;
    void *ipPktPullSock;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    struct ip *newIphdr;

    /* Init log context */
    ret = initLog (agentConfigInstance.logLevel);
    if (ret < 0) {
        LOGE ("Init log context error.\n");
        exitNormally = FALSE;
        goto exit;
    }

    /* Init ip context */
    ret = initIp ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        exitNormally = FALSE;
        goto destroyLog;
    }

    ipPktPullSock = zsocket_new (zmqHubContext (), ZMQ_PULL);
    if (ipPktPullSock == NULL) {
        LOGE ("Create ipPktPullSock error.\n");
        exitNormally = FALSE;
        goto destroyIp;
    }
    /* Set ipPktPullSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (ipPktPullSock, 500000);
    retries = 3;
    while (retries --)
    {
        ret = zsocket_connect (ipPktPullSock, IP_PACKET_PUSH_CHANNEL);
        if (ret < 0) {
            if (retries)
                sleep (1);
            else {
                LOGE ("Connect to %s error.\n", IP_PACKET_PUSH_CHANNEL);
                exitNormally = FALSE;
                goto destroyIpPktPullSock;
            }
        }
    }

    /* Init dispatch router */
    ret = initDispatchRouter (pktParsingThreads, tcpPktParsingService, TCP_PACKET_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Init dispatch router error.\n");
        exitNormally = FALSE;
        goto destroyIpPktPullSock;
    }

    while (!agentInterrupted) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (ipPktPullSock);
            if (tmFrame == NULL) {
                if (!agentInterrupted) {
                    exitNormally = FALSE;
                    LOGE ("Receive timestamp zframe fatal error.\n");
                }
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        pktFrame = zframe_recv (ipPktPullSock);
        if (pktFrame == NULL) {
            if (!agentInterrupted) {
                exitNormally = FALSE;
                LOGE ("Receive ip packet zframe fatal error.\n");
            }
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        ret = ipDefrag ((struct ip *) zframe_data (pktFrame), (timeValPtr) zframe_data (tmFrame), &newIphdr);
        if (ret < 0)
            LOGE ("Ip packet defragment error.\n");
        else if (newIphdr) {
            routerDispatch ((struct ip *) newIphdr, (timeValPtr) zframe_data (tmFrame));
            /* New ip packet after defragment */
            if (newIphdr != (struct ip *) zframe_data (pktFrame))
                free (newIphdr);
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("IpPktParsingService will exit...\n");
    destroyDispatchRouter ();
destroyIpPktPullSock:
    zsocket_destroy (zmqHubContext (), ipPktPullSock);
destroyIp:
    destroyIp ();
destroyLog:
    destroyLog ();
exit:
    if (!exitNormally)
        pushSharedStatus (SHARED_STATUS_EXIT);

    return NULL;
}

/*
 * Session breakdown sink service.
 * Gather session breakdown from tcpPktParsingService and publish it
 * out.
 */
static void *
sessionBreakdownSinkService (void *args) {
    int ret;
    BOOL exitNormally = TRUE;
    void *sessionBreakdownPullSock;
    void *sessionBreakdownPushSock;
    char *sessionBreakdown;

    /* Init log context */
    ret = initLog (agentConfigInstance.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        exitNormally = FALSE;
        goto exit;
    }

    sessionBreakdownPullSock = zsocket_new (zmqHubContext (), ZMQ_PULL);
    if (sessionBreakdownPullSock == NULL) {
        LOGE ("Create sessionBreakdownPullSock error.\n");
        exitNormally = FALSE;
        goto destroyLog;
    }
    /* Set sessionBreakdownPullSock rcvhwm to 500,000 */
    zsocket_set_rcvhwm (sessionBreakdownPullSock, 500000);
    ret = zsocket_bind (sessionBreakdownPullSock, SESSION_BREAKDOWN_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", SESSION_BREAKDOWN_PUSH_CHANNEL);
        exitNormally = FALSE;
        goto destroySessionBreakdownPullSock;
    }

    sessionBreakdownPushSock = zsocket_new (zmqHubContext (), ZMQ_PUSH);
    if (sessionBreakdownPushSock == NULL) {
        LOGE ("Create sessionBreakdownPushSock error.\n");
        exitNormally = FALSE;
        goto destroySessionBreakdownPullSock;
    }
    /* Set sessionBreakdownPushSock sndhwm to 500,000 */
    zsocket_set_sndhwm (sessionBreakdownPushSock, 500000);
    ret = zsocket_connect (sessionBreakdownPushSock, "tcp://%s:%u", agentStateCacheInstance.pubIp,
                           agentStateCacheInstance.pubPort);
    if (ret < 0) {
        LOGE ("Connect to tcp://%s:%u error.\n", agentStateCacheInstance.pubIp, agentStateCacheInstance.pubPort);
        exitNormally = FALSE;
        goto destroySessionBreakdownPushSock;
    }

    while (!agentInterrupted) {
        sessionBreakdown = zstr_recv (sessionBreakdownPullSock);
        if (sessionBreakdown) {
            zstr_send (sessionBreakdownPushSock, sessionBreakdown);
#ifndef NDEBUG
            LOGD ("Session breakdown-------------------count: %u\n%s\n",
                  ATOMIC_FETCH_AND_ADD (&sessionBreakdownCount, 1), sessionBreakdown);
#endif
            free (sessionBreakdown);
        }
    }

    LOGD ("SessionBreakdownSinkService will exit...\n");
destroySessionBreakdownPushSock:
    zsocket_destroy (zmqHubContext (), sessionBreakdownPushSock);
destroySessionBreakdownPullSock:
    zsocket_destroy (zmqHubContext (), sessionBreakdownPullSock);
destroyLog:
    destroyLog ();
exit:
    if (!exitNormally)
        pushSharedStatus (SHARED_STATUS_EXIT);

    return NULL;
}

/*
 * Check agent id.
 * If agent id is valid return 0 else return -1
 */
static int
checkAgentId (json_t *profile) {
    json_t *tmp;

    tmp = json_object_get (profile, "agent-id");
    if (tmp == NULL)
        return -1;

    if (!strEqual (agentStateCacheInstance.agentId, json_string_value (tmp)))
        return -1;

    return 0;
}

/*
 * @brief Add and init agent configuration
 *
 * @param profile add agent profile
 *
 * @return 0 if success else -1
 */
static int
addAgent (json_t *profile) {
    json_t *tmp;

    if (agentStateCacheInstance.state != AGENT_STATE_INIT) {
        LOGE ("Add-agent error: agent already added.\n");
        return -1;
    }

    if ((json_object_get (profile, "agent-id") == NULL) ||
        (json_object_get (profile, "ip") == NULL) ||
        (json_object_get (profile, "port") == NULL)) {
        LOGE ("Add-agent profile parse error.\n");
        return -1;
    }

    /* Update agent state */
    agentStateCacheInstance.state = AGENT_STATE_STOPPED;

    /* Get agent id */
    tmp = json_object_get (profile, "agent-id");
    agentStateCacheInstance.agentId = strdup (json_string_value (tmp));
    if (agentStateCacheInstance.agentId == NULL) {
        LOGE ("Get agentId error.\n");
        resetAgentStateCache ();
        return -1;
    }

    /* Get pubIp */
    tmp = json_object_get (profile, "ip");
    agentStateCacheInstance.pubIp = strdup (json_string_value (tmp));
    if (agentStateCacheInstance.pubIp == NULL) {
        LOGE ("Get pubIp error.\n");
        resetAgentStateCache ();
        return -1;
    }

    /* Get pubPort */
    tmp = json_object_get (profile, "port");
    agentStateCacheInstance.pubPort = json_integer_value (tmp);

    /* Save agent state cache */
    dumpAgentStateCache ();

    return 0;
}

/*
 * @brief Remove agent if agent is not running and reset agent
 *        configuration.
 *
 * @param profile remove agent profile
 *
 * @return 0 if success else -1
 */
static int
removeAgent (json_t *profile) {
    int ret;

    if (agentStateCacheInstance.state == AGENT_STATE_RUNNING) {
        LOGE ("Agent is running, please stop it before removing.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    /* Reset agent cache */
    resetAgentStateCache ();
    /* Save agent state cache */
    dumpAgentStateCache ();

    return 0;
}

/* Real agent running entry */
static int
agentRun (void) {
    taskId tid;

    /* Restore agent interrupt flag */
    agentInterrupted = FALSE;

    tid = newTask (rawPktCaptureService, NULL);
    if (tid < 0) {
        LOGE ("Create rawPktCaptureService task error.\n");
        return -1;
    }

    tid = newTask (ipPktParsingService, NULL);
    if (tid < 0) {
        LOGE ("Create ipPktParsingService task error.\n");
        return -1;
    }

    tid = newTask (sessionBreakdownSinkService, NULL);
    if (tid < 0) {
        LOGE ("Create sessionBreakdownSinkService task error.\n");
        return -1;
    }

    return 0;
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


    if (agentStateCacheInstance.state == AGENT_STATE_INIT) {
        LOGE ("Agent is not ready now.\n");
        return -1;
    }

    if (agentStateCacheInstance.state == AGENT_STATE_RUNNING) {
        LOGE ("Agent is running now.\n");
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
        stopAllTask ();
        return -1;
    }

    /* Update agent state */
    agentStateCacheInstance.state = AGENT_STATE_RUNNING;
    /* Save agent state cache */
    dumpAgentStateCache ();

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

    if (agentStateCacheInstance.state != AGENT_STATE_RUNNING) {
        LOGE ("Agent is not running.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    /* Stop all tasks */
    stopAllTask ();
    /* Update agent state */
    agentStateCacheInstance.state = AGENT_STATE_STOPPED;
    /* Save agent state cache */
    dumpAgentStateCache ();

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
    json_t *services;

    if (agentStateCacheInstance.state == AGENT_STATE_INIT) {
        LOGE ("Agent has not been added.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Check agent id error.\n");
        return -1;
    }

    services = json_object_get (profile, "services");
    if ((services == NULL) || !json_is_array (services)) {
        LOGE ("Get services error.\n");
        return -1;
    }

    json_object_clear (agentStateCacheInstance.services);
    agentStateCacheInstance.services = services;

    /* Update service */
    ret = updateService (agentStateCacheInstance.services);
    if (ret < 0) {
        LOGE ("Update service error.\n");
        return -1;
    }

    /* Update filter */
    if (agentStateCacheInstance.state == AGENT_STATE_RUNNING) {
        filter = getServiceFilter ();
        if (filter == NULL) {
            LOGE ("Get service filter error.\n");
            return -1;
        }

        ret = updateFilter (filter);
        free (filter);
        if (ret < 0) {
            LOGE ("Update filter error.\n");
            return -1;
        }
    }
    /* Save agent state cache */
    dumpAgentStateCache ();

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
agentManagementMessageHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    char *msg;
    const char *cmd;
    char *resp;
    json_error_t error;
    json_t *root, *tmp, *body;

    msg = zstr_recv_nowait (agentManagementRespSock);
    if (msg == NULL)
        return 0;

    root = json_loads (msg, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "command") == NULL) ||
        (json_object_get (root, "body") == NULL)) {
        LOGE ("Agent management message parse error: %s\n", error.text);
        ret = -1;
    } else {
        tmp = json_object_get (root, "command");
        cmd = json_string_value (tmp);
        body = json_object_get (root, "body");

        if (strEqual ("add-agent", cmd))
            ret = addAgent (body);
        else if (strEqual ("remove-agent", cmd))
            ret = removeAgent (body);
        else if (strEqual ("start-agent", cmd))
            ret = startAgent (body);
        else if (strEqual ("stop-agent", cmd))
            ret = stopAgent (body);
        else if (strEqual ("heartbeat", cmd))
            ret = heartbeat (body);
        else if (strEqual ("push-profile", cmd))
            ret = pushProfile (body);
        else
            ret = -1;
    }

    if (ret < 0)
        resp = buildAgentManagementResponse (AGENT_MANAGEMENT_RESPONSE_ERROR, AGENT_STATE_ERROR);
    else
        resp = buildAgentManagementResponse (AGENT_MANAGEMENT_RESPONSE_SUCCESS, agentStateCacheInstance.state);

    if (resp) {
        zstr_send (agentManagementRespSock, resp);
        free (resp);
    } else {
        if (ret < 0)
            zstr_send (agentManagementRespSock, AGENT_MANAGEMENT_RESPONSE_ERROR_MESSAGE);
        else
            zstr_send (agentManagementRespSock, AGENT_MANAGEMENT_RESPONSE_SUCCESS_MESSAGE);
    }

    LOGD ("%s\n", msg);
    free (msg);
    return 0;
}

static int
sharedStatusMessageHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    char *status;

    status = readSharedStatusNonBlock ();
    if (status == NULL)
        return 0;

    if (strEqual (status, SHARED_STATUS_EXIT)) {
        free (status);
        return -1;
    }

    free (status);
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
    struct sigaction action;
    zloop_t *loop;
    zmq_pollitem_t pollItems [2];

    /* Install SIGUSR1 handler */
    action.sa_handler = sigUser1Handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction(SIGUSR1, &action, NULL);

    /* Lock agent pid file */
    ret = lockPidFile ();
    if (ret < 0) {
        logToConsole ("Lock pid file error.\n");
        return -1;
    }

    /* Init log context */
    ret = initLog (agentConfigInstance.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    /* Init message channel */
    ret = initZmqhub ();
    if (ret < 0) {
        LOGE ("Init zmqhub error.\n");
        ret = -1;
        goto destroyLog;
    }

    /* Init task manager */
    ret = initTaskManager ();
    if (ret < 0) {
        LOGE ("Init task manager error.\n");
        ret = -1;
        goto destroyZmqhub;
    }

    /* Init service manager */
    ret = initServiceManager ();
    if (ret < 0) {
        LOGE ("Init service manager error.\n");
        ret = -1;
        goto destroyTaskManager;
    }

    /* Init agent state cache */
    initAgentStateCache ();

    /* Get parsing threads number */
    pktParsingThreads = getCpuCores () * 2 + 1;
    if (pktParsingThreads < MIN_PACKET_PARSING_THREADS)
        pktParsingThreads = MIN_PACKET_PARSING_THREADS;
    else if (pktParsingThreads > MAX_PACKET_PARSING_THREADS)
        pktParsingThreads = MAX_PACKET_PARSING_THREADS;

    /* Init agentManagementRespSock */
    agentManagementRespSock = zsocket_new (zmqHubContext (), ZMQ_REP);
    if (agentManagementRespSock == NULL) {
        LOGE ("Create agentManagementRespSock error.\n");
        ret = -1;
        goto resetAgentStateCache;
    }
    ret = zsocket_bind (agentManagementRespSock, "tcp://*:%u", AGENT_MANAGEMENT_RESPONSE_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", AGENT_MANAGEMENT_RESPONSE_PORT);
        ret = -1;
        goto destroyAgentManagementRespSock;
    }

    /* Init sharedStatusPushSock */
    sharedStatusPushSock = zsocket_new (zmqHubContext (), ZMQ_PUSH);
    if (sharedStatusPushSock == NULL) {
        LOGE ("Create sharedStatusPushSock error.\n");
        ret = -1;
        goto destroyAgentManagementRespSock;
    }

    sharedStatusPullSock = zsocket_new (zmqHubContext (), ZMQ_PULL);
    if (sharedStatusPullSock == NULL) {
        LOGE ("Create sharedStatusPullSock error.\n");
        ret = -1;
        goto destroySharedStatusPushSock;
    }

    ret = zsocket_bind (sharedStatusPushSock, SHARED_STATUS_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", SHARED_STATUS_PUSH_CHANNEL);
        ret = -1;
        goto destroySharedStatusPullSock;
    }

    ret = zsocket_connect (sharedStatusPullSock, SHARED_STATUS_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", SHARED_STATUS_PUSH_CHANNEL);
        ret = -1;
        goto destroySharedStatusPullSock;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto destroySharedStatusPullSock;
    }

    /* Init poll item 0*/
    pollItems [0].socket = agentManagementRespSock;
    pollItems [0].fd = 0;
    pollItems [0].events = ZMQ_POLLIN;

    /* Init poll item 1*/
    pollItems [1].socket = sharedStatusPullSock;
    pollItems [1].fd = 0;
    pollItems [1].events = ZMQ_POLLIN;

    /* Register poll item 0 */
    ret = zloop_poller (loop, &pollItems [0], agentManagementMessageHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [0] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Register poll item 1 */
    ret = zloop_poller (loop, &pollItems [1], sharedStatusMessageHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [1] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    if (agentStateCacheInstance.state == AGENT_STATE_RUNNING) {
        ret = agentRun ();
        if (ret < 0) {
            LOGE ("Restore agent to run error.\n");
            ret = -1;
            goto stopAllTask;
        }
    }

    /* Start zloop */
    ret = zloop_start (loop);

stopAllTask:
    stopAllTask ();
    if (ret < 0)
        LOGE ("Agent exit abnormally.\n");
    else
        LOGD ("Agent exit normally.\n");
destroyZloop:
    zloop_destroy (&loop);
destroySharedStatusPullSock:
    zsocket_destroy (zmqHubContext (), sharedStatusPullSock);
destroySharedStatusPushSock:
    zsocket_destroy (zmqHubContext (), sharedStatusPushSock);
destroyAgentManagementRespSock:
    zsocket_destroy (zmqHubContext (), agentManagementRespSock);
resetAgentStateCache:
    resetAgentStateCache ();
    destroyServiceManager ();
destroyTaskManager:
    destroyTaskManager ();
destroyZmqhub:
    destroyZmqhub ();
destroyLog:
    destroyLog ();
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
    ret = get_config_item ("MAIN", "daemonMode", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"daemonMode\" error\n");
        ret = -1;
        goto exit;
    }
    agentConfigInstance.daemonMode = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"daemonMode\" error.\n");
        ret = -1;
        goto exit;
    }

    /* Get mirror interface */
    ret = get_config_item ("MAIN", "mirrorInterface", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"mirrorInterface\" error\n");
        ret = -1;
        goto exit;
    }
    tmp = get_const_string_config_value (item, &error);
    if (error) {
        logToConsole ("Parse \"mirrorInterface\" error.\n");
        ret = -1;
        goto exit;
    }
    agentConfigInstance.mirrorInterface = strdup (tmp);
    if (agentConfigInstance.mirrorInterface == NULL) {
        logToConsole ("Get \"mirrorInterface\" error\n");
        ret = -1;
        goto exit;
    }

    /* Get log level */
    ret = get_config_item ("LOG", "logLevel", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"logLevel\" error\n");
        ret = -1;
        goto exit;
    }
    agentConfigInstance.logLevel = get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"logLevel\" error.\n");
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
    char option;
    BOOL showVersion = FALSE;
    BOOL showHelp = FALSE;

    while ((option = getopt_long (argc, argv, "Dm:l:vh?", agentOptions, NULL)) != -1) {
        switch (option) {
            case 'D':
                agentConfigInstance.daemonMode = 1;
                break;

            case 'm':
                agentConfigInstance.mirrorInterface = strdup (optarg);
                if (agentConfigInstance.mirrorInterface == NULL) {
                    logToConsole ("Get mirroring interface error!\n");
                    return -1;
                }
                break;

            case 'l':
                agentConfigInstance.logLevel = atoi (optarg);
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

    if (agentConfigInstance.daemonMode)
        ret = agentDaemon ();
    else
        ret = agentService ();
exit:
    freeAgentConfiguration ();
    return ret;
}
