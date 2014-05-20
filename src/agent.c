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

#define AGENT_CONTROL_RESPONSE_SUCCESS 0
#define AGENT_CONTROL_RESPONSE_MESSAGE_SUCCESS "{\"code\":0}"
#define AGENT_CONTROL_RESPONSE_FAILURE 1
#define AGENT_CONTROL_RESPONSE_MESSAGE_ERROR "{\"code\":1}"

#define DEFAULT_PARSING_THREADS 5

/* Agent pid file fd */
static int agentPidFd = -1;
/* Agent parsing threads */
static u_int parsingThreads = DEFAULT_PARSING_THREADS;

#ifndef NDEBUG
/* Session breakdown count */
static u_int sessionBreakdownCount = 0;
#endif

/* Global agent parameters */
static agentParams agentParameters = {
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
    .linkType = -1
};

static inline void
resetAgentParameters (void) {
    agentParameters.daemonMode = 0;
    free (agentParameters.mirrorInterface);
    agentParameters.logLevel = 0;
}

static void
resetAgentStateCache (void) {
    agentStateCacheInstance.state = AGENT_STATE_INIT;
    free (agentStateCacheInstance.agentId);
    agentStateCacheInstance.agentId = NULL;
    free (agentStateCacheInstance.pubIp);
    agentStateCacheInstance.pubIp = NULL;
    agentStateCacheInstance.pubPort = 0;
    free (agentStateCacheInstance.services);
    agentStateCacheInstance.services = NULL;
}

static void
resetMirrorNic (void) {
    free (mirrorInterface.name);
    mirrorInterface.name = NULL;
    freePcapDev (mirrorInterface.pcapDesc);
    mirrorInterface.pcapDesc = NULL;
    mirrorInterface.linkType = -1;
}

void
dumpAgentStateCache (void) {
    int fd;
    json_t *root;
    char *out;

    if (!fileExist (AGENT_RUN_DIR) && (mkdir (AGENT_RUN_DIR, 0755) < 0)) {
        LOGE ("Create agent run directory error: %s.\n", strerror (errno));
        return;
    }

    fd = open (AGENT_STATE_CACHE_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    if (fd < 0) {
        LOGE ("Open %s error: %s\n", AGENT_STATE_CACHE_FILE, strerror (errno));
        return;
    }

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return;
    }

    json_object_set_new (root, "state", json_integer (agentStateCacheInstance.state));
    if (agentStateCacheInstance.state != AGENT_STATE_INIT) {
        json_object_set_new (root, "agentId", json_string (agentStateCacheInstance.agentId));
        json_object_set_new (root, "pubIp", json_string (agentStateCacheInstance.pubIp));
        json_object_set_new (root, "pubPort", json_integer (agentStateCacheInstance.pubPort));
        json_object_set_new (root, "services", json_string (agentStateCacheInstance.services));
    }
    out = json_dumps (root, JSON_INDENT (4));
    json_object_clear (root);

    safeWrite (fd, dumpOut, strlen (dumpOut));
    close (fd);
}

void
initAgentStateCache (void) {
    int ret;
    int fd;
    json_error_t error;
    json_t *root, *tmp;

    /* If AGENT_STATE_CACHE_FILE doesn't exist, use init configuration */
    if (!fileExist (AGENT_STATE_CACHE_FILE))
        return;

    fd = open (AGENT_STATE_CACHE_FILE, O_RDONLY);
    if (fd < 0) {
        LOGE ("Open %s error: %s.\n", AGENT_STATE_CACHE_FILE, strerror (errno));
        return;
    }

    root = json_load_file (AGENT_STATE_CACHE_FILE, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "state") == NULL) || (json_object_get (root, "agentId") == NULL) ||
        (json_object_get (root, "pubIp") == NULL) || (json_object_get (root, "pubPort") == NULL)) {
        close (fd);
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
        agentStateCacheInstance.services = strdup (json_string_value (tmp));

    if ((agentStateCacheInstance.state == AGENT_STATE_INIT) || (agentStateCacheInstance.agentId == NULL) ||
        (agentStateCacheInstance.pubIp == NULL) || (agentStateCacheInstance.pubPort == 0)) {
        /* Reset Agent cache */
        resetAgentStateCache ();
    }

    /* Update service */
    if (agentStateCacheInstance.services)
        updateService (agentStateCacheInstance.services);

    close (fd);
}

/*
 * @brief Build agent control response message
 *
 * @param code response code, 0 for success and 1 for error
 * @param status response status, 1 for stopped, 2 for running and 3 for error.
 *
 * @return response message in json if success else NULL
 */
static char *
buildAgentControlResponse (int code, int status) {
    char *json;
    json_ *root, *tmp;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Alloc json object root error.\n");
        return  NULL;
    }

    /* Set response code */
    json_object_set_new (resp, "code", json_integer (code));

    /* Set response body:status */
    if (status != AGENT_STATE_INIT) {
        tmp = json_object ();
        if (tmp == NULL) {
            LOGE ("Alloc json object tmp error.\n");
            json_object_clear (root);
            return NULL;
        }
        json_object_set_new (tmp, "status", json_integer (status));
        json_object_set_new (root, "body", tmp);
    }

    json = json_dumps (resp, JSON_INDENT (4));
    json_object_clear (root);

    return json;
}

static int
checkAgentId (const char *profile) {
    json_error_t error;
    json_t *root, *tmp;

    root = json_loads (profile, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL)
        return -1;

    tmp = json_object_get (root, "agent-id");
    if (tmp == NULL) {
        json_object_clear (root);
        return -1;
    }

    if (!strEqual (agentStateCacheInstance.agentId, json_string_value (tmp))) {
        json_object_clear (root);
        return -1;
    }

    json_object_clear (root);
    return 0;
}

static int
setFilter (const char *filter) {
    int ret;
    char errBuf [PCAP_ERRBUF_SIZE];
    struct bpf_program pcapFilter;

    ret = pcap_compile (mirrorNic.pcapDesc, &pcapFilter, filter, 1, 0);
    if (ret < 0) {
        LOGE ("Pcap filter compile error: %s\n", errBuf);
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
    char *filter

            /* Set mirrorNic name */
            mirrorNic.name = strdup (agentParameters.mirrorInterface);
    if (mirrorNic.name == NULL) {
        LOGE ("Strdup mirrorNic name error: %s.\n", strerror (errno));
        return -1;
    }

    /* Create pcap descriptor */
    mirrorNic.pcapDesc = newPcapDev (mirrorNic.name);
    if (mirrorNic.pcapDesc == NULL) {
        LOGE ("Create pcap descriptor for %s error: %s.\n", mirrorNic.name, errBuf);
        resetMirrorNic ();
        return -1;
    }

    /* Get link type */
    mirrorNic.linkType = pcap_datalink (mirrorNic.pcapDesc);
    if (mirrorNic.linkType < 0) {
        LOGE ("Get datalink type error.\n");
        resetMirrorNic ();
        return -1;
    }

    /* Get service filter */
    filter = getServiceFilter ();
    if (filter == NULL) {
        LOGE ("Get service filter error.\n");
        resetMirrorNic ();
        return -1;
    }

    /* Set service filter */
    ret = setFilter (filter);
    free (filter);
    if (ret < 0) {
        LOGE ("Set filter error.\n");
        resetMirrorNic ();
        return -1;
    }

    return 0;
}

static void *
rawPktCaptureService (void *args) {
    int ret;
    void *ipPktParsingPushSock;
    struct pcap_pkthdr *capPkthdr;
    u_char *rawPkt;
    struct ip *ipPkt;
    timeVal captureTime;
    zframe_t *frame;

    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    ret = initMirrorNic ();
    if (ret < 0) {
        LOGE ("Init mirror NIC error.\n");
        goto destroyLogContext;
    }

    ipPktParsingPushSock = newZSock (ZMQ_PUSH);
    if (ipPktParsingPushSock == NULL) {
        LOGE ("Create ipPktParsingPushSock error.\n");
        goto resetMirrorNic;
    }
    /* Set ipPktParsingPushSock send hwm to 500000 */
    zsocket_set_sndhwm (ipPktParsingPushSock, 500000);

    ret = zsocket_connect (ipPktParsingPushSock, IP_PACKET_PARSING_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", IP_PACKET_PARSING_PUSH_CHANNEL);
        goto destroyIpPktParsingPushSock;
    }

    while (!zctx_interrupted)
    {
        ret = pcap_next_ex (mirrorNic.pcapDesc, &capPkthdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter incomplete packet */
            if (capPkthdr->caplen != capPkthdr->len)
                continue;

            /* Get ip packet */
            ipPkt = (struct ip *) getIpHeader (capPkthdr, rawPkt, mirrorNic.linkType);
            if (ipPkt == NULL)
                continue;

            /* Get packet capture timestamp */
            captureTime.tvSec = htonll (capPkthdr->ts.tv_sec);
            captureTime.tvUsec = htonll (capPkthdr->ts.tv_usec);

            /* Push capture timestamp and ip packet */
            frame = zframe_new (tm, sizeof (timeVal));
            if (frame == NULL) {
                LOGE ("Create packet timestamp zframe error.\n");
                continue;
            }

            ret = zframe_send (&frame, ipPktParsingPushSock, ZFRAME_MORE);
            if (ret < 0) {
                LOGE ("Push packet timestamp zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }

            frame = zframe_new (ipPkt, ntohs (ipPkt->ip_len));
            if (frame == NULL) {
                LOGE ("Create ip packet zframe error.\n");
                continue;
            }

            ret = zframe_send (&frame, sndSock, 0);
            if (ret < 0) {
                LOGE ("Push ip packet zframe error.\n");
                zframe_destroy (&frame);
                continue;
            }
        } else if (ret == 0) {
            LOGD ("Capture packet timeout.\n");
            continue;
        } else if (ret == -1) {
            LOGE ("Capture packet fatal error, rawPktCaptureService will exit...\n");
            goto destroyIpPktParsingPushSock;
        }
    }

destroyIpPktParsingPushSock:
    closeZSock (ipPktParsingPushSock);
resetMirrorNic:
    resetMirrorNic ();
destroyLogContext:
    destroyLog ();
exit:
    subThreadStatusPush (SUB_THREAD_EXIT);

    return NULL;
}

void *
ipPktParsingService (void *args) {
    int ret;
    u_int cpuNum, parsingThreads;
    void *ipPktParsingPullSock;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    struct ip *newIphdr;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        LOGE ("Init log context error.\n");
        goto exit;
    }

    /* Init ip context */
    ret = initIp ();
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLogContext;
    }

    ipPktParsingPullSock = newZSock (ZMQ_PULL);
    if (ipPktParsingPullSock == NULL) {
        LOGE ("Create ipPktParsingPullSock error.\n");
        goto destroyIp;
    }

    /* Set ipPktParsingPullSock hwm to 500000 */
    zsocket_set_rcvhwm(ipPktParsingPullSock, 500000);

    ret = initDispatchRouter (parsingThreads);
    if (ret < 0) {
        LOGE ("Init dispatch router error.\n");
        goto destroyIpPktParsingPullSock;
    }

    while (!zctx_interrupted) {
        /* Receive timestamp */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (ipPktParsingPullSock);
            if ((tmFrame == NULL) && !zctx_interrupted)
                continue;
            else if (!zframe_more (tmFrame)) {
                LOGE ("Wrong timestamp frame.\n");
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive packet data */
        pktFrame = zframe_recv (ipPktParsingPullSock);
        if ((pktFrame == NULL) && !zctx_interrupted)
            continue;
        else if (zframe_more (pktFrame)) {
            LOGE ("Wrong ip packet frame.\n");
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        ret = ipDefrag ((struct ip *) zframe_data (pktFrame), zframe_size (pktFrame),
                        (timeValPtr) zframe_data (tmFrame), &newIphdr);
        if (ret < 0)
            LOGE ("Ip defrag error.\n");
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

    destroyDispatchRouter ();
destroyIpPktParsingPullSock:
    closeZSock (ipPktParsingPullSock);
destroyIp:
    destroyIp ();
destroyLogContext:
    destroyLog ();
exit:
    subThreadStatusPush (SUB_THREAD_EXIT);

    return NULL;
}

static void
publishSessionBreakdownCallback (const char *sessionBreakdown, void *args) {
    void *tcpBreakdownPushSock = args;

    zstr_send (tcpBreakdownPushSock, tcpBreakdown);
}

static void *
tcpPktParsingService (void *args) {
    int ret;
    u_int id;
    timeValPtr tm;
    struct ip *iphdr;
    zframe_t *tmFrame;
    zframe_t *pktFrame;
    u_int pktLen;
    void *sessionBreakdownSinkPushSock;
    void *tcpPktParsingPullSock;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    sessionBreakdownSinkPushSock = newZSock (ZMQ_PUSH);
    if (sessionBreakdownSinkPushSock == NULL) {
        LOGE ("Create sessionBreakdownSinkPushSock error.\n");
        goto destroyLogContext;
    }
    /* Set sessionBreakdownSinkPushSock sndhwm to 50000 */
    zsocket_set_sndhwm (sessionBreakdownSinkPushSock, 50000);
    ret = zsocket_connect (sessionBreakdownSinkPushSock, SESSION_BREAKDOWN_SINK_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", BREAKDOWN_SINK_PUSH_CHANNEL);
        goto destroySessionBreakdownSinkPushSock;
    }

    /* Init tcp context */
    ret = initTcp (tcpPublishBreakdownCallback, sessionBreakdownSinkPushSock);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroySessionBreakdownSinkPushSock;
    }

    ret = initProto ();
    if (ret < 0) {
        LOGE ("Init proto context error.\n");
        goto destroyTcp;
    }

    tcpPktParsingPullSock = newZSock (ZMQ_PULL);
    if (tcpPktParsingPullSock == NULL) {
        LOGE ("Create tcpPktParsingPullSock error.\n");
        goto destroyProto;
    }
    /* Set tcpPktParsingPullSock rcvhwm to 500000 */
    zsocket_set_rcvhwm (tcpPktParsingPullSock, 500000);
    ret = zsocket_bind (tcpPktParsingPullSock, TCP_PACKET_PARSING_PUSH_CHANNEL ":%u", (u_int) *args);
    if (ret < 0) {
        LOGE ("Connect to %s error.\n", BREAKDOWN_SINK_PUSH_CHANNEL);
        goto destroyTcpPktParsingPullSock;
    }

    while (!zctx_interrupted) {
        /* Receive timestamp */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktParsingPullSock);
            if ((tmFrame == NULL) && !zctx_interrupted)
                continue;
            else if (!zframe_more (tmFrame)) {
                LOGE ("Wrong timestamp frame.\n");
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive packet data */
        pktFrame = zframe_recv (tcpPktParsingPullSock);
        if ((pktFrame == NULL) && !zctx_interrupted)
            continue;
        else if (zframe_more (pktFrame)) {
            LOGE ("Wrong ip packet frame.\n");
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iphdr = (struct ip *) zframe_data (pktFrame);
        pktLen = zframe_size (pktFrame);
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcpProcess (iphdr, pktLen, tm);
                break;

            default:
                break;
        }
        
        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

destroyTcpPktParsingPullSock:
    closeZSock (tcpPktParsingPullSock);
destroyProto:
    destroyProto ();
destroyTcp:
    destroyTcp ();
destroySessionBreakdownSinkPushSock:
    closeZSock (sessionBreakdownSinkPushSock);
destroyLogContext:
    destroyLog ();
exit:
    subThreadStatusPush (SUB_THREAD_EXIT);

    return NULL;
}

static void *
sessionBreakdownSinkService (void *args) {
    int ret;
    void *sessionBreakdownSinkPullSock;
    void *sessionBreakdownPushSock;
    char *sessionBreakdown;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    sessionBreakdownSinkPullSock = newZSock (ZMQ_PULL);
    if (sessionBreakdownSinkPullSock == NULL) {
        LOGE ("Create sessionBreakdownSinkPullSock error.\n");
        goto destroyLogContext;
    }
    /* Set sessionBreakdownSinkPullSock rcvhwm to 500000 */
    zsocket_set_rcvhwm (sessionBreakdownSinkPullSock, 500000);
    ret = zsocket_bind (sessionBreakdownSinkPullSock, SESSION_BREAKDOWN_SINK_PUSH_CHANNEL);
    if (ret < 0) {
        LOGE ("Bind to %s error.\n", BREAKDOWN_SINK_PUSH_CHANNEL);
        goto destroySessionBreakdownSinkPullSock;
    }

    sessionBreakdownPushSock = newZSock (ZMQ_PUSH);
    if (sessionBreakdownPushSock == NULL) {
        LOGE ("Create sessionBreakdownPushSock error.\n");
        goto destroySessionBreakdownSinkPullSock;
    }
    /* Set sessionBreakdownPushSock sndhwm to 500000 */
    zsocket_set_sndhwm (sessionBreakdownPushSock, 500000);
    ret = zsocket_connect (sessionBreakdownPushSock, "tcp://%s:%u", agentStateCacheInstance.pubIp,
                           agentStateCacheInstance.pubPort);
    if (ret < 0) {
        LOGE ("Connect to tcp://%s:%u error.\n", agentStateCacheInstance.pubIp,
              agentStateCacheInstance.pubPort);
        goto destroySessionBreakdownPushSock;
    }
    
    while (!zctx_interrupted) {
        sessionBreakdown = zstr_recv (tbdRecvSock);
        if (sessionBreakdown) {
            zstr_send (sessionBreakdownPushSock, sessionBreakdown);
#ifndef NDEBUG
            LOGD ("Session breakdown-------------------count: %u\n%s\n",
                  ATOMIC_FETCH_AND_ADD (&sessionBreakdownCount, 1), sessionBreakdown);
#endif
            free (sessionBreakdown);
        }
    }

destroySessionBreakdownPushSock:
    closeZSock (sessionBreakdownPushSock);
destroySessionBreakdownSinkPullSock:
    closeZSock (sessionBreakdownSinkPullSock);
destroyLogContext:
    destroyLog ();
exit:
    subThreadStatusPush (SUB_THREAD_EXIT);

    return NULL;
}

static int
addAgent (const char *profile) {
    json_error_t error;
    json_t *root, *tmp;

    if (agentStateCacheInstance.state != AGENT_STATE_INIT) {
        LOGE ("Add-agent error: agent already added.\n");
        return -1;
    }

    root = json_loads (profile, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "ip") == NULL) ||
        (json_object_get (root, "port") == NULL) ||
        (json_object_get (root, "agent-id") == NULL)) {
        LOGE ("Json parse error.\n");
        return -1;
    }

    /* Get pubIp */
    tmp = json_object_get (root, "ip");
    agentStateCacheInstance.pubIp = strdup (json_string_value (tmp));
    if (agentStateCacheInstance.pubIp == NULL) {
        LOGE ("Get pubIp error.\n");
        resetAgentStateCache ();
        json_object_clear (root);
        return -1;
    }

    /* Get pubPort */
    tmp = json_object_get (root, "port");
    agentStateCacheInstance.pubPort = json_integer_value (tmp);

    /* Get agent id */
    tmp = json_object_get (root, "agent-id");
    agentStateCacheInstance.agentId = strdup (json_string_value (tmp));
    if (agentStateCacheInstance.agentId == NULL) {
        LOGE ("Get agentId error.\n");
        resetAgentStateCache ();
        json_object_clear (root);
        return -1;
    }

    json_object_clear (root);
    /* Update agent state */
    agentStateCacheInstance.state = AGENT_STATE_STOPPED;
    /* Save agent profile */
    dumpAgentStateCache ();

    return 0;
}

static int
removeAgent (const char *profile) {
    int ret;

    if (agentStateCacheInstance.state == AGENT_STATE_RUNNING) {
        LOGE ("Agent is running, please stop it before removing.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Remove with wrong agent-id.\n");
        return -1;
    }

    /* Reset agent profile */
    resetAgentStateCache ();
    /* Save agent profile */
    dumpAgentStateCache ();

    return 0;
}

static int
startAgent (const char *profile) {
    int ret;

    if (agentStateCacheInstance.state != AGENT_STATE_STOPPED) {
        LOGE ("Agent is not ready.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Start with wrong agent-id.\n");
        return -;
    }

    return 0;
}

static int
stopAgent (const char *profile) {
    int ret;

    if (agentStateCacheInstance.state != AGENT_STATE_RUNNING) {
        LOGE ("Agent is not running.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Stop with wrong agent-id.\n");
        return -;
    }

    /* Stop all tasks */
    stopAllTask ();
    /* Update agent state */
    agentStateCacheInstance.state = AGENT_STATE_STOPPED;
    /* Save agent profile */
    dumpAgentStateCache ();

    return 0;
}

static int
heartbeat (const char *profile) {
    int ret;

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Heartbeat with wrong agent-id.\n");
        return -1;
    }

    return 0;
}

static int
pushProfile (const char *profile) {
    int ret;
    char *filter;
    json_error_t error;
    json_t *root, *tmp;

    if (agentStateCacheInstance.state == AGENT_STATE_INIT) {
        LOGE ("Agent doesn't exist, please add agent first.\n");
        return -1;
    }

    ret = checkAgentId (profile);
    if (ret < 0) {
        LOGE ("Push profile with wrong agent-id.\n");
        return -1;
    }

    root = json_loads (profile, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        LOGE ("Parse profile error: %s.\n", error.text);
        return -1;
    }

    tmp = json_object_get (root, "services");
    if ((root == NULL) || !json_is_array (root)) {
        LOGE ("Get services error.\n");
        json_object_clear (root);
        return -1;
    }

    /* Update agent services */
    free (agentStateCacheInstance.services);
    agentStateCacheInstance.services = strdup (json_string_value (tmp));
    if (agentStateCacheInstance.services == NULL) {
        LOGE ("Strdup agent services error: %s.\n", strerror (errno));
        json_object_clear (root);
        return -1;
    }

    json_object_clear (root);

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

        ret = setFilter (filter);
        free (filter);
        if (ret < 0) {
            LOGE ("Set filter error.\n");
            return -1;
        }
    }
    /* Save agent profile */
    dumpAgentStateCache ();

    return 0;
}

/* Agent control message handler, this handler will always return 0. */
static int
agentControlMessageHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    char *msg;
    char *cmd, body, out;
    json_error_t error;
    json_t *root, *tmp;

    msg = zstr_recv_nowait (item->socket);
    if (msg == NULL)
        return 0;

    root = json_loads (msg, JSON_DISABLE_EOF_CHECK, &error);
    if ((root == NULL) ||
        (json_object_get (root, "command") == NULL) ||
        (json_object_get (root, "body") == NULL)) {
        LOGE ("Json parse error.\n");
        out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
    } else {
        tmp = json_object_get (root, "command");
        command = json_string_value (tmp);
        tmp = json_object_get (root, "body");
        body = json_string_value (tmp);

        if (strEqual ("add-agent", command)) {
            ret = addAgent (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);
        } else if (strEqual("remove-agent", command)) {
            ret = removeAgent (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);

        } else if (strEqual ("start-agent", command)) {
            ret = startAgent (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);

        } else if (strEqual ("stop-agent", command)) {
            ret = stopAgent (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);

        } else if (strEqual ("heartbeat", command)) {
            ret = heartbeat (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);

        } else if (strEqual ("push-profile", command)) {
            ret = pushProfile (body);
            if (ret < 0)
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
            else
                out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_SUCCESS, agentStateCacheInstance.state);
        } else {
            LOGE ("Unknown agent control command.\n");
            out = buildAgentControlResponse (AGENT_CONTROL_RESPONSE_FAILURE, AGENT_STATE_ERROR);
        }
    }

    if (out) {
        zstr_send (item->socket, out);
        free (out);
    } else {
        if ((root == NULL) || (ret < 0))
            zstr_send (item->socket, AGENT_CONTROL_RESPONSE_MESSAGE_ERROR);
        else
            zstr_send (item->socket, AGENT_CONTROL_RESPONSE_MESSAGE_SUCCESS);
    }

    free (msg);
    return 0;
}

/*
 * Sub-thread status message handler, when receiving SUB_THREAD_EXIT
 * then return -1 to exit.
 */
static int
subThreadStatusMessageHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    char *status;

    status = subThreadStatusRecvNonBlock ();
    if (status == NULL)
        return 0;

    if (strEqual (status, SUB_THREAD_EXIT)) {
        LOGE ("Sub-threads exit abnormally\n");
        free (status);
        return -1;
    }

    free (status);
    return 0;
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
    void *agentControlRecvSock;
    void *subThreadStatusRecvSock;
    zloop_t *loop;
    zmq_pollitem_t pollItems [2];

    if (lockPidFile () < 0)
        return -1;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    /* Init message channel */
    ret = initMessageChannel ();
    if (ret < 0) {
        LOGE ("Init message channel error.\n");
        ret = -1;
        goto destroyLogContext;
    }

    /* Init task manager */
    ret = initTaskManager ();
    if (ret < 0) {
        LOGE ("Init task manager error.\n");
        ret = -1;
        goto destroyMessageChannel;
    }

    /* Init service manager */
    ret = initServiceManager ();
    if (ret < 0) {
        LOGE ("Init service manager error.\n");
        ret = -1;
        goto destroyTaskManager;
    }

    /* Init agent state cache */
    ret = initAgentStateCache ();
    if (ret < 0) {
        LOGE ("Init agent state cache error.\n");
        ret = -1;
        goto destroyServiceManager;
    }

    /* Get parsing threads */
    parsingThreads = getCpuCores () * 2 + 1;
    if (parsingThreads < DEFAULT_PARSING_THREADS)
        parsingThreads = DEFAULT_PARSING_THREADS;

    /* Init agent control socket */
    agentControlRecvSock = newZSock (ZMQ_REP);
    if (agentControlRecvSock == NULL) {
        LOGE ("Create agentControlRecvSock error.\n");
        ret = -1;
        goto resetAgentStateCache;
    }
    ret = zsocket_bind (agentControlRecvSock, "tcp://*:%u", AGENT_CONTROL_PORT);
    if (ret < 0) {
        LOGE ("Bind to tcp://*:%u error.\n", AGENT_CONTROL_PORT);
        ret = -1;
        goto destroyAgentControlRecvSock;
    }

    /* Get sub-thread status receive socket */
    subThreadStatusRecvSock = getStatusRecvSock ();
    if (subThreadStatusRecvSock == NULL) {
        LOGE ("Get subThreadStatusRecvSock error.\n");
        ret = -1;
        goto destroyAgentControlRecvSock;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == Null) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto destroyAgentControlRecvSock;
    }

    /* Init poll item 0*/
    pollItems [0].socket = agentControlRecvSock;
    pollItems [0].fd = 0;
    pollItems [0].events = ZMQ_POLLIN;

    /* Init poll item 1*/
    pollItems [1].socket = subThreadStatusRecvSock;
    pollItems [1].fd = 0;
    pollItems [1].events = ZMQ_POLLIN;

    /* Register poll item 0 */
    ret = zloop_poller (loop, &pollItems [0], agentControlMessageHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [0] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Register poll item 1 */
    ret = zloop_poller(loop, &pollItems [0], subThreadStatusMessageHandler, NULL);
    if (ret < 0) {
        LOGE ("Register poll items [1] error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Start zloop */
    ret = zloop_start (loop);
    if (ret < 0)
        LOGE ("Stopped with error");
    else
        LOGD ("Stopped by interrupt.\n");

destroyZloop:
    zloop_destroy (&loop);
destroyAgentControlRecvSock:
    closeZSock (agentControlRecvSock);
resetAgentStateCache:
    resetAgentStateCache ();
destroyServiceManager:
    destroyServiceManager ();
destroyTaskManager:
    destroyTaskManager ();
destroyMessageChannel:
    destroyMessageChannel ();
destroyLogContext:
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
    agentParameters.daemonMode = get_int_config_value (item, 1, -1, &error);
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
    agentParameters.mirrorInterface = strdup (tmp);
    if (agentParameters.mirrorInterface == NULL) {
        logToConsole ("Get \"mirrorInterface\" error\n");
        ret = -1;
        goto exit;
    }

    /* Get default log level */
    ret = get_config_item ("LOG", "logLevel", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"logLevel\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.logLevel = get_int_config_value (item, 1, -1, &error);
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
    resetAgentParameters ();
    return ret;
}
