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
#include "byte-order.h"
#include "service.h"
#include "redis-client.h"
#include "router.h"
#include "ip-packet.h"
#include "tcp-packet.h"
#include "agent.h"

#define PCAP_MAX_CAPLEN 65535
#define PCAP_MAX_TIMEOUT 1000
#define PCAP_PROMISC_FLAG 1
#define PCAP_DEFAULT_BUFFER_SIZE (16 * 1024 * 1024)

/* Pcap fragmented ip packet filter */
#define BPF_IP_FRAGMENT_FILTER "(tcp and (ip[6] & 0x20 != 0 or (ip[6] & 0x20 = 0 and ip[6:2] & 0x1fff != 0)))"
#define FILTER_SIZE_FOR_EACH_SERVICE 256

#define STATUS_READY "READY"
#define STATUS_EXITING "EXITING"

#define AGENT_GLOBAL_STATUS_INPROC_ADDRESS "inproc://agentGlobalStatus"
#define AGENT_PACKET_SHARING_INPROC_ADDRESS "inproc://agentPacketSharing"
#define AGENT_TCP_BREAKDOWN_SINK_INPROC_ADDRESS "inproc://agentTcpBreakdownSink"

static int agentPidFd = -1;

/* Shared status push socket */
static void *statusPushSock;
static pthread_mutex_t statusPushSockMutex = PTHREAD_MUTEX_INITIALIZER;

/* Parameters of agent */
static agentParams agentParameters = {
    .agentId = 0,
    .daemonMode = 0,
    .parsingThreads = 0,
    .mirrorInterface = NULL,
    .pcapDumpTimeout = 0,
    .logLevel = 0,
    .logFileDir = NULL,
    .logFileName = NULL,
    .redisSrvIp = NULL,
    .redisSrvPort = 0,
};

/* Network interface */
static netInterface mirrorNic = {
    .name = NULL,
    .ipaddr = NULL,
    .pcapDesc = NULL,
    .linkType = -1,
    .linkOffset = -1,
    .pstat = {0, 0},
};

static inline void
statusPush (const char *msg) {
    pthread_mutex_lock (&statusPushSockMutex);
    zstr_send (statusPushSock, msg);
    pthread_mutex_unlock (&statusPushSockMutex);
}

static void
freeAgentParameters (void) {
    free (agentParameters.mirrorInterface);
    free (agentParameters.logFileDir);
    free (agentParameters.logFileName);
    free (agentParameters.redisSrvIp);
}

static void
freeMirrorNic (void) {
    free (mirrorNic.name);
    free (mirrorNic.ipaddr);
    pcap_close (mirrorNic.pcapDesc);
}

/*
 * @brief Get ip address of interface
 *
 * @param interface interface name, like eth0
 *
 * @return Ip address if exists else NULL
 */
static char *
getIpAddr (const char *interface) {
    int sockfd;
    size_t ifNameLen;
    struct ifreq ifr;
    char *ipAddr = NULL;
    struct sockaddr_in *sockAddr;

    ifNameLen = strlen (interface);
    if (ifNameLen < sizeof (ifr.ifr_name)) {
        strncpy (ifr.ifr_name, interface, ifNameLen);
        ifr.ifr_name [ifNameLen] = 0;
    } else
        return NULL;

    if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
        return NULL;
    if (ioctl (sockfd, SIOCGIFADDR, &ifr) < 0) {
        LOGE ("Get ip addr error: %s\n", strerror (errno));
        close (sockfd);
        return NULL;
    }

    sockAddr = (struct sockaddr_in *) &ifr.ifr_addr;
    ipAddr = strdup ((const char*) inet_ntoa (sockAddr->sin_addr));

    close (sockfd);
    return ipAddr;
}

/*
 * @brief Get datalink offset
 *
 * @param datalinkType datalink type
 *
 * @return Link offset of packet frame, else return -1
 */
static int
getDatalinkOffset (int datalinkType) {
    int offset;

    switch (datalinkType) {
        /* BSD loopback encapsulation */
        case DLT_NULL:
            offset = 4;
            break;

            /* Ethernet (10Mb, 100Mb, 1000Mb or higher) */
        case DLT_EN10MB:
            offset = 14;
            break;

            /* Token Ring Support */
        case DLT_IEEE802:
            offset = 22;
            break;

            /* Serial line ip packet */
        case DLT_SLIP:
            offset = 0;
            break;

            /* Point-to-point Protocol */
        case DLT_PPP:
            offset = 4;
            break;

            /* FDDI */
        case DLT_FDDI:
            offset = 21;
            break;

            /* Raw ip packet */
        case DLT_RAW:
            offset = 0;
            break;

            /* This is for Linux cooked sockets */
        case DLT_LINUX_SLL:
            offset = 16;
            break;

            /* PPP over serial with HDLC encapsulation */
        case DLT_PPP_SERIAL:
            offset = 4;
            break;

        default:
            logToConsole ("Unknown link type.\n");
            offset = -1;
    }

    return offset;
}

static int
initMirrorNic (void) {
    int ret;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("Pcap find all devices error.\n");
        return -1;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (!strcmp (devptr->name, agentParameters.mirrorInterface))
            break;
    }

    if (devptr == NULL) {
        LOGE ("Interface: %s not exists.\n", agentParameters.mirrorInterface);
        return -1;
    }

    /* Get interface name */
    mirrorNic.name = strdup (agentParameters.mirrorInterface);
    if (mirrorNic.name == NULL) {
        LOGE ("Get mirror interface name error: %s.\n", strerror (errno));
        return -1;
    }

    /* Get interface ip if exits */
    mirrorNic.ipaddr = getIpAddr (mirrorNic.name);
    if (mirrorNic.ipaddr == NULL)
        LOGW ("Warning: interface %s has no ip address.\n", mirrorNic.name);

    /* Create pcap descriptor */
    mirrorNic.pcapDesc = pcap_create (mirrorNic.name, errBuf);
    if (mirrorNic.pcapDesc == NULL) {
        LOGE ("Open NIC %s error: %s.\n", mirrorNic.name, errBuf);
        freeMirrorNic ();
        return -1;
    }

    /* Set pcap snaplen */
    ret = pcap_set_snaplen (mirrorNic.pcapDesc, PCAP_MAX_CAPLEN);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (mirrorNic.pcapDesc, PCAP_MAX_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set pcap timeout error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (mirrorNic.pcapDesc, PCAP_DEFAULT_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap buffer size error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (mirrorNic.pcapDesc, PCAP_PROMISC_FLAG);
    if (ret < 0) {
        LOGE ("Set pcap promisc error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Activate pcap descriptor */
    ret = pcap_activate (mirrorNic.pcapDesc);
    if (ret < 0) {
        LOGE ("Activate pcap handler error.\n");
        freeMirrorNic ();
        return -1;
    }

    mirrorNic.linkType = pcap_datalink (mirrorNic.pcapDesc);
    if (mirrorNic.linkType < 0) {
        LOGE ("Get datalink type error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Get pcap linkOffset */
    mirrorNic.linkOffset = getDatalinkOffset (mirrorNic.linkType);
    if (mirrorNic.linkOffset < 0) {
        LOGE ("Get linkOffset error.\n");
        freeMirrorNic ();
        return -1;
    }

    /* Init pcap statistic info */
    mirrorNic.pstat.pktRecv = 0;
    mirrorNic.pstat.pktDrop = 0;

    return 0;
}

/*
 * @brief Send packet to packet parsing service, including capture
 *        time and ip packet.
 *
 * @param sndSock socket of packet parsing service
 * @param tm capture time of packet
 * @param iphdr ip packet to send
 * @param len length of ip packet
 */
static void
sendToPktParsingService (void *sndSock, timeValPtr tm, u_char *iphdr, int len) {
    int ret;
    zframe_t *frame;

    frame = zframe_new ((void *) tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Zframe_new error: %s.\n", strerror (errno));
        return;
    }
    ret = zframe_send (&frame, sndSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Zframe_send error: %s.\n", strerror (errno));
        zframe_destroy (&frame);
        return;
    }

    frame = zframe_new (iphdr, len);
    if (frame == NULL) {
        LOGE ("Zframe_new error: %s.\n", strerror (errno));
        return;
    }

    ret = zframe_send (&frame, sndSock, 0);
    if (ret < 0) {
        LOGE ("Zframe_send error: %s.\n", strerror (errno));
        zframe_destroy (&frame);
        return;
    }
}

/*
 * @brief Remove header link layer header and return ip header address
 *
 * @param pkthdr packet pcap header
 * @param linkLayerHeader packet captured from link layer
 *
 * @return Ip header if success else null
 */
static const u_char *
getIpHeader (const struct pcap_pkthdr *pkthdr, const u_char *linkLayerHeader) {
    /* Make sure the packet captured is complete */
    if (pkthdr->caplen != pkthdr->len) {
        LOGE ("Packet length doesn't equal to capture length.\n");
        return NULL;
    }

    switch (mirrorNic.linkType) {
        case DLT_EN10MB:
            /* Wrong packet */
            if (pkthdr->caplen < 14)
                return NULL;
            /* Recheck link offset */
            if ((linkLayerHeader [12] == 0x08) && (linkLayerHeader [13] == 0x00))
                /* Regular ip frame */
                mirrorNic.linkOffset = 14;
            else
                /* 802.1Q VLAN frame */
                if ((linkLayerHeader [12] == 0x81) && (linkLayerHeader [13] == 0x00)) {
                    /*
                     * +----------------------------------------------------------------------+
                     * | Dest Mac: 6 bytes | Src Mac: 6 bytes ||TPID|PCP|CFI|VID|| Ether type |
                     * +----------------------------------------------------------------------+
                     *                                        ^                  ^
                     *                                        |  802.1Q header   |
                     * skip VLAN header, include TPID(Tag Protocal Identifier: 16 bits),
                     * PCP(Priority Code Point: 3 bits), CFI(Canonical Format Indicator: 1 bits) ,
                     * VID(VLAN Identifier: 12 bits)
                     */
                    mirrorNic.linkOffset = 18;
                } else {
                    /* Non-ip packet */
                    LOGE ("Capture non-ip packet.\n");
                    return NULL;
                }
            break;

        default:
            /* For other link type do nothing */
            break;
    }

    /* Recheck packet len, especially for DLT_EN10MB */
    if (pkthdr->caplen < mirrorNic.linkOffset) {
        LOGE ("Packet capture length:%d less than data link offset:%d.\n",
              mirrorNic.linkOffset, pkthdr->caplen);
        return NULL;
    }
    return (linkLayerHeader + mirrorNic.linkOffset);
}

static int
generateFilterFromEachItem (void *data, void *args) {
    int ret;
    int len;
    servicePtr svc = (servicePtr) data;
    char *filter = (char *) args;

    len = strlen (filter);
    ret = snprintf (filter + len, FILTER_SIZE_FOR_EACH_SERVICE,
                    "(ip host %s and (tcp port %u or %s)) or ",
                    svc->ip, svc->port, BPF_IP_FRAGMENT_FILTER);
    if (ret < 0)
        return -1;
    else
        return 0;
}

/* Generate BPF filter from services */
static char *
generateFilter (void) {
    int ret;
    int len;
    size_t svcSize, filterSize;
    char *filter;

    svcSize = serviceNum ();
    filterSize = FILTER_SIZE_FOR_EACH_SERVICE * (svcSize + 2);
    filter = malloc (filterSize);
    if (filter == NULL) {
        LOGE ("Alloc filter error: %s\n", strerror (errno));
        return NULL;
    }

    memset (filter, 0, filterSize);
    if (svcSize == 0) {
        snprintf (filter, (filterSize - 1), "tcp");
        return filter;
    } else {
        ret = serviceLoopDo (generateFilterFromEachItem, filter);
        if (ret < 0) {
            LOGE ("Generate filter from services error.\n");
            free (filter);
            return NULL;
        } else {
            /* Remove the last ' or ' string */
            len = strlen (filter);
            *(filter + len - 4) = 0;
            return filter;
        }
    }
}

/*
 * @brief Set filter on mirror interface
 *
 * @param filter filter to set
 *
 * @return 0 if success, else return -1
 */
static int
setFilter (char *filter) {
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

/* Service update callback */
static void
serviceUpdate (svcUpdateType updateType, servicePtr svc) {
    int ret;
    char *filter;

    ret = updateService (updateType, svc);
    if (ret == 0) {
        /* Update BPF filter */
        filter = generateFilter ();
        if (filter) {
            ret = setFilter (filter);
            if (ret < 0)
                LOGE ("Set filter error.\n");
            else
                LOGD ("Set fiter with %s\n", filter);
            free (filter);
        } else
            LOGE ("Generate filter error.\n");
    }
}

/*
 * Service update monitor thread which used to monitor
 * service update and generate new filter rule for packet
 * capturing.
 */
static void *
serviceUpdateMonitor (void *args) {
    int ret;
    char *filter;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        statusPush (STATUS_EXITING);
        return NULL;
    }

    ret = initRedisContext (agentParameters.agentId,
                            agentParameters.redisSrvIp,
                            agentParameters.redisSrvPort);
    if (ret < 0) {
        LOGE ("Init redis context error.\n");
        statusPush (STATUS_EXITING);
        return NULL;
    }

    ret = initServiceContext ();
    if (ret < 0) {
        LOGE ("Init service context error.\n");
        destroyRedisContext ();
        statusPush (STATUS_EXITING);
        return NULL;
    }

    ret = initServiceFromRedis ();
    if (ret < 0) {
        LOGE ("Init services from redis error.\n");
        destroyServiceContext ();
        destroyRedisContext ();
        statusPush (STATUS_EXITING);
        return NULL;
    }

    /* Create BPF filter */
    filter = generateFilter ();
    if (filter) {
        /* Set filter for mirror interface */
        ret = setFilter (filter);
        if (ret < 0) {
            LOGE ("Set filter error.\n");
            free (filter);
            destroyServiceContext ();
            destroyRedisContext ();
            statusPush (STATUS_EXITING);
            return NULL;
        } else {
            LOGD ("Set filter: %s\n", filter);
            free (filter);
        }
    } else {
        LOGE ("Generate filter error.\n");
        destroyServiceContext ();
        destroyRedisContext ();
        statusPush (STATUS_EXITING);
        return NULL;
    }

    statusPush (STATUS_READY);
    /* Subscribe service update method */
    serviceUpdateSub (serviceUpdate);

    LOGD ("serviceUpdateMonitor thread will exit.\n");
    destroyServiceContext ();
    destroyRedisContext ();
    destroyLog ();
    statusPush (STATUS_EXITING);

    return NULL;
}

static char *
pcapStat2Json (pcapStatPtr stat) {
    char *out;
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    json_object_set_new (root, "pktRecv", json_integer (stat->pktRecv));
    json_object_set_new (root, "pktDrop", json_integer (stat->pktDrop));

    out = json_dumps (root, JSON_INDENT (4));
    json_object_clear (root);
    return out;
}

static void
dumpPcapStat (void) {
    int ret;
    char *json;
    struct pcap_stat stat;

    if (mirrorNic.pcapDesc == NULL)
        return;

    ret = pcap_stats (mirrorNic.pcapDesc, &stat);
    if (ret < 0)
        return;

    mirrorNic.pstat.pktRecv = stat.ps_recv;
    mirrorNic.pstat.pktDrop = stat.ps_drop;
    json = pcapStat2Json (&mirrorNic.pstat);
    if (json) {
        pubPcapStat (json);
        free (json);
    }
}

static void
showPcapStat (void) {
    LOGI ("Statistic info of %s:\n"
          "--Packets received: %d\n"
          "--Packets discard: %d\n"
          "--Packets discard probabilities: %%%f\n",
          mirrorNic.name, mirrorNic.pstat.pktRecv, mirrorNic.pstat.pktDrop,
          (double) mirrorNic.pstat.pktDrop / (double) (mirrorNic.pstat.pktDrop ? mirrorNic.pstat.pktDrop : 1));
}

/* Pcap statistic dumper */
static void *
pcapStatDumper (void *args) {
    int ret;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        return NULL;
    }

    ret = initRedisContext (agentParameters.agentId,
                            agentParameters.redisSrvIp,
                            agentParameters.redisSrvPort);
    if (ret < 0) {
        LOGE ("Init redis context error.\n");
        statusPush(STATUS_EXITING);
        return NULL;
    }

    while (!zctx_interrupted) {
        sleep (agentParameters.pcapDumpTimeout);
        dumpPcapStat ();
    }

    LOGD ("pcapStatDumper thread will exit.\n");
    showPcapStat ();
    destroyRedisContext ();
    destroyLog ();
    statusPush (STATUS_EXITING);

    return NULL;
}

static void
publishTcpBreakdown (const char *tcpBreakdown, void *args) {
    void *tbdSndSock = args;

    zstr_send (tbdSndSock, tcpBreakdown);
}

/* Tcp packet process entry */
static void *
packetProcess (void *args) {
    int ret;
    timeValPtr tm;
    struct ip *iphdr;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    int pktLen;
    routerSockPtr routerSocks = (routerSockPtr) args;
    void *pktRecvSock = routerSocks->pktRecvSock;
    void *tbdSndSock = routerSocks->tbdSndSock;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Init tcp context */
    ret = initTcp (publishTcpBreakdown, tbdSndSock);
    if (ret < 0) {
        LOGE ("Init tcp process context error.\n");
        goto freeLogContext;
    }

    while (!zctx_interrupted) {
        /* Receive timestamp frame */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (pktRecvSock);
            if (tmFrame) {
                if (!zframe_more (tmFrame)) {
                    LOGE ("Receive timestamp frame error.\n");
                    zframe_destroy (&tmFrame);
                    continue;
                }
            } else {
                if (!zctx_interrupted)
                    LOGE ("Receive timestamp frame error.\n");
                continue;
            }
        }

        /* Receive packet data */
        pktFrame = zframe_recv (pktRecvSock);
        if (pktFrame) {
            /* Not packet packet */
            if (zframe_more (pktFrame)) {
                LOGE ("Receive packet frame error.\n");
                zframe_destroy (&tmFrame);
                tmFrame = pktFrame;
                pktFrame = NULL;
                continue;
            }
        } else {
            if (!zctx_interrupted)
                LOGE ("Receive packet frame error.\n");
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iphdr = (struct ip *) zframe_data (pktFrame);
        pktLen = zframe_size (pktFrame);
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcpProcess ((u_char *) iphdr, pktLen, tm);
                break;

            default:
                break;
        }

        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("packetProcess thread will exit.\n");
    destroyTcp ();
freeLogContext:
    destroyLog ();
exit:
    statusPush (STATUS_EXITING);

    return NULL;
}

/*
 * Tcp breakdown sink thread, this thread will collect all tcp
 * breakdown from tcp processing thread and send them to redis
 * server.
 */
static void *
tcpBreakdownSink (void *args) {
    int ret;
    char *tcpBreakdown;
    void *tbdRecvSock = args;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Init redis context */
    ret = initRedisContext (agentParameters.agentId,
                            agentParameters.redisSrvIp,
                            agentParameters.redisSrvPort);
    if (ret < 0) {
        LOGE ("Init redis context error.\n");
        goto freeLogContext;
    }

    while (!zctx_interrupted) {
        tcpBreakdown = zstr_recv (tbdRecvSock);
        if (tcpBreakdown) {
            pushSessionBreakdown (tcpBreakdown);
            free (tcpBreakdown);
        }
    }

    LOGD ("tcpBreakdownSink thread will exit.\n");
    destroyRedisContext ();
freeLogContext:
    destroyLog ();
exit:
    statusPush (STATUS_EXITING);

    return NULL;
}

/* Tcp/Ip parsing service */
static void *
pktParsingService (void *args) {
    int ret;
    /* Zmq context */
    zctx_t *zmqCtx;
    /* Socket used to receive tcp breakdown */
    void *tbdRecvSock;
    /* Packet sharing receive socket */
    void *pktSharingRcvSock = args;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    struct ip *newIphdr;
    pthread_t tcpBreakdownSinkTid;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        goto exit;
    }

    /* Init ip processing context */
    ret = initIp ();
    if (ret < 0) {
        LOGE ("Ip processing context init error.\n");
        goto freeLogContext;
    }

    /* Init application level protocol processing context */
    ret = initProto ();
    if (ret < 0) {
        LOGE ("Proto processing context init error.\n");
        goto freeIpContext;
    }

    /* Init zmq context */
    zmqCtx = zctx_new ();
    if (zmqCtx == NULL) {
        LOGE ("Create zmq context error: %s.\n", strerror (errno));
        goto freeProtoContext;
    }
    /* Set zctx linger time to 0 */
    zctx_set_linger (zmqCtx, 0);
    /* Set zctx iothreads to 3 */
    zctx_set_iothreads (zmqCtx, 3);

    /* Init tcpBreakdownSink sub-thread context */
    tbdRecvSock = zsocket_new (zmqCtx, ZMQ_PULL);
    if (tbdRecvSock == NULL) {
        LOGE ("Create tbdRecvSock error: %s.\n", strerror (errno));
        goto freeZmqContext;
    }
    zsocket_set_rcvhwm (tbdRecvSock, 50000);

    ret = zsocket_bind (tbdRecvSock, AGENT_TCP_BREAKDOWN_SINK_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Bind to \"%s\" error: %s.\n", AGENT_TCP_BREAKDOWN_SINK_INPROC_ADDRESS, strerror (errno));
        goto freeZmqContext;
    }

    ret = pthread_create (&tcpBreakdownSinkTid, NULL, tcpBreakdownSink, tbdRecvSock);
    if (ret < 0) {
        LOGE ("Create tcpBreakdownSink thread error: %s.\n", strerror (errno));
        goto freeZmqContext;
    }

    ret = initRouter (zmqCtx, agentParameters.parsingThreads, packetProcess, AGENT_TCP_BREAKDOWN_SINK_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Init packet processing dispatch router error.\n");
        goto freeTcpBreakdownSink;
    }

    while (!zctx_interrupted) {
        /* Receive timestamp */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (pktSharingRcvSock);
            if (tmFrame) {
                if (!zframe_more (tmFrame)) {
                    LOGE ("Receive timestamp frame error.\n");
                    zframe_destroy (&tmFrame);
                    continue;
                }
            } else {
                if (!zctx_interrupted)
                    LOGE ("Receive timestamp frame error.\n");
                continue;
            }
        }

        /* Receive packet data */
        pktFrame = zframe_recv (pktSharingRcvSock);
        if (pktFrame) {
            /* Not packet packet */
            if (zframe_more (pktFrame)) {
                LOGE ("Receive packet frame error.\n");
                zframe_destroy (&tmFrame);
                tmFrame = pktFrame;
                pktFrame = NULL;
                continue;
            }
        } else {
            if (!zctx_interrupted)
                LOGE ("Receive packet frame error.\n");
            continue;
        }

        /* Filter timeout packet */
        if (zframe_size (pktFrame) < sizeof (struct ip)) {
            zframe_destroy (&tmFrame);
            zframe_destroy (&pktFrame);
            continue;
        }

        ret = ipDefragProcess (zframe_data (pktFrame), zframe_size (pktFrame), &newIphdr);
        switch (ret) {
            case IPF_NOTF:
                routerDispatch ((struct ip *) zframe_data (pktFrame), (timeValPtr) zframe_data (tmFrame));
                break;

            case IPF_NEW:
                routerDispatch (newIphdr, (timeValPtr) zframe_data (tmFrame));
                free (newIphdr);
                break;

            default:
                break;
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGD ("pktParsingService thread will exit.\n");
    destroyRouter ();
freeTcpBreakdownSink:
    pthread_kill (tcpBreakdownSinkTid, SIGINT);
    /* Wait for sub-threads exit completely */
    usleep (200000);
freeZmqContext:
    zctx_destroy (&zmqCtx);
freeProtoContext:
    destroyProto ();
freeIpContext:
    destroyIp ();
freeLogContext:
    destroyLog ();
exit:
    statusPush (STATUS_EXITING);

    return NULL;
}

static int
lockPidFile (void) {
    pid_t pid;
    ssize_t n;
    char buf [16];

    pid = getpid ();

    agentPidFd = open (WDM_AGENT_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (agentPidFd < 0) {
        fprintf(stderr, "Open pid file %s error: %s.\n", WDM_AGENT_PID_FILE, strerror (errno));
        return -1;
    }

    if (flock (agentPidFd, LOCK_EX | LOCK_NB) == 0) {
        snprintf (buf, sizeof (buf), "%d", pid);
        n = write (agentPidFd, buf, strlen (buf));
        if (n != strlen (buf)) {
            fprintf(stderr, "Write pid to pid file error: %s.\n", strerror (errno));
            close (agentPidFd);
            remove (WDM_AGENT_PID_FILE);
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
    remove (WDM_AGENT_PID_FILE);
}

static int
agentRun (void) {
    int ret;
    char *status;
    zctx_t *zmqCtx;
    /* Socket used to get globally shared status */
    void *statusRecvSock;
    /* Socket used to sharing packets */
    void *pktSharingSndSock;
    void *pktSharingRcvSock;
    /* Sub-thread id */
    pthread_t svcUpdateMonitorTid;
    pthread_t pcapStatDumperTid;
    pthread_t pktParsingServiceTid;
    struct pcap_pkthdr *pkthdr;
    const u_char *pktdata;
    struct ip *iphdr;
    int ipLen;
    timeVal captureTime;

    if (lockPidFile () < 0)
        return -1;

    /* Init log context */
    ret = initLog (agentParameters.logLevel);
    if (ret < 0) {
        logToConsole ("Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    ret = initMirrorNic ();
    if (ret < 0) {
        LOGE ("Init device error.\n");
        ret = -1;
        goto freeLogContext;
    }

    /* Init zmq context */
    zmqCtx = zctx_new ();
    if (zmqCtx == NULL) {
        LOGE ("Create zmq context error: %s.\n", strerror (errno));
        ret = -1;
        goto freeMirrorNic;
    }
    zctx_set_linger (zmqCtx, 0);

    statusPushSock = zsocket_new (zmqCtx, ZMQ_PAIR);
    if (statusPushSock == NULL) {
        LOGE ("Create statusPushSock error: %s.\n", strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    statusRecvSock = zsocket_new (zmqCtx, ZMQ_PAIR);
    if (statusRecvSock == NULL) {
        LOGE ("Create statusRecvSock error: %s.\n", strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    ret = zsocket_bind (statusRecvSock, AGENT_GLOBAL_STATUS_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Bind \"%s\" error: %s.\n", AGENT_GLOBAL_STATUS_INPROC_ADDRESS, strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    ret = zsocket_connect (statusPushSock, AGENT_GLOBAL_STATUS_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Connect to \"%s\" error: %s.\n", AGENT_GLOBAL_STATUS_INPROC_ADDRESS, strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    pktSharingSndSock = zsocket_new (zmqCtx, ZMQ_PAIR);
    if (pktSharingSndSock == NULL) {
        LOGE ("Create pktSharingSndSock error: %s.\n", strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }
    /* Set pktSharingSndSock send hwm to 500000 */
    zsocket_set_sndhwm (pktSharingSndSock, 500000);

    pktSharingRcvSock = zsocket_new (zmqCtx, ZMQ_PAIR);
    if (pktSharingRcvSock == NULL) {
        LOGE ("Create pktSharingRcvSock error: %s.\n", strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }
    zsocket_set_rcvhwm (pktSharingRcvSock, 500000);

    ret = zsocket_bind (pktSharingRcvSock, AGENT_PACKET_SHARING_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Bind \"%s\" error: %s.\n", AGENT_PACKET_SHARING_INPROC_ADDRESS, strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    ret = zsocket_connect (pktSharingSndSock, AGENT_PACKET_SHARING_INPROC_ADDRESS);
    if (ret < 0) {
        LOGE ("Connect \"%s\" error: %s.\n", AGENT_PACKET_SHARING_INPROC_ADDRESS, strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    /* Create serviceUpdateMonitor thread */
    ret = pthread_create (&svcUpdateMonitorTid, NULL, serviceUpdateMonitor, NULL);
    if (ret < 0) {
        LOGE ("Create serviceUpdateMonitor thread error: %s.\n", strerror (errno));
        ret = -1;
        goto freeZmqContext;
    }

    /* Create sub-thread to dump pcap statistic periodically */
    ret = pthread_create (&pcapStatDumperTid, NULL, pcapStatDumper, NULL);
    if (ret < 0) {
        LOGE ("Create pcapStatDumper thread error: %s.\n", strerror (errno));
        ret = -1;
        goto freeSvcUpdateMonitor;
    }

    /* Check service initialization is complete */
    status = zstr_recv (statusRecvSock);
    if (STRNEQ (status, STATUS_READY)) {
        free (status);
        ret = -1;
        goto freePcapStatDumper;
    }
    free (status);

    /* Create real-time packet parsing service */
    ret = pthread_create (&pktParsingServiceTid, NULL, pktParsingService, pktSharingRcvSock);
    if (ret < 0) {
        LOGE ("Create pktParsingService error: %s.\n", strerror (errno));
        ret = -1;
        goto freePcapStatDumper;
    }

    while (!zctx_interrupted) {
        status = zstr_recv_nowait (statusRecvSock);
        if (status) {
            if (STREQ (status, STATUS_EXITING)) {
                free (status);
                ret = -1;
                goto freePktParsingService;
            } else
                free (status);
        }

        ret = pcap_next_ex (mirrorNic.pcapDesc, &pkthdr, &pktdata);
        if (ret == 1) {
            iphdr = (struct ip *) getIpHeader (pkthdr, pktdata);
            if (iphdr == NULL)
                continue;

            /* Filter frame incomplete */
            ipLen = ntohs (iphdr->ip_len);
            if ((pkthdr->caplen - mirrorNic.linkOffset) < ipLen) {
                LOGE ("Capture incomplete frame.\n");
                continue;
            }

            captureTime.tvSec = hton64 (pkthdr->ts.tv_sec);
            captureTime.tvUsec = hton64 (pkthdr->ts.tv_usec);
            sendToPktParsingService (pktSharingSndSock, &captureTime, (u_char *) iphdr, ipLen);
        } else if (ret == -1) {
            LOGE ("Capture packet error: %s.\n", pcap_geterr (mirrorNic.pcapDesc));
            ret = -1;
            goto freePktParsingService;
        }
    }
    /* Terminated by interrupt */
    ret = 0;

freePktParsingService:
    pthread_kill (pktParsingServiceTid, SIGINT);
freePcapStatDumper:
    pthread_kill (pcapStatDumperTid, SIGINT);
freeSvcUpdateMonitor:
    pthread_kill (svcUpdateMonitorTid, SIGINT);
    /* Wait for sub-threads exit completely */
    usleep (200000);
freeZmqContext:
    zctx_destroy (&zmqCtx);
freeMirrorNic:
    freeMirrorNic();
freeLogContext:
    destroyLog ();
unlockPidFile:
    unlockPidFile ();

    return ret;
}

static int
agentDaemon (void) {
    pid_t pid, next_pid;
    int stdinfd = -1;
    int stdoutfd = -1;

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

/* Agent cmd options */
static struct option agentOptions [] = {
    {"agent-id", required_argument, NULL, 'i'},
    {"parsing-threads", required_argument, NULL, 'n'},
    {"mirror-interface", required_argument, NULL, 'm'},
    {"pcap-dump-timeout", required_argument, NULL, 't'},
    {"log-level", required_argument, NULL, 'l'},
    {"redis-srv-ip", required_argument, NULL, 'r'},
    {"redis-srv-port", required_argument, NULL, 'p'},
    {"daemon-mode", no_argument, NULL, 'D'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0},
};

static void
showHelpInfo (const char *cmd) {
    const char *cmdName;

    cmdName = strrchr (cmd, '/') ? (strrchr (cmd, '/') + 1) : cmd;
    logToConsole ("Usage: %s -m <eth*> -s <ip> [options]\n"
                  "       %s [-vh]\n"
                  "Basic options: \n"
                  "  -i|--agent-id <id> agent id\n"
                  "  -n|--parsing-threads <number> parsing threads number\n"
                  "  -m|--mirror-interface <eth*> interface to collect packets\n"
                  "  -t|--pcap-dump-timeout <timeout>, timeout for dumping pcap statistic\n"
                  "  -l|--log-level <level> log level\n"
                  "       Optional level: 0-ERR 1-WARNING 2-INFO 3-DEBUG\n"
                  "  -r|--redis-srv-ip <ip>, ip of redis server\n"
                  "  -p|--redis-srv-port <port>, port of redis server\n"
                  "  -D|--daemon-mode, run as daemon\n"
                  "  -v|--version, version of %s\n"
                  "  -h|--help, help information\n",
                  cmdName, cmdName, cmdName);
}

/* Cmd line parser */
static int
parseCmdline (int argc, char *argv []) {
    char option;
    int showVersion = 0;
    int showHelp = 0;

    while ((option = getopt_long (argc, argv, "i:n:m:t:l:d:f:r:p:Dvh?", agentOptions, NULL)) != -1) {
        switch (option) {
            case 'i':
                agentParameters.agentId = (u_short) atoi (optarg);
                break;

            case 'n':
                agentParameters.parsingThreads = (u_short) atoi (optarg);
                break;

            case 'm':
                agentParameters.mirrorInterface = strdup (optarg);
                if (agentParameters.mirrorInterface == NULL) {
                    logToConsole ("Get mirroring interface error!\n");
                    return -1;
                }
                break;

            case 't':
                agentParameters.pcapDumpTimeout = (u_short) atoi (optarg);
                break;

            case 'l':
                agentParameters.logLevel = (u_short) atoi (optarg);
                break;

            case 'r':
                agentParameters.redisSrvIp = strdup (optarg);
                if (agentParameters.redisSrvIp == NULL) {
                    logToConsole ("Get redis server ip error.\n");
                    return -1;
                }
                break;

            case 'p':
                agentParameters.redisSrvPort = (u_short) atoi (optarg);
                break;

            case 'D':
                agentParameters.daemonMode = 1;
                break;

            case 'v':
                showVersion = 1;
                break;

            case 'h':
                showHelp = 1;
                break;

            case '?':
                logToConsole ("Unknown options.\n");
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            logToConsole ("Current version: %d.%d\n", WDM_AGENT_VERSION_MAJOR, WDM_AGENT_VERSION_MINOR);
        if (showHelp)
            showHelpInfo (argv [0]);
        exit (0);
    }

    return 0;
}

/* Parse configuration of agent */
static int
parseConf (void) {
    int ret, error;
    const char *tmp;
    struct collection_item *iniConfig = NULL;
    struct collection_item *errorSet = NULL;
    struct collection_item *item;

    ret = config_from_file ("Agent", WDM_AGENT_CONFIG_FILE,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        logToConsole ("Parse config file: %s error.\n", WDM_AGENT_CONFIG_FILE);
        return -1;
    }

    /* Get agent id */
    ret = get_config_item ("MAIN", "agent_id", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"agent_id\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.agentId = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"agent_id\" error.\n");
        ret = -1;
        goto exit;
    }

    /* Get daemon mode */
    ret = get_config_item ("MAIN", "daemon_mode", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"daemon_mode\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.daemonMode = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"daemon_mode\" error.\n");
        ret = -1;
        goto exit;
    }

    /* Get parsing threads number */
    ret = get_config_item ("MAIN", "parsing_threads", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"parsing_threads\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.parsingThreads = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"parsing_threads\" error.\n");
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

    /* Get pcap_dump_timeout */
    ret = get_config_item ("MAIN", "pcap_dump_timeout", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"pcap_dump_timeout\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.pcapDumpTimeout = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"pcap_dump_timeout\" error.\n");
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
    agentParameters.logLevel = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"log_level\" error.\n");
        ret = -1;
        goto exit;
    }

    /* Get redis server ip */
    ret = get_config_item ("REDIS", "redis_server_ip", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"redis_server_ip\" error\n");
        ret = -1;
        goto exit;
    }
    tmp = get_const_string_config_value (item, &error);
    if (error) {
        logToConsole ("Parse \"redis_server_ip\" error.\n");
        ret = -1;
        goto exit;
    }
    agentParameters.redisSrvIp = strdup (tmp);
    if (agentParameters.redisSrvIp == NULL) {
        logToConsole ("Get \"redis_server_ip\" error\n");
        ret = -1;
        goto exit;
    }

    /* Get redis server port */
    ret = get_config_item ("REDIS", "redis_server_port", iniConfig, &item);
    if (ret) {
        logToConsole ("Get_config_item \"redis_server_port\" error\n");
        ret = -1;
        goto exit;
    }
    agentParameters.redisSrvPort = (u_short) get_int_config_value (item, 1, -1, &error);
    if (error) {
        logToConsole ("Parse \"redis_server_port\" error.\n");
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
