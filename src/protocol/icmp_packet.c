#include <stdlib.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <czmq.h>
#include "util.h"
#include "log.h"
#include "app_service_manager.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "icmp_packet.h"

/* Icmp breakdown send sock */
static void *icmpBreakdownSendSock;

static void
publishIcmpBreakdown (char *sessionBreakdown) {
    int ret;
    u_int retries = 3;

    do {
        ret = zstr_send (icmpBreakdownSendSock, sessionBreakdown);
        retries -= 1;
    } while ((ret < 0) && retries);

    if (ret < 0)
        LOGE ("Send icmp breakdown error.\n");
}

static char *
icmpBreakdown2Json (icmpBreakdownPtr ibd) {
    char *out;
    json_t *root;
    char buf [64];
    
    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Icmp timestamp */
    formatLocalTimeStr (&ibd->timestamp, buf, sizeof (buf));
    json_object_set_new (root, ICMP_SKBD_TIMESTAMP, json_string (buf));
    /* Icmp protocol */
    json_object_set_new (root, ICMP_SKBD_PROTOCOL, json_string ("ICMP"));
    /* Icmp type */
    json_object_set_new (root, ICMP_SKBD_ICMP_TYPE, json_integer (ibd->type));
    /* Icmp code */
    json_object_set_new (root, ICMP_SKBD_ICMP_CODE, json_integer (ibd->code));
    /* Icmp dest unreach ip */
    json_object_set_new (root, ICMP_SKBD_ICMP_DEST_UNREACH_IP, json_string (inet_ntoa (ibd->ip)));
    /* Icmp dest unreach port */
    if (ibd->code == ICMP_PORT_UNREACH)
        json_object_set_new (root, ICMP_SKBD_ICMP_DEST_UNREACH_PORT, json_integer (ibd->port));

    out = json_dumps (root, JSON_INDENT (4));
    json_object_clear (root);

    return out;
}

static boolean
icmpPktShouldDrop (iphdrPtr iph, tcphdrPtr tcph) {
    char key [32];

    snprintf (key, sizeof (key), "%s:%d", inet_ntoa (iph->ipDest), ntohs (tcph->dest));
    if (getAppServiceProtoAnalyzer (key))
        return False;
    else
        return True;
}

/*
 * @brief Icmp pakcet processor
 * 
 * @param iph ip packet header
 * @param tm packet capture timestamp
 */
void
icmpProcess (iphdrPtr iph, timeValPtr tm) {
    u_int len;
    icmphdrPtr icmph;
    iphdrPtr origIph;
    tcphdrPtr origTcph;
    icmpBreakdown ibd;
    char *jsonStr;

    len = ntohs (iph->ipLen) - iph->iphLen * 4;
    if (len < sizeof (icmphdr)) {
        LOGW ("Incomplete icmp packet.\n");
        return;
    }

    /* Get icmp header */
    icmph = (icmphdrPtr) ((u_char *) iph + iph->iphLen * 4);
    if ((icmph->type > NR_ICMP_TYPES) ||
        (icmph->type != ICMP_DEST_UNREACH) ||
        (icmph->code > NR_ICMP_UNREACH))
        return;

    len -= sizeof (icmphdr);
    if (len < sizeof (iphdr))
        return;

    /* Get origin ip header */
    origIph = (iphdrPtr) (icmph + 1);
    if (origIph->ipProto != IPPROTO_TCP)
        return;

    ibd.timestamp.tvSec = ntohll (tm->tvSec);
    ibd.timestamp.tvUsec = ntohll (tm->tvUsec);
    ibd.type = icmph->type;
    ibd.code = icmph->code;
    ibd.ip = origIph->ipDest;

    if (icmph->code == ICMP_PORT_UNREACH) {
        origTcph = (tcphdrPtr) ((u_char *) origIph + origIph->iphLen * 4);
        if (icmpPktShouldDrop (origIph, origTcph))
            return;
        ibd.port = ntohs (origTcph->dest);
    }

    jsonStr = icmpBreakdown2Json (&ibd);
    if (jsonStr == NULL) {
        LOGE ("IcmpBreakdown2Json error.\n");
        return;
    }

    publishIcmpBreakdown (jsonStr);
    free (jsonStr);
}

int
initIcmp (void *sock) {
    icmpBreakdownSendSock = sock;

    return 0;
}

void
destroyIcmp (void) {
    return;
}
