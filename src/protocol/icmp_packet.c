#include <stdlib.h>
#include <arpa/inet.h>
#include <jansson.h>
#include "util.h"
#include "log.h"
#include "app_service_manager.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "icmp_packet.h"

/* Icmp breakdown publish callback */
static publishSessionBreakdownCB publishSessionBreakdownCallbackFunc;
/* Icmp breakdown publish callback args */
static void *publishSessionBreakdownCallbackArgs;

static char *
icmpBreakdown2Json (icmpBreakdownPtr ibd) {
    char *out;
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Icmp timestamp */
    json_object_set_new (root, ICMP_SKBD_TIMESTAMP, json_integer (ibd->timestamp));
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
        return false;
    else
        return true;
}

void
icmpProcess (iphdrPtr iph, timeValPtr tm) {
    u_int len;
    icmphdrPtr icmph;
    iphdrPtr origIph;
    tcphdrPtr origTcph;
    icmpBreakdown breakdown;
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

    breakdown.timestamp = ntohll (tm->tvSec);
    breakdown.type = icmph->type;
    breakdown.code = icmph->code;
    breakdown.ip = origIph->ipDest;

    if (icmph->code == ICMP_PORT_UNREACH) {
        origTcph = (tcphdrPtr) ((u_char *) origIph + origIph->iphLen * 4);
        if (icmpPktShouldDrop (origIph, origTcph))
            return;
        breakdown.port = ntohs (origTcph->dest);
    }

    jsonStr = icmpBreakdown2Json (&breakdown);
    if (jsonStr == NULL) {
        LOGE ("IcmpBreakdown2Json error.\n");
        return;
    }

    publishSessionBreakdownCallbackFunc (jsonStr, publishSessionBreakdownCallbackArgs);
    free (jsonStr);
}

int
initIcmp (publishSessionBreakdownCB callback, void *args) {
    if (callback == NULL) {
        LOGE ("Publish session breakdown callback is null.\n");
        return -1;
    }

    publishSessionBreakdownCallbackFunc = callback;
    publishSessionBreakdownCallbackArgs = args;

    return 0;
}

void
destroyIcmp (void) {
    return;
}
