#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "log.h"
#include "topology_entry.h"

topologyEntryPtr
newTopologyEntry (char *srcIp, char *destIp) {
    topologyEntryPtr entry;

    entry = (topologyEntryPtr) malloc (sizeof (topologyEntry));
    if (entry == NULL)
        return NULL;

    entry->srcIp = strdup (srcIp);
    if (entry->srcIp == NULL) {
        free (entry);
        return NULL;
    }

    entry->destIp = strdup (destIp);
    if (entry->destIp == NULL) {
        free (entry->srcIp);
        entry->srcIp = NULL;
        free (entry);
        return NULL;
    }

    return entry;
}

void
freeTopologyEntry (topologyEntryPtr entry) {
    if (entry == NULL)
        return;

    free (entry->srcIp);
    entry->srcIp = NULL;
    free (entry->destIp);
    entry->destIp = NULL;
    free (entry);
}

void
freeTopologyEntryForHash (void *data) {
    freeTopologyEntry ((topologyEntryPtr) data);
}

json_t *
topologyEntry2Json (topologyEntryPtr entry) {
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Topology entry source ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_SOURCE_IP, json_string (entry->srcIp));
    /* Topology entry dest ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_DEST_IP, json_string (entry->destIp));

    return root;
}
