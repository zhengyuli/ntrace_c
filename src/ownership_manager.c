#include <error.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "log.h"
#include "zmq_hub.h"
#include "ownership_manager.h"

#define OWNERSHIP_MAP_SIZE 128

/* Zmq context */
static zctx_t *zmqContext = NULL;

/* Ownership instance num */
static u_int ownershipInstanceNum = 0;
/* Ownership instance list */
static listHead ownershipInstanceList;

/* Master ownership map rwlock */
static pthread_rwlock_t ownershipMapMasterRWLock;
/* Master ownership map */
static ownershipPtr *ownershipMapMaster;
/* Slave ownership map */
static ownershipPtr *ownershipMapSlave;

static ownershipPtr
newOwnership (ownershipType type) {
    ownershipPtr tmp;

    tmp = (ownershipPtr) malloc (sizeof (ownership));
    if (tmp == NULL)
        return NULL;

    tmp->type = type;
    tmp->ip = NULL;
    tmp->cpuCores = 0;
    tmp->totalMem = 0;
    tmp->freeMem = 0;
    tmp->pktSendSock = NULL;
    initListHead (&tmp->node);

    return tmp;
}

static void
freeOwnership (ownershipPtr self) {
    free (self->ip);
    self->ip = NULL;
    zsocket_destroy (zmqContext, self->pktSendSock);

    free (self);
}

static void
swapOwnershipMap (void) {
    ownershipPtr *tmp;

    tmp = ownershipMapMaster;
    pthread_rwlock_wrlock (&ownershipMapMasterRWLock);
    ownershipMapMaster = ownershipMapSlave;
    pthread_rwlock_unlock (&ownershipMapMasterRWLock);
    ownershipMapSlave = tmp;
}

/*
 * @brief Get packet ownership send sock.
 *
 * @param hash packet hash
 *
 * @return NULL for OWNERSHIP_LOCAL else return pktSendSock of ownership
 */
inline void *
getOwnershipPktSendSock (u_int hash) {
    void *sock;
    
    pthread_rwlock_rdlock (&ownershipMapMasterRWLock);
    if (ownershipMapMaster [hash % OWNERSHIP_MAP_SIZE]->type == OWNERSHIP_LOCAL)
        sock = getTcpPktSendSock (hash % getTcpProcessThreadsNum ());
    else
        sock = ownershipMapMaster [hash % OWNERSHIP_MAP_SIZE]->pktSendSock;
    pthread_rwlock_unlock (&ownershipMapMasterRWLock);

    return sock;
}

int
initOwnershipManager (void) {
    int ret, i;
    ownershipPtr localOwnershipInstance;

    zmqContext = zctx_new ();
    if (zmqContext == NULL) {
        LOGE ("Create zmq context error.\n");
        return -1;
    }
    zctx_set_linger (zmqContext, 0);

    initListHead (&ownershipInstanceList);
    
    localOwnershipInstance = newOwnership (OWNERSHIP_LOCAL);
    if (localOwnershipInstance == NULL) {
        LOGE ("Create localOwnershipInstance error.\n");
        goto destroyZmqCtxt;
    }

    localOwnershipInstance->cpuCores = getCpuCoresNum ();
    getMemInfo (&localOwnershipInstance->totalMem,
                &localOwnershipInstance->freeMem);

    ret = pthread_rwlock_init (&ownershipMapMasterRWLock, NULL);
    if (ret) {
        LOGE ("Init ownershipMapMasterRWLock error.\n");
        goto freeLocalOwnershipInstance;
    }

    ownershipMapMaster = (ownershipPtr *) malloc (sizeof (ownershipPtr) * OWNERSHIP_MAP_SIZE);
    if (ownershipMapMaster == NULL) {
        LOGE ("Alloc ownershipMapMaster error.\n");
        goto destroyOwnershipMapMasterRWLock;
    }

    ownershipMapSlave = (ownershipPtr *) malloc (sizeof (ownershipPtr) * OWNERSHIP_MAP_SIZE);
    if (ownershipMapSlave == NULL) {
        LOGE ("Alloc ownershipMapSlave error.\n");
        goto freeOwnershipMapMaster;
    }
    
    /* Init master/slave ownership map */
    for (i = 0; i < OWNERSHIP_MAP_SIZE; i++) {
        ownershipMapMaster [i] = localOwnershipInstance;
        ownershipMapSlave [i] = localOwnershipInstance;
    }

    listAdd (&localOwnershipInstance->node, &ownershipInstanceList);
    ownershipInstanceNum = 1;
    
    return 0;

freeOwnershipMapMaster:
    free (ownershipMapMaster);
destroyOwnershipMapMasterRWLock:
    pthread_rwlock_destroy (&ownershipMapMasterRWLock);
freeLocalOwnershipInstance:
    freeOwnership (localOwnershipInstance);
destroyZmqCtxt:
    zctx_destroy (&zmqContext);
    return -1;
}

void
destroyOwnershipManager (void) {
    ownershipPtr entry;
    listHeadPtr pos, npos;

    pthread_rwlock_destroy (&ownershipMapMasterRWLock);
    free (ownershipMapMaster);
    free (ownershipMapSlave);
    
    listForEachEntrySafe (entry, pos, npos, &ownershipInstanceList, node) {
        listDel (&entry->node);
        freeOwnership (entry);
    }
    ownershipInstanceNum = 0;

    zctx_destroy (&zmqContext);
}
