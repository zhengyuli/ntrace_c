#ifndef __OWNERSHIP_MANAGER_H__
#define __OWNERSHIP_MANAGER_H__

#include <stdlib.h>
#include <czmq.h>
#include "list.h"

typedef enum {
    OWNERSHIP_LOCAL = 0,
    OWNERSHIP_REMOTE = 1,
} ownershipType;

typedef struct _ownership ownership;
typedef ownership *ownershipPtr;

struct _ownership {
    ownershipType type;
    char *ip;
    u_int cpuCores;
    u_int totalMem;
    u_int freeMem;
    void *pktSendSock;
    listHead node;
};

/*========================Interfaces definition============================*/
inline void *
getOwnershipPktSendSock (u_int hash);
int
initOwnershipManager (void);
void
destroyOwnershipManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __OWNERSHIP_MANAGER_H__ */
