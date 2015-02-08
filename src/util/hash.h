#ifndef __HASH_H__
#define __HASH_H__

#include "util.h"

typedef struct _hashTable hashTable;
typedef hashTable *hashTablePtr;

typedef void (*hashItemFreeCB) (void *data);
typedef int (*hashLoopDoCB) (void *data, void *args);
typedef boolean (*hashLoopCheckToRemoveCB) (void *data, void *args);

/*========================Interfaces definition============================*/
int
hashInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun);
int
hashRemove (hashTablePtr htbl, char *key);
int
hashUpdate (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun);
void *
hashLookup (hashTablePtr htbl, char *key);
int
hashRename (hashTablePtr htbl, char *old_key, char *new_key);
int
hashLoopDo (hashTablePtr htbl, hashLoopDoCB fun, void *args);
void
hashLoopCheckToRemove (hashTablePtr htbl, hashLoopCheckToRemoveCB fun, void *args);
u_int
hashSize (hashTablePtr htbl);
u_int
hashLimit (hashTablePtr htbl);
hashTablePtr
hashNew (u_int hashSize);
void
hashClean (hashTablePtr htbl);
void
hashDestroy (hashTablePtr htbl);
/*=======================Interfaces definition end=========================*/

#endif /* __HASH_H__ */
