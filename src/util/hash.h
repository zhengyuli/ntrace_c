#ifndef __HASH_H__
#define __HASH_H__

#include "util.h"

typedef struct _hlistNode hlistNode;
typedef hlistNode *hlistNodePtr;

struct _hlistNode {
    hlistNodePtr next;
    hlistNodePtr *pprev;
};

typedef struct _hlistHead hlistHead;
typedef hlistHead *hlistHeadPtr;

struct _hlistHead {
    hlistNodePtr first;
};

typedef void (*hashItemFreeCB) (void *data);

typedef struct _hashItem hashItem;
typedef hashItem *hashItemPtr;

struct _hashItem {
    char *key;                          /**< Hash key */
    u_int index;                        /**< Hash Index */
    void *data;                         /**< Opaque item value */
    hashItemFreeCB fun;                 /**< Hash item free callback */
    hlistNode node;                     /**< Hash list node */
};

typedef struct _hashTable hashTable;
typedef hashTable *hashTablePtr;

struct _hashTable {
    u_int capacity;                     /**< Capacity of hash table */
    u_int limit;                        /**< Limit of hash table */
    u_int size;                         /**< Size of hash table */
    hlistHeadPtr heads;                 /**< Hash list head array */
};

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
