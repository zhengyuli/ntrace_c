#ifndef __HASH_H__
#define __HASH_H__

#include "util.h"
#include "list.h"

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

#define HLIST_HEAD(head) hlistHead head = {.first = NULL}

static inline void
initHlistHead (hlistHeadPtr head) {
    head->first = NULL;
}

static inline void
initHlistNode (hlistNodePtr node) {
    node->next = NULL;
    node->pprev = NULL;
}

/* Callback function definitions */
typedef void (*hashItemFreeCB) (void *item);
typedef int (*hashForEachItemDoCB) (void *item, void *args);
typedef boolean (*hashForEachItemDelInSomeCaseCB) (void *item, void *args);

typedef struct _hashItem hashItem;
typedef hashItem *hashItemPtr;

struct _hashItem {
    char *key;                          /**< Hash key */
    u_int index;                        /**< Index in hash table */
    void *data;                         /**< Opaque item value */
    hashItemFreeCB freeFun;             /**< Hash item free callback */
    hlistNode node;                     /**< Hash list node */
};

typedef struct _hashTable hashTable;
typedef hashTable *hashTablePtr;

struct _hashTable {
    u_int size;                         /**< Size of hash table */
    u_int capacity;                     /**< Capacity of hash table */
    u_int limit;                        /**< Limit of hash table */
    hlistHeadPtr heads;                 /**< Array of hlist head */
};

/* Get container of hash list node */
#define hlistEntry(ptr, type, member)           \
    containerOfMember (ptr, type, member)

/* Iterate over hash list */
#define hlistForEach(pos, head)                     \
    for (pos = (head)->first; pos; pos = pos->next)

/* Iterate over hash list of given type */
#define hlistForEachEntry(tpos, pos, head, member)                      \
    for (tpos = NULL, pos = (head)->first;                              \
         pos && ({tpos = hlistEntry (pos, typeof (*tpos), member); 1;}); \
         pos = pos->next)

/* Iterate over hash list of given type safe version */
#define hlistForEachEntrySafe(tpos, pos, tmp, head, member)             \
    for (tpos = NULL, pos = (head)->first;                              \
         pos && ({tmp = pos->next; 1;}) && ({tpos = hlistEntry (pos, typeof (*tpos), member); 1;}); \
         pos = tmp)

/* Iterate over hash list of given type from pos */
#define hlistForEachEntryFrom(tpos, pos, member)                        \
    for (; pos && ({tpos = hlistEntry (pos, typeof (*tpos), member); 1;}); \
         pos = pos->next)

/* Iterate over hash list of given type from pos safe version */
#define hlistForEachEntryFromSafe(tpos, pos, tmp, member)               \
    for (; pos && ({tmp = pos->next; 1;}) && ({tpos = hlistEntry (pos, typeof (*tpos), member); 1;}); \
         pos = tmp)

/*========================Interfaces definition============================*/
int
hashInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun);
int
hashDel (hashTablePtr htbl, char *key);
int
hashUpdate (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun);
void *
hashLookup (hashTablePtr htbl, char *key);
int
hashRename (hashTablePtr htbl, char *old_key, char *new_key);
int
hashForEachItemDo (hashTablePtr htbl, hashForEachItemDoCB fun, void *args);
void
hashForEachItemDelInSomeCase (hashTablePtr htbl, hashForEachItemDelInSomeCaseCB fun, void *args);
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
