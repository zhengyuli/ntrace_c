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

static inline boolean
hlistIsEmpty (const hlistHeadPtr head) {
    if (head->first == NULL)
        return true;
    else
        return false;
}

static inline void
hlistDel (hlistNodePtr node) {
    hlistNodePtr next = node->next;
    hlistNodePtr *pprev = node->pprev;

    if (pprev)
        *pprev = next;
    if (next)
        next->pprev = pprev;

    node->next = NULL;
    node->pprev = NULL;
}

static inline void
hlistAdd (hlistNodePtr node, hlistHeadPtr head) {
    hlistNodePtr first;

    first = head->first;
    node->next = first;
    head->first = node;
    node->pprev = &head->first;
    if (first)
        first->pprev = &node->next;
}

static inline void
hlistAddBefore (hlistNodePtr node, hlistNodePtr nnode) {
    node->pprev = nnode->pprev;
    *node->pprev = node;
    node->next = nnode;
    nnode->pprev = &node->next;
}

static inline void
hlistAddAfter (hlistNodePtr node, hlistNodePtr pnode) {
    node->next = pnode->next;
    pnode->next = node;
    node->pprev = &pnode->next;
    if (node->next)
        node->next->pprev = &node->next;
}

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
hashTablePtr
hashNew (u_int hashSize);
void
hashClean (hashTablePtr htbl);
void
hashDestroy (hashTablePtr htbl);
int
hashInsert (hashTablePtr htbl, const char *key, void *data, hashItemFreeCB fun);
int
hashUpdate (hashTablePtr htbl, const char *key, void *data, hashItemFreeCB fun);
int
hashDel (hashTablePtr htbl, const char *key);
void *
hashLookup (hashTablePtr htbl, const char *key);
int
hashRename (hashTablePtr htbl, const char *old_key, const char *new_key);
u_int
hashSize (hashTablePtr htbl);
u_int
hashLimit (hashTablePtr htbl);
int
hashForEachItemDo (hashTablePtr htbl, hashForEachItemDoCB fun, void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __HASH_H__ */
