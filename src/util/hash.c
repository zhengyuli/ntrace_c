#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"
#include "hash.h"

/* Default hash table capacity */
#define DEFAULT_HASH_TABLE_CAPACITY 255
/* Percent loading brefore splitting */
#define HASH_TABLE_LOAD_FACTOR 75
/* Resize factor after splitting */
#define HASH_TABLE_RESIZE_FACTOR 2

/* ========================================================================== */

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

typedef struct _hashItem hashItem;
typedef hashItem *hashItemPtr;

struct _hashItem {
    char *key;                          /**< Hash key */
    u_int index;                        /**< Hash Index */
    void *data;                         /**< Opaque item value */
    hashItemFreeCB fun;                 /**< Hash item free callback */
    hlistNode node;                     /**< Hash list node */
};

struct _hashTable {
    u_int capacity;                     /**< Capacity of hash table */
    u_int limit;                        /**< Limit of hash table */
    u_int size;                         /**< Size of hash table */
    hlistHeadPtr heads;                 /**< Hash list head array */
};

/* ========================================================================== */

#define hlistEntry(pos, type, member) ({                                \
            typeof (((type *) 0)->member) *mptr = (pos);                \
            (type *) ((u_char *) mptr - ((size_t) &((type *) 0)->member));})

#define hlistForEachEntry(tpos, pos, head, member)                      \
    for ((tpos) = NULL, (pos) = (head)->first;                          \
         (pos) && ({(tpos) = hlistEntry ((pos), typeof (*(tpos)), member); 1;}); \
         (pos) = (pos)->next)

#define hlistForEachEntrySafe(tpos, pos, npos, head, member)             \
    for ((tpos) = NULL, (pos) = (head)->first;                          \
         (pos) && ({(npos) = (pos)->next; 1;}) && ({(tpos) = hlistEntry ((pos), typeof (*(tpos)), member); 1;}); \
         (pos) = (npos))

#define hlistForEachEntryFrom(tpos, pos, member)                        \
    for (;                                                              \
         (pos) && ({(tpos) = hlistEntry ((pos), typeof (*(tpos)), member); 1;}); \
         (pos) = (pos)->next)

#define hlistForEachEntryFromSafe(tpos, pos, npos, member)               \
    for (;                                                              \
         (pos) && ({(npos) = (pos)->next; 1;}) && ({(tpos) = hlistEntry ((pos), typeof (*(tpos)), member); 1;}); \
         (pos) = (npos))

static void
hlistAdd (hlistNodePtr node, hlistHeadPtr head) {
    hlistNodePtr first;

    first = head->first;
    node->next = first;
    head->first = node;
    node->pprev = &head->first;
    if (first)
        first->pprev = &node->next;
}

static void
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

/* ========================================================================== */

static u_int
itemHash (char *key) {
    u_int hash = 0;
    u_int seed = 16777619;

    while (*key) {
        hash *= seed;
        hash ^= (u_int) (*key);
        key++;
    }

    return hash;
}

static hashItemPtr
hashItemLookup (hashTablePtr htbl, char *key, u_int *index) {
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hnode, tmp;

    *index = itemHash (key) % htbl->capacity;
    head = &htbl->heads [*index];

    hlistForEachEntrySafe (item, hnode, tmp, head, node) {
        if (item && strEqual (item->key, key))
            return item;
    }

    return NULL;
}

static int
hashItemInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr item;

    /* First lookup if duplicate key */
    item = hashItemLookup (htbl, key, &index);

    if (item == NULL) {
        item = (hashItemPtr ) malloc (sizeof (hashItem));
        if (item == NULL) {
            fun (data);
            return -1;
        }

        item->data = data;
        item->key = strdup (key);
        if (item->key == NULL) {
            fun (data);
            free (item);
            return -1;
        }
        item->index = index;
        item->fun = fun;

        head = &htbl->heads [index];
        hlistAdd (&item->node, head);
        htbl->size++;
        return 0;
    } else {
        fun (data);
        return -1;
    }
}

static void
hashItemDel (hashTablePtr htbl, hashItemPtr item) {
    /* Delete item from hash list */
    hlistDel (&item->node);

    /* Free item */
    if (item->fun)
        (item->fun) (item->data);
    free (item->key);
    free (item);
    htbl->size--;
}

static int
hashItemAttach (hashTablePtr htbl, hashItemPtr item) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr tmp;

    /* Check hash duplicate key */
    tmp = hashItemLookup (htbl, item->key, &index);

    if (tmp == NULL) {
        item->index = index;
        head = &htbl->heads [index];
        hlistAdd (&item->node, head);
        htbl->size++;
        return 0;
    } else
        return -1;
}


static void
hashItemDetach (hashTablePtr htbl, hashItemPtr item) {
    hlistDel (&item->node);
    htbl->size--;
}

/*
 * @brief Insert new item.
 *        If current size is exceed limit size then recreate a new hash
 *        table and attach all items to new hash table.
 *
 * @param htbl hash table to insert
 * @param key hash key
 * @param data opaque data
 * @param func free function
 *
 * @return 0 if success, else reutrn -1
 */
int
hashInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun) {
    int ret;
    u_int index;
    u_int newMemSize;
    u_int newLimit;
    hashItemPtr item;
    u_int newCapacity, oldCapacity;
    hlistHeadPtr newHeads, oldHeads, head;

    if (key == NULL || data == NULL || fun == NULL)
        return -1;

    if (htbl->size >= htbl->limit) {
        newCapacity = htbl->capacity * HASH_TABLE_RESIZE_FACTOR;
        newLimit = (newCapacity * HASH_TABLE_LOAD_FACTOR) / 100;
        newMemSize = newCapacity * sizeof (hlistHead);

        newHeads = (hlistHeadPtr) malloc (newMemSize);
        if (newHeads == NULL) {
            ret = hashItemInsert (htbl, key, data, fun);
            if (ret < 0)
                return -1;

            return 0;
        }

        for (index = 0; index < newCapacity; index++)
            newHeads [index].first = NULL;

        /* Backup hash table */
        oldCapacity = htbl->capacity;
        oldHeads = htbl->heads;

        /* Update hash table */
        htbl->capacity = newCapacity;
        htbl->limit = newLimit;

        /* Update hash list heads */
        htbl->heads = newHeads;

        /* Attach items to new hash table */
        for (index = 0; index < oldCapacity; index++) {
            head = &oldHeads [index];

            while (head->first) {
                item = hlistEntry (head->first, hashItem, node);

                hashItemDetach (htbl, item);

                ret = hashItemAttach (htbl, item);
                if (ret < 0) {
                    hlistDel (&item->node);
                    if (item->fun)
                        (item->fun) (item->data);
                    free (item->key);
                    free (item);
                }
            }
        }
        /* Destroy old hash list heads */
        free (oldHeads);
    }

    /* Finally, insert hash item */
    ret = hashItemInsert (htbl, key, data, fun);
    if (ret < 0)
        return -1;

    return 0;
}

/*
 * @brief Remove hash item.
 *        Lookup item with key and delete it from hash table.
 *
 * @param htbl hash table
 * @param key hash key.
 *
 * @return 0 if success else -1
 */
int
hashRemove (hashTablePtr htbl, char *key) {
    u_int index;
    hashItemPtr item;

    if (key == NULL)
        return -1;

    item = hashItemLookup (htbl, key, &index);
    if (item == NULL)
        return -1;

    hashItemDel (htbl, item);
    return 0;
}

/*
 * @brief Update item specified key.
 *        Lookup item with key, if key is present then destroy
 *        the old item and insert the new one.
 *
 * @param htbl hash table
 * @param key hash key
 * @param data new opaque data
 * @param fun data free function
 *
 * @return 0 if success else return -1
 */
int
hashUpdate (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun) {
    u_int index;
    hashItemPtr item;

    if (key == NULL || data == NULL || fun == NULL)
        return -1;

    item = hashItemLookup (htbl, key, &index);
    if (item == NULL)
        return hashInsert (htbl, key, data, fun);

    if (item->fun)
        (item->fun) (item->data);
    item->data = data;
    item->fun = fun;
    return 0;
}

/*
 * @brief Lookup hash item.
 *        Lookup hash item with key, if exists return opaque data of it
 *        else return NULL.
 *
 * @param htbl hash table
 * @param key hash key
 *
 * @return opaque data if success, else return NULL;
 */
void *
hashLookup (hashTablePtr htbl, char *key) {
    u_int index;
    hashItemPtr item;

    if (key == NULL)
        return NULL;

    item = hashItemLookup (htbl, key, &index);
    if (item)
        return item->data;
    else
        return NULL;
}

/*
 * @brief Rename hash item key.
 *        Lookup hash item with old key and replace old key with new one.
 *
 * @param htbl hash table
 * @param oldKey old hash key
 * @param newKey new hash key
 *
 * @return 0 if success, else return -1
 */
int
hashRename (hashTablePtr htbl, char *oldKey, char *newKey) {
    int ret;
    u_int index;
    hashItemPtr item;

    if (oldKey == NULL || newKey == NULL)
        return -1;

    item = hashItemLookup (htbl, newKey, &index);
    if (item)
        return -1;

    item = hashItemLookup (htbl, oldKey, &index);
    if (item == NULL)
        return -1;

    hashItemDetach (htbl, item);
    free (item->key);
    item->key = strdup (newKey);
    if (item->key == NULL) {
        if (item->fun)
            (item->fun) (item->data);
        free (item);
        return -1;
    }

    ret = hashItemAttach (htbl, item);
    if (ret < 0) {
        if (item->fun)
            (item->fun) (item->data);
        free (item->key);
        free (item);
        return -1;
    }

    return 0;
}

/*
 * @brief Iterate each item and apply fun to it.
 *
 * @param htbl hash table
 * @param fun callback function
 * @param args arguments of fun
 *
 * @return 0 if success else -1
 */
int
hashLoopDo (hashTablePtr htbl, hashLoopDoCB fun, void *args) {
    int ret;
    u_int index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hnode, tmp;

    if (fun == NULL)
        return -1;

    for (index = 0; index < htbl->capacity; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hnode, tmp, head, node) {
            ret = fun (item->data, args);
            if (ret < 0)
                return -1;
        }
    }

    return 0;
}

/*
 * @brief Iterate each item and remove it when check return ture.
 *        Iterate each item and do remove check, if check return ture then
 *        remove it from hash table else do nothing.
 *
 * @param htbl hash table
 * @param fun check function
 * @param args arguments for check
 */
void
hashLoopCheckToRemove (hashTablePtr htbl, hashLoopCheckToRemoveCB fun, void *args) {
    u_int index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hnode, tmp;

    if (fun == NULL)
        return;

    for (index = 0; index < htbl->capacity; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hnode, tmp, head, node) {
            if (fun (item->data, args))
                hlistDel (&item->node);
        }
    }
}

u_int
hashSize (hashTablePtr htbl) {
    return htbl->size;
}

u_int
hashLimit (hashTablePtr htbl) {
    return htbl->limit;
}

/*
 * @brief Create hash table.
 *        If capacity is 0 then use default hash table size,
 *        else use capacity instead.
 *
 * @param capacity hash table capacity
 *
 * @return hash table if success else NULL
 */
hashTablePtr
hashNew (u_int capacity) {
    u_int i;
    u_int memSize;

    hashTablePtr htbl = (hashTablePtr ) malloc (sizeof (hashTable));
    if (htbl == NULL)
        return NULL;

    htbl->capacity = capacity ? capacity : DEFAULT_HASH_TABLE_CAPACITY;
    htbl->limit = (htbl->capacity * HASH_TABLE_LOAD_FACTOR) / 100;
    htbl->size = 0;

    memSize = htbl->capacity * sizeof (hlistHead);
    htbl->heads = (hlistHeadPtr) malloc (memSize);
    if (htbl->heads == NULL) {
        free (htbl);
        return NULL;
    }
    for (i = 0; i < htbl->capacity; i++)
        htbl->heads [i].first = NULL;

    return htbl;
}

/* Cleanup hash table */
void
hashClean (hashTablePtr htbl) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr item;

    if (!htbl->size)
        return;

    for (index = 0; index < htbl->capacity; index++) {
        head = &htbl->heads [index];
        while (head->first) {
            item = hlistEntry (head->first, hashItem, node);
            hashItemDel (htbl, item);
        }
    }
}

/* Destroy hash table */
void
hashDestroy (hashTablePtr htbl) {
    hashClean (htbl);
    free (htbl->heads);
    free (htbl);
}
