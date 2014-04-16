#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"
#include "hash.h"

/* Initial index of hash size table */
#define HASH_TABLE_INIT_SIZE 331
#define HASH_TABLE_RESIZE_FACTOR 2
/* Load factor of hash table */
#define HASH_TABLE_LOAD_FACTOR 80

/*
 * @brief Generate hash number from hash key and hash table size.
 *
 * @param key hash key to generate hash value
 * @param tableSize hash table size
 *
 * @return hash number
 */
static size_t
itemHash (const char *key, size_t tableSize) {
    size_t hash = 0;
    size_t seed = 16777619;

    while (*key) {
        hash *= seed;
        hash ^= (size_t) (*key);
        key++;
    }

    return (hash % tableSize);
}

/*
 * @brief Lookup the corresponding item, if not exits return null,
 *        else return it.
 *
 * @param htbl hash table
 * @param key hash key
 * @param hash return hash number
 *
 * @return Return hash item if exists, else reutrn NULL.
 */
static hashItemPtr
hashItemLookup (hashTablePtr htbl, const char *key, size_t *hash) {
    size_t index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    index = itemHash (key, htbl->totalSize);
    *hash = index;
    head = &htbl->heads [index];
    hlistForEachEntrySafe (item, hNode, tmp, head, node) {
        if (item && STREQ (item->key, key))
            return item;
    }

    return NULL;
}

/*
 * @brief Insert item to hash table.
 *
 * @param htbl hash table to insert
 * @param key hash key
 * @param data item to insert
 * @param fun item free function
 *
 * @return 0 if success else -1
 */
static int
hashItemInsert (hashTablePtr htbl, const char *key, void *data, hashFreeFun freeFun) {
    size_t index;
    hlistHeadPtr head;
    hashItemPtr item;

    /* Check that if there is a item with the same key */
    item = hashItemLookup (htbl, key, &index);
    if (item == NULL) {
        item = (hashItemPtr ) malloc (sizeof (hashItem));
        if (!item) {
            /* Free memory */
            freeFun (data);
            return -1;
        }
        item->data = data;
        item->key = strdup (key);
        item->index = index;
        item->freeFun = freeFun;
        head = &htbl->heads [index];
        hlistAddHead (&item->node, head);
        htbl->currSize++;
        return 0;
    } else {
        freeFun (data);
        return -1;
    }
}

/*
 * @brief Delete an item from hash table.
 *
 * @param htbl hash table
 * @param item item to delete
 */
static void
hashItemDel (hashTablePtr htbl, hashItemPtr item) {
    if (item == NULL)
        return;

    hlistDel (&item->node);
    if (item->freeFun)
        (item->freeFun) (item->data);
    free (item->key);
    free (item);
    htbl->currSize--;
}

/*
 * @brief Attach an item detached from old hash table to the
 *        the new hash table.
 *
 * @param htbl hash table to insert
 * @param item item to attach
 *
 * @return 0 if attach success, else return -1
 */
static int
hashItemAttach (hashTablePtr htbl, hashItemPtr item) {
    hlistHeadPtr head;
    size_t index;
    hashItemPtr tmp;

    if (item == NULL)
        return -1;

    tmp = hashItemLookup (htbl, item->key, &index);
    if (tmp == NULL) {
        item->index = index;
        head = &htbl->heads [index];
        hlistAddHead (&item->node, head);
        htbl->currSize++;
        return 0;
    } else
        return -1;
}


/*
 * @brief Detach item from hash list.
 *
 * @param htbl hash table to delete detach
 * @param item item to detach
 */
static void
hashItemDetach (hashTablePtr htbl, hashItemPtr item) {
    if (item == NULL)
        return;

    hlistDel (&item->node);
    htbl->currSize--;
}

/* Create a new hash table */
/*
 * @brief Create a new hash table, if hashSize is 0 then use
 *        default hash table init size, else use hashSize instead.
 *
 * @param hashSize hash table size to create
 *
 * @return new hash table if success else NULL
 */
hashTablePtr
hashNew (u_int hashSize) {
    int i;
    size_t memSize;

    hashTablePtr htbl = (hashTablePtr ) malloc (sizeof (hashTable));
    if (htbl) {
        htbl->currSize = 0;
        if (hashSize)
            htbl->totalSize = hashSize;
        else
            htbl->totalSize = HASH_TABLE_INIT_SIZE;
        htbl->limit = (htbl->totalSize * HASH_TABLE_LOAD_FACTOR) / 100;
        memSize = htbl->totalSize * sizeof (hlistHead);
        htbl->heads = (hlistHeadPtr ) malloc (memSize);
        if (htbl->heads == NULL) {
            free (htbl);
            return NULL;
        } else {
            for (i = 0; i < htbl->totalSize; i++)
                INIT_HLIST_HEAD (&htbl->heads [i]);
            return htbl;
        }
    } else
        return NULL;
}

/* Destroy hash table */
void
hashDestroy (hashTablePtr *htblPtr) {
    size_t index;
    hlistHeadPtr head;
    hashTablePtr htbl;
    hashItemPtr item;

    if (htblPtr == NULL || *htblPtr == NULL)
        return;

    htbl = *htblPtr;
    for (index = 0; index < htbl->totalSize; index++) {
        head = &htbl->heads [index];
        while (head->first) {
            item = hlistEntry (head->first, hashItem, node);
            hashItemDel (htbl, item);
        }
    }
    free (htbl->heads);
    free (htbl);
    *htblPtr = NULL;
}

/*
 * @brief Insert a new item into hash table, if current size is over
 *        then recreate a new hash table and copy all items to new hash table.
 *
 * @param htbl hash table
 * @param key hash key to insert
 * @param data opaque data
 * @param func free function provided by user
 *
 * @return 0 if success, else reutrn -1
 */
int
hashInsert (hashTablePtr htbl, const char *key, void *data, hashFreeFun fun) {
    int ret;
    size_t index;
    size_t newMemSize;
    size_t newLimit;
    hashItemPtr item;
    size_t newTotalSize, oldTotalSize;
    hlistHeadPtr newHeads, oldHeads, head;

    if (key == NULL || data == NULL || !fun)
        return -1;

    if (htbl->currSize >= htbl->limit) {
        newTotalSize = htbl->totalSize * HASH_TABLE_RESIZE_FACTOR;
        newLimit = (newTotalSize * HASH_TABLE_LOAD_FACTOR) / 100;
        newMemSize = newTotalSize * sizeof (hlistHead);
        newHeads = (hlistHeadPtr) malloc (newMemSize);
        if (newHeads == NULL) {
            ret = hashItemInsert (htbl, key, data, fun);
            if (ret < 0)
                return -1;
            else
                return 0;
        }

        for (index = 0; index < newTotalSize; index++)
            INIT_HLIST_HEAD (&newHeads [index]);

        /* remap items in the old hash table */
        oldTotalSize = htbl->totalSize;
        oldHeads = htbl->heads;

        htbl->totalSize = newTotalSize;
        htbl->limit = newLimit;
        /* Set new head, size, index and limit of hash table */
        htbl->heads = newHeads;
        /* Move items from old hash table to new one */
        for (index = 0; index < oldTotalSize; index++) {
            head = &oldHeads [index];
            while (head->first) {
                item = hlistEntry (head->first, hashItem, node);
                hashItemDetach (htbl, item);
                ret = hashItemAttach (htbl, item);
                if (ret < 0) {
                    hlistDel (&item->node);
                    if (item->freeFun)
                        (item->freeFun) (item->data);
                    free (item->key);
                    free (item);
                }
            }
        }
        /* Destroy old hash table heads */
        free (oldHeads);
    }
    /* Insert new hash node */
    ret = hashItemInsert (htbl, key, data, fun);
    if (ret < 0)
        return -1;
    else
        return 0;
}

/*
 * @brief Update item in hash table with specified key,
 *        if key is already present then destroy the old
 *        item and insert the new one.
 *
 * @param htbl hash table
 * @param key hash key string
 * @param data new opaque data
 * @param fun free function
 *
 * @return 0 if success else return -1
 */
int
hashUpdate (hashTablePtr htbl, const char *key, void *data, hashFreeFun fun) {
    size_t index;
    hashItemPtr item;

    if (htbl == NULL || key == NULL)
        return -1;

    if (data && !fun)
        return -1;

    item = hashItemLookup (htbl, key, &index);
    if (item) {
        if (item->freeFun)
            (item->freeFun) (item->data);
        item->data = data;
        item->freeFun = fun;
        return 0;
    } else
        return hashInsert (htbl, key, data, fun);
}

/*
 * @brief Delete an item with specified key from hash table,
 *        if this item is not exist, then call freeFun to free data
 *
 * @param htbl hash table
 * @param key hash key of item to delete.
 *
 * @return 0 if success else -1
 */
int
hashDel (hashTablePtr htbl, const char *key) {
    size_t index;
    hashItemPtr item;

    if (key == NULL)
        return -1;

    item = hashItemLookup (htbl, key, &index);
    if (item) {
        hashItemDel (htbl, item);
        return 0;
    } else
        return -1;
}

/*
 * @brief Lookup hash item with specified hash key, if exists
 *        return htbl->data, else return NULL
 *
 * @param htbl hash table
 * @param key hash key to search
 *
 * @return htbl->data if success, else return NULL;
 */
void *
hashLookup (hashTablePtr htbl, const char *key) {
    size_t index;
    hashItemPtr item;

    if (htbl == NULL || key == NULL)
        return NULL;

    item = hashItemLookup (htbl, key, &index);
    if (item)
        return item->data;
    else
        return NULL;
}

/*
 * @brief Reindex an item from oldKey to newKey, if there is
 *        no such item, does nothing, else detach this item and
 *        reindex it wiht the new key.
 *
 * @param htbl hash table
 * @param oldKey the old key
 * @param newKey the new key
 *
 * @return 0 if success, else return -1
 */
int
hashRename (hashTablePtr htbl, const char *oldKey, const char *newKey) {
    int ret;
    size_t index;
    hashItemPtr item;

    if (oldKey == NULL || NULL == newKey)
        return -1;

    /* if there is a item with the newKey, reutrn
     * -1, else rename the item with the newKey
     */
    item = hashItemLookup (htbl, newKey, &index);
    if (item)
        return -1;

    item = hashItemLookup (htbl, oldKey, &index);
    if (item) {
        hashItemDetach (htbl, item);
        free (item->key);
        item->key = strdup (newKey);
        /* If strdup new hash key failed then free item */
        if (item->key == NULL) {
            if (item->freeFun)
                (item->freeFun) (item->data);
            free (item->key);
            free (item);
            return -1;
        }
        ret = hashItemAttach (htbl, item);
        if (ret < 0) {
            if (item->freeFun)
                (item->freeFun) (item->data);
            free (item->key);
            free (item);
            return -1;
        } else
            return 0;
    } else
        return -1;
}

/*
 * @brief return current items of hash table
 *
 * @param htbl hash table
 *
 * @return count of current items
 */
inline size_t
hashSize (hashTablePtr htbl) {
    return htbl->currSize;
}

/*
 * @brief return hash table limit
 *
 * @param htbl hash table
 *
 * @return current limit size
 */
inline size_t
hashLimit (hashTablePtr htbl) {
    return htbl->limit;
}

/*
 * @brief for each item in hash table call fun
 *
 * @param htbl hash table
 * @param fun callback function
 *
 * @return 0 if success else -1
 */
int
hashForEachItemDo (hashTablePtr htbl, hashForEachItemDoFun fun, void *args) {
    int ret;
    size_t index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    if (htbl == NULL)
        return -1;

    for (index = 0; index < htbl->totalSize; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hNode, tmp, head, node) {
            ret = fun (item->data, args);
            if (ret < 0)
                return -1;
        }
    }

    return 0;
}

/*
 * @brief Delete items from hash table if fun return non zero
 *
 * @param htbl hash table
 * @param fun check fun
 * @param args arguments for check fun
 */
void
hashForEachItemDelIf (hashTablePtr htbl, hashForEachItemDelIfFun fun, void *args) {
    size_t index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    if (htbl == NULL)
        return;

    for (index = 0; index < htbl->totalSize; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hNode, tmp, head, node) {
            if (fun (item->data, args))
                hashItemDel (htbl, item);
        }
    }
}

/*
 * @brief Lookup hash map and find the first item which
 *        check success.
 *
 * @param htbl hash map to search
 * @param fun check function
 * @param data arguments
 *
 * @return the first item if success else NULL
 */
void *
hashForEachItemCheck (hashTablePtr htbl, hashForEachItemCheckFun fun, void *args) {
    void *ret;
    size_t index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    for (index = 0; index < htbl->totalSize; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hNode, tmp, head, node) {
            ret = fun (item->data, args);
            if (ret)
                return ret;
        }
    }
    return NULL;
}
