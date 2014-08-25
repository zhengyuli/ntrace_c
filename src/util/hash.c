#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"
#include "hash.h"

/* Default hash table size */
#define DEFAULT_HASH_TABLE_SIZE 331
#define HASH_TABLE_RESIZE_FACTOR 2
#define HASH_TABLE_LOAD_FACTOR 80

/* Generate index from hash key and hash table size */
static u_int
itemIndex (const char *key, u_int tableSize) {
    u_int hash = 0;
    u_int seed = 16777619;

    while (*key) {
        hash *= seed;
        hash ^= (u_int) (*key);
        key++;
    }

    return (hash % tableSize);
}

/*
 * @brief Lookup hash item by key.
 *
 * @param htbl hash table
 * @param key hash key
 * @param index pointer to return item hash index
 *
 * @return Return hash item if exists else reutrn NULL.
 */
static hashItemPtr
hashItemLookup (hashTablePtr htbl, const char *key, u_int *index) {
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    *index = itemIndex (key, htbl->totalSize);
    head = &htbl->heads [*index];
    hlistForEachEntrySafe (item, hNode, tmp, head, node) {
        if (item && strEqual (item->key, key))
            return item;
    }

    return NULL;
}

/*
 * @brief Insert item to hash table.
 *        It will call freeFun to free opaque data if alloc hash item failed.
 *
 * @param htbl hash table to insert
 * @param key hash key
 * @param data item to insert
 * @param freeFun item free function
 *
 * @return 0 if success else -1
 */
static int
hashItemInsert (hashTablePtr htbl, const char *key, void *data, hashFreeCB freeFun) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr item;

    /* Check item with duplicate key */
    item = hashItemLookup (htbl, key, &index);
    if (item == NULL) {
        item = (hashItemPtr ) malloc (sizeof (hashItem));
        if (item == NULL) {
            freeFun (data);
            return -1;
        }
        item->data = data;
        item->key = strdup (key);
        if (item->key == NULL) {
            freeFun (data);
            free (item);
            return -1;
        }
        item->index = index;
        item->freeFun = freeFun;
        head = &htbl->heads [index];
        hlistAdd (&item->node, head);
        htbl->currSize++;
        return 0;
    } else {
        freeFun (data);
        return -1;
    }
}

/*
 * @brief Delete item from hash table.
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
 * @brief Attach item to hash table.
 *
 * @param htbl hash table to attach
 * @param item item to attach
 *
 * @return 0 if attach success, else return -1
 */
static int
hashItemAttach (hashTablePtr htbl, hashItemPtr item) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr tmp;

    if (item == NULL)
        return -1;

    tmp = hashItemLookup (htbl, item->key, &index);
    if (tmp == NULL) {
        item->index = index;
        head = &htbl->heads [index];
        hlistAdd (&item->node, head);
        htbl->currSize++;
        return 0;
    } else
        return -1;
}


/*
 * @brief Detach item from hash table.
 *
 * @param htbl hash table to detach
 * @param item item to detach
 */
static void
hashItemDetach (hashTablePtr htbl, hashItemPtr item) {
    if (item == NULL)
        return;

    hlistDel (&item->node);
    htbl->currSize--;
}

/*
 * @brief Create a new hash table.
 *        If hashSize is 0 then use default hash table size,
 *        else use hashSize instead.
 *
 * @param hashSize hash table size to create
 *
 * @return new hash table if success else NULL
 */
hashTablePtr
hashNew (u_int hashSize) {
    u_int i;
    u_int memSize;

    hashTablePtr htbl = (hashTablePtr ) malloc (sizeof (hashTable));
    if (htbl) {
        htbl->currSize = 0;
        if (hashSize)
            htbl->totalSize = hashSize;
        else
            htbl->totalSize = DEFAULT_HASH_TABLE_SIZE;
        htbl->limit = (htbl->totalSize * HASH_TABLE_LOAD_FACTOR) / 100;
        memSize = htbl->totalSize * sizeof (hlistHead);
        htbl->heads = (hlistHeadPtr) malloc (memSize);
        if (htbl->heads == NULL) {
            free (htbl);
            return NULL;
        }
        for (i = 0; i < htbl->totalSize; i++)
            INIT_HLIST_HEAD (&htbl->heads [i]);
        return htbl;
    } else
        return NULL;
}

/* Cleanup hash table */
void
hashClean (hashTablePtr htbl) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr item;

    if (htbl == NULL || !htbl->currSize)
        return;

    for (index = 0; index < htbl->totalSize; index++) {
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

/*
 * @brief Insert new item into hash table.
 *        If current size is exceed limit size then recreate a new hash
 *        table and copy all items to the new hash table.
 *
 * @param htbl hash table to insert
 * @param key hash key
 * @param data opaque data
 * @param func free function
 *
 * @return 0 if success, else reutrn -1
 */
int
hashInsert (hashTablePtr htbl, const char *key, void *data, hashFreeCB fun) {
    int ret;
    u_int index;
    u_int newMemSize;
    u_int newLimit;
    hashItemPtr item;
    u_int newTotalSize, oldTotalSize;
    hlistHeadPtr newHeads, oldHeads, head;

    if ((key == NULL) || (data == NULL) || (fun == NULL))
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

        /* Backup hash table */
        oldTotalSize = htbl->totalSize;
        oldHeads = htbl->heads;
        /* Update hash table */
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
    /* Do insert */
    ret = hashItemInsert (htbl, key, data, fun);
    if (ret < 0)
        return -1;
    else
        return 0;
}

/*
 * @brief Update item in hash table with specified key, if key is already
 *        present then destroy the old item and insert the new one.
 *
 * @param htbl hash table
 * @param key hash key string
 * @param data new opaque data
 * @param fun free function
 *
 * @return 0 if success else return -1
 */
int
hashUpdate (hashTablePtr htbl, const char *key, void *data, hashFreeCB fun) {
    u_int index;
    hashItemPtr item;

    if ((key == NULL) || (data == NULL) || (fun == NULL))
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
 * @brief Delete an item with specified key from hash table, if this item
 *        is not exist, then call freeFun to free data.
 *
 * @param htbl hash table
 * @param key hash key of item to delete.
 *
 * @return 0 if success else -1
 */
int
hashDel (hashTablePtr htbl, const char *key) {
    u_int index;
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
 * @param key hash key
 *
 * @return htbl->data if success, else return NULL;
 */
void *
hashLookup (hashTablePtr htbl, const char *key) {
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
 * @brief Reindex an item from oldKey to newKey, if there is no such item,
 *        does nothing, else detach this item and reindex it with the new
 *        key.
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
    u_int index;
    hashItemPtr item;

    if ((oldKey == NULL) || (newKey == NULL))
        return -1;

    item = hashItemLookup (htbl, newKey, &index);
    if (item)
        return -1;

    item = hashItemLookup (htbl, oldKey, &index);
    if (item) {
        hashItemDetach (htbl, item);
        free (item->key);
        item->key = strdup (newKey);
        if (item->key == NULL) {
            if (item->freeFun)
                (item->freeFun) (item->data);
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
 * @brief Return current size of hash table
 *
 * @param htbl hash table
 *
 * @return current size of hash table
 */
inline u_int
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
inline u_int
hashLimit (hashTablePtr htbl) {
    return htbl->limit;
}

/*
 * @brief Search all items in hash table and call fun.
 *
 * @param htbl hash table
 * @param fun callback function
 * @param args arguments for fun
 *
 * @return 0 if success else -1
 */
int
hashForEachItemDo (hashTablePtr htbl, hashForEachItemDoCB fun, void *args) {
    int ret;
    u_int index;
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
 * @brief Search all items in hash table and remove items if remove condition
 *        match.
 *
 * @param htbl hash table
 * @param fun remove condition check fun
 * @param args arguments for fun
 */
void
hashForEachItemRemoveWithCondition (hashTablePtr htbl, hashForEachItemRemoveWithConditionCB fun, void *args) {
    BOOL ret;
    u_int index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    if (htbl == NULL)
        return;

    for (index = 0; index < htbl->totalSize; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hNode, tmp, head, node) {
            ret = fun (item->data, args);
            if (ret)
                hashItemDel (htbl, item);
        }
    }
}

/*
 * @brief Lookup hash table and find the first item which check success.
 *
 * @param htbl hash table
 * @param fun check function
 * @param args arguments for fun
 *
 * @return The first item if success else NULL
 */
void *
hashForEachItemCheck (hashTablePtr htbl, hashForEachItemCheckCB fun, void *args) {
    void *ret;
    u_int index;
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
