#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"
#include "hash.h"

#define DEFAULT_HASH_TABLE_SIZE 331
#define HASH_TABLE_RESIZE_FACTOR 2
#define HASH_TABLE_LOAD_FACTOR 80

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
hashItemLookup (hashTablePtr htbl, char *key, u_int *index) {
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    *index = itemHash (key) % htbl->capacity;
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
hashItemInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB freeFun) {
    u_int index;
    hlistHeadPtr head;
    hashItemPtr item;

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
        htbl->size++;
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
    hlistDel (&item->node);
    if (item->freeFun)
        (item->freeFun) (item->data);
    free (item->key);
    free (item);
    htbl->size--;
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


/*
 * @brief Detach item from hash table.
 *
 * @param htbl hash table to detach
 * @param item item to detach
 */
static void
hashItemDetach (hashTablePtr htbl, hashItemPtr item) {
    hlistDel (&item->node);
    htbl->size--;
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
hashInsert (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun) {
    int ret;
    u_int index;
    u_int newMemSize;
    u_int newLimit;
    hashItemPtr item;
    u_int newCapacity, oldCapacity;
    hlistHeadPtr newHeads, oldHeads, head;

    if ((key == NULL) || (data == NULL) || (fun == NULL))
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
            initHlistHead (&newHeads [index]);

        /* Backup hash table */
        oldCapacity = htbl->capacity;
        oldHeads = htbl->heads;
        /* Update hash table */
        htbl->capacity = newCapacity;
        htbl->limit = newLimit;
        /* Set new head, size, index and limit of hash table */
        htbl->heads = newHeads;
        /* Move items from old hash table to new one */
        for (index = 0; index < oldCapacity; index++) {
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

    ret = hashItemInsert (htbl, key, data, fun);
    if (ret < 0)
        return -1;

    return 0;
}

/*
 * @brief Delete an item with specified key from hash table.
 *
 * @param htbl hash table
 * @param key hash key of item to delete.
 *
 * @return 0 if success else -1
 */
int
hashDel (hashTablePtr htbl, char *key) {
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
hashUpdate (hashTablePtr htbl, char *key, void *data, hashItemFreeCB fun) {
    u_int index;
    hashItemPtr item;

    if ((key == NULL) || (data == NULL) || (fun == NULL))
        return -1;

    item = hashItemLookup (htbl, key, &index);
    if (item == NULL)
        return hashInsert (htbl, key, data, fun);

    if (item->freeFun)
        (item->freeFun) (item->data);
    item->data = data;
    item->freeFun = fun;
    return 0;
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
hashRename (hashTablePtr htbl, char *oldKey, char *newKey) {
    int ret;
    u_int index;
    hashItemPtr item;

    if ((oldKey == NULL) || (newKey == NULL))
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
    }

    return 0;
}

/*
 * @brief Iterate all items in hash table and call fun.
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

    if (fun == NULL)
        return -1;

    for (index = 0; index < htbl->capacity; index++) {
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
 * @brief Iterate all items in hash table and delete item when
 *        hashForEachItemDelInSomeCaseCB return true.
 *
 * @param htbl hash table
 * @param fun callback function
 * @param args arguments for fun
 */
void
hashForEachItemDelInSomeCase (hashTablePtr htbl, hashForEachItemDelInSomeCaseCB fun, void *args) {
    u_int index;
    hashItemPtr item;
    hlistHeadPtr head;
    hlistNodePtr hNode, tmp;

    if (fun == NULL)
        return;

    for (index = 0; index < htbl->capacity; index++) {
        head = & htbl->heads [index];
        hlistForEachEntrySafe (item, hNode, tmp, head, node) {
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

    htbl->size = 0;
    htbl->capacity = capacity ? capacity : DEFAULT_HASH_TABLE_SIZE;
    htbl->limit = (htbl->capacity * HASH_TABLE_LOAD_FACTOR) / 100;

    memSize = htbl->capacity * sizeof (hlistHead);
    htbl->heads = (hlistHeadPtr) malloc (memSize);
    if (htbl->heads == NULL) {
        free (htbl);
        return NULL;
    }
    for (i = 0; i < htbl->capacity; i++)
        initHlistHead (&htbl->heads [i]);

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
