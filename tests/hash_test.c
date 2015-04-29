#include <stdio.h>
#include <assert.h>
#include "util.h"
#include "hash.h"

typedef struct _hItem hItem;
typedef hItem *hItemPtr;

struct _hItem {
    char *key;
    int val;
};

static char *hkey [] = {
    "hash test 1",
    "hash test 2",
    "hash test 3",
    "hash test 4",
    "hash test 5",
    "hash test 6",
    "hash test 7",
    "hash test 8",
    "hash test 9",
    "hash test 10"
};

static void
itemFree (void *data) {
    hItemPtr ptr = (hItemPtr) data;

    free (ptr->key);
    free (ptr);
}

static int
hashLoopDoFun (void *data, void *args) {
    hItem *ptr = (hItem *) data;

    printf ("Hash item key: %s, value: %d\n", ptr->key, ptr->val);
    return 0;
}

static boolean
hashLoopCheckToRemoveFun (void *data, void *args) {
    hItem *ptr = (hItem *) data;

    if (ptr->val == 2)
        return True;
    else
        return False;
}

int main (int argc, char *argv[]) {
    int i, cnt;
    hashTablePtr htbl;
    hItemPtr ptr;

    printf ("HashTest start.\n");

    cnt = TABLE_SIZE (hkey);

    htbl = hashNew (0);
    assert (htbl);

    for (i = 0; i < cnt; i++) {
        ptr = (hItemPtr) malloc (sizeof (hItem));
        assert (ptr);

        ptr->key = strdup (hkey [i]);
        assert (ptr->key);
        ptr->val = i + 1;

        assert (!hashInsert (htbl, ptr->key, ptr, itemFree));
    }
    printf ("Test hashInsert success.\n");

    assert (hashSize (htbl) == cnt);
    printf ("Test hashSize success.\n");

    ptr = (hItemPtr) malloc (sizeof (hItem));
    assert (ptr);

    ptr->key = strdup ("hash test 1 update");
    assert (ptr->key);
    ptr->val = cnt + 1;

    assert (!hashUpdate (htbl, hkey [0], ptr, itemFree));
    printf ("Test hashUpdate success\n");

    ptr = (hItemPtr) hashLookup (htbl, hkey [0]);
    assert (ptr);
    printf ("Test hashLookup success\n");

    assert (!hashRemove (htbl, hkey [0]));
    printf ("Test hashRemove success\n");

    assert (!hashRename (htbl, hkey [1], "hash test 2 new"));
    printf ("Test hashRename success\n");

    assert (!hashLoopDo (htbl, hashLoopDoFun, NULL));
    printf ("Test hashLoopDo success\n");

    hashLoopCheckToRemove (htbl, hashLoopCheckToRemoveFun, NULL);
    assert (hashLookup (htbl, hkey [1]) == NULL);
    printf ("Test hashLoopCheckToRemove success\n");

    hashClean (htbl);
    assert (!hashSize (htbl));
    printf ("Test hashClean success\n");

    hashDestroy (htbl);
    printf ("HashTest [Passed]\n");
    return 0;
}
