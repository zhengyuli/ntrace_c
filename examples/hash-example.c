#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "hash.h"

static char *hkey[] = {
    "hello",
    "world",
    "you are my apple",
    "fuck",
    "go away",
    "you",
    "go home",
    "i like you",
    "you are not person",
    "fuck you",
    "hash",
    "yesterday",
    "tomorrow",
    "thuesday",
    "friday",
    "sunday",
    "kkkkkkk"
};

typedef struct _hItem hItem;
typedef hItem *hItemPtr;

struct _hItem {
    char *key;
    int val;
};

void itemFree (void *data) {
    hItemPtr ptr = (hItemPtr) data;
    free (ptr->key);
    free (ptr);
}

int forEachItemFun (void *data, void *args) {
    static int count;
    hItem *ptr = (hItem *) data;
    count++;
    printf ("Item value: %d    ", ptr->val);
    printf ("count: %d\n", count);
    return 0;
}

int main (int argc, char *argv[]) {
    int i, cnt;
    hashTablePtr htb;
    hItemPtr ptr;

    cnt = TABLE_SIZE (hkey);
    htb = hashNew (0);

    printf ("current size: %lld\n", (long long) hashSize (htb));

    for (i = 0; i < cnt; i++) {
        ptr = (hItemPtr) malloc (sizeof (hItem));
        ptr->val = i;
        ptr->key = strdup (hkey [i]);
        hashInsert (htb, ptr->key, ptr, itemFree);
    }

    printf ("current size: %lld\n", (long long) hashSize (htb));

    for (i = 0; i < cnt; i++) {
        ptr = (hItemPtr) hashLookup (htb, hkey [i]);
        printf ("hash_key: %s  val= %d\n", ptr->key, ptr->val);
    }


    ptr = (hItemPtr) malloc (sizeof (hItem));
    ptr->val = 1000000;
    ptr->key = strdup ("1234567890");
    hashUpdate (htb, "kkkkkkk", ptr, itemFree);

    ptr = (hItemPtr) hashLookup (htb, "kkkkkkk");
    printf ("hash_key: %s  val= %d\n", ptr->key, ptr->val);


    hashRename (htb, "kkkkkkk", "1234567890");

    printf ("------------------------------------------------------\n");
    ptr = (hItemPtr) hashLookup (htb, "kkkkkkk");
    if (ptr)
        printf ("hash_key: %s  val= %d\n", ptr->key, ptr->val);
    else
        printf ("hask_key: %s doesn't exist\n", "kkkkkkk");

    printf ("------------------------------------------------------\n");
    hashDel (htb, "kkkkkkk");
    hashDel (htb, "hello");
    hashDel (htb, "world");
    hashDel (htb, "hash");
    hashDel (htb, "yesterday");
    for (i = 0; i < cnt; i++) {
        ptr = (hItemPtr) hashLookup (htb, hkey [i]);
        if (ptr)
            printf ("hash_key: %s  val= %d\n", ptr->key, ptr->val);
    }

    for (i = 0; i < 1600000; i++) {
        char buf[20];
        snprintf (buf, 20, "123%d", i);
        ptr = (hItemPtr) malloc (sizeof (hItem));
        ptr->val = i;
        ptr->key = strdup (buf);
        hashInsert (htb, ptr->key, ptr, itemFree);
    }

    printf ("current size: %lld\n", (long long) hashSize (htb));

    printf ("***********************************************************\n");
    for (i = 0; i < cnt; i++)
        hashDel (htb, hkey [i]);

    hashForEachItemDo (htb, forEachItemFun, NULL);
    printf ("***********************************************************\n");

    printf ("current size: %lld\n", (long long) hashSize (htb));
    hashDestroy (&htb);
    return 0;
}
