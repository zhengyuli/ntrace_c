#include <stdio.h>
#include <stdlib.h>
#include "list.h"

typedef struct _container container;
typedef container *containerPtr;

struct _container {
    int val;
    listHead node;
};

static LIST_HEAD (head);
static LIST_HEAD (headReverse);

int main (int argc, char *argv[]) {
    int i;
    containerPtr cp1, cp2, cp;
    listHeadPtr pos;
    for (i = 0; i < 100; i++) {
        cp1 = malloc (sizeof (container));
        cp2 = malloc (sizeof (container));
        cp1->val = i;
        cp2->val = i;
        listAdd (&cp1->node, &head);
        listAddTail (&cp2->node, &headReverse);
    }

    i = 0;
    listForEach (pos, &head) {
        i++;
        cp1 = listEntry (pos, container, node);
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("-------------------------------------------------------------------------------------\n");
    listHeadPtr listPtr;
    listPtr = head.next;
    listDel (head.next);
    listAddTail (listPtr, &head);
    listPtr = head.next;
    listDel (head.next);
    listAddTail (listPtr, &head);
    listPtr = head.next;
    listDel (head.next);
    listAddTail (listPtr, &head);
    listPtr = head.next;
    listDel (head.next);
    listAddTail (listPtr, &head);
    listForEach (pos, &head) {
        i++;
        cp1 = listEntry (pos, container, node);
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }
    printf ("-------------------------------------------------------------------------------------\n");

    i = 0;
    printf ("\n\n");
    listForEach (pos, &headReverse) {
        i++;
        cp1 = listEntry (pos, container, node);
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");

    i = 0;
    listForEachEntry (cp1, &head, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");


    i = 0;
    listForEachEntryReverse (cp1, &headReverse, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");

    i = 0;
    listForEachEntrySafe (cp1, cp, &head, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");


    i = 0;
    listForEachEntrySafeReverse (cp1, cp, &headReverse, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");

    i = 0;
    cp1 = listEntry (head.next->next->next, container, node);
    listForEachEntryFromReverse (cp1, &head, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");


    i = 0;
    cp1 = listEntry (head.next->next->next, container, node);
    listForEachEntrySafeFromReverse (cp1, cp, &head, node) {
        i++;
        printf ("%d ", cp1->val);
        if ((i % 10) == 0)
            printf ("\n");
    }

    printf ("\n");

    return 0;
}
