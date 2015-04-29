#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "list.h"

typedef struct _container container;
typedef container *containerPtr;

struct _container {
    int val;
    listHead node;
};

int
main (int argc, char *argv[]) {
    int i;
    listHead head, headReverse;
    containerPtr cp, pcp;
    listHeadPtr pos, npos;

    printf ("ListTest start.\n");

    initListHead (&head);
    initListHead (&headReverse);

    cp = (containerPtr) malloc (sizeof (container));
    assert (cp);
    assert (listEntry (&cp->node, container, node));
    printf ("Test listEntry success.\n");

    for (i = 0; i < 10000; i++) {
        cp = malloc (sizeof (container));
        assert (cp);
        cp->val = i + 1;
        listAdd (&cp->node, &head);

        cp = malloc (sizeof (container));
        assert (cp);
        cp->val = i + 1;
        listAddTail (&cp->node, &headReverse);
    }

    cp = listHeadEntry (&head, container, node);
    assert (cp->val == 10000);
    printf ("Test listHeadEntry success.\n");

    cp = listHeadEntry (&head, container, node);
    assert (cp->val == 10000);
    printf ("Test listTailEntry success.\n");

    i = 0;
    listForEachEntry (cp, pos, &head, node) {
        assert (cp->val == (10000 - i));
        i++;
    }
    assert (i == 10000);

    i = 0;
    listForEachEntry (cp, pos, &headReverse, node) {
        i++;
        assert (cp->val == i);
    }
    assert (i == 10000);
    printf ("Test listForEachEntry success.\n");

    i = 0;
    listForEachEntryKeepPrev (pcp, cp, pos, &head, node) {
        i++;
        if (pcp)
            assert (pcp->val == (cp->val + 1));
    }
    assert (i == 10000);

    i = 0;
    listForEachEntryKeepPrev (pcp, cp, pos, &headReverse, node) {
        i++;
        if (pcp)
            assert (pcp->val == (cp->val - 1));
    }
    assert (i == 10000);
    printf ("Test listForEachEntryKeepPrev success.\n");

    i = 0;
    listForEachEntryReverse (cp, pos, &head, node) {
        i++;
        assert (cp->val == i);
    }
    assert (i == 10000);

    i = 0;
    listForEachEntryReverse (cp, pos, &headReverse, node) {
        assert (cp->val == (10000 - i));
        i++;
    }
    assert (i == 10000);
    printf ("Test listForEachEntryReverse success.\n");

    i = 0;
    listForEachEntryReverseKeepPrev (pcp, cp, pos, &head, node) {
        i++;
        if (pcp)
            assert (pcp->val == (cp->val - 1));
    }
    assert (i == 10000);

    i = 0;
    listForEachEntryReverseKeepPrev (pcp, cp, pos, &headReverse, node) {
        i++;
        if (pcp)
            assert (pcp->val == (cp->val + 1));
    }
    assert (i == 10000);
    printf ("Test listForEachEntryReverseKeepPrev success.\n");

    listForEachEntrySafe (cp, pos, npos, &head, node) {
        listDel (&cp->node);
        free (cp);
    }
    assert (listIsEmpty (&head));

    listForEachEntrySafe (cp, pos, npos, &headReverse, node) {
        listDel (&cp->node);
        free (cp);
    }
    assert (listIsEmpty (&headReverse));
    printf ("Test listForEachEntrySafe success.\n");
    printf ("Test listDel success.\n");

    printf ("ListTest [Passed]\n");
    return 0;
}
