#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>
#include "util.h"

typedef struct _listHead listHead;
typedef listHead *listHeadPtr;

struct _listHead {
    listHeadPtr prev;
    listHeadPtr next;
};

static inline void
initListHead (listHeadPtr head) {
    head->prev = head;
    head->next = head;
}

/* ======================================================================================== */

#define listEntry(pos, type, member) ({                                 \
            typeof (((type *) 0)->member) *mptr = (pos);                \
            (type *) ((u_char *) mptr - ((size_t) &((type *) 0)->member)); \
        })

#define listHeadEntry(head, type, member) ({                    \
            type *entry;                                        \
            if (listIsEmpty (head))                             \
                entry = NULL;                                   \
            else                                                \
                entry = listEntry ((head)->next, type, member); \
            entry;                                              \
        })

#define listTailEntry(head, type, member) ({                    \
            type *entry;                                        \
            if (listIsEmpty (head))                             \
                entry = NULL;                                   \
            else                                                \
                entry = listEntry ((head)->prev, type, member); \
            entry;                                              \
        })

#define listForEachEntry(entry, pos, head, member)                       \
    for ((entry) = NULL, (pos) = (head)->next;                           \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (pos)->next)

#define listForEachEntryKeepPrev(prevEntry, entry, pos, head, member)          \
    for ((prevEntry) = NULL, (entry) = NULL, (pos) = (head)->next;            \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (prevEntry) = (entry), (pos) = (pos)->next)

#define listForEachEntrySafe(entry, pos, npos, head, member)              \
    for ((entry) = NULL, (pos) = (head)->next;                           \
         (pos) != (head) && ({(npos) = (pos)->next; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (npos))

#define listForEachEntrySafeKeepPrev(prevEntry, entry, pos, npos, head, member) \
    for ((prevEntry) = NULL, (entry) = NULL, (pos) = (head)->next;            \
         (pos) != (head) && ({(npos) = (pos)->next; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (prevEntry) = (entry), (pos) = (npos))

#define listForEachEntryReverse(entry, pos, head, member)                \
    for ((entry) = NULL, (pos) = (head)->prev;                           \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (pos)->prev)

#define listForEachEntryReverseKeepPrev(prevEntry, entry, pos, head, member)          \
    for ((prevEntry) = NULL, (entry) = NULL, (pos) = (head)->prev;            \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (prevEntry) = (entry), (pos) = (pos)->prev)

#define listForEachEntryReverseSafe(entry, pos, ppos, head, member)              \
    for ((entry) = NULL, (pos) = (head)->prev;                           \
         (pos) != (head) && ({(ppos) = (pos)->prev; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (ppos))

#define listForEachEntryReverseSafeKeepPrev(prevEntry, entry, pos, ppos, head, member) \
    for ((prevEntry) = NULL, (entry) = NULL, (pos) = (head)->prev;            \
         (pos) != (head) && ({(ppos) = (pos)->prev; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (prevEntry) = (entry), (pos) = (ppos))

#define listForEachEntryFrom(entry, pos, head, member)                   \
    for ((entry) = NULL;                                             \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (pos)->next)

#define listForEachEntryFromSafe(entry, pos, npos, head, member)          \
    for ((entry) = NULL;                                             \
         (pos) != (head) && ({(npos) = (pos)->next; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (npos))

#define listForEachEntryFromReverse(entry, pos, head, member)                   \
    for ((entry) = NULL;                                             \
         (pos) != (head) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (pos)->prev)

#define listForEachEntryFromReverseSafe(entry, pos, ppos, head, member)          \
    for ((entry) = NULL;                                             \
         (pos) != (head) && ({(ppos) = (pos)->next; 1;}) && ({(entry) = listEntry ((pos), typeof (*(entry)), member); 1;}); \
         (pos) = (ppos))

/* ======================================================================================== */

/* Add an item to the head of the list */
static inline void
listAdd (listHeadPtr new, listHeadPtr head) {
    new->prev = head;
    new->next = head->next;
    (head->next)->prev = new;
    head->next = new;
}

/* Aadd an item to the tail of the list */
static inline void
listAddTail (listHeadPtr new, listHeadPtr head) {
    listAdd (new, head->prev);
}

/* Delete an item from list */
static inline void
listDel (listHeadPtr node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
}

/* Check list size */
static inline boolean
listIsEmpty (const listHeadPtr head) {
    if (head->next == head)
        return True;
    else
        return False;
}

#endif /* __LIST_H__ */
