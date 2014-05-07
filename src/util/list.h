#ifndef __AGENT_LIST_H__
#define __AGENT_LIST_H__

#include <stddef.h>
#include "util.h"

typedef struct _listHead listHead;
typedef listHead *listHeadPtr;

struct _listHead {
    listHeadPtr prev;
    listHeadPtr next;
};

#define LIST_HEAD(head)                         \
    listHead head = {&(head), &(head)}

static inline void
initListHead (listHeadPtr head) {
    head->prev = head;
    head->next = head;
}

/*
 * @brief Insert the new entry after head, the head entry can be
 *        the head of list or any entries in the list
 *
 * @param new the new entry
 * @param head the head node to be inserted after
 */
static inline void
listAdd (listHeadPtr new, listHeadPtr head) {
    new->prev = head;
    new->next = head->next;
    (head->next)->prev = new;
    head->next = new;
}

/*
 * @brief Add node before nodeNext
 *
 * @param node node to add
 * @param nodeNext node to add before
 */
static inline void
listAddBefore (listHeadPtr node, listHeadPtr nodeNext) {
    nodeNext->prev->next = node;
    node->next = nodeNext;
    node->prev = nodeNext->prev;
    nodeNext->prev = node;
}

/* Insert the new entry to the end of list */
static inline void
listAddTail (listHeadPtr new, listHeadPtr head) {
    listAdd (new, head->prev);
}

/*
 * @brief Delete entry from list
 *
 * @param entry the element to delete
 */
static inline void
listDel (listHeadPtr entry) {
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->next = entry;
    entry->prev = entry;
}

/*
 * @brief Replace the old element with the new entry
 *
 * @param old the element to be replaced
 * @param new the new element to replace
 */
static inline void
listReplace (listHeadPtr old, listHeadPtr new) {
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
    /* Detach it from list */
    old->next = old;
    old->prev = old;
}

static inline BOOL
listIsLast (const listHeadPtr entry, const listHeadPtr head) {
    if (entry->next == head)
        return TRUE;
    else
        return FALSE;
}

static inline BOOL
listIsEmpty (const listHeadPtr head) {
    if (head->next == head)
        return TRUE;
    else
        return FALSE;
}

/* Offset of member in type */
#define offsetOfMember(type, member)            \
    ((size_t) &((type *) 0)->member)

/*
 * Cast a member of a structure out to the containing structure, for
 * macro definition,it uses {...} and ({...}) to describe compound
 * expressions but ({...}) has the same effect as comma expression and
 * return the result of the last expression
 */
#define containerOfMember(pos, type, member) ({                         \
            const typeof (((type *) 0)->member) *mptr = (pos);          \
            (type *) ((u_char *) mptr - offsetOfMember (type, member));})

#define listEntry(pos, type, member)            \
    containerOfMember (pos, type, member)

#define listForEach(pos, head)                                  \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define listForEachReverse(pos, head)                           \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define listFirstEntry(pos, head, member) ({                            \
            if (listIsEmpty (head))                                     \
                pos = NULL;                                             \
            else                                                        \
                pos = listEntry ((head)->next, typeof (*pos), member);})

#define listTailEntry(pos, head, member) ({                             \
            if (listIsEmpty (head))                                     \
                pos = NULL;                                             \
            else                                                        \
                pos = listEntry ((head)->prev, typeof (*pos), member);})

#define listForEachEntry(pos, head, member)                         \
    for (pos = listEntry ((head)->next, typeof (*pos), member);     \
         &pos->member != (head);                                    \
         pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntrySafe(pos, tmp, head, member)                      \
    for (pos = listEntry ((head)->next, typeof (*pos), member),         \
         tmp = listEntry (pos->member.next, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = tmp, tmp = listEntry (tmp->member.next, typeof (*tmp), member))

#define listForEachEntryKeepPrev(prev, pos, head, member)               \
    for (prev = listEntry (head, typeof (*pos), member),                \
          pos = listEntry ((head)->next, typeof (*pos), member);        \
         &pos->member != (head);                                        \
         prev = pos, pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntryReverse(pos, head, member)                      \
        for (pos = listEntry ((head)->prev, typeof (*pos), member);     \
             &pos->member != (head);                                    \
             pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntryReverseSafe(pos, tmp, head, member)               \
    for (pos = listEntry ((head)->prev, typeof (*pos), member),         \
         tmp = listEntry (pos->member.prev, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = tmp, tmp = listEntry (tmp->member.prev, typeof (*tmp), member))

#define listForEachEntryFrom(pos, head, member)                     \
    for (; &pos->member != (head);                                  \
         pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntryFromSafe(pos, tmp, head, member)                  \
    for (tmp = listEntry (pos->member.next, typeof (*pos), member);       \
         &pos->member != (head);                                        \
         pos = tmp, tmp = listEntry (tmp->member.next, typeof (*tmp), member))

#define listForEachEntryFromReverse(pos, head, member)              \
    for (; &pos->member != (head);                                  \
         pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntryFromReverseSafe(pos, tmp, head, member)           \
    for ( tmp = listEntry (pos->member.prev, typeof (*pos), member);      \
          &pos->member != (head);                                       \
          pos = tmp, tmp = listEntry (tmp->member.prev, typeof (*tmp), member))

#endif /* __AGENT_LIST_H__ */
