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

#define LIST_HEAD(head)                         \
    listHead head = {&(head), &(head)}

static inline void
initListHead (listHeadPtr head) {
    head->prev = head;
    head->next = head;
}

/* Insert new node after head */
static inline void
listAdd (listHeadPtr new, listHeadPtr head) {
    new->prev = head;
    new->next = head->next;
    (head->next)->prev = new;
    head->next = new;
}

/* Add new node before nodeNext. */
static inline void
listAddBefore (listHeadPtr new, listHeadPtr nodeNext) {
    nodeNext->prev->next = new;
    new->next = nodeNext;
    new->prev = nodeNext->prev;
    nodeNext->prev = new;
}

/* Insert new node to the tail */
static inline void
listAddTail (listHeadPtr new, listHeadPtr head) {
    listAdd (new, head->prev);
}

/* Delete node from list */
static inline void
listDel (listHeadPtr node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
}

/* Replace old node with new one. */
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

/* Check whether node is the tail node of list.  */
static inline boolean
listIsTail (const listHeadPtr node, const listHeadPtr head) {
    if (node->next == head)
        return true;
    else
        return false;
}

/* Check whether list is empty */
static inline boolean
listIsEmpty (const listHeadPtr head) {
    if (head->next == head)
        return true;
    else
        return false;
}

/* Get offset of member in type */
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

#define listForEachEntryKeepPrev(prev, pos, head, member)               \
    for (prev = NULL,                                                   \
          pos = listEntry ((head)->next, typeof (*pos), member);        \
         &pos->member != (head);                                        \
         prev = pos, pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntrySafe(pos, tmp, head, member)                    \
    for (pos = listEntry ((head)->next, typeof (*pos), member),         \
         tmp = listEntry (pos->member.next, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = tmp, tmp = listEntry (tmp->member.next, typeof (*tmp), member))

#define listForEachEntrySafeKeepPrev(prev, pos, tmp, head, member)      \
     for (prev = NULL,                                                  \
          pos = listEntry ((head)->next, typeof (*pos), member),        \
          tmp = listEntry (pos->member.next, typeof (*pos), member);    \
          &pos->member != (head);                                       \
          prev = pos, pos = tmp, tmp = listEntry (tmp->member.next, typeof (*tmp), member))

#define listForEachEntryReverse(pos, head, member)                  \
    for (pos = listEntry ((head)->prev, typeof (*pos), member);     \
         &pos->member != (head);                                    \
         pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntryReverseKeepPrev(prev, pos, head, member)        \
    for (prev = NULL,                                                   \
          pos = listEntry ((head)->prev, typeof (*pos), member);        \
         &pos->member != (head);                                        \
         prev = pos, pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntryReverseSafe(pos, tmp, head, member)             \
    for (pos = listEntry ((head)->prev, typeof (*pos), member),         \
         tmp = listEntry (pos->member.prev, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = tmp, tmp = listEntry (tmp->member.prev, typeof (*tmp), member))

#define listForEachEntryReverseSafeKeepPrev(prev, pos, tmp, head, member) \
    for (prev = NULL,                                                   \
          pos = listEntry ((head)->prev, typeof (*pos), member),        \
          tmp = listEntry (pos->member.prev, typeof (*pos), member);    \
         &pos->member != (head);                                        \
         prev = pos, pos = tmp, tmp = listEntry (tmp->member.prev, typeof (*tmp), member))

#define listForEachEntryFrom(pos, head, member)                     \
    for (; &pos->member != (head);                                  \
         pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntryFromSafe(pos, tmp, head, member)                \
    for (tmp = listEntry (pos->member.next, typeof (*pos), member); \
         &pos->member != (head);                                    \
         pos = tmp, tmp = listEntry (tmp->member.next, typeof (*tmp), member))

#define listForEachEntryFromReverse(pos, head, member)                  \
    for (; &pos->member != (head);                                      \
         pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntryFromReverseSafe(pos, tmp, head, member)         \
    for ( tmp = listEntry (pos->member.prev, typeof (*pos), member);    \
          &pos->member != (head);                                       \
          pos = tmp, tmp = listEntry (tmp->member.prev, typeof (*tmp), member))

#endif /* __LIST_H__ */
