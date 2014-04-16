#ifndef __WDM_AGENT_LIST_H__
#define __WDM_AGENT_LIST_H__

#include <stddef.h>

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
 * @brief insert the new entry after head, the head entry can be
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
 * @brief add node before nodeNext
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

/* insert the new entry to the end of list */
static inline void
listAddTail (listHeadPtr new, listHeadPtr head) {
    listAdd (new, head->prev);
}

/*
 * @brief delete entry from list
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
 * @brief replace the old element with the new entry
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
    /* detach it from list */
    old->next = old;
    old->prev = old;
}

static inline int
listIsLast (const listHeadPtr entry, const listHeadPtr head) {
    return (entry->next == head);
}

static inline int
listIsEmpty (const listHeadPtr head) {
    return (head->next == head);
}

/* offset of member in type */
#define offsetOfMember(type, member)            \
    ((size_t)&((type *)0)->member)

/*
 * cast a member of a structure out to the containing structure, for
 * macro definition,it uses {...} and ({...}) to describe compound
 * expressions but ({...}) has the same effect as comma expression and
 * return the result of the last expression
 */
#define containerOfMember(pos, type, member) ({                         \
            const typeof (((type *) 0)->member) *mptr = (pos);          \
            (type *) ((char *) mptr - offsetOfMember (type, member));})

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

#define listForEachEntrySafe(pos, n, head, member)                      \
    for (pos = listEntry ((head)->next, typeof (*pos), member),         \
           n = listEntry (pos->member.next, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = n, n = listEntry (n->member.next, typeof (*n), member))

#define listForEachEntryKeepPrev(prev, pos, head, member)               \
    for (prev = listEntry (head, typeof (*pos), member),                \
          pos = listEntry ((head)->next, typeof (*pos), member);        \
         &pos->member != (head);                                        \
         prev = pos, pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntryReverse(pos, head, member)                      \
        for (pos = listEntry ((head)->prev, typeof (*pos), member);     \
             &pos->member != (head);                                    \
             pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntrySafeReverse(pos, n, head, member)               \
    for (pos = listEntry ((head)->prev, typeof (*pos), member),         \
           n = listEntry (pos->member.prev, typeof (*pos), member);     \
         &pos->member != (head);                                        \
         pos = n, n = listEntry (n->member.prev, typeof (*n), member))

#define listForEachEntryFrom(pos, head, member)                     \
    for (; &pos->member != (head);                                  \
         pos = listEntry (pos->member.next, typeof (*pos), member))

#define listForEachEntrySafeFrom(pos, n, head, member)                  \
    for (n = listEntry (pos->member.next, typeof (*pos), member);       \
         &pos->member != (head);                                        \
         pos = n, n = listEntry (n->member.next, typeof (*n), member))

#define listForEachEntryFromReverse(pos, head, member)              \
    for (; &pos->member != (head);                                  \
         pos = listEntry (pos->member.prev, typeof (*pos), member))

#define listForEachEntrySafeFromReverse(pos, n, head, member)           \
    for ( n = listEntry (pos->member.prev, typeof (*pos), member);      \
          &pos->member != (head);                                       \
          pos = n, n = listEntry (n->member.prev, typeof (*n), member))

#endif /* __WDM_AGENT_LIST_H__ */
