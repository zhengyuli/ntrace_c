#include "list.h"

/* Init list head */
void
initListHead (listHeadPtr head) {
    head->prev = head;
    head->next = head;
}

/* Add an item to the head of the list */
inline void
listAdd (listHeadPtr new, listHeadPtr head) {
    new->prev = head;
    new->next = head->next;
    (head->next)->prev = new;
    head->next = new;
}

/* Aadd an item to the tail of the list */
inline void
listAddTail (listHeadPtr new, listHeadPtr head) {
    listAdd (new, head->prev);
}

/* Delete an item from list */
inline void
listDel (listHeadPtr node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
}

/* Check list size */
inline boolean
listIsEmpty (listHeadPtr head) {
    if (head->next == head)
        return True;
    else
        return False;
}
