/* Atomic operations provide by gcc */

#ifndef __AGENT_ATOMIC_H__
#define __AGENT_ATOMIC_H__

#define ATOMIC_INC(xPtr) __sync_add_and_fetch ((xPtr), 1)
#define ATOMIC_DEC(xPtr) __sync_sub_and_fetch ((xPtr), 1)

#define ATOMIC_FETCH_AND_ADD(xPtr, y) __sync_fetch_and_add ((xPtr), (y))
#define ATOMIC_FETCH_AND_SUB(xPtr, y) __sync_fetch_and_sub ((xPtr), (y))
#define ATOMIC_FETCH_AND_OR(xPtr, y) __sync_fetch_and_or ((xPtr), (y))
#define ATOMIC_FETCH_AND_AND(xPtr, y) __sync_fetch_and_and ((xPtr), (y))
#define ATOMIC_FETCH_AND_XOR(xPtr, y) __sync_fetch_and_xor ((xPtr), (y))
#define ATOMIC_FETCH_AND_NAND(xPtr, y) __sync_fetch_and_nand ((xPtr), (y))

#define ATOMIC_ADD_AND_FETCH(xPtr, y) __sync_add_and_fetch ((xPtr), (y))
#define ATOMIC_SUB_AND_FETCH(xPtr, y) __sync_sub_and_fetch ((xPtr), (y))
#define ATOMIC_OR_AND_FETCH(xPtr, y) __sync_or_and_fetch ((xPtr), (y))
#define ATOMIC_AND_AND_FETCH(xPtr, y) __sync_and_and_fetch ((xPtr), (y))
#define ATOMIC_XOR_AND_FETCH(xPtr, y) __sync_xor_and_fetch ((xPtr), (y))
#define ATOMIC_NAND_AND_FETCH(xPtr, y) __sync_nand_and_fetch ((xPtr), (y))

/* If *xPtr == oldVal then wrtie newVal to *xPtr and return true, else return false */
#define ATOMIC_BOOL_COMPARE_AND_SWAP(xPtr, oldVal, newVal) __sync_BOOL_compare_and_swap ((xPtr), (oldVal), (newVal))
/* If *xPtr == oldVal then write newVal to *xPtr and return *xPtr before write operation */
#define ATOMIC_VAL_COMPARE_AND_SWAP(xPtr, oldVal, newVal) __sync_val_compare_and_swap ((xPtr), (oldVal), (newVal))

#define ATOMIC_FETCH_AND_SET(xPtr, y) __sync_lock_test_and_set ((xPtr), y)
#define ATOMIC_RELEASE(xPtr) __sync_lock_release ((xPtr))

#endif /* __AGENT_ATOMIC_H__ */
