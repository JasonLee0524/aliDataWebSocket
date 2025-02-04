#ifndef __BASE_UTILS_H__
#define __BASE_UTILS_H__

#include "aliwebdll.h"

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

typedef const char cchar;

#define COL_DEF "\x1B[0m"   //white
#define COL_RED "\x1B[31m"  //red
#define COL_GRE "\x1B[32m"  //green
#define COL_BLU "\x1B[34m"  //blue
#define COL_YEL "\x1B[33m"  //yellow
#define COL_WHE "\x1B[37m"  //white
#define COL_CYN "\x1B[36m"
#define COL_MAG "\x1B[35m"

/* log declare section end */

/* list declare section begin */
#ifndef container_of
#define container_of(ptr, type, member)  \
    ((type *) ((char *) (ptr) - offsetof(type, member)))
#endif

//typedef struct ut_list_head ut_list_head_t;

struct ut_list_head {
    struct ut_list_head *next, *prev;
};

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

#define UT_LIST_HEAD_INIT(name) { &(name), &(name) }

#define UT_LIST_HEAD(name) \
    struct ut_list_head name = UT_LIST_HEAD_INIT(name)

static inline void UT_INIT_LIST_HEAD(struct ut_list_head *list)
{
    list->next = list;
    list->prev = list;
}

/*
 * Insert a new_item entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void ut__list_add(struct ut_list_head *new_item,
                              struct ut_list_head *prev,
                              struct ut_list_head *next)
{
    next->prev = new_item;
    new_item->next = next;
    new_item->prev = prev;
    prev->next = new_item;
}

/**
 * list_add - add a new_item entry
 * @new_item: new_item entry to be added
 * @head: list head to add it after
 *
 * Insert a new_item entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void ut_list_add(struct ut_list_head *new_item, struct ut_list_head *head)
{
    ut__list_add(new_item, head, head->next);
}


/**
 * list_add_tail - add a new_item entry
 * @new_item: new_item entry to be added
 * @head: list head to add it before
 *
 * Insert a new_item entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void ut_list_add_tail(struct ut_list_head *new_item, struct ut_list_head *head)
{
    ut__list_add(new_item, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void ut__list_del(struct ut_list_head *prev, struct ut_list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void ut__list_del_entry(struct ut_list_head *entry)
{
    ut__list_del(entry->prev, entry->next);
}

static inline void ut_list_del(struct ut_list_head *entry)
{
    ut__list_del(entry->prev, entry->next);
}

/**
 * list_replace - replace old entry by new_item one
 * @old : the element to be replaced
 * @new_item : the new_item element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void ut_list_replace(struct ut_list_head *old,
                                struct ut_list_head *new_item)
{
    new_item->next = old->next;
    new_item->next->prev = new_item;
    new_item->prev = old->prev;
    new_item->prev->next = new_item;
}

static inline void ut_list_replace_init(struct ut_list_head *old,
                                     struct ut_list_head *new_item)
{
    ut_list_replace(old, new_item);
    UT_INIT_LIST_HEAD(old);
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void ut_list_del_init(struct ut_list_head *entry)
{
    ut__list_del_entry(entry);
    UT_INIT_LIST_HEAD(entry);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void ut_list_move(struct ut_list_head *list, struct ut_list_head *head)
{
    ut__list_del_entry(list);
    ut_list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void ut_list_move_tail(struct ut_list_head *list,
                                  struct ut_list_head *head)
{
    ut__list_del_entry(list);
    ut_list_add_tail(list, head);
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int ut_list_is_last(const struct ut_list_head *list,
                               const struct ut_list_head *head)
{
    return list->next == head;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int ut_list_empty(const struct ut_list_head *head)
{
    return head->next == head;
}

/**
 * list_empty_careful - tests whether a list is empty and not being modified
 * @head: the list to test
 *
 * Description:
 * tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
static inline int ut_list_empty_careful(const struct ut_list_head *head)
{
    struct ut_list_head *next = head->next;
    return (next == head) && (next == head->prev);
}

/**
 * list_rotate_left - rotate the list to the left
 * @head: the head of the list
 */
static inline void ut_list_rotate_left(struct ut_list_head *head)
{
    struct ut_list_head *first;

    if (!ut_list_empty(head)) {
        first = head->next;
        ut_list_move_tail(first, head);
    }
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int ut_list_is_singular(const struct ut_list_head *head)
{
    return !ut_list_empty(head) && (head->next == head->prev);
}

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define ut_list_first_entry(ptr, type, member) \
    ut_list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define ut_list_last_entry(ptr, type, member) \
    ut_list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define ut_list_first_entry_or_null(ptr, type, member) \
    (!ut_list_empty(ptr) ? ut_list_first_entry(ptr, type, member) : NULL)

/**
 * list_next_entry - get the next element in list
 * @pos:    the type * to cursor
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_next_entry(pos, member) \
    ut_list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:    the type * to cursor
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_prev_entry(pos, member) \
    ut_list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each    -   iterate over a list
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 */
#define ut_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * __list_for_each  -   iterate over a list
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 *
 * This variant doesn't differ from list_for_each() any more.
 * We don't do prefetching in either case.
 */
#define __list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev   -   iterate over a list backwards
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 */
#define ut_list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define ut_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define ut_list_for_each_prev_safe(pos, n, head) \
    for (pos = (head)->prev, n = pos->prev; \
         pos != (head); \
         pos = n, n = pos->prev)

/**
 * list_for_each_entry  -   iterate over list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_for_each_entry(pos, head, member)             \
    for (pos = ut_list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head);    \
         pos = ut_list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_for_each_entry_reverse(pos, head, member)         \
    for (pos = ut_list_entry((head)->prev, typeof(*pos), member); \
         &pos->member != (head);    \
         pos = ut_list_entry(pos->member.prev, typeof(*pos), member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:    the type * to use as a start point
 * @head:   the head of the list
 * @member: the name of the list_struct within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define ut_list_prepare_entry(pos, head, member) \
    ((pos) ? : ut_list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define ut_list_for_each_entry_continue(pos, head, member)        \
    for (pos = ut_list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head);    \
         pos = ut_list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define ut_list_for_each_entry_continue_reverse(pos, head, member)        \
    for (pos = ut_list_entry(pos->member.prev, typeof(*pos), member); \
         &pos->member != (head);    \
         pos = ut_list_entry(pos->member.prev, typeof(*pos), member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define ut_list_for_each_entry_from(pos, head, member)            \
    for (; &pos->member != (head);  \
         pos = ut_list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define ut_list_for_each_entry_safe(pos, n, head, member)         \
    for (pos = ut_list_entry((head)->next, typeof(*pos), member), \
         n = ut_list_entry(pos->member.next, typeof(*pos), member);    \
         &pos->member != (head);                    \
         pos = n, n = ut_list_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define ut_list_for_each_entry_safe_continue(pos, n, head, member)        \
    for (pos = ut_list_entry(pos->member.next, typeof(*pos), member),         \
         n = ut_list_entry(pos->member.next, typeof(*pos), member);        \
         &pos->member != (head);                        \
         pos = n, n = ut_list_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define ut_list_for_each_entry_safe_from(pos, n, head, member)            \
    for (n = ut_list_entry(pos->member.next, typeof(*pos), member);       \
         &pos->member != (head);                        \
         pos = n, n = ut_list_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define ut_list_for_each_entry_safe_reverse(pos, n, head, member)     \
    for (pos = ut_list_entry((head)->prev, typeof(*pos), member), \
         n = ut_list_entry(pos->member.prev, typeof(*pos), member);    \
         &pos->member != (head);                    \
         pos = n, n = ut_list_entry(n->member.prev, typeof(*n), member))

/**
 * list_safe_reset_next - reset a stale list_for_each_entry_safe loop
 * @pos:    the loop cursor used in the list_for_each_entry_safe loop
 * @n:      temporary storage used in list_for_each_entry_safe
 * @member: the name of the list_struct within the struct.
 *
 * list_safe_reset_next is not safe to use in general if the list may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the list,
 * and list_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define ut_list_safe_reset_next(pos, n, member)               \
    n = ut_list_entry(pos->member.next, typeof(*pos), member)

/* list declare section end */

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif /* __BASE_UTILS_H__ */

