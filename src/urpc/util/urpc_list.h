/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc list
 * Create: 2024-1-1
 * History: 2024-1-1
 */
#ifndef URPC_LIST_H
#define URPC_LIST_H

#include <stddef.h>
#include <stdbool.h>
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIST_POISON_NEXT ((void *)0x100)
#define LIST_POSION_PREV ((void *)0x200)

#define URPC_LIST_FOR_EACH(ITER, MEMBER, LIST)                                      \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->next, MEMBER); &(ITER)->MEMBER != (LIST); \
        ASSIGN_CONTAINER_PTR(ITER, (ITER)->MEMBER.next, MEMBER))

#define URPC_LIST_FOR_EACH_SAFE(ITER, NEXT, MEMBER, LIST)                   \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->next, MEMBER);                   \
         (&(ITER)->MEMBER != (LIST))                                       \
          && (INIT_CONTAINER_PTR(NEXT, (ITER)->MEMBER.next, MEMBER), 1);   \
         (ITER) = (NEXT))

typedef struct urpc_list {
    struct urpc_list *prev, *next;
} urpc_list_t;

static inline bool urpc_list_is_empty(const struct urpc_list *list)
{
    return list == list->prev;
}

static inline bool urpc_list_is_in_list(const struct urpc_list *list)
{
    return list->prev != NULL && list->prev != LIST_POSION_PREV && list->prev != list;
}

static inline void urpc_list_init(struct urpc_list *list)
{
    list->prev = list;
    list->next = list;
}

static inline void urpc_list_insert_before(struct urpc_list *cur_node, struct urpc_list *new_node)
{
    if (cur_node->prev != NULL) {
        cur_node->prev->next = new_node;
    }
    new_node->prev = cur_node->prev;
    cur_node->prev = new_node;
    new_node->next = cur_node;
}

static inline void urpc_list_push_back(struct urpc_list *list, struct urpc_list *new_node)
{
    urpc_list_insert_before(list, new_node);
}

static inline void urpc_list_insert_after(struct urpc_list *cur_node, struct urpc_list *new_node)
{
    cur_node->next->prev = new_node;
    new_node->next = cur_node->next;
    cur_node->next = new_node;
    new_node->prev = cur_node;
}

static inline void urpc_list_push_front(struct urpc_list *list, struct urpc_list *new_node)
{
    urpc_list_insert_after(list, new_node);
}

static inline void urpc_list_remove(struct urpc_list *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;

    node->next = (struct urpc_list *)LIST_POISON_NEXT;
    node->prev = (struct urpc_list *)LIST_POSION_PREV;
}

static inline struct urpc_list *urpc_list_pop_front(struct urpc_list *list)
{
    struct urpc_list *node = list->next;
    urpc_list_remove(list->next);
    return node;
}

static inline struct urpc_list *urpc_list_pop_back(struct urpc_list *list)
{
    struct urpc_list *node = list->prev;
    urpc_list_remove(list->prev);
    return node;
}

static inline size_t urpc_list_size(const struct urpc_list *list)
{
    size_t count = 0;
    struct urpc_list *node = list->next;

    while (node != list) {
        count++;
        node = node->next;
    }

    return count;
}

// Move up to n nodes from src list to dst list (at the back of dst)
// Returns actual number of nodes moved
static ALWAYS_INLINE uint32_t urpc_list_move_n(urpc_list_t *src, urpc_list_t *dst, uint32_t n)
{
    if (urpc_list_is_empty(src) || n == 0) {
        return 0;
    }

    // Find the nth node (or end of list)
    struct urpc_list *last = src;
    uint32_t count = 0;

    while (last->next != src && count < n) {
        last = last->next;
        count++;
    }

    // Connect src head to node after last (skip moved portion)
    struct urpc_list *first = src->next;
    struct urpc_list *node_after_last = last->next;
    src->next = node_after_last;
    node_after_last->prev = src;

    // Connect dst tail to first moved node, last moved node to dst head
    if (count > 0) {
        struct urpc_list *dst_tail = dst->prev;
        dst_tail->next = first;
        first->prev = dst_tail;
        last->next = dst;
        dst->prev = last;
    }

    return count;
}

#define URPC_LIST_FOR_EACH_REVERSE(ITER, MEMBER, LIST)                       \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->prev, MEMBER);                    \
         &(ITER)->MEMBER != (LIST);                                         \
         ASSIGN_CONTAINER_PTR(ITER, (ITER)->MEMBER.prev, MEMBER))

/* used to get first node of a list, if list is empty, ITER will be set to NULL */
#define URPC_LIST_FIRST_NODE(ITER, MEMBER, LIST)                            \
    do {                                                                    \
        if (urpc_list_is_empty(LIST)) {                                       \
            (ITER) = NULL;                                                  \
        } else {                                                            \
            ASSIGN_CONTAINER_PTR((ITER), (LIST)->next, MEMBER);             \
        }                                                                   \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif