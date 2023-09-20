/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub list head file
 * Author: Lilijun
 * Create: 2020-8-11
 * Note:
 * History: 2020-8-11 define list APIs
 */

#ifndef UB_LIST_H
#define UB_LIST_H

#include "ub_util.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct ub_list {
    struct ub_list *prev, *next;
};

#define UB_LIST_INITIALIZER(LIST_NAME) {LIST_NAME, LIST_NAME}

enum list_insert_direct {
    INSERT_BEFORE,
    INSERT_AFTER
};

static inline void ub_list_init(struct ub_list *list)
{
    list->prev = list;
    list->next = list;
}

/* insert the new node to the current node before */
static inline void ub_list_insert_before(struct ub_list *cur_node, struct ub_list *new_node)
{
    if (cur_node->prev != NULL) {
        cur_node->prev->next = new_node;
    }
    new_node->prev = cur_node->prev;
    cur_node->prev = new_node;
    new_node->next = cur_node;
}

/* insert the new node to the current node after */
static inline void ub_list_insert_after(struct ub_list *cur_node, struct ub_list *new_node)
{
    cur_node->next->prev = new_node;
    new_node->next = cur_node->next;
    cur_node->next = new_node;
    new_node->prev = cur_node;
}

/* insert the new node to the front of the list */
static inline void ub_list_push_front(struct ub_list *list, struct ub_list *new_node)
{
    ub_list_insert_after(list, new_node);
}

/* insert the new node to the end of the list */
static inline void ub_list_push_back(struct ub_list *list, struct ub_list *new_node)
{
    ub_list_insert_before(list, new_node);
}

static inline void ub_list_remove(struct ub_list *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

/* remove the first node of the list and return it */
static inline struct ub_list *ub_list_pop_front(struct ub_list *list)
{
    struct ub_list *node = list->next;
    ub_list_remove(list->next);
    return node;
}

/* remove the last node of the list and return it */
static inline struct ub_list *ub_list_pop_back(struct ub_list *list)
{
    struct ub_list *node = list->prev;
    ub_list_remove(list->prev);
    return node;
}

static inline bool ub_list_is_empty(const struct ub_list *list)
{
    return list == list->prev;
}

static inline size_t ub_list_size(const struct ub_list *list)
{
    size_t count = 0;
    struct ub_list *node = list->next;

    while (node != list) {
        count++;
        node = node->next;
    }

    return count;
}

/*
 * If want to use the ordered list, should only use the ub_list_insert_ordered to insert node.
 * If compare function returns true, new_node will insert before node_to_compare.
 */
static inline void ub_list_insert_ordered(struct ub_list *list, struct ub_list *new_node,
    bool (*compare)(const struct ub_list *new_node, const struct ub_list *node_to_compare))
{
    struct ub_list *cur_node = list->next;
    while (cur_node != list) {
        if (compare(new_node, cur_node)) {
            ub_list_insert_before(cur_node, new_node);
            return;
        }
        cur_node = cur_node->next;
    }
    /* insert new node to the end. */
    ub_list_insert_before(list, new_node);
}

/*
 * If want to use the ordered list without repetition, should only use
 * the ub_list_insert_ordered_without_repetition to insert node.
 * If compare function returns positive, new_node will insert before node_to_compare.
 * If compare function returns zero, new_node does not insert and returns -1.
 */
static inline int ub_list_insert_ordered_without_repetition(struct ub_list *list, struct ub_list *new_node,
    int (*compare)(const struct ub_list *new_node, const struct ub_list *node_to_compare))
{
    struct ub_list *cur_node = list->next;
    while (cur_node != list) {
        int ret = compare(new_node, cur_node);
        if (ret > 0) {
            ub_list_insert_before(cur_node, new_node);
            return 0;
        } else if (ret == 0) {
            return -1;
        }
        cur_node = cur_node->next;
    }
    /* insert new node to the end. */
    ub_list_insert_before(list, new_node);
    return 0;
}


#define UB_LIST_FOR_EACH(ITER, MEMBER, LIST)                               \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->next, MEMBER);                    \
         &(ITER)->MEMBER != (LIST);                                         \
         ASSIGN_CONTAINER_PTR(ITER, (ITER)->MEMBER.next, MEMBER))

#define UB_LIST_FOR_EACH_SAFE(ITER, NEXT, MEMBER, LIST)                   \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->next, MEMBER);                   \
         (&(ITER)->MEMBER != (LIST))                                       \
          && (INIT_CONTAINER_PTR(NEXT, (ITER)->MEMBER.next, MEMBER), 1);   \
         (ITER) = (NEXT))

#define UB_LIST_FOR_EACH_POP_FRONT(ITER, MEMBER, LIST)                     \
    for (; !ub_list_is_empty(LIST)                                         \
           && (INIT_CONTAINER_PTR(ITER, ub_list_pop_front(LIST), MEMBER), 1);)

#define UB_LIST_FOR_EACH_REVERSE(ITER, MEMBER, LIST)                       \
    for (INIT_CONTAINER_PTR(ITER, (LIST)->prev, MEMBER);                    \
         &(ITER)->MEMBER != (LIST);                                         \
         ASSIGN_CONTAINER_PTR(ITER, (ITER)->MEMBER.prev, MEMBER))

/* for list that each node has a different data struct */
#define UB_LIST_FOR_EACH_BY_NODE(NODE, HEAD) \
    for ((NODE = HEAD->next); ((NODE != HEAD) && (NODE != NULL)); (NODE = NODE->next))

#define UB_LIST_FOR_EACH_BY_NODE_SAFE(NODE, NEXT_NODE, HEAD) \
    for ((NODE = HEAD->next); ((NODE != HEAD) && (NODE != NULL) && (NEXT_NODE = NODE->next, 1)); \
        (NODE = NEXT_NODE))

/* used to get first node of a list, if list is empty, ITER will be set to NULL */
#define UB_LIST_FIRST_NODE(ITER, MEMBER, LIST)                              \
    do {                                                                    \
        if (ub_list_is_empty(LIST)) {                                       \
            (ITER) = NULL;                                                  \
        } else {                                                            \
            ASSIGN_CONTAINER_PTR((ITER), (LIST)->next, MEMBER);             \
        }                                                                   \
    } while (0)

/*
 * used to get next node, if next node is head, go to next node again;
 * if list is empty, ITER will be set to NULL.
 */
#define UB_LIST_NEXT_NODE(ITER, MEMBER, LIST)                               \
    do {                                                                    \
        if (ub_list_is_empty(LIST)) {                                       \
            (ITER) = NULL;                                                  \
        } else {                                                            \
            ASSIGN_CONTAINER_PTR((ITER), (ITER)->MEMBER.next, MEMBER);      \
        }                                                                   \
    } while ((&(ITER)->MEMBER == (LIST)) && (!(ub_list_is_empty(LIST))))

#ifdef __cplusplus
}
#endif

#endif
