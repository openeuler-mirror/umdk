/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Generic intrusive doubly-linked circular list for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-18
 * Note:
 *   Intrusive list design: the list node is embedded inside the container
 *   struct rather than wrapping the data. This avoids extra allocations and
 *   allows a single struct to participate in multiple lists simultaneously.
 *
 *   The list is circular with a sentinel head node. An empty list has
 *   head->next == head->prev == head. This eliminates special-case branches
 *   for insertions and removals at list boundaries.
 *
 *   Usage example:
 *
 *     struct my_entry {
 *         int value;
 *         struct ums_agent_list_node node;
 *     };
 *
 *     struct ums_agent_list_node list;
 *     ums_agent_list_init(&list);
 *
 *     struct my_entry *e = malloc(sizeof(*e));
 *     e->value = 42;
 *     ums_agent_list_add_tail(&e->node, &list);
 *
 *     struct ums_agent_list_node *pos;
 *     ums_agent_list_for_each(pos, &list) {
 *         struct my_entry *entry = ums_agent_list_entry(pos, struct my_entry, node);
 *         printf("%d\n", entry->value);
 *     }
 *
 *   Thread safety: this module provides no synchronization. Callers must
 *   protect shared lists with appropriate locking.
 *
 * History: 2026-05-18  Create File
 */

#ifndef UMS_AGENT_LIST_H
#define UMS_AGENT_LIST_H

#include <stdbool.h>
#include <stddef.h>

/*
 * struct ums_agent_list_node - Node embedded in container structs.
 *
 * In an empty list initialized by ums_agent_list_init(), both next and prev
 * point to the node itself. When linked into a list, next points to the
 * successor and prev points to the predecessor.
 */
struct ums_agent_list_node {
    struct ums_agent_list_node *next;
    struct ums_agent_list_node *prev;
};

/*
 * ums_agent_list_init - Initialize a list head or a standalone node.
 *
 * After initialization, the node forms a self-referencing circle:
 * node->next == node->prev == node. For a head node this represents an
 * empty list; for a member node this prepares it for insertion.
 */
static inline void ums_agent_list_init(struct ums_agent_list_node *head)
{
    head->next = head;
    head->prev = head;
}

/*
 * ums_agent_list_empty - Test whether a list is empty.
 *
 * Returns true if the list has no nodes besides the head, false otherwise.
 * A list is empty when head->next == head (equivalently, head->prev == head).
 */
static inline bool ums_agent_list_empty(const struct ums_agent_list_node *head)
{
    return head->next == head;
}

/*
 * ums_agent_list_add - Insert a node at the head of the list (LIFO order).
 *
 * The new node becomes the first node after the sentinel head.
 * Equivalent to a stack push operation.
 */
static inline void ums_agent_list_add(struct ums_agent_list_node *node,
    struct ums_agent_list_node *head)
{
    head->next->prev = node;
    node->next = head->next;
    node->prev = head;
    head->next = node;
}

/*
 * ums_agent_list_add_tail - Insert a node at the tail of the list (FIFO order).
 *
 * The new node becomes the last node before the sentinel head.
 * Equivalent to a queue enqueue operation.
 */
static inline void ums_agent_list_add_tail(struct ums_agent_list_node *node,
    struct ums_agent_list_node *head)
{
    head->prev->next = node;
    node->prev = head->prev;
    node->next = head;
    head->prev = node;
}

/*
 * ums_agent_list_remove - Remove a node from whatever list it belongs to.
 *
 * Unlinks the node from its current list and re-initializes it as a
 * self-referencing circle. The re-initialization prevents stale pointers
 * from being followed after removal and makes double-remove a safe no-op.
 *
 * The caller is responsible for freeing the container object after removal.
 * When removing during iteration, use ums_agent_list_for_each_safe to
 * save the next pointer before removal.
 */
static inline void ums_agent_list_remove(struct ums_agent_list_node *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
}

/*
 * ums_agent_list_entry - Get the containing struct from a list node pointer.
 *
 * @ptr:    Pointer to the struct ums_agent_list_node embedded in the container.
 * @type:   The type of the containing struct.
 * @member: The name of the ums_agent_list_node field within the container type.
 *
 * Uses pointer arithmetic based on offsetof to recover the container address.
 */
#define ums_agent_list_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

/*
 * ums_agent_list_for_each - Iterate over a list (read-only).
 *
 * @pos:  Cursor, set to each node pointer in turn.
 * @head: The sentinel head node of the list.
 *
 * The iteration visits head->next, head->next->next, ..., until reaching
 * head again. The body must NOT add or remove nodes from the list; use
 * ums_agent_list_for_each_safe when modification is needed.
 */
#define ums_agent_list_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/*
 * ums_agent_list_for_each_safe - Iterate over a list, safe against node removal.
 *
 * @pos:  Cursor, set to each node pointer in turn.
 * @n:    Temporary storage for the next node pointer.
 * @head: The sentinel head node of the list.
 *
 * The next pointer (@n) is captured before the loop body executes, so it
 * remains valid even if the current node (@pos) is removed and freed inside
 * the body. Use this variant whenever the loop body may call
 * ums_agent_list_remove() or free the container object.
 */
#define ums_agent_list_for_each_safe(pos, n, head) \
    for ((pos) = (head)->next, (n) = (pos)->next; (pos) != (head); \
         (pos) = (n), (n) = (pos)->next)

#endif /* UMS_AGENT_LIST_H */
