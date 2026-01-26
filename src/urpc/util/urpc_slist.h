/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc Singly-linked list
 */
#ifndef URPC_SLIST_H
#define URPC_SLIST_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * URPC Singly-linked List declarations.
 */
#define URPC_SLIST_ENTRY(type)      \
struct {                            \
    struct type *next;              \
}

#define URPC_SLIST_HEAD(name, type)         \
struct name {                               \
    struct type *first;                     \
}

/*
 * URPC Singly-linked List functions.
 */
#define URPC_SLIST_FIRST(head)    ((head)->first)

#define URPC_SLIST_INIT(head) do {                      \
    URPC_SLIST_FIRST((head)) = NULL;                    \
} while (0)

#define URPC_SLIST_EMPTY(head)    ((head)->first == NULL)

#define URPC_SLIST_NEXT(element, field)    ((element)->field.next)

#define URPC_SLIST_INSERT_HEAD(head, element, field) do {                   \
    URPC_SLIST_NEXT((element), field) = URPC_SLIST_FIRST((head));           \
    URPC_SLIST_FIRST((head)) = (element);                                   \
} while (0)

#define	URPC_SLIST_INSERT_AFTER(element1, element2, field) do {                  \
    URPC_SLIST_NEXT((element2), field) = URPC_SLIST_NEXT((element1), field);     \
    URPC_SLIST_NEXT((element1), field) = (element2);                             \
} while (0)

#define URPC_SLIST_FOR_EACH(element, head, field)                   \
    for ((element) = URPC_SLIST_FIRST((head));                      \
        (element);                                                  \
        (element) = URPC_SLIST_NEXT((element), field))

#define URPC_SLIST_FOR_EACH_SAFE(element, head, field, next)            \
    for ((element) = URPC_SLIST_FIRST((head));                          \
        (element) && ((next) = URPC_SLIST_NEXT((element), field), 1);   \
        (element) = (next))

#define URPC_SLIST_REMOVE_HEAD(head, field) do {                                    \
    URPC_SLIST_FIRST((head)) = URPC_SLIST_NEXT(URPC_SLIST_FIRST((head)), field);    \
} while (0)

#define URPC_SLIST_REMOVE_AFTER(element, field) do {                \
    URPC_SLIST_NEXT(element, field) =                               \
        URPC_SLIST_NEXT(URPC_SLIST_NEXT(element, field), field);    \
} while (0)

#define URPC_SLIST_REMOVE(head, element, type, field) do {          \
    if (URPC_SLIST_FIRST((head)) == (element)) {                    \
        URPC_SLIST_REMOVE_HEAD((head), field);                      \
    } else {                                                         \
        struct type *curelement = URPC_SLIST_FIRST(head);           \
        while (URPC_SLIST_NEXT(curelement, field) != (element))     \
            curelement = URPC_SLIST_NEXT(curelement, field);        \
        URPC_SLIST_REMOVE_AFTER(curelement, field);                 \
    }                                                               \
} while (0)

#ifdef __cplusplus
}
#endif

#endif