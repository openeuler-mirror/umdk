/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub shash head file
 * Author: Yan Fangfang
 * Create: 2020-09-29
 * Note:
 * History: 2020-09-29 Yan Fangfang define ub shash APIs
 */

#ifndef UB_SHASH_H
#define UB_SHASH_H

#include <glib-object.h>

#ifdef __cplusplus
extern "C" {
#endif

struct shash_node {
    char *name;
    void *data;
};

struct shash {
    GHashTable *tbl;
};

#define SHASH_INITIALIZER(SHASH) {                            \
        NULL                     \
    }

#define SHASH_FOR_EACH(SHASH_NODE, SHASH)              \
    GHashTableIter __iter;                             \
    void **_key = NULL;                                \
    if ((SHASH)->tbl != NULL) {                        \
        g_hash_table_iter_init(&__iter, (SHASH)->tbl); \
    }                                                  \
    while ((SHASH)->tbl != NULL && g_hash_table_iter_next(&__iter, _key, (void **)&(SHASH_NODE)))


void shash_init(struct shash *sh);
void shash_destroy(struct shash *sh);
bool shash_is_empty(const struct shash *sh);
size_t shash_count(const struct shash *sh);
struct shash_node *shash_add(struct shash *sh, const char *key, void *data);
bool shash_add_once(struct shash *sh, const char *key, void *data);
struct shash_node *shash_find(const struct shash *sh, const char *key);
void *shash_find_data(const struct shash *sh, const char *key);
void *shash_find_and_delete(struct shash *sh, const char *key);
const struct shash_node **shash_sort(const struct shash *sh);
bool shash_delete(struct shash *sh, struct shash_node *node);
void shash_clear(struct shash *sh);

#ifdef __cplusplus
}
#endif
#endif
