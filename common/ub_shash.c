/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub shash implemention file
 * Author: Yan Fangfang
 * Create: 2020-09-29
 * Note:
 * History: 2020-09-29 Yan Fangfang define ub shash APIs
 */
#include "ub_util.h"
#include "ub_shash.h"

static inline GHashTable *_shash_get_tbl(GHashTable *tbl)
{
    if (tbl != NULL) {
        return tbl;
    } else {
        return g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
    }
}

void shash_init(struct shash *sh)
{
    sh->tbl = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
}

void shash_destroy(struct shash *sh)
{
    if (sh->tbl == NULL) {
        return;
    }
    g_hash_table_destroy(sh->tbl);
    sh->tbl = NULL;
}

void shash_clear(struct shash *sh)
{
    if (sh->tbl == NULL) {
        return;
    }
    g_hash_table_remove_all(sh->tbl);
}

bool shash_is_empty(const struct shash *sh)
{
    if (sh->tbl == NULL) {
        return true;
    }
    return g_hash_table_size(sh->tbl) == 0;
}

size_t shash_count(const struct shash *sh)
{
    if (sh->tbl == NULL) {
        return 0;
    }
    return g_hash_table_size(sh->tbl);
}

/* Add data by key into sh. Caller should avoid duplicate keys. */
struct shash_node *shash_add(struct shash *sh, const char *key, void *data)
{
    struct shash_node *node = NULL;

    /* if use SHASH_INITIALIZER, we need alloc tbl first. */
    sh->tbl = _shash_get_tbl(sh->tbl);
    if (sh->tbl == NULL) {
        return NULL;
    }
    node = malloc(sizeof(*node));
    if (node == NULL) {
        return NULL;
    }

    node->name = strdup(key);
    if (node->name == NULL) {
        free(node);
        return NULL;
    }
    node->data = data;

    /* If already exist, ghash will free new key (node->name) and old value */
    bool ret = (bool)g_hash_table_insert(sh->tbl, node->name, node);
    if (ret == false) {
        /* Free node->name and node here will cause double free */
        return NULL;
    }
    return node;
}

bool shash_add_once(struct shash *sh, const char *key, void *data)
{
    if (shash_find(sh, key) == NULL) {
        struct shash_node *node = shash_add(sh, key, data);
        return node != NULL ? true : false;
    } else {
        return false;
    }
}

/* Delete node from sh. Caller should free node->data if needed. */
bool shash_delete(struct shash *sh, struct shash_node *node)
{
    char *key = node->name;

    if (sh->tbl == NULL) {
        return false;
    }
    return (bool)g_hash_table_remove(sh->tbl, key);
}

struct shash_node *shash_find(const struct shash *sh, const char *key)
{
    if (sh->tbl == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(sh->tbl, key);
}

void *shash_find_data(const struct shash *sh, const char *key)
{
    struct shash_node *node = NULL;

    if (sh->tbl == NULL) {
        return NULL;
    }
    node = g_hash_table_lookup(sh->tbl, key);
    if (node != NULL) {
        return node->data;
    } else {
        return NULL;
    }
}

void *shash_find_and_delete(struct shash *sh, const char *key)
{
    struct shash_node *node = shash_find(sh, key);

    if (node != NULL) {
        void *data = node->data;
        (void)shash_delete(sh, node);
        return data;
    } else {
        return NULL;
    }
}

static int _compare_node_func(const void *n1, const void *n2)
{
    const struct shash_node * const * n1_ = n1;
    const struct shash_node * const * n2_ = n2;

    return strncmp((*n1_)->name, (*n2_)->name, strlen((*n1_)->name));
}

const struct shash_node **shash_sort(const struct shash *sh)
{
    const struct shash_node **node_arr = NULL;
    struct shash_node *node = NULL;
    size_t i, n;

    if (shash_is_empty(sh)) {
        return NULL;
    }

    n = shash_count(sh);
    node_arr = calloc(1, n * sizeof(*node_arr));
    if (node_arr == NULL) {
        return NULL;
    }
    i = 0;
    SHASH_FOR_EACH(node, sh) {
        node_arr[i++] = node;
    }

    qsort(node_arr, n, sizeof(*node_arr), _compare_node_func);

    return node_arr;
}
