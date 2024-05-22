/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub smap API implementation
 * Author: Yan Fangfang
 * Create: 2020-09-25
 * Note:
 * History: 2020-09-25 Yan Fangfang define ub smap APIs
 */

#include <stdio.h>
#include "ub_smap.h"

/* init xpf smap */
void ub_smap_init(ub_smap **smap)
{
    *smap = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
}

bool ub_smap_insert(ub_smap *smap, const char *key, const char *value)
{
    return (bool)g_hash_table_insert(smap, strdup(key), strdup(value));
}

bool ub_smap_insert_ncp(ub_smap *smap, const char *key, const char *value)
{
    return (bool)g_hash_table_insert(smap, strdup(key), (char*)value);
}

char *ub_smap_get(ub_smap *smap, const char *key)
{
    return g_hash_table_lookup(smap, key);
}

bool ub_smap_replace(ub_smap *smap, const char *key, const char *new_value)
{
    return (bool)g_hash_table_replace(smap, strdup(key), strdup(new_value));
}

bool ub_smap_remove(ub_smap *smap, const char *key)
{
    return (bool)g_hash_table_remove(smap, key);
}

void ub_smap_destroy(ub_smap *smap)
{
    if (smap == NULL) {
        return;
    }
    g_hash_table_destroy(smap);
}

#define ARGS_LEN 128UL

bool ub_smap_add_format(ub_smap *smap, const char *key, const char *format, ...)
{
    size_t len;
    int ret;
    char *value = NULL;
    va_list args_list;

    value = calloc(1, ARGS_LEN);
    if (value == NULL) {
        return false;
    }

    va_start(args_list, format);
    ret = vsnprintf(value, ARGS_LEN, format, args_list);
    if (ret <= 0 || ret >= ARGS_LEN) {
        va_end(args_list);
        free(value);
        return false;
    }
    va_end(args_list);

    len = (size_t)ret;
    value[len] = '\0';

    return ub_smap_insert_ncp(smap, key, value);
}

void ub_smap_iter_init(ub_smap *smap, ub_smap_iter *iter)
{
    if (smap == NULL || iter == NULL) {
        return;
    }
    g_hash_table_iter_init(iter, smap);
}

bool ub_smap_iter_next(ub_smap_iter *iter, char **key, char **value)
{
    return (bool)g_hash_table_iter_next(iter, (void *)key, (void *)value);
}

bool ub_smap_equal(ub_smap *smap1, ub_smap *smap2)
{
    char *key = NULL;
    char *value = NULL;
    ub_smap_iter iter;

    if (ub_smap_count(smap1) != ub_smap_count(smap2)) {
        return false;
    }

    ub_smap_iter_init(smap1, &iter);
    while (ub_smap_iter_next(&iter, &key, &value)) {
        const char *value2 = ub_smap_get(smap2, (char *)key);
        if (value2 == NULL || strcmp(value, value2) != 0) {
            return false;
        }
    }

    return true;
}

void ub_smap_clone(ub_smap **dst_smap, ub_smap *src_smap)
{
    char *key = NULL;
    char *value = NULL;
    ub_smap_iter iter;

    if (dst_smap == NULL) {
        return;
    }

    if (src_smap == NULL) {
        *dst_smap = NULL;
        return;
    }
    ub_smap_init(dst_smap);
    ub_smap_iter_init(src_smap, &iter);
    while (ub_smap_iter_next(&iter, &key, &value)) {
        (void)ub_smap_insert(*dst_smap, key, value);
    }
}
