/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: smap head file
 * Author: Yan Fangfang
 * Create: 2020-9-25
 * Note:
 * History: 2020-9-25 define smap structure
 */

#ifndef UB_SMAP_H
#define UB_SMAP_H

#include <glib-object.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef GHashTable ub_smap;
typedef GHashTableIter ub_smap_iter;

void ub_smap_init(ub_smap **smap);
bool ub_smap_insert(ub_smap *smap, const char *key, const char *value);
bool ub_smap_insert_ncp(ub_smap *smap, const char *key, const char *value);
char *ub_smap_get(ub_smap *smap, const char *key);
bool ub_smap_replace(ub_smap *smap, const char *key, const char *new_value);
bool ub_smap_remove(ub_smap *smap, const char *key);
void ub_smap_destroy(ub_smap *smap);

bool ub_smap_add_format(ub_smap *smap, const char *key, const char *format, ...);
bool ub_smap_equal(ub_smap *smap1, ub_smap *smap2);
void ub_smap_clone(ub_smap **dst_smap, ub_smap *src_smap);

void ub_smap_iter_init(ub_smap *smap, ub_smap_iter *iter);
bool ub_smap_iter_next(ub_smap_iter *iter, char **key, char **value);
static inline unsigned int ub_smap_count(ub_smap *smap)
{
    return (unsigned int)g_hash_table_size(smap);
}

static inline void ub_smap_clear(ub_smap *smap)
{
    g_hash_table_remove_all(smap);
}

#ifdef __cplusplus
}
#endif

#endif
