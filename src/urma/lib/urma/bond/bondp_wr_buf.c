/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider wr buf implementation file
 * Author: Wang Hang
 * Create: 2026-03-17
 * Note:
 * History: 2026-03-17  Create file
 */

#include <stdlib.h>
#include <string.h>

#include "bondp_types.h"
#include "ub_hash.h"
#include "ub_hmap.h"

#include "bondp_wr_buf.h"

static inline uint32_t wr_id_to_idx(uint64_t wr_id, uint32_t max_wr_num)
{
    return (wr_id - 1) % max_wr_num;
}
static inline uint32_t idx_to_wr_id(uint32_t idx)
{
    return (uint32_t)(idx + 1);
}
static inline void *wr_buf_idx(xwr_buf_t *buf, uint32_t idx)
{
    return ((char *)buf->entries + idx * buf->wr_entry_size);
}

int wr_buf_init(xwr_buf_t *buf, uint32_t max_wr_num)
{
    if (buf == NULL || max_wr_num == 0) {
        return -EINVAL;
    }
    const uint32_t max_entry_size = MAX(sizeof(jfs_wr_entry_t), sizeof(jfr_wr_entry_t));
    buf->entries = calloc(max_wr_num, max_entry_size);
    if (buf->entries == NULL) {
        return -ENOMEM;
    }
    buf->max_wr_num = max_wr_num;
    buf->wr_entry_size = max_entry_size;
    buf->latest_used = 0;
    return 0;
}

void wr_buf_uninit(xwr_buf_t *buf)
{
    if (buf == NULL) {
        return;
    }
    free(buf->entries);
    buf->entries = NULL;
    buf->max_wr_num = 0;
    buf->wr_entry_size = 0;
    buf->latest_used = 0;
}

jfs_wr_entry_t *jfs_wr_buf_get(xwr_buf_t *buf, uint64_t wr_id)
{
    return (jfs_wr_entry_t *)wr_buf_idx(buf, wr_id_to_idx(wr_id, buf->max_wr_num));
}

jfr_wr_entry_t *jfr_wr_buf_get(xwr_buf_t *buf, uint64_t wr_id)
{
    return (jfr_wr_entry_t *)wr_buf_idx(buf, wr_id_to_idx(wr_id, buf->max_wr_num));
}

static void *wr_buf_alloc(xwr_buf_t *buf)
{
    uint32_t start = (buf->latest_used + 1) % buf->max_wr_num;
    uint32_t idx = start;
    do {
        void *e = wr_buf_idx(buf, idx);
        uint64_t *wr_id = (uint64_t *)e;
        if (*wr_id == 0) {
            *wr_id = idx_to_wr_id(idx);
            buf->latest_used = idx;
            return e;
        }
        idx = (idx + 1) % buf->max_wr_num;
    } while (idx != start);

    // Since the wr_buf size should be equal to the JFC depth, this branch is unreachable.
    return NULL;
}

jfs_wr_entry_t *jfs_wr_buf_alloc(xwr_buf_t *buf)
{
    return (jfs_wr_entry_t *)wr_buf_alloc(buf);
}

jfr_wr_entry_t *jfr_wr_buf_alloc(xwr_buf_t *buf)
{
    return (jfr_wr_entry_t *)wr_buf_alloc(buf);
}

void jfs_wr_buf_release(jfs_wr_entry_t *entry)
{
    memset(entry, 0, sizeof(jfs_wr_entry_t));
}

void jfr_wr_buf_release(jfr_wr_entry_t *entry)
{
    memset(entry, 0, sizeof(jfr_wr_entry_t));
}
