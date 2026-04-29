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

#include "bondp_datapath_convert.h"

#include "bondp_wr_buf.h"

int wr_buf_init(wr_buf_t *buf, uint32_t max_wr_num)
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
    buf->latest_used = max_wr_num - 1;
    return 0;
}

void wr_buf_uninit(wr_buf_t *buf)
{
    if (buf == NULL || buf->entries == NULL) {
        return;
    }

    for (uint32_t idx = 0; idx < buf->max_wr_num; idx++) {
        wr_buf_entry_hdr_t *entry_hdr = (wr_buf_entry_hdr_t *)__wr_buf_idx(buf, idx);
        if (entry_hdr->wr_id == 0) {
            continue;
        }

        if (entry_hdr->entry_type == WR_BUF_ENTRY_JFS) {
            jfs_wr_entry_t *entry = (jfs_wr_entry_t *)__wr_buf_idx(buf, idx);
            convert_jfs_pwr_to_vwr_resend(&entry->wr, &entry->target_vjetty->v_tjetty);
            release_vwr_use_cnt(&entry->wr);
            free_jfs_wr(&entry->wr);
        } else if (entry_hdr->entry_type == WR_BUF_ENTRY_JFR) {
            jfr_wr_entry_t *entry = (jfr_wr_entry_t *)__wr_buf_idx(buf, idx);
            free_jfr_wr(&entry->wr);
        }
    }

    free(buf->entries);
    buf->entries = NULL;
    buf->max_wr_num = 0;
    buf->wr_entry_size = 0;
    buf->latest_used = 0;
}

static void *wr_buf_alloc(wr_buf_t *buf, wr_buf_entry_type_t entry_type)
{
    uint32_t start = (buf->latest_used + 1) % buf->max_wr_num;
    uint32_t idx = start;
    do {
        void *e = __wr_buf_idx(buf, idx);
        wr_buf_entry_hdr_t *entry_hdr = (wr_buf_entry_hdr_t *)e;
        if (entry_hdr->wr_id == 0) {
            entry_hdr->wr_id = __idx_to_wr_id(idx);
            entry_hdr->entry_type = (uint8_t)entry_type;
            buf->latest_used = idx;
            return e;
        }
        idx = (idx + 1) % buf->max_wr_num;
    } while (idx != start);

    // Since the wr_buf size should be equal to the JFC depth, this branch is unreachable.
    return NULL;
}

jfs_wr_entry_t *jfs_wr_buf_alloc(wr_buf_t *buf)
{
    return (jfs_wr_entry_t *)wr_buf_alloc(buf, WR_BUF_ENTRY_JFS);
}

jfr_wr_entry_t *jfr_wr_buf_alloc(wr_buf_t *buf)
{
    return (jfr_wr_entry_t *)wr_buf_alloc(buf, WR_BUF_ENTRY_JFR);
}

void jfs_wr_buf_release(jfs_wr_entry_t *entry)
{
    memset(entry, 0, sizeof(jfs_wr_entry_t));
}

void jfr_wr_buf_release(jfr_wr_entry_t *entry)
{
    memset(entry, 0, sizeof(jfr_wr_entry_t));
}
