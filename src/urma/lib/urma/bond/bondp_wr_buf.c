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
#include <errno.h>

#include "urma_log.h"
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
        goto WR_BUF_FAIL;
    }

    buf->next_free = (uint32_t *)malloc(max_wr_num * sizeof(uint32_t));
    if (buf->next_free == NULL) {
        goto WR_BUF_FREE_ENTRIES;
    }

    if (pthread_spin_init(&buf->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        goto WR_BUF_FREE_NEXT_FREE;
    }

    buf->max_wr_num = max_wr_num;
    buf->wr_entry_size = max_entry_size;
    buf->latest_used = max_wr_num - 1;

    /* Build single free list: 0 -> 1 -> 2 -> ... -> max_wr_num-1 -> UINT32_MAX */
    for (uint32_t i = 0; i < max_wr_num; i++) {
        buf->next_free[i] = (i == max_wr_num - 1) ? UINT32_MAX : (i + 1);
    }
    buf->free_head = 0;

    return 0;

WR_BUF_FREE_NEXT_FREE:
    free(buf->next_free);
    buf->next_free = NULL;
WR_BUF_FREE_ENTRIES:
    free(buf->entries);
    buf->entries = NULL;
WR_BUF_FAIL:
    return -ENOMEM;
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
        } else if (entry_hdr->entry_type == WR_BUF_ENTRY_JFR) {
            /* sge is embedded in jfr_wr_entry_t, no need to free */
        }
    }

    pthread_spin_destroy(&buf->lock);
    free(buf->next_free);
    buf->next_free = NULL;
    const uint32_t max_entry_size = MAX(sizeof(jfs_wr_entry_t),
        sizeof(jfr_wr_entry_t));
    memset(buf->entries, 0, buf->max_wr_num * max_entry_size);
    free(buf->entries);
    buf->entries = NULL;
    buf->max_wr_num = 0;
    buf->wr_entry_size = 0;
    buf->latest_used = 0;
    buf->free_head = UINT32_MAX;
}

/**
 * Allocate a WR entry from the free list.
 */
static void *wr_buf_alloc(wr_buf_t *buf, wr_buf_entry_type_t entry_type)
{
    pthread_spin_lock(&buf->lock);
    if (buf->free_head == UINT32_MAX) {
        pthread_spin_unlock(&buf->lock);
        return NULL;
    }
    uint32_t idx = buf->free_head;
    buf->free_head = buf->next_free[idx];
    pthread_spin_unlock(&buf->lock);

    void *e = __wr_buf_idx(buf, idx);
    wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)e;
    hdr->wr_id = __idx_to_wr_id(idx);
    hdr->entry_type = (uint8_t)entry_type;
    return e;
}

jfs_wr_entry_t *jfs_wr_buf_alloc(wr_buf_t *buf)
{
    return (jfs_wr_entry_t *)wr_buf_alloc(buf, WR_BUF_ENTRY_JFS);
}

jfr_wr_entry_t *jfr_wr_buf_alloc(wr_buf_t *buf)
{
    return (jfr_wr_entry_t *)wr_buf_alloc(buf, WR_BUF_ENTRY_JFR);
}

/**
 * Batch allocation: pop up to @count entries in one lock/unlock.
 * Returns the number of entries actually allocated (may be less than @count).
 * Note: entry_type is NOT set here.
 */
static uint32_t wr_buf_alloc_batch(wr_buf_t *buf,
    char **entries, uint32_t count)
{
    if (count == 0) {
        return 0;
    }
    uint32_t indices[BONDP_BATCH_POST_MAX_NUM];
    uint32_t allocated = 0;
    pthread_spin_lock(&buf->lock);
    while (allocated < count && buf->free_head != UINT32_MAX) {
        indices[allocated] = buf->free_head;
        buf->free_head = buf->next_free[buf->free_head];
        allocated++;
    }
    for (uint32_t i = 0; i < allocated; i++) {
        char *e = (char *)__wr_buf_idx(buf, indices[i]);
        wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)e;
        hdr->wr_id = __idx_to_wr_id(indices[i]);
        entries[i] = e;
    }
    pthread_spin_unlock(&buf->lock);

    return allocated;
}

uint32_t jfs_wr_buf_alloc_batch(wr_buf_t *buf, jfs_wr_entry_t **entries, uint32_t count)
{
    return wr_buf_alloc_batch(buf, (char **)entries, count);
}

uint32_t jfr_wr_buf_alloc_batch(wr_buf_t *buf, jfr_wr_entry_t **entries, uint32_t count)
{
    return wr_buf_alloc_batch(buf, (char **)entries, count);
}

/**
 * Release a WR entry back to the free list.
 */
static void wr_buf_release_entry(wr_buf_t *buf, uint32_t idx)
{
    /* Only clear the header (wr_id + entry_type) to mark the entry free */
    pthread_spin_lock(&buf->lock);
    void *e = __wr_buf_idx(buf, idx);
    wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)e;
    hdr->wr_id = 0;
    hdr->entry_type = 0;
    buf->next_free[idx] = buf->free_head;
    buf->free_head = idx;
    pthread_spin_unlock(&buf->lock);
}

void jfs_wr_buf_release(wr_buf_t *buf, jfs_wr_entry_t *entry)
{
    uint32_t idx = wr_buf_idx_from_ptr(buf, (char *)entry);
    wr_buf_release_entry(buf, idx);
}

void jfr_wr_buf_release(wr_buf_t *buf, jfr_wr_entry_t *entry)
{
    uint32_t idx = wr_buf_idx_from_ptr(buf, (char *)entry);
    wr_buf_release_entry(buf, idx);
}

/**
 * Batch release: push multiple entries back
 */
static void wr_buf_release_batch(wr_buf_t *buf, uint32_t *indices, uint32_t count)
{
    if (count == 0) {
        return;
    }
    pthread_spin_lock(&buf->lock);
    /* Only clear headers (wr_id + entry_type) to mark entries free */
    for (uint32_t i = 0; i < count; i++) {
        void *e = __wr_buf_idx(buf, indices[i]);
        wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)e;
        hdr->wr_id = 0;
        hdr->entry_type = 0;
    }
    /* Push all entries back to free list */
    for (uint32_t i = 0; i < count; i++) {
        buf->next_free[indices[i]] = buf->free_head;
        buf->free_head = indices[i];
    }
    pthread_spin_unlock(&buf->lock);
}

void jfs_wr_buf_release_batch(wr_buf_t *buf, jfs_wr_entry_t **entries, uint32_t count)
{
    uint32_t indices[BONDP_BATCH_POST_MAX_NUM];
    if (count == 0) {
        return;
    }
    if (count > BONDP_BATCH_POST_MAX_NUM) {
        URMA_LOG_ERR("JFS WR buf release failed: count = %u, limit = %u",
            count, BONDP_BATCH_POST_MAX_NUM);
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        indices[i] = wr_buf_idx_from_ptr(buf, (char *)entries[i]);
    }
    wr_buf_release_batch(buf, indices, count);
}

void jfr_wr_buf_release_batch(wr_buf_t *buf, jfr_wr_entry_t **entries, uint32_t count)
{
    uint32_t indices[BONDP_BATCH_POST_MAX_NUM];
    if (count == 0) {
        return;
    }
    if (count > BONDP_BATCH_POST_MAX_NUM) {
        URMA_LOG_ERR("JFR WR buf release failed: count = %u, limit = %u",
            count, BONDP_BATCH_POST_MAX_NUM);
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        indices[i] = wr_buf_idx_from_ptr(buf, (char *)entries[i]);
    }
    wr_buf_release_batch(buf, indices, count);
}
