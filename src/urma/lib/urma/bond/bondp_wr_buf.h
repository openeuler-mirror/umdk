/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider wr buf header file
 * Author: Wang Hang
 * Create: 2026-03-17
 * Note:
 * History: 2026-03-17   Create File
 */

#ifndef BONDP_WR_BUF_H
#define BONDP_WR_BUF_H

#include <stdint.h>
#include <pthread.h>

#include "urma_types.h"

#define BONDP_MAX_SGE_NUM             (32)
#define BONDP_BATCH_POST_MAX_NUM      (280)

#ifdef __cplusplus
extern "C" {
#endif

struct bondp_comp;
struct bondp_target_jetty;

typedef enum wr_buf_entry_type {
    WR_BUF_ENTRY_NONE = 0,
    WR_BUF_ENTRY_JFS,
    WR_BUF_ENTRY_JFR,
} wr_buf_entry_type_t;

typedef struct wr_buf_entry_hdr {
    uint64_t wr_id;
    uint8_t entry_type;
} wr_buf_entry_hdr_t;

typedef struct bondp_chip_id_info {
    uint32_t src_chip_id;
    uint32_t dst_chip_id;
} bondp_chip_id_info_t;

/*
 * sge_data is a flexible array member at the end of the entry.
 * For jfs: [0 .. max_sge-1] = src_sge, [max_sge .. 2*max_sge-1] = dst_sge.
 * For jfr: [0 .. max_sge-1] = src_sge.
 * The actual entry size is computed at wr_buf_init time as:
 *   sizeof(header) + <num_sge_arrays> * max_sge * sizeof(urma_sge_t)
 */
typedef struct jfs_wr_entry {
    uint64_t wr_id;
    uint8_t entry_type;
    urma_jfs_wr_t wr;
    uint64_t user_ctx;
    struct bondp_comp *bdp_comp;
    struct bondp_target_jetty *target_vjetty;
    uint32_t send_idx;
    uint32_t target_idx;
    bondp_chip_id_info_t info;
    urma_sge_t sge_data[];
} jfs_wr_entry_t;

typedef struct jfr_wr_entry {
    uint64_t wr_id;
    uint8_t entry_type;
    urma_jfr_wr_t wr;
    uint64_t user_ctx;
    struct bondp_comp *bdp_comp;
    uint32_t recv_idx;
    urma_sge_t sge_data[];
} jfr_wr_entry_t;

/* sge access helpers */
static inline urma_sge_t *jfs_wr_entry_src_sge(jfs_wr_entry_t *e)
{
    return e->sge_data;
}
static inline urma_sge_t *jfs_wr_entry_dst_sge(jfs_wr_entry_t *e, uint32_t max_sge)
{
    return e->sge_data + max_sge;
}
static inline urma_sge_t *jfr_wr_entry_src_sge(jfr_wr_entry_t *e)
{
    return e->sge_data;
}

typedef struct wr_buf {
    uint32_t max_wr_num;
    uint32_t latest_used;       /* deprecated: only used by WR_BUF_FOREACH, no longer updated */
    uint32_t wr_entry_size;
    uint32_t max_sge;           /* max sge count per sge array in each entry */
    void *entries;
    uint32_t free_head;         /* index of first free entry, UINT32_MAX = empty */
    uint32_t *next_free;        /* next_free[idx] = next free entry index, UINT32_MAX = end */
    pthread_spinlock_t lock;    /* protects free_head and next_free */
} wr_buf_t;

static inline uint32_t __wr_id_to_idx(uint64_t wr_id, uint32_t max_wr_num)
{
    return (wr_id - 1) % max_wr_num;
}
static inline uint32_t __idx_to_wr_id(uint32_t idx)
{
    return (uint32_t)(idx + 1);
}
static inline void *__wr_buf_idx(wr_buf_t *buf, uint32_t idx)
{
    return ((char *)buf->entries + idx * buf->wr_entry_size);
}
static inline uint32_t wr_buf_idx_from_ptr(wr_buf_t *buf, char *ptr)
{
    return (uint32_t)((ptr - (char *)buf->entries) / buf->wr_entry_size);
}

#define WR_BUF_FOREACH(buf, entry_type, idx_var, entry_var)                               \
    for (uint32_t __wr_buf_i = 0, idx_var = ((buf)->latest_used + 1) % (buf)->max_wr_num; \
         __wr_buf_i < (buf)->max_wr_num &&                                                \
         ((entry_var) = (entry_type *)__wr_buf_idx((buf), idx_var), true);                \
         __wr_buf_i++, idx_var = (idx_var + 1) % (buf)->max_wr_num)

#define JFS_WR_BUF_FOREACH(buf, idx_var, entry_var) \
    WR_BUF_FOREACH((buf), jfs_wr_entry_t, idx_var, entry_var)

#define JFR_WR_BUF_FOREACH(buf, idx_var, entry_var) \
    WR_BUF_FOREACH((buf), jfr_wr_entry_t, idx_var, entry_var)

int wr_buf_init(wr_buf_t *buf, uint32_t max_wr_num, uint32_t max_sge);
void wr_buf_uninit(wr_buf_t *buf);

void jfs_wr_get_refs(urma_jfs_wr_t *wr);
void jfs_wr_put_refs(urma_jfs_wr_t *wr);

static inline jfs_wr_entry_t *jfs_wr_buf_get(wr_buf_t *buf, uint64_t wr_id)
{
    jfs_wr_entry_t *wr_entry;
    wr_entry = (jfs_wr_entry_t *)__wr_buf_idx(buf, __wr_id_to_idx(wr_id, buf->max_wr_num));
    return wr_entry->wr_id == wr_id && wr_id != 0 ? wr_entry : NULL;
}

static inline jfr_wr_entry_t *jfr_wr_buf_get(wr_buf_t *buf, uint64_t wr_id)
{
    jfr_wr_entry_t *wr_entry;
    wr_entry = (jfr_wr_entry_t *)__wr_buf_idx(buf, __wr_id_to_idx(wr_id, buf->max_wr_num));
    return wr_entry->wr_id == wr_id ? wr_entry : NULL;
}

jfs_wr_entry_t *jfs_wr_buf_alloc(wr_buf_t *buf);
jfr_wr_entry_t *jfr_wr_buf_alloc(wr_buf_t *buf);

/**
 * Batch allocation: pop up to @count entries in one lock/unlock.
 * Returns the number of entries actually allocated (may be less than @count).
 */
uint32_t jfs_wr_buf_alloc_batch(wr_buf_t *buf, jfs_wr_entry_t **entries, uint32_t count);
uint32_t jfr_wr_buf_alloc_batch(wr_buf_t *buf, jfr_wr_entry_t **entries, uint32_t count);

void jfs_wr_buf_release(wr_buf_t *buf, jfs_wr_entry_t *entry);
void jfr_wr_buf_release(wr_buf_t *buf, jfr_wr_entry_t *entry);

/**
 * Batch release: push multiple entries back in one lock/unlock.
 */
void jfs_wr_buf_release_batch(wr_buf_t *buf, jfs_wr_entry_t **entries, uint32_t count);
void jfr_wr_buf_release_batch(wr_buf_t *buf, jfr_wr_entry_t **entries, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif // BONDP_WR_BUF_H
