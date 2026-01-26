/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc dynamic buffer statistics
 */
#ifndef URPC_BUF_STAT_H
#define URPC_BUF_STAT_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct urpc_dbuf {
    uint64_t size : 32;
    uint64_t type : 6;
    uint64_t rsvd : 26;
    uint8_t buf[0];
} urpc_dbuf_t;

typedef enum urpc_dbuf_type {
    URPC_DBUF_TYPE_QUEUE,
    URPC_DBUF_TYPE_CHANNEL,
    URPC_DBUF_TYPE_PROVIDER,
    URPC_DBUF_TYPE_TIMEOUT,
    URPC_DBUF_TYPE_ALLOCATOR,
    URPC_DBUF_TYPE_DFX,
    URPC_DBUF_TYPE_KEEPALIVE,
    URPC_DBUF_TYPE_NOTIFY,
    URPC_DBUF_TYPE_DP,
    URPC_DBUF_TYPE_CP,
    URPC_DBUF_TYPE_FUNC,
    URPC_DBUF_TYPE_ENCRYPT,
    URPC_DBUF_TYPE_UTIL,
    URPC_DBUF_TYPE_MAX,
} urpc_dbuf_type_t;

#define URPC_DBUF_STAT_NUM (URPC_DBUF_TYPE_MAX + 1)     // statistics data includes one more "total usage"

typedef struct urpc_dbuf_stat {
    volatile uint64_t total_size;
} urpc_dbuf_stat_t;

void *urpc_dbuf_malloc(urpc_dbuf_type_t type, uint32_t size);
void *urpc_dbuf_calloc(urpc_dbuf_type_t type, uint32_t nitems, uint32_t size);
void *urpc_dbuf_aligned_alloc(
    urpc_dbuf_type_t type, uint32_t alignment, uint32_t size, void **head_addr, uint64_t *alloc_size);
void urpc_dbuf_free(void *ptr);

const char *urpc_dbuf_stat_name_get(int type);
void urpc_dbuf_stat_get(uint64_t *stat, int stat_len);

void urpc_dbuf_stat_record_enable(void);
void urpc_dbuf_stat_record_disable(void);

#ifdef __cplusplus
}
#endif

#endif