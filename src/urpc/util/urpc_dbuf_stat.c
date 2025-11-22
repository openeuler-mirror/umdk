/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc dynamic buffer statistics
 */
#include "urpc_util.h"
#include "util_log.h"
#include "urpc_dbuf_stat.h"

urpc_dbuf_stat_t g_urpc_dbuf_stat[URPC_DBUF_TYPE_MAX];
bool g_urpc_dbuf_record_enable = false;
static const char *g_urpc_dbuf_stat_name[URPC_DBUF_STAT_NUM] = {
    "Queue",
    "Channel",
    "Provider",
    "Timeout",
    "Allocator",
    "DFX",
    "Keepalive",
    "Notify",
    "Data Plane",
    "Control Plane",
    "Function",
    "Encrypt",
    "Util",
    "Total Usage"
};

void *urpc_dbuf_malloc(urpc_dbuf_type_t type, uint32_t size)
{
    if (!g_urpc_dbuf_record_enable) {
        return malloc(size);
    }

    uint64_t total_size = (uint64_t)(sizeof(urpc_dbuf_t) + size);
    urpc_dbuf_t *dbuf = (urpc_dbuf_t *)malloc(total_size);
    if (dbuf == NULL) {
        return NULL;
    }

    dbuf->size = total_size;
    dbuf->type = type;
    (void)__sync_add_and_fetch(&g_urpc_dbuf_stat[type].total_size, total_size);
    return (void *)dbuf->buf;
}

void *urpc_dbuf_calloc(urpc_dbuf_type_t type, uint32_t nitems, uint32_t size)
{
    if (!g_urpc_dbuf_record_enable) {
        return calloc(nitems, size);
    }

    uint64_t buf_size = (uint64_t)nitems * size;
    if (buf_size > UINT32_MAX) {
        return NULL;
    }

    uint64_t total_size = (uint64_t)(sizeof(urpc_dbuf_t) + buf_size);
    urpc_dbuf_t *dbuf = (urpc_dbuf_t *)calloc(1, total_size);
    if (dbuf == NULL) {
        return NULL;
    }

    dbuf->size = total_size;
    dbuf->type = type;
    (void)__sync_add_and_fetch(&g_urpc_dbuf_stat[type].total_size, total_size);
    return (void *)dbuf->buf;
}

void *urpc_dbuf_aligned_alloc(
    urpc_dbuf_type_t type, uint32_t alignment, uint32_t size, void **head_addr, uint64_t *alloc_size)
{
    uint64_t total_size = (uint64_t)size;
    if (!g_urpc_dbuf_record_enable) {
        total_size += alignment - (total_size % alignment);
        void *buf = aligned_alloc(alignment, total_size);
        *alloc_size = total_size;
        *head_addr = buf;
        return buf;
    }
 
    total_size = (uint64_t)(sizeof(urpc_dbuf_t) + size);
    total_size += alignment - (total_size % alignment);
    urpc_dbuf_t *dbuf = (urpc_dbuf_t *)aligned_alloc(alignment, total_size);
    if (dbuf == NULL) {
        return NULL;
    }
 
    dbuf->size = total_size;
    dbuf->type = type;
    *head_addr = (void *)dbuf;
    *alloc_size = total_size;
    (void)__sync_add_and_fetch(&g_urpc_dbuf_stat[type].total_size, total_size);
    return (void *)dbuf->buf;
}

void urpc_dbuf_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    if (!g_urpc_dbuf_record_enable) {
        free(ptr);
        return;
    }

    urpc_dbuf_t *dbuf = CONTAINER_OF_FIELD(ptr, urpc_dbuf_t, buf);
    if (dbuf == NULL) {
        return;
    }

    __sync_sub_and_fetch(&g_urpc_dbuf_stat[dbuf->type].total_size, dbuf->size);
    free(dbuf);
}

const char *urpc_dbuf_stat_name_get(int type)
{
    if (URPC_UNLIKELY(type >= (int)URPC_DBUF_STAT_NUM)) {
        return "Unknown";
    }

    return g_urpc_dbuf_stat_name[type];
}

void urpc_dbuf_stat_get(uint64_t *stat, int stat_len)
{
    for (int i = 0; i < (int)URPC_DBUF_TYPE_MAX && i < stat_len; i++) {
        stat[i] = __sync_add_and_fetch(&g_urpc_dbuf_stat[i].total_size, 0);
    }

    uint64_t total_size = 0;
    for (int i = 0; i < (int)URPC_DBUF_TYPE_MAX && i < stat_len; i++) {
        total_size += stat[i];
    }

    stat[URPC_DBUF_TYPE_MAX] = total_size;
}

void urpc_dbuf_stat_record_enable(void)
{
    g_urpc_dbuf_record_enable = true;
    UTIL_LOG_INFO("enable dynamic buffer statistics successful\n");
}

void urpc_dbuf_stat_record_disable(void)
{
    g_urpc_dbuf_record_enable = false;
    UTIL_LOG_INFO("disable dynamic buffer statistics successful\n");
}