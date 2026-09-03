/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: helper for qbuf pool allocation
 * Create: 2026-6-26
 * Note:
 * History: 2026-6-26
 */

#include "umq_qbuf_pool_helper.h"
#include "umq_errno.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_rx_qbuf_pool.h"
#include "umq_tiny_qbuf_pool.h"
#include "umq_vlog.h"
#include <malloc.h>
#include <sys/mman.h>

static uint32_t umq_qbuf_alloc_headroom_get(umq_alloc_option_t *option)
{
    return (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ? option->headroom_size :
                                                                                     umq_qbuf_headroom_get();
}

static uint32_t umq_qbuf_alloc_effective_size(uint32_t request_size, uint32_t headroom_size)
{
    uint32_t factor = (umq_qbuf_mode_get() == UMQ_BUF_SPLIT) ? 0 : (uint32_t)sizeof(umq_buf_t);
    return request_size + headroom_size + factor;
}

static int umq_qbuf_alloc_from_pool(umq_alloc_pool_type_t pool_type, uint32_t request_size, uint32_t num,
                                    umq_alloc_option_t *option, umq_buf_list_t *list)
{
    uint32_t headroom_size = umq_qbuf_alloc_headroom_get(option);
    uint32_t effective_size = umq_qbuf_alloc_effective_size(request_size, headroom_size);

    switch (pool_type) {
        case UMQ_ALLOC_POOL_TINY:
            if (!umq_tiny_qbuf_can_alloc(request_size, effective_size)) {
                return -UMQ_ERR_EINVAL;
            }
            return umq_tiny_qbuf_alloc(request_size, num, option, list);
        case UMQ_ALLOC_POOL_HUGE: {
            huge_qbuf_pool_size_type_t type = umq_huge_qbuf_get_type_by_size(effective_size);
            return umq_huge_qbuf_alloc(type, request_size, num, option, list);
        }
        case UMQ_ALLOC_POOL_ESCAPE:
            return umq_qbuf_escape_alloc(request_size, num, option, list);
        case UMQ_ALLOC_POOL_RX:
            return umq_rx_qbuf_alloc(request_size, num, option, list);
        case UMQ_ALLOC_POOL_NORMAL:
        default:
            return umq_normal_qbuf_alloc(request_size, num, option, list);
    }
}

int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    umq_alloc_pool_type_t pool_type = UMQ_ALLOC_POOL_AUTO;
    if (option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0) {
        if (option->pool_type >= UMQ_ALLOC_POOL_MAX) {
            UMQ_VLOG_ERR(VLOG_UMQ, "alloc pool type %d invalid\n", option->pool_type);
            return -UMQ_ERR_EINVAL;
        }
        pool_type = option->pool_type;
    }

    int ret;
    if (pool_type == UMQ_ALLOC_POOL_AUTO) {
        pool_type = UMQ_ALLOC_POOL_NORMAL;
        ret = umq_qbuf_alloc_from_pool(pool_type, request_size, num, option, list);
        if (ret != UMQ_SUCCESS) {
            ret = umq_qbuf_alloc_from_pool(UMQ_ALLOC_POOL_ESCAPE, request_size, num, option, list);
        }
        return ret;
    }

    return umq_qbuf_alloc_from_pool(pool_type, request_size, num, option, list);
}

static inline uint64_t align_up_u64(uint64_t v, uint32_t align)
{
    return (v + align - 1) & ~((uint64_t)align - 1);
}

void *umq_qbuf_unified_io_buf_malloc(umq_buf_mode_t mode, const umq_qbuf_pool_plan_t *plan)
{
    if (plan == NULL) {
        return NULL;
    }

    uint64_t total_size = plan->normal_io_buf_size;
    uint64_t rx_offset = 0;
    uint64_t tiny_offset = 0;

    if (plan->rx_block_count > 0) {
        rx_offset = align_up_u64(total_size, UMQ_RX_QBUF_BLOCK_SIZE);
        total_size = rx_offset + plan->rx_io_buf_size;
    }
    if (plan->tiny_io_buf_size > 0) {
        uint32_t tiny_align = plan->tiny_block_size > 0 ? plan->tiny_block_size : UMQ_TINY_QBUF_BLOCK_SIZE;
        tiny_offset = align_up_u64(total_size, tiny_align);
        total_size = tiny_offset + plan->tiny_io_buf_size;
    }

    void *buf = (void *)memalign(QBUF_MEMALIGN_SIZE, total_size);
    if (buf == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "unified io buf malloc failed, total_size %llu, errno %d\n",
                     (unsigned long long)total_size, errno);
        return NULL;
    }
    madvise(buf, total_size, MADV_HUGEPAGE);
    qbuf_touch_huge_pages(buf, total_size);
    UMQ_VLOG_INFO(VLOG_UMQ, "malloc unified io buf %llu bytes (normal %llu + rx %llu + tiny %llu)\n",
                  (unsigned long long)total_size, (unsigned long long)plan->normal_io_buf_size,
                  (unsigned long long)plan->rx_io_buf_size, (unsigned long long)plan->tiny_io_buf_size);

    char *base = (char *)buf;
    umq_io_buf_set_buffer(base, plan->normal_io_buf_size);

    if (plan->rx_block_count > 0) {
        umq_rx_io_buf_set_buffer(base + rx_offset, plan->rx_io_buf_size);
    }
    if (plan->tiny_io_buf_size > 0) {
        umq_tiny_io_buf_set_buffer(base + tiny_offset, plan->tiny_io_buf_size);
    }

    return buf;
}

void umq_qbuf_unified_io_buf_free(void)
{
    umq_io_buf_free();
    umq_rx_io_buf_set_buffer(NULL, 0);
    umq_tiny_io_buf_set_buffer(NULL, 0);
}
