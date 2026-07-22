/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: helper for qbuf pool allocation
 * Create: 2026-6-26
 * Note:
 * History: 2026-6-26
 */

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_tiny_qbuf_pool.h"
#include "umq_qbuf_pool_helper.h"

static uint32_t umq_qbuf_alloc_headroom_get(umq_alloc_option_t *option)
{
    return (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
        option->headroom_size : umq_qbuf_headroom_get();
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
        if (umq_huge_qbuf_pool_is_inited()) {
            uint32_t headroom_size = umq_qbuf_alloc_headroom_get(option);
            uint32_t effective_size = umq_qbuf_alloc_effective_size(request_size, headroom_size);
            if (effective_size >= umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID)) {
                pool_type = UMQ_ALLOC_POOL_HUGE;
            }
        }
        ret = umq_qbuf_alloc_from_pool(pool_type, request_size, num, option, list);
        if (ret != UMQ_SUCCESS && pool_type != UMQ_ALLOC_POOL_HUGE) {
            ret = umq_qbuf_alloc_from_pool(UMQ_ALLOC_POOL_ESCAPE, request_size, num, option, list);
        }
        return ret;
    }

    return umq_qbuf_alloc_from_pool(pool_type, request_size, num, option, list);
}
