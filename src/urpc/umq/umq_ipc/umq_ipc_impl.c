/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ipc impl realization for UMQ
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/futex.h>

#include "msg_ring.h"
#include "umq_vlog.h"
#include "umq_inner.h"
#include "umq_shm_qbuf_pool.h"
#include "util_id_generator.h"
#include "umq_ipc_impl.h"

typedef struct umq_ipc_init_ctx {
    uint32_t feature;
    volatile uint32_t ref_cnt;
    bool io_lock_free;
} umq_ipc_init_ctx_t;

typedef struct umq_ipc_ring_info {
    void *addr;
    int shm_fd;
    int shm_size;
    char ipc_name[MAX_MSG_RING_NAME + 1];
    uint32_t tx_buf_size;
    uint32_t tx_depth;
    uint32_t rx_buf_size;
    uint32_t rx_depth;
    uint32_t transmit_queue_buf_size;
    bool owner;
} umq_ipc_ring_info_t;

typedef struct ipc_bind_ctx {
    umq_trans_mode_t trans_mode;
    uint64_t qbuf_pool_handle;
    msg_ring_t *remote_msg_ring;
    umq_ipc_ring_info_t remote_ring;
} ipc_bind_ctx_t;

typedef struct umq_ipc_info {
    umq_trans_mode_t trans_mode;
    ipc_bind_ctx_t *bind_ctx;
    volatile uint32_t ref_cnt;
    msg_ring_t *local_msg_ring;
    uint64_t qbuf_pool_handle;
    umq_ipc_ring_info_t local_ring;
    uint32_t umq_id;
    uint64_t umqh;
    umq_queue_mode_t queue_mode;
} umq_ipc_info_t;

typedef struct umq_ipc_bind_info {
    bool is_binded;
    umq_trans_mode_t trans_mode;
    uint32_t tx_depth;
    uint32_t rx_depth;
    uint32_t shm_total_size;

    uint32_t transmit_queue_buf_size;
    uint32_t shm_qbuf_pool_data_size;         // size of one data slab
    uint32_t shm_qbuf_pool_headroom_size;     // reserve head room size
    umq_buf_mode_t shm_qbuf_pool_mode;

    char ipc_name[MAX_MSG_RING_NAME + 1];
} umq_ipc_bind_info_t;

// ipc supports only one ctx
static umq_ipc_init_ctx_t *g_ipc_ctx = NULL;
static util_id_allocator_t g_umq_id_allocator = {0};

uint8_t *umq_ipc_ctx_init_impl(umq_init_cfg_t *cfg)
{
    if (g_ipc_ctx != NULL) {
        UMQ_VLOG_WARN("umq ipc already inited\n");
        return (uint8_t *)g_ipc_ctx;
    }

    if (util_id_allocator_init(&g_umq_id_allocator, UMQ_MAX_QUEUE_NUMBER, 0) != 0) {
        UMQ_VLOG_ERR("id allocator init failed\n");
        return NULL;
    }

    g_ipc_ctx = (umq_ipc_init_ctx_t *)calloc(1, sizeof(umq_ipc_init_ctx_t));
    if (g_ipc_ctx == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        goto UNINIT_ALLOCATOR;
    }

    for (uint32_t i = 0; i < cfg->trans_info_num; ++i) {
        umq_trans_info_t *info = &cfg->trans_info[i];
        if (info->trans_mode != UMQ_TRANS_MODE_IPC) {
            UMQ_VLOG_INFO("trans init mode: %d not ipc, skip it\n", info->trans_mode);
            continue;
        }

        g_ipc_ctx->io_lock_free = cfg->io_lock_free;
        g_ipc_ctx->feature = cfg->feature;
        g_ipc_ctx->ref_cnt = 1;
        break;
    }

    if (g_ipc_ctx->ref_cnt == 0) {
        UMQ_VLOG_ERR("umq ipc not enabled\n");
        goto FREE_CTX;
    }

    return (uint8_t *)(uintptr_t)g_ipc_ctx;

FREE_CTX:
    free(g_ipc_ctx);
    g_ipc_ctx = NULL;

UNINIT_ALLOCATOR:
    util_id_allocator_uninit(&g_umq_id_allocator);
    return NULL;
}

void umq_ipc_ctx_uninit_impl(uint8_t *ipc_ctx)
{
    umq_ipc_init_ctx_t *context = (umq_ipc_init_ctx_t *)ipc_ctx;
    if (context != g_ipc_ctx) {
        UMQ_VLOG_ERR("ipc ctx is invalid\n");
        return;
    }

    if (umq_fetch_ref(context->io_lock_free, &context->ref_cnt) > 1) {
        UMQ_VLOG_ERR("device ref cnt not cleared\n");
        return;
    }

    umq_dec_ref(context->io_lock_free, &context->ref_cnt, 1);
    util_id_allocator_uninit(&g_umq_id_allocator);
    free(context);
    g_ipc_ctx = NULL;
}

static ALWAYS_INLINE int umq_ipc_map_memory(umq_ipc_ring_info_t *ring)
{
    int shm_fd = -1;
    if (ring->owner) {
        shm_fd = shm_open(ring->ipc_name, O_CREAT | O_RDWR | O_EXCL, SHM_MODE);
        if (shm_fd == -1) {
            UMQ_VLOG_ERR("shm open failed, name: %s errno: %d\n", ring->ipc_name, errno);
            goto ERR_SHM_OPEN;
        }

        // set share memory size
        if (ftruncate(shm_fd, ring->shm_size) != 0) {
            UMQ_VLOG_ERR("ftruncate failed, errno: %d\n", errno);
            goto ERR_SHM_SIZE;
        }
    } else {
        shm_fd = shm_open(ring->ipc_name, O_RDWR, SHM_MODE);
        if (shm_fd == -1) {
            UMQ_VLOG_ERR("shm open failed, name: %s errno: %d\n", ring->ipc_name, errno);
            goto ERR_SHM_OPEN;
        }
    }
    ring->shm_fd = shm_fd;
    ring->addr = mmap(0, ring->shm_size, PROT_WRITE | PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ring->addr == MAP_FAILED) {
        UMQ_VLOG_ERR("map failed, errno: %d\n", errno);
        goto ERR_SHM_MMAP;
    }

    return 0;

ERR_SHM_MMAP:
ERR_SHM_SIZE:
    close(shm_fd);
    if (ring->owner) {
        shm_unlink(ring->ipc_name);
    }

ERR_SHM_OPEN:
    return -1;
}

static ALWAYS_INLINE void umq_ipc_unmap_memory(umq_ipc_ring_info_t *ring)
{
    if (ring->addr) {
        munmap(ring->addr, ring->shm_size);
        ring->addr = NULL;
    }

    if (ring->shm_fd != -1) {
        close(ring->shm_fd);
        ring->shm_fd = -1;
    }

    if (ring->owner) {
        shm_unlink(ring->ipc_name);
    }
}

static ALWAYS_INLINE int fill_ring_info(umq_create_option_t *option, umq_ipc_ring_info_t *ring, bool owner)
{
    if (strlen(option->name) > MAX_MSG_RING_NAME) {
        UMQ_VLOG_ERR("name length exceeds %d\n", MAX_MSG_RING_NAME);
        return -UMQ_ERR_EINVAL;
    }

    (void)memcpy(ring->ipc_name, option->name, strlen(option->name));

    ring->tx_buf_size = (option->create_flag & UMQ_CREATE_FLAG_TX_BUF_SIZE) ?
        option->tx_buf_size : UMQ_DEFAULT_BUF_SIZE;
    ring->tx_depth = (option->create_flag & UMQ_CREATE_FLAG_TX_DEPTH) ? option->tx_depth : UMQ_DEFAULT_DEPTH;
    ring->rx_depth = ring->tx_depth;

    uint64_t data_zone_size =
        ring->tx_depth * (umq_buf_size_small() + sizeof(umq_buf_t) * (1 + UMQ_EMPTY_HEADER_COEFFICIENT));

    // transmit queue and manage queue size calculate
    uint64_t post_data_size = sizeof(uint32_t) + sizeof(uint64_t);
    uint64_t tx_post_queue_size = sizeof(shm_ring_hdr_t) + ring->tx_depth * post_data_size;
    uint64_t rx_post_queue_size = sizeof(shm_ring_hdr_t) + ring->tx_depth * post_data_size;
    uint64_t rounded_post_size = round_up(tx_post_queue_size + rx_post_queue_size, umq_buf_size_small());
    ring->transmit_queue_buf_size = rounded_post_size;

    ring->shm_size = round_up(data_zone_size + rounded_post_size, umq_buf_size_small());
    ring->owner = owner;

    return UMQ_SUCCESS;
}

uint64_t umq_ipc_create_impl(uint64_t umqh, uint8_t *ipc_ctx, umq_create_option_t *option)
{
    umq_ipc_init_ctx_t *ctx = (umq_ipc_init_ctx_t *)ipc_ctx;
    if (ctx != g_ipc_ctx) {
        UMQ_VLOG_ERR("ipc ctx is invalid\n");
        return UMQ_INVALID_HANDLE;
    }

    if (option->mode < 0 || option->mode >= UMQ_MODE_MAX) {
        UMQ_VLOG_ERR("queue mode[%d] is invalid\n", option->mode);
        return UMQ_INVALID_HANDLE;
    }

    umq_inc_ref(ctx->io_lock_free, &ctx->ref_cnt, 1);
    umq_ipc_info_t *tp = (umq_ipc_info_t *)calloc(1, sizeof(umq_ipc_info_t));
    if (tp == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        umq_dec_ref(ctx->io_lock_free, &ctx->ref_cnt, 1);
        return UMQ_INVALID_HANDLE;
    }

    tp->trans_mode = option->trans_mode;
    if (fill_ring_info(option, &tp->local_ring, true) != UMQ_SUCCESS) {
        goto FREE_TP;
    }

    tp->queue_mode = (option->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) ? option->mode : UMQ_MODE_POLLING;
    if (umq_ipc_map_memory(&tp->local_ring) != 0) {
        UMQ_VLOG_ERR("ipc map memory failed\n");
        goto FREE_TP;
    }

    msg_ring_option_t ipc_option = {
        .owner = true,
        .tx_max_buf_size = sizeof(uint64_t) + sizeof(uint32_t),
        .tx_depth = tp->local_ring.tx_depth,
        .rx_max_buf_size = sizeof(uint64_t) + sizeof(uint32_t),
        // rx ring is used to recycle buffers, so its count is equal to tx depth
        .rx_depth = tp->local_ring.tx_depth,
        .addr = tp->local_ring.addr,
    };
    tp->local_msg_ring = msg_ring_create("", 0, &ipc_option);
    if (tp->local_msg_ring == NULL) {
        UMQ_VLOG_ERR("ipc create failed\n");
        goto UNMAP;
    }

    tp->umq_id = util_id_allocator_get(&g_umq_id_allocator);

    qbuf_pool_cfg_t global_pool_cfg;
    umq_qbuf_config_get(&global_pool_cfg);
    // initialize shm_qbuf
    shm_qbuf_pool_cfg_t sm_qbuf_pool_cfg = {
        .buf_addr = tp->local_ring.addr + tp->local_ring.transmit_queue_buf_size,
        .total_size = tp->local_ring.shm_size - tp->local_ring.transmit_queue_buf_size,
        .data_size = umq_buf_size_small(),
        .headroom_size = global_pool_cfg.headroom_size,
        .mode = global_pool_cfg.mode,
        .type = SHM_QBUF_POOL_TYPE_LOCAL,
        .local = {
            .umqh = umqh,
            .id = tp->umq_id,
        },
        .msg_ring = tp->local_msg_ring,
    };

    tp->qbuf_pool_handle = umq_shm_global_pool_init(&sm_qbuf_pool_cfg);
    if (tp->qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        goto RELEASE_ID;
    }

    tp->umqh = umqh;
    tp->ref_cnt = 1;
    UMQ_VLOG_DEBUG("create ipc tp succeed\n");
    return (uint64_t)(uintptr_t)tp;

RELEASE_ID:
    util_id_allocator_release(&g_umq_id_allocator, tp->umq_id);
    msg_ring_destroy(tp->local_msg_ring);

UNMAP:
    umq_ipc_unmap_memory(&tp->local_ring);

FREE_TP:
    free(tp);
    umq_dec_ref(ctx->io_lock_free, &ctx->ref_cnt, 1);
    return UMQ_INVALID_HANDLE;
}

int32_t umq_ipc_destroy_impl(uint64_t umqh_tp)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (umq_fetch_ref(g_ipc_ctx->io_lock_free, &tp->ref_cnt) != 1) {
        UMQ_VLOG_ERR("umqh ref cnt is not 0\n");
        return -UMQ_ERR_EBUSY;
    }

    if (tp->bind_ctx != NULL) {
        UMQ_VLOG_ERR("umqh has not been unbinded\n");
        return -UMQ_ERR_EBUSY;
    }

    umq_shm_global_pool_uninit(tp->qbuf_pool_handle);
    util_id_allocator_release(&g_umq_id_allocator, tp->umq_id);

    // release ipc resource
    if (tp->local_msg_ring != NULL) {
        msg_ring_destroy(tp->local_msg_ring);
        tp->local_msg_ring = NULL;
    }

    umq_ipc_unmap_memory(&tp->local_ring);
    free(tp);
    umq_dec_ref(g_ipc_ctx->io_lock_free, &g_ipc_ctx->ref_cnt, 1);
    UMQ_VLOG_DEBUG("umqh destroyed\n");
    return UMQ_SUCCESS;
}

int32_t umq_ipc_bind_info_get_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (bind_info_size < sizeof(umq_ipc_bind_info_t)) {
        UMQ_VLOG_ERR("bind_info_size[%u] is less than required size[%u]\n",
            bind_info_size, sizeof(umq_ipc_bind_info_t));
        return -UMQ_ERR_EINVAL;
    }

    umq_ipc_bind_info_t *tmp_info = (umq_ipc_bind_info_t *)bind_info;
    memset(tmp_info, 0, sizeof(umq_ipc_bind_info_t));
    tmp_info->is_binded = tp->bind_ctx != NULL ? true : false;
    tmp_info->trans_mode = tp->trans_mode;
    tmp_info->tx_depth = tp->local_ring.tx_depth;
    tmp_info->rx_depth = tp->local_ring.rx_depth;
    tmp_info->shm_total_size = tp->local_ring.shm_size;
    tmp_info->transmit_queue_buf_size = tp->local_ring.transmit_queue_buf_size;

    qbuf_pool_cfg_t global_pool_cfg;
    umq_qbuf_config_get(&global_pool_cfg);
    tmp_info->shm_qbuf_pool_data_size = umq_buf_size_small();
    tmp_info->shm_qbuf_pool_headroom_size = global_pool_cfg.headroom_size;
    tmp_info->shm_qbuf_pool_mode = global_pool_cfg.mode;

    strcpy(tmp_info->ipc_name, tp->local_ring.ipc_name);

    return sizeof(umq_ipc_bind_info_t);
}

int32_t umq_ipc_bind_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    umq_ipc_bind_info_t *tmp_info = (umq_ipc_bind_info_t *)bind_info;
    if (tp->bind_ctx != NULL || tmp_info->is_binded) {
        UMQ_VLOG_ERR("umq has already been binded\n");
        return -UMQ_ERR_EEXIST;
    }

    if (bind_info_size < sizeof(umq_ipc_bind_info_t)) {
        UMQ_VLOG_ERR("bind_info_size is invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    if (tmp_info->trans_mode != UMQ_TRANS_MODE_IPC) {
        UMQ_VLOG_ERR("trans mode: %d is invalid, bind failed\n", tmp_info->trans_mode);
        return -UMQ_ERR_EINVAL;
    }
    ipc_bind_ctx_t *ctx = (ipc_bind_ctx_t *)calloc(1, sizeof(ipc_bind_ctx_t));
    if (ctx == NULL) {
        UMQ_VLOG_ERR("bind ctx alloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    ctx->remote_ring.shm_size = tmp_info->shm_total_size;
    ctx->remote_ring.tx_buf_size = umq_buf_size_small();
    ctx->remote_ring.tx_depth = tmp_info->tx_depth;
    ctx->remote_ring.rx_buf_size = umq_buf_size_small();
    ctx->remote_ring.rx_depth = tmp_info->rx_depth;
    ctx->remote_ring.transmit_queue_buf_size = tmp_info->transmit_queue_buf_size;
    ctx->remote_ring.owner = false;
    (void)memcpy(ctx->remote_ring.ipc_name, tmp_info->ipc_name, strlen(tmp_info->ipc_name));

    if (umq_ipc_map_memory(&ctx->remote_ring) != 0) {
        UMQ_VLOG_ERR("ipc map memory failed\n");
        goto FREE_CTX;
    }

    msg_ring_option_t ipc_option = {
        .owner = false,
        .tx_max_buf_size = sizeof(uint64_t) + sizeof(uint32_t),
        .tx_depth = ctx->remote_ring.tx_depth,
        .rx_max_buf_size = sizeof(uint64_t) + sizeof(uint32_t),
        .rx_depth = ctx->remote_ring.tx_depth,
        .addr = ctx->remote_ring.addr,
    };

    ctx->remote_msg_ring = msg_ring_create("", 0, &ipc_option);
    if (ctx->remote_msg_ring == NULL) {
        goto UNMAP;
    }

    shm_qbuf_pool_cfg_t sm_qbuf_pool_cfg = {
        .buf_addr = ctx->remote_ring.addr + ctx->remote_ring.transmit_queue_buf_size,
        .total_size = ctx->remote_ring.shm_size - ctx->remote_ring.transmit_queue_buf_size,
        .data_size = umq_buf_size_small(),
        .headroom_size = tmp_info->shm_qbuf_pool_headroom_size,
        .mode = tmp_info->shm_qbuf_pool_mode,
        .type = SHM_QBUF_POOL_TYPE_REMOTE,
        .msg_ring = ctx->remote_msg_ring,
    };

    ctx->qbuf_pool_handle = umq_shm_global_pool_init(&sm_qbuf_pool_cfg);
    if (ctx->qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        goto DESTROY_IPC;
    }

    ctx->trans_mode = UMQ_TRANS_MODE_IPC;
    tp->bind_ctx = ctx;
    UMQ_VLOG_DEBUG("bind succeed\n");
    return UMQ_SUCCESS;

DESTROY_IPC:
    msg_ring_destroy(ctx->remote_msg_ring);

UNMAP:
    umq_ipc_unmap_memory(&ctx->remote_ring);

FREE_CTX:
    free(ctx);
    return UMQ_FAIL;
}

int32_t umq_ipc_unbind_impl(uint64_t umqh_tp)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    msg_ring_destroy(tp->bind_ctx->remote_msg_ring);
    umq_ipc_unmap_memory(&tp->bind_ctx->remote_ring);

    umq_shm_global_pool_uninit(tp->bind_ctx->qbuf_pool_handle);
    free(tp->bind_ctx);
    tp->bind_ctx = NULL;
    UMQ_VLOG_DEBUG("unbind succeed\n");
    return UMQ_SUCCESS;
}

int umq_ipc_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf)
{
    return UMQ_FAIL;
}

int umq_ipc_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count)
{
    return UMQ_FAIL;
}

static ALWAYS_INLINE bool is_local_addr(umq_ipc_info_t *tp, umq_buf_t *qbuf)
{
    uint64_t addr = (uint64_t)(uintptr_t)qbuf;
    uint64_t addr_from = (uint64_t)(uintptr_t)tp->local_ring.addr;
    uint64_t addr_to = addr_from + (uint64_t)(uintptr_t)tp->local_ring.shm_size;
    return (addr_from <= addr) && (addr < addr_to);
}

static ALWAYS_INLINE bool is_remote_addr(umq_ipc_info_t *tp, umq_buf_t *qbuf)
{
    if (tp->bind_ctx == NULL) {
        return false;
    }

    uint64_t addr = (uint64_t)(uintptr_t)qbuf;
    uint64_t addr_from = (uint64_t)(uintptr_t)tp->bind_ctx->remote_ring.addr;
    uint64_t addr_to = addr_from + (uint64_t)(uintptr_t)tp->bind_ctx->remote_ring.shm_size;
    return (addr_from <= addr) && (addr < addr_to);
}

static ALWAYS_INLINE int enqueue_data(uint64_t umqh_tp, uint64_t *offset, uint32_t num)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (num > UMQ_POST_POLL_BATCH) {
        UMQ_LIMIT_VLOG_ERR("enqueue data num %u exceeds max_post_size %d\n", num, UMQ_POST_POLL_BATCH);
        return -UMQ_ERR_EINVAL;
    }

    uint32_t sizes[num];
    for (uint32_t i = 0; i < num; i++) {
        sizes[i] = sizeof(uint64_t);
    }

    int ret = msg_ring_post_tx_batch(tp->local_msg_ring, (char **)&offset, sizes, num);
    if (ret != 0) {
        UMQ_LIMIT_VLOG_ERR("ipc post tx failed\n");
        return ret;
    }
    return UMQ_SUCCESS;
}

int umq_ipc_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }
    if (!is_local_addr(tp, qbuf)) {
        UMQ_LIMIT_VLOG_ERR("qbuf addr is not local addr\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_shm_qbuf_enqueue(qbuf, umqh_tp, tp->qbuf_pool_handle, false, enqueue_data);
    if (ret != UMQ_SUCCESS) {
        *bad_qbuf = qbuf;
    }

    return ret;
}

static ALWAYS_INLINE int dequeue_data(uint64_t umq_tp, uint64_t *offset, uint32_t num)
{
    uint64_t *rx_data_ptr[num];
    for (uint32_t i = 0; i < num; i++) {
        rx_data_ptr[i] = &offset[i];
    }

    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umq_tp;
    // poll offset from shm, then transform to qbuf
    uint32_t polled_buf_size[num];
    int ret = msg_ring_poll_tx_batch(tp->bind_ctx->remote_msg_ring, (char **)&rx_data_ptr,
        sizeof(uint64_t), polled_buf_size, num);
    if (ret < 0) {
        UMQ_LIMIT_VLOG_ERR("ipc poll rx failed\n");
        return -UMQ_ERR_EINVAL;
    }

    return ret;
}

umq_buf_t *umq_ipc_dequeue_impl(uint64_t umqh_tp)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return NULL;
    }

    // poll shm queue
    bool rendezvous = false;
    umq_buf_t *polled_buf = umq_shm_qbuf_dequeue(tp->umqh, umqh_tp, tp->bind_ctx->qbuf_pool_handle,
        &rendezvous, dequeue_data);
    if (polled_buf == NULL) {
        UMQ_LIMIT_VLOG_DEBUG("umq_shm_qbuf_dequeue return nothing\n");
    }

    return polled_buf;
}

umq_buf_t *umq_ipc_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR("no qbuf pool is valid for this umq\n");
        return NULL;
    }

    umq_buf_list_t head;
    QBUF_LIST_INIT(&head);
    if (umq_shm_qbuf_alloc(tp->qbuf_pool_handle, request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
        return NULL;
    }

    return QBUF_LIST_FIRST(&head);
}

void umq_tp_ipc_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    uint64_t qbuf_pool_handle = UMQ_INVALID_HANDLE;
    if (is_remote_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->bind_ctx->qbuf_pool_handle;
    } else if (is_local_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->qbuf_pool_handle;
    } else {
        UMQ_VLOG_ERR("qbuf is invalid for this umq\n");
    }

    if (qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR("no qbuf pool is valid for this umq\n");
        return;
    }

    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    umq_shm_qbuf_free(qbuf_pool_handle, &head);
}

int umq_tp_ipc_buf_headroom_reset_impl(umq_buf_t *qbuf, uint16_t headroom_size)
{
    umq_t *umq = (umq_t *)(uintptr_t)qbuf->umqh;
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umq->umqh_tp;
    uint64_t qbuf_pool_handle = UMQ_INVALID_HANDLE;
    if (is_remote_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->bind_ctx->qbuf_pool_handle;
    } else if (is_local_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->qbuf_pool_handle;
    } else {
        UMQ_VLOG_ERR("qbuf is invalid for this umq\n");
    }

    if (qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR("no qbuf pool is valid for this umq\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq_shm_qbuf_headroom_reset(qbuf_pool_handle, qbuf, headroom_size);
}

static ALWAYS_INLINE int futex_wake(atomic_int *addr, int n)
{
    return syscall(SYS_futex, addr, FUTEX_WAKE, n, NULL, NULL, 0);
}

void umq_ipc_notify_impl(uint64_t umqh_tp)
{
    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->queue_mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return;
    }

    // notify peer that some events triggered
    atomic_store(&tp->local_msg_ring->shm_tx_ring_hdr->cq_event_flag, 1);
    atomic_fetch_add(&tp->local_msg_ring->shm_tx_ring_hdr->pending_events, 1);
    futex_wake(&tp->local_msg_ring->shm_tx_ring_hdr->cq_event_flag, 1);
}

int umq_ipc_rearm_interrupt_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->queue_mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return -UMQ_ERR_EINVAL;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE int futex_wait(atomic_int *addr, int val, int timeout)
{
    int ret = -1;
    struct timespec ts;
    struct timespec *ts_ptr = NULL;
    if (timeout >= 0) {
        ts.tv_sec = timeout / MS_PER_SEC;
        ts.tv_nsec = (timeout % MS_PER_SEC) * NS_PER_MS;
        ts_ptr = &ts;
    } else if (timeout < -1) {
        return ret;
    }

    do { // handle spurious wakeup
        ret = syscall(SYS_futex, addr, FUTEX_WAIT, val, ts_ptr, NULL, 0);
        if (ret == 0 || errno == EAGAIN || errno == EINTR) {
            continue;
        } else if (ret == -1) {
            break;
        }
    } while (atomic_load(addr) == val);

    return ret;
}

int32_t umq_ipc_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)wait_umqh_tp;
    if (tp->queue_mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return -UMQ_ERR_EINVAL;
    }
    shm_ring_hdr_t *hdr = option->direction == UMQ_IO_TX ? tp->local_msg_ring->shm_tx_ring_hdr :
        tp->bind_ctx->remote_msg_ring->shm_tx_ring_hdr;

    int ret = futex_wait(&hdr->cq_event_flag, 0, time_out);
    if (ret == 0 || errno == EAGAIN) {
        return atomic_load(&hdr->pending_events);
    } else if (errno == ETIMEDOUT) {
        return 0;
    }

    return ret;
}

void umq_ipc_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option invalid\n");
        return;
    }

    umq_ipc_info_t *tp = (umq_ipc_info_t *)(uintptr_t)umqh_tp;
    if (tp->queue_mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return;
    }
    shm_ring_hdr_t *hdr = option->direction == UMQ_IO_TX ? tp->local_msg_ring->shm_tx_ring_hdr :
        tp->bind_ctx->remote_msg_ring->shm_tx_ring_hdr;

    atomic_fetch_sub(&hdr->pending_events, nevents);
    if (atomic_load(&hdr->pending_events) == 0) {
        atomic_store(&hdr->cq_event_flag, 0);
    }
}
