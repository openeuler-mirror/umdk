/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ubmm impl realization for UMQ
 */
#include <string.h>

#include "umq_vlog.h"
#include "obmem_common.h"
#include "umq_inner.h"
#include "umq_ub_impl.h"
#include "umq_shm_qbuf_pool.h"
#include "util_id_generator.h"
#include "msg_ring.h"
#include "umq_ub_imm_data.h"
#include "umq_ubmm_impl.h"

#define UMQ_MAX_TSEG_NUM 255

typedef struct umq_ubmm_init_ctx {
    uint8_t *ub_init_ctx;
    umq_trans_info_t trans_info;
    uint32_t feature;
    volatile uint32_t ref_cnt;
    uint16_t local_cna;
    uint32_t ubmm_eid;     // ub controller eid
    bool io_lock_free;
} umq_ubmm_init_ctx_t;

typedef struct umq_ubmm_ring_buffer {
    void *addr;
    uint64_t handle;
    obmem_export_info_t ubmm_export;
    uint32_t tx_buf_size;
    uint32_t tx_depth;
    uint32_t rx_buf_size;
    uint32_t rx_depth;
    uint32_t transmit_queue_buf_size;
    uint16_t cna;
} umq_ubmm_ring_buffer_t;

typedef struct ubmm_bind_ctx {
    msg_ring_t *remote_msg_ring;
    uint64_t remote_notify_addr;
    uint64_t qbuf_pool_handle;
    umq_ubmm_ring_buffer_t remote_ring;
} ubmm_bind_ctx_t;

typedef struct umq_ubmm_info {
    ubmm_bind_ctx_t *bind_ctx;
    umq_ubmm_init_ctx_t *ubmm_ctx;
    uint64_t ub_handle;
    msg_ring_t *local_msg_ring;
    umq_buf_t *notify_buf;
    uint64_t qbuf_pool_handle;
    umq_ubmm_ring_buffer_t local_ring;
    volatile uint32_t ref_cnt;
    uint32_t umq_id;
    uint64_t umqh;
} umq_ubmm_info_t;

typedef struct umq_ubmm_bind_info {
    bool is_binded;
    umq_trans_mode_t trans_mode;
    // ubmem related
    uint32_t token_id;
    uint64_t uba;
    uint64_t size;
    uint16_t cna;

    uint64_t notify_buf;
    // shm ring related
    uint32_t tx_depth;
    uint32_t rx_depth;

    // shm buf pool related
    uint32_t transmit_queue_buf_size;
    uint32_t shm_qbuf_pool_data_size;         // size of one data slab
    uint32_t shm_qbuf_pool_headroom_size;     // reserve head room size
    umq_buf_mode_t shm_qbuf_pool_mode;
    uint32_t peer_eid;
} umq_ubmm_bind_info_t;

typedef struct umq_ubmm_ref_sge_info {
    uint32_t sge_num;
    uint16_t msg_id;
    char ub_ref_info[0];
} __attribute__((packed)) umq_ubmm_ref_sge_info_t;
static const uint32_t UMQ_IPC_DATA_SIZE = sizeof(uint64_t) + sizeof(uint32_t);
static umq_ubmm_init_ctx_t *g_ubmm_ctx = NULL;
static uint32_t g_ubmm_ctx_count = 0;
util_id_allocator_t g_umq_id_allocator = {0};

uint8_t *umq_ubmm_ctx_init_impl(umq_init_cfg_t *cfg)
{
    if (g_ubmm_ctx_count > 0) {
        UMQ_VLOG_WARN("already inited\n");
        return (uint8_t *)g_ubmm_ctx;
    }

    if (util_id_allocator_init(&g_umq_id_allocator, UMQ_MAX_QUEUE_NUMBER, 0) != 0) {
        UMQ_VLOG_ERR("id allocator init failed\n");
        return NULL;
    }

    g_ubmm_ctx = (umq_ubmm_init_ctx_t *)calloc(MAX_UMQ_TRANS_INFO_NUM, sizeof(umq_ubmm_init_ctx_t));
    if (g_ubmm_ctx == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        goto UNINIT_ALLOCATOR;
    }

    uint8_t *ub_init_ctx = NULL;
    for (uint32_t i = 0; i < cfg->trans_info_num; ++i) {
        umq_trans_info_t *info = &cfg->trans_info[i];
        if (info->trans_mode != UMQ_TRANS_MODE_UBMM && info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
            UMQ_VLOG_INFO("trans init mode: %d not UBMM, skip it\n", info->trans_mode);
            continue;
        }

        if (ub_init_ctx == NULL) {
            ub_init_ctx = umq_ub_ctx_init_impl(cfg);
            if (ub_init_ctx == NULL) {
                goto FREE_CTX;
            }
        }

        (void)memcpy(&g_ubmm_ctx[g_ubmm_ctx_count].trans_info, info, sizeof(umq_trans_info_t));
        g_ubmm_ctx[g_ubmm_ctx_count].io_lock_free = cfg->io_lock_free;
        g_ubmm_ctx[g_ubmm_ctx_count].feature = cfg->feature;
        g_ubmm_ctx[g_ubmm_ctx_count].ub_init_ctx = ub_init_ctx;
        g_ubmm_ctx[g_ubmm_ctx_count].local_cna = cfg->cna;
        g_ubmm_ctx[g_ubmm_ctx_count].ubmm_eid = cfg->ubmm_eid;
        g_ubmm_ctx[g_ubmm_ctx_count].ref_cnt = 1;
        ++g_ubmm_ctx_count;
    }

    if (g_ubmm_ctx_count == 0) {
        goto UNINIT_UB;
    }

    return (uint8_t *)(uintptr_t)g_ubmm_ctx;

UNINIT_UB:
    if (ub_init_ctx != NULL) {
        umq_ub_ctx_uninit_impl(ub_init_ctx);
    }

FREE_CTX:
    g_ubmm_ctx_count = 0;
    free(g_ubmm_ctx);
    g_ubmm_ctx = NULL;

UNINIT_ALLOCATOR:
    util_id_allocator_uninit(&g_umq_id_allocator);
    return NULL;
}

void umq_ubmm_ctx_uninit_impl(uint8_t *ubmm_ctx)
{
    umq_ubmm_init_ctx_t *context = (umq_ubmm_init_ctx_t *)ubmm_ctx;
    if (context != g_ubmm_ctx) {
        UMQ_VLOG_ERR("ubmm ctx is invalid\n");
        return;
    }

    for (uint32_t i = 0; i < g_ubmm_ctx_count; ++i) {
        if (umq_fetch_ref(context[i].io_lock_free, &context[i].ref_cnt) > 1) {
            UMQ_VLOG_ERR("device ref cnt not cleared\n");
            return;
        }
    }

    bool ub_ctx_uninited = false;
    for (uint32_t i = 0; i < g_ubmm_ctx_count; ++i) {
        if (context[i].ub_init_ctx != NULL && !ub_ctx_uninited) {
            umq_ub_ctx_uninit_impl(context[i].ub_init_ctx);
            ub_ctx_uninited = true;
        }

        umq_dec_ref(context[i].io_lock_free, &context[i].ref_cnt, 1);
    }

    util_id_allocator_uninit(&g_umq_id_allocator);
    free(context);
    g_ubmm_ctx = NULL;
    g_ubmm_ctx_count = 0;
}

uint64_t umq_ubmm_create_impl(uint64_t umqh, uint8_t *ubmm_ctx, umq_create_option_t *option)
{
    umq_ubmm_init_ctx_t *ctx = (umq_ubmm_init_ctx_t *)ubmm_ctx;
    umq_ubmm_init_ctx_t *dev_ctx = NULL;
    for (uint32_t i = 0; i < g_ubmm_ctx_count; i++) {
        if (memcmp(&ctx[i].trans_info.dev_info, &option->dev_info, sizeof(umq_dev_assign_t)) == 0) {
            dev_ctx = &ctx[i];
            break;
        }
    }

    if (dev_ctx == NULL) {
        UMQ_VLOG_ERR("device find failed\n");
        return UMQ_INVALID_HANDLE;
    }

    umq_inc_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)calloc(1, sizeof(umq_ubmm_info_t));
    if (tp == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
        return UMQ_INVALID_HANDLE;
    }

    // call ub create
    tp->ub_handle = umq_ub_create_impl(umqh, dev_ctx->ub_init_ctx, option);
    if (tp->ub_handle == UMQ_INVALID_HANDLE) {
        goto FREE_INFO;
    }

    tp->local_ring.tx_buf_size = (option->create_flag & UMQ_CREATE_FLAG_TX_BUF_SIZE) ?
                                 option->tx_buf_size : UMQ_DEFAULT_BUF_SIZE;
    tp->local_ring.tx_depth = (option->create_flag & UMQ_CREATE_FLAG_TX_DEPTH) ?
                              option->tx_depth : UMQ_DEFAULT_DEPTH;

    /*
        shared memory layout
    -------------------------------------------------------------
    |                       transmit queue                      |
    -------------------------------------------------------------
    |                        manage queue                       |
    -------------------------------------------------------------
    |                              .                            |
    |                              .                            |
    |                          data zone                        |
    |                              .                            |
    |                              .                            |
    -------------------------------------------------------------
        */

    // data zone size calculate
    uint32_t header_multiply = 1 + UMQ_EMPTY_HEADER_COEFFICIENT;
    uint64_t data_zone_size = tp->local_ring.tx_depth * (UMQ_SIZE_SMALL + sizeof(umq_buf_t) * header_multiply);

    // transmit queue and manage queue size calculate
    uint64_t post_data_size = sizeof(uint32_t) + sizeof(uint64_t);
    uint64_t tx_post_queue_size = sizeof(shm_ring_hdr_t) + tp->local_ring.tx_depth * post_data_size;
    uint64_t rx_post_queue_size = sizeof(shm_ring_hdr_t) + tp->local_ring.tx_depth * post_data_size * header_multiply;
    uint64_t rounded_post_size = round_up(tx_post_queue_size + rx_post_queue_size, UMQ_SIZE_SMALL);

    uint64_t total_size = round_up(data_zone_size + rounded_post_size, UMQ_SIZE_4M);
    obmem_export_memory_param_t export_param = {
        .len = total_size,
        .cacheable = false,
    };

    *(uint32_t *)export_param.deid = dev_ctx->ubmm_eid;
    tp->local_ring.transmit_queue_buf_size = rounded_post_size;
    tp->local_ring.addr =
        obmem_export_memory(&export_param, &tp->local_ring.handle, &tp->local_ring.ubmm_export);
    if (tp->local_ring.addr == NULL) {
        UMQ_VLOG_ERR("ubmem export memory failed\n");
        goto DESTROY_UB;
    }

    tp->local_ring.cna = dev_ctx->local_cna;
    msg_ring_option_t ipc_option = {
        .owner = true,
        .tx_max_buf_size = UMQ_IPC_DATA_SIZE,
        .tx_depth = tp->local_ring.tx_depth,
        .rx_max_buf_size = UMQ_IPC_DATA_SIZE,
        // rx ring is used to recycle buffers, so its count is equal to tx depth
        .rx_depth = tp->local_ring.tx_depth,
        .addr = tp->local_ring.addr,
    };

    tp->local_msg_ring = msg_ring_create("", 0, &ipc_option);
    if (tp->local_msg_ring == NULL) {
        UMQ_VLOG_ERR("ipc create failed\n");
        goto RELEASE_EXPORT;
    }

    tp->umq_id = util_id_allocator_get(&g_umq_id_allocator);
    qbuf_pool_cfg_t global_pool_cfg;
    umq_qbuf_config_get(&global_pool_cfg);
    // initialize shm_qbuf
    shm_qbuf_pool_cfg_t sm_qbuf_pool_cfg = {
        .buf_addr = tp->local_ring.addr + tp->local_ring.transmit_queue_buf_size,
        .total_size = total_size - tp->local_ring.transmit_queue_buf_size,
        .data_size = UMQ_SIZE_SMALL,
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
        goto DESTROY_IPC;
    }

    tp->notify_buf = umq_buf_alloc(1, 1, UMQ_INVALID_HANDLE, NULL);
    if (tp->notify_buf == NULL) {
        UMQ_VLOG_ERR("buf alloc failed\n");
        goto UNINIT_SM_POOL;
    }

    tp->umqh = umqh;
    tp->ubmm_ctx = dev_ctx;
    tp->ref_cnt = 1;
    UMQ_VLOG_INFO("create ubmm tp succeed, umq id: %d\n", tp->umq_id);
    return (uint64_t)(uintptr_t)tp;

UNINIT_SM_POOL:
    umq_shm_global_pool_uninit(tp->qbuf_pool_handle);

DESTROY_IPC:
    if (tp->local_msg_ring != NULL) {
        msg_ring_destroy(tp->local_msg_ring);
    }

RELEASE_EXPORT:
    if (tp->local_ring.handle != 0) {
        obmem_release_export_memory(tp->local_ring.handle, tp->local_ring.addr, total_size);
    }

DESTROY_UB:
    umq_ub_destroy_impl(tp->ub_handle);

FREE_INFO:
    free(tp);

    umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
    return UMQ_INVALID_HANDLE;
}

int32_t umq_ubmm_destroy_impl(uint64_t umqh_tp)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;

    if (umq_fetch_ref(tp->ubmm_ctx->io_lock_free, &tp->ref_cnt) != 1) {
        UMQ_VLOG_ERR("umqh ref cnt is not 0");
        return -UMQ_ERR_EINVAL;
    }

    if (tp->bind_ctx != NULL) {
        UMQ_VLOG_ERR("umqh[%lu] has not been unbinded", umqh_tp);
        return -UMQ_ERR_ENODEV;
    }

    msg_ring_destroy(tp->local_msg_ring);
    // release ub resource first
    umq_buf_free(tp->notify_buf);
    umq_shm_global_pool_uninit(tp->qbuf_pool_handle);
    umq_ub_destroy_impl(tp->ub_handle);
    obmem_release_export_memory(tp->local_ring.handle, tp->local_ring.addr, tp->local_ring.ubmm_export.size);

    util_id_allocator_release(&g_umq_id_allocator, tp->umq_id);
    umq_dec_ref(tp->ubmm_ctx->io_lock_free, &tp->ubmm_ctx->ref_cnt, 1);
    free(tp);
    return UMQ_SUCCESS;
}

int32_t umq_ubmm_bind_info_get_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (bind_info_size < sizeof(umq_ubmm_bind_info_t)) {
        UMQ_VLOG_ERR("bind_info_size[%u] is less than required size[%u]",
            bind_info_size, sizeof(umq_ubmm_bind_info_t));
        return -UMQ_ERR_EINVAL;
    }

    int32_t ret = 0;
    ret = umq_ub_bind_info_get_impl(tp->ub_handle, bind_info + sizeof(umq_ubmm_bind_info_t),
        bind_info_size - sizeof(umq_ubmm_bind_info_t));
    if (ret <= 0) {
        UMQ_VLOG_ERR("umq get ub bind info failed\n");
        return -UMQ_ERR_ENODEV;
    }

    umq_ubmm_bind_info_t *tmp_info = (umq_ubmm_bind_info_t *)bind_info;
    tmp_info->is_binded = tp->bind_ctx != NULL ? true : false;
    tmp_info->trans_mode = tp->ubmm_ctx->trans_info.trans_mode;
    tmp_info->token_id = tp->local_ring.ubmm_export.token_id;
    tmp_info->uba = tp->local_ring.ubmm_export.uba;
    tmp_info->size = tp->local_ring.ubmm_export.size;
    tmp_info->tx_depth = tp->local_ring.tx_depth;
    // remote size use rx depth to recycle memory, so rx_depth is equal to tx_depth
    tmp_info->rx_depth = tp->local_ring.tx_depth;
    tmp_info->cna = tp->ubmm_ctx->local_cna;
    tmp_info->transmit_queue_buf_size = tp->local_ring.transmit_queue_buf_size;
    tmp_info->notify_buf = (uint64_t)(uintptr_t)tp->notify_buf->buf_data;

    qbuf_pool_cfg_t global_pool_cfg;
    umq_qbuf_config_get(&global_pool_cfg);
    tmp_info->shm_qbuf_pool_data_size = UMQ_SIZE_SMALL;
    tmp_info->shm_qbuf_pool_headroom_size = global_pool_cfg.headroom_size;
    tmp_info->shm_qbuf_pool_mode = global_pool_cfg.mode;
    tmp_info->peer_eid = tp->ubmm_ctx->ubmm_eid;

    return sizeof(umq_ubmm_bind_info_t) + ret;
}

int32_t umq_ubmm_bind_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    umq_ubmm_bind_info_t *tmp_info = (umq_ubmm_bind_info_t *)bind_info;
    if (tp->bind_ctx != NULL || tmp_info->is_binded) {
        UMQ_VLOG_ERR("umq has already been binded\n");
        return -UMQ_ERR_EEXIST;
    }

    if (bind_info_size < sizeof(umq_ubmm_bind_info_t)) {
        UMQ_VLOG_ERR("bind_info_size is invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    ubmm_bind_ctx_t *ctx = (ubmm_bind_ctx_t *)calloc(1, sizeof(ubmm_bind_ctx_t));
    if (ctx == NULL) {
        UMQ_VLOG_ERR("bind ctx alloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    int ret = UMQ_SUCCESS;
    if (tmp_info->trans_mode != UMQ_TRANS_MODE_UBMM && tmp_info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_ERR("trans mode: %d is invalid\n", tmp_info->trans_mode);
        ret = -UMQ_ERR_EINVAL;
        goto FREE_CTX;
    }
    ret = umq_ub_bind_impl(tp->ub_handle, bind_info + sizeof(umq_ubmm_bind_info_t),
                           bind_info_size - sizeof(umq_ubmm_bind_info_t));
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("ub bind failed");
        goto FREE_CTX;
    }

    ctx->remote_ring.ubmm_export.token_id = tmp_info->token_id;
    ctx->remote_ring.ubmm_export.uba = tmp_info->uba;
    ctx->remote_ring.ubmm_export.size = tmp_info->size;
    ctx->remote_ring.tx_depth = tmp_info->tx_depth;
    ctx->remote_ring.rx_depth = tmp_info->rx_depth;
    ctx->remote_ring.transmit_queue_buf_size = tmp_info->transmit_queue_buf_size;
    ctx->remote_ring.cna = tmp_info->cna;
    ctx->remote_notify_addr = tmp_info->notify_buf;

    obmem_import_memory_param_t import_param = {
        .import_cna = tp->ubmm_ctx->local_cna,
        .export_cna = ctx->remote_ring.cna,
        .cacheable = false,
    };

    *(uint32_t *)import_param.seid = tp->ubmm_ctx->ubmm_eid;
    *(uint32_t *)import_param.deid = tmp_info->peer_eid;
    ctx->remote_ring.addr = obmem_import_memory(&import_param, &ctx->remote_ring.ubmm_export, &ctx->remote_ring.handle);
    if (ctx->remote_ring.addr == NULL) {
        UMQ_VLOG_ERR("ubmm import memory failed\n");
        ret = UMQ_FAIL;
        goto UB_UNBIND;
    }

    msg_ring_option_t ipc_option = {
        .owner = false,
        .tx_max_buf_size = UMQ_IPC_DATA_SIZE,
        .tx_depth = ctx->remote_ring.tx_depth,
        .rx_max_buf_size = UMQ_IPC_DATA_SIZE,
        .rx_depth = ctx->remote_ring.rx_depth,
        .addr = ctx->remote_ring.addr,
    };

    ctx->remote_msg_ring = msg_ring_create("", 0, &ipc_option);
    if (ctx->remote_msg_ring == NULL) {
        UMQ_VLOG_ERR("ipc create failed\n");
        ret = UMQ_FAIL;
        goto UNIMPORT;
    }

    if (tmp_info->size < tmp_info->transmit_queue_buf_size) {
        UMQ_VLOG_ERR("transmit queue buf size should be less than shm buf size\n");
        ret = UMQ_FAIL;
        goto DESTROY_IPC;
    }
    shm_qbuf_pool_cfg_t sm_qbuf_pool_cfg = {
        .buf_addr = ctx->remote_ring.addr + tmp_info->transmit_queue_buf_size,
        .total_size = tmp_info->size - tmp_info->transmit_queue_buf_size,
        .data_size = UMQ_SIZE_SMALL,
        .headroom_size = tmp_info->shm_qbuf_pool_headroom_size,
        .mode = tmp_info->shm_qbuf_pool_mode,
        .type = SHM_QBUF_POOL_TYPE_REMOTE,
        .msg_ring = ctx->remote_msg_ring,
    };

    ctx->qbuf_pool_handle = umq_shm_global_pool_init(&sm_qbuf_pool_cfg);
    if (ctx->qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        ret = UMQ_FAIL;
        goto DESTROY_IPC;
    }

    tp->bind_ctx = ctx;
    UMQ_VLOG_INFO("ubmm bind succeed\n");
    return UMQ_SUCCESS;

DESTROY_IPC:
    msg_ring_destroy(ctx->remote_msg_ring);

UNIMPORT:
    obmem_release_import_memory(ctx->remote_ring.handle, ctx->remote_ring.addr, ctx->remote_ring.ubmm_export.size);

UB_UNBIND:
    umq_ub_unbind_impl(tp->ub_handle);

FREE_CTX:
    free(ctx);

    return ret;
}

int32_t umq_ubmm_unbind_impl(uint64_t umqh_tp)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    if (umq_ub_unbind_impl(tp->ub_handle) != UMQ_SUCCESS) {
        return -UMQ_ERR_EAGAIN;
    }

    msg_ring_destroy(tp->bind_ctx->remote_msg_ring);
    umq_shm_global_pool_uninit(tp->bind_ctx->qbuf_pool_handle);
    obmem_release_import_memory(tp->bind_ctx->remote_ring.handle, tp->bind_ctx->remote_ring.addr,
                                tp->bind_ctx->remote_ring.ubmm_export.size);
    free(tp->bind_ctx);
    tp->bind_ctx = NULL;

    return UMQ_SUCCESS;
}

umq_buf_t *umq_ubmm_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
                                   umq_alloc_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
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

static ALWAYS_INLINE bool is_local_addr(umq_ubmm_info_t *tp, umq_buf_t *qbuf)
{
    uint64_t addr = (uint64_t)(uintptr_t)qbuf;
    return addr >= (uint64_t)(uintptr_t)tp->local_ring.addr &&
    addr < (uint64_t)(uintptr_t)tp->local_ring.addr + tp->local_ring.ubmm_export.size;
}

static ALWAYS_INLINE bool is_remote_addr(umq_ubmm_info_t *tp, umq_buf_t *qbuf)
{
    uint64_t addr = (uint64_t)(uintptr_t)qbuf;
    return tp->bind_ctx != NULL && addr >= (uint64_t)(uintptr_t)tp->bind_ctx->remote_ring.addr &&
    addr < (uint64_t)(uintptr_t)tp->bind_ctx->remote_ring.addr + tp->bind_ctx->remote_ring.ubmm_export.size;
}

void umq_tp_ubmm_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    // decide which pool to return
    uint64_t qbuf_pool_handle = UMQ_INVALID_HANDLE;
    if (is_remote_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->bind_ctx->qbuf_pool_handle;
    } else if (is_local_addr(tp, qbuf)) {
        qbuf_pool_handle = tp->qbuf_pool_handle;
    }

    if (qbuf_pool_handle == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR("no qbuf pool is valid for this qbuf\n");
        return;
    }

    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    umq_shm_qbuf_free(qbuf_pool_handle, &head);
}

int umq_tp_ubmm_buf_headroom_reset_impl(umq_buf_t *qbuf, uint16_t headroom_size)
{
    umq_t *umq = (umq_t *)(uintptr_t)qbuf->umqh;
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umq->umqh_tp;
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
        return -UMQ_ERR_ENOMEM;
    }

    return umq_shm_qbuf_headroom_reset(qbuf_pool_handle, qbuf, headroom_size);
}

static ALWAYS_INLINE int enqueue_data(uint64_t umqh_tp, uint64_t *offset, uint32_t num)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (num > UMQ_POST_POLL_BATCH) {
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

static ALWAYS_INLINE umq_buf_t *umq_prepare_rendezvous_data(umq_ubmm_info_t *tp, umq_buf_t *qbuf, uint16_t *msg_id)
{
    umq_buf_t *send_buf = umq_buf_alloc(UMQ_SIZE_SMALL, 1, tp->umqh, NULL);
    if (send_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("alloc rendezvoud buf failed\n");
        return NULL;
    }

    uint32_t max_ref_sge_num =
        (UMQ_SIZE_SMALL - sizeof(umq_ubmm_ref_sge_info_t) - sizeof(umq_imm_head_t)) / sizeof(ub_ref_sge_t);

    umq_ubmm_ref_sge_info_t *ref_sge_info = (umq_ubmm_ref_sge_info_t *)(uintptr_t)send_buf->buf_data;
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)ref_sge_info->ub_ref_info;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);
    ub_fill_umq_imm_head(umq_imm_head, qbuf);

    ub_import_mempool_info_t import_mempool_info[UMQ_MAX_TSEG_NUM];
    umq_buf_t *tmp_buf = qbuf;
    uint32_t idx = 0;
    while (tmp_buf != NULL) {
        if (idx >= max_ref_sge_num) {
            UMQ_LIMIT_VLOG_ERR("rendezvoud buf count exceed max support count[%u]\n", max_ref_sge_num);
            umq_buf_free(send_buf);
            return NULL;
        }

        ubmm_fill_big_data_ref_sge(
            tp->ub_handle, ref_sge, tmp_buf, &import_mempool_info[umq_imm_head->mempool_num], umq_imm_head);
        tmp_buf = tmp_buf->qbuf_next;
        ref_sge = ref_sge + 1;
        idx++;
    }

    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_IMPORT_MEM) {
        if ((sizeof(umq_imm_head_t) + sizeof(ub_ref_sge_t) * idx +
            sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num) > UMQ_SIZE_SMALL) {
            UMQ_LIMIT_VLOG_ERR("import mempool info is not enough\n");
            umq_buf_free(send_buf);
            return NULL;
        }
        (void)memcpy(ref_sge,
            import_mempool_info, sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num);
    }

    ref_sge_info->sge_num = idx;
    ref_sge_info->msg_id = util_id_allocator_get(umq_ub_get_msg_id_generator(tp->ub_handle));
    *msg_id = ref_sge_info->msg_id;

    return send_buf;
}

int umq_ubmm_plus_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    umq_buf_t *send_buf = qbuf;
    bool rendezvous = false;
    uint16_t msg_id = 0;
    // handle rendezvous data
    if (qbuf->umqh == UMQ_INVALID_HANDLE) {
        rendezvous = true;
        send_buf = umq_prepare_rendezvous_data(tp, qbuf, &msg_id);
        if (send_buf == NULL) {
            *bad_qbuf = qbuf;
            return -UMQ_ERR_ENODEV;
        }
        umq_ub_record_rendezvous_buf(tp->ub_handle, msg_id, qbuf);
    }

    int ret = umq_shm_qbuf_enqueue(send_buf, umqh_tp, tp->qbuf_pool_handle, rendezvous, enqueue_data);
    if (ret != UMQ_SUCCESS) {
        if (rendezvous) {
            umq_buf_free(send_buf);
        }
        *bad_qbuf = qbuf;
        umq_ub_remove_rendezvous_buf(tp->ub_handle, msg_id);
        return UMQ_FAIL;
    }

    return ret;
}

static ALWAYS_INLINE int dequeue_data(uint64_t umq, uint64_t *offset, uint32_t num)
{
    uint64_t *rx_data_ptr[num];
    for (uint32_t i = 0; i < num; i++) {
        rx_data_ptr[i] = &offset[i];
    }

    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umq;
    // poll offset from shm, then transform to qbuf
    uint32_t polled_buf_size[num];
    int ret = msg_ring_poll_tx_batch(tp->bind_ctx->remote_msg_ring, (char **)&rx_data_ptr,
        sizeof(uint64_t), polled_buf_size, num);
    if (ret < 0) {
        UMQ_LIMIT_VLOG_ERR("ipc poll rx failed\n");
        return -UMQ_ERR_EAGAIN;
    }

    return ret;
}

umq_buf_t *umq_ubmm_plus_dequeue_impl(uint64_t umqh_tp)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return NULL;
    }

    // try to dequeue ub to get read data and handle notify
    umq_buf_t *buf = umq_ub_dequeue_impl_plus(tp->ub_handle);
    if (buf == NULL) {
        UMQ_LIMIT_VLOG_DEBUG("ub dequeue return nothing\n");
    }

    // poll shm queue
    bool rendezvous = false;
    umq_buf_t *polled_buf = umq_shm_qbuf_dequeue(tp->umqh, umqh_tp, tp->bind_ctx->qbuf_pool_handle,
        &rendezvous, dequeue_data);
    if (polled_buf == NULL) {
        UMQ_LIMIT_VLOG_DEBUG("umq_shm_qbuf_dequeue return nothing\n");
    } else if (rendezvous) {
        umq_ubmm_ref_sge_info_t *ref_sge_info = (umq_ubmm_ref_sge_info_t *)polled_buf->buf_data;
        umq_ub_imm_t imm_data = {
            .ub_plus = {
                .msg_id = ref_sge_info->msg_id,
                .msg_num = ref_sge_info->sge_num,
            }
        };
        (void)umq_qbuf_headroom_reset(polled_buf, sizeof(umq_ubmm_ref_sge_info_t));
        if (umq_ub_read(tp->ub_handle, polled_buf, imm_data) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_DEBUG("send read failed\n");
            umq_buf_free(polled_buf);
        }
    } else {
        if (buf == NULL) {
            buf = polled_buf;
        } else {
            umq_buf_t *tmp_buf = buf;
            while (tmp_buf->qbuf_next) {
                tmp_buf = tmp_buf->qbuf_next;
            }
            tmp_buf->qbuf_next = polled_buf;
        }
    }

    return buf;
}

void umq_ubmm_notify_impl(uint64_t umqh_tp)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    if (tp->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return;
    }

    umq_ub_imm_t imm = { .bs = { .umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_NOTIFY} };
    umq_ub_write_imm(tp->ub_handle, tp->bind_ctx->remote_notify_addr, 1, imm.value);
}

int umq_ubmm_rearm_interrupt_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    return umq_ub_rearm_impl(tp->ub_handle, solicated, option);
}

int32_t umq_ubmm_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)wait_umqh_tp;
    return umq_ub_wait_interrupt_impl(tp->ub_handle, time_out, option);
}

void umq_ubmm_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    return umq_ub_ack_interrupt_impl(tp->ub_handle, nevents, option);
}

int umq_ubmm_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    return umq_ub_get_cq_event_impl(tp->ub_handle, option);
}

int umq_ubmm_interrupt_fd_get_impl(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    umq_ubmm_info_t *tp = (umq_ubmm_info_t *)(uintptr_t)umqh_tp;
    return umq_ub_interrupt_fd_get_impl(tp->ub_handle, option);
}

int32_t umq_ubmm_register_memory_impl(uint8_t *ubmm_ctx, void *buf, uint64_t size)
{
    umq_ubmm_init_ctx_t *context = (umq_ubmm_init_ctx_t *)ubmm_ctx;
    return umq_ub_register_memory_impl(context->ub_init_ctx, buf, size);
}

void umq_ubmm_unregister_memory_impl(uint8_t *ubmm_ctx)
{
    umq_ubmm_init_ctx_t *context = (umq_ubmm_init_ctx_t *)ubmm_ctx;
    return umq_ub_unregister_memory_impl(context->ub_init_ctx);
}
