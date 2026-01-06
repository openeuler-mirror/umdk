/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB implementation
 * Create: 2025-7-19
 * Note:
 * History: 2025-7-19
 */

#include <pthread.h>
#include <sys/queue.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>

#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "uvs_api.h"
#include "perf.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "urma_api.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_inner.h"
#include "umq_huge_qbuf_pool.h"
#include "util_id_generator.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_imm_data.h"
#include "umq_ub_private.h"
#include "umq_ub_impl.h"

#define UMQ_FLUSH_MAX_RETRY_TIMES 10000
#define DEV_STR_LENGTH 64

static umq_ub_ctx_t *g_ub_ctx = NULL;
static uint32_t g_ub_ctx_count = 0;

static int huge_qbuf_pool_memory_init(uint8_t mempool_id, huge_qbuf_pool_size_type_t type, void **buffer_addr)
{
    uint32_t blk_size = umq_huge_qbuf_get_size_by_type(type);
    uint32_t total_len = blk_size * HUGE_QBUF_BUFFER_INC_BATCH;
    void *addr = (void *)memalign(UMQ_QBUF_ALIGN_SIZE, total_len);
    if (addr == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    uint32_t failed_idx = 0;
    int ret = 0;
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        ret = umq_ub_register_seg(&g_ub_ctx[i], mempool_id, addr, total_len);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR("ub ctx[%u] register segment failed\n", i);
            goto UNREGISTER_MEM;
        }
    }

    *buffer_addr = addr;
    return UMQ_SUCCESS;

UNREGISTER_MEM:
    umq_ub_unregister_seg(g_ub_ctx, failed_idx, mempool_id);
    free(addr);
    return ret;
}

static void huge_qbuf_pool_memory_uninit(uint8_t mempool_id, void *buf_addr)
{
    umq_ub_unregister_seg(g_ub_ctx, g_ub_ctx_count, mempool_id);
    free(buf_addr);
}

int umq_ub_log_config_set_impl(umq_log_config_t *config)
{
    if (config->log_flag & UMQ_LOG_FLAG_LEVEL) {
        urma_log_set_level((urma_vlog_level_t)config->level);
    }

    if (config->log_flag & UMQ_LOG_FLAG_FUNC) {
        if (config->func == NULL) {
            return urma_unregister_log_func();
        } else {
            return urma_register_log_func(config->func);
        }
    }
    return UMQ_SUCCESS;
}

int umq_ub_log_config_reset_impl(void)
{
    urma_log_set_level(URMA_VLOG_LEVEL_INFO);
    return urma_unregister_log_func();
}

int32_t umq_ub_huge_qbuf_pool_init(umq_init_cfg_t *cfg)
{
    int ret = 0;
    uint32_t i = 0;
    huge_qbuf_pool_cfg_t pool_cfg = {
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
        .memory_init_callback = huge_qbuf_pool_memory_init,
        .memory_uninit_callback = huge_qbuf_pool_memory_uninit,
    };

    for (i = 0; i < HUGE_QBUF_POOL_SIZE_TYPE_MAX; i++) {
        pool_cfg.data_size = umq_huge_qbuf_get_size_by_type(i);
        pool_cfg.total_size = pool_cfg.data_size * HUGE_QBUF_BUFFER_INC_BATCH;
        pool_cfg.type = i;
        ret = umq_huge_qbuf_config_init(&pool_cfg);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("initialize configuration for huge qbuf pool type(%d) failed\n", i);
            goto CONFIG_UNINIT;
        }
    }
    umq_huge_qbuf_pool_ctx_common_cfg_set(&pool_cfg);
    return UMQ_SUCCESS;

CONFIG_UNINIT:
    for (uint32_t j = 0; j < i; j++) {
        umq_huge_qbuf_config_uninit(j);
    }

    return ret;
}

void umq_ub_huge_qbuf_pool_uninit(void)
{
    umq_huge_qbuf_pool_uninit();
}

int umq_ub_bind_info_get_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    if (bind_info_size < sizeof(umq_ub_bind_info_t)) {
        UMQ_VLOG_ERR("bind_info_size[%u] is less than required size[%u]\n", bind_info_size, sizeof(umq_ub_bind_info_t));
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_ub_bind_info_t *info = (umq_ub_bind_info_t *)bind_info;
    info->is_binded = queue->bind_ctx != NULL ? true : false;
    info->umq_trans_mode = queue->dev_ctx->trans_info.trans_mode;
    info->trans_mode = URMA_TM_RC;
    info->order_type = queue->dev_ctx->order_type;
    info->jetty_id = queue->jetty->jetty_id;
    info->type = URMA_JETTY;
    info->token = queue->jetty->jetty_cfg.shared.jfr->jfr_cfg.token_value;
    info->notify_buf = umq_ub_notify_buf_addr_get(queue, OFFSET_MEM_IMPORT);
    info->rx_depth = queue->rx_depth;
    info->tx_depth = queue->tx_depth;
    info->win_buf_addr = queue->flow_control.enabled ? umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL) : 0;
    info->win_buf_len = queue->flow_control.enabled ? UMQ_UB_RW_SEGMENT_LEN : 0;
    info->rx_buf_size = queue->rx_buf_size;
    info->feature = queue->dev_ctx->feature;
    info->state = queue->state;
    info->pid = getpid();
    (void)memcpy(&info->tseg, queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID], sizeof(urma_target_seg_t));
    info->buf_pool_mode = umq_qbuf_mode_get();
    return sizeof(umq_ub_bind_info_t);
}

int umq_ub_bind_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    if (bind_info_size < sizeof(umq_ub_bind_info_t)) {
        UMQ_VLOG_ERR("bind info size invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_ub_bind_info_t *info = (umq_ub_bind_info_t *)bind_info;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;

    int ret = umq_ub_bind_info_check(queue, info);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    if (umq_ub_window_init(&queue->flow_control, info) != UMQ_SUCCESS) {
        return -UMQ_ERR_EINVAL;
    }
    return umq_ub_bind_inner_impl(queue, info);
}

int32_t umq_ub_register_memory_impl(void *buf, uint64_t size)
{
    if (g_ub_ctx == NULL) {
        UMQ_VLOG_ERR("no device is available to register memory\n");
        return -UMQ_ERR_ENODEV;
    }

    if (buf == NULL || size == 0) {
        UMQ_VLOG_ERR("invalid addr or size\n");
        return -UMQ_ERR_EINVAL;
    }

    uint32_t failed_idx;
    int ret = 0;
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        ret = umq_ub_register_seg(&g_ub_ctx[i], UMQ_QBUF_DEFAULT_MEMPOOL_ID, buf, size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR("ub ctx[%u] register segment failed\n", i);
            goto UNREGISTER_MEM;
        }
    }
    return UMQ_SUCCESS;

UNREGISTER_MEM:
    umq_ub_unregister_seg(g_ub_ctx, failed_idx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    return ret;
}

void umq_ub_unregister_memory_impl(void)
{
    for (uint32_t tseg_idx = 0; tseg_idx < UMQ_MAX_TSEG_NUM; tseg_idx++) {
        umq_ub_unregister_seg(g_ub_ctx, g_ub_ctx_count, tseg_idx);
    }
}

umq_buf_t *umq_ub_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    umq_buf_list_t head;
    QBUF_LIST_INIT(&head);
    if (umq_qbuf_alloc(request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
        return NULL;
    }

    return QBUF_LIST_FIRST(&head);
}

umq_buf_t *umq_ub_plus_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    uint32_t headroom_size = umq_qbuf_headroom_get();
    umq_buf_mode_t mode = umq_qbuf_mode_get();
    uint32_t factor = (mode == UMQ_BUF_SPLIT) ? 0 : sizeof(umq_buf_t);
    umq_buf_list_t head;

    QBUF_LIST_INIT(&head);
    uint32_t buf_size = request_size + headroom_size + factor;

    if (buf_size < umq_buf_size_middle()) {
        if (umq_qbuf_alloc(request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
            return NULL;
        }
    } else {
        huge_qbuf_pool_size_type_t type = umq_huge_qbuf_get_type_by_size(buf_size);
        if (umq_huge_qbuf_alloc(type, request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
            return NULL;
        }
    }

    return QBUF_LIST_FIRST(&head);
}

void umq_ub_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    umq_qbuf_free(&head);
}

void umq_ub_plus_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    if (QBUF_LIST_NEXT(qbuf) == NULL) {
        if (qbuf->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
            umq_huge_qbuf_free(&head);
        } else {
            umq_qbuf_free(&head);
        }

        return;
    }

    /* Here, the free list will be traversed, and an attempt will be made to scan each qbuf object.
    * If there exist n consecutive qbuf objects that belong to the same memory pool, they will be
    * released in batch. */
    umq_buf_t *cur_node = NULL;
    umq_buf_t *next_node = NULL;
    umq_buf_t *last_node = NULL;
    umq_buf_t *free_node = qbuf; // head of the list to be released
    umq_buf_list_t free_head;
    QBUF_LIST_FIRST(&free_head) = free_node;
    bool is_huge = qbuf->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID; // Specify the list to be released currently
                                                                    // belongs to large or general pool.
    QBUF_LIST_FIRST(&head) = QBUF_LIST_NEXT(qbuf);

    QBUF_LIST_FOR_EACH_SAFE(cur_node, &head, next_node)
    {
        if ((is_huge && (cur_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID)) ||
            (!is_huge && (cur_node->mempool_id == 0))) {
            // current qbuf is in the same pool, scan the next one directly
            last_node = cur_node;
            continue;
        }

        QBUF_LIST_NEXT(last_node) = NULL;
        QBUF_LIST_FIRST(&free_head) = free_node;
        free_node = cur_node;
        is_huge = cur_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID;
        if (free_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
            umq_huge_qbuf_free(&free_head);
        } else {
            umq_qbuf_free(&free_head);
        }
    }

    QBUF_LIST_FIRST(&free_head) = free_node;
    if (free_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
        umq_huge_qbuf_free(&free_head);
    } else {
        umq_qbuf_free(&free_head);
    }
    return;
}

static int dev_str_get(umq_dev_assign_t *dev_info, char *dev_str, size_t dev_str_len)
{
    int res = 0;
    if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_DEV) {
        char *dev_name = dev_info->dev.dev_name;
        res = snprintf(dev_str, dev_str_len, "%s", dev_name);
        if (res < 0 || (size_t)res >= dev_str_len) {
            UMQ_VLOG_ERR("snprintf failed, res: %d\n", res);
            return UMQ_FAIL;
        }
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_EID) {
        res = snprintf(dev_str, dev_str_len, ""EID_FMT"", EID_ARGS(dev_info->eid.eid));
        if (res < 0 || (size_t)res >= dev_str_len) {
            UMQ_VLOG_ERR("snprintf failed, res: %d\n", res);
            return UMQ_FAIL;
        }
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ||
               dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV6) {
        char *ip_addr = dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ? dev_info->ipv4.ip_addr
                                                                            : dev_info->ipv6.ip_addr;
        res = snprintf(dev_str, dev_str_len, "%s", ip_addr);
        if (res < 0 || (size_t)res >= dev_str_len) {
            UMQ_VLOG_ERR("snprintf failed, res: %d\n", res);
            return UMQ_FAIL;
        }
    } else {
        UMQ_VLOG_ERR("assign mode: %d not supported\n", dev_info->assign_mode);
        return -UMQ_ERR_EINVAL;
    }
    return UMQ_SUCCESS;
}

static int umq_find_ub_device(umq_trans_info_t *info, umq_ub_ctx_t *ub_ctx)
{
    char dev_str[DEV_STR_LENGTH] = {'\0'};
    int ret = dev_str_get(&info->dev_info, dev_str, sizeof(dev_str));
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    if (g_ub_ctx_count >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR("ub ctx cnt exceeded the maximum limit %u\n", MAX_UMQ_TRANS_INFO_NUM);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &info->dev_info) != NULL) {
        UMQ_VLOG_ERR("ub ctx already exists, dev: %s\n", dev_str);
        return -UMQ_ERR_EEXIST;
    }

    urma_device_t *urma_dev;
    uint32_t eid_index = 0;
    uint32_t eid_cnt = umq_ub_get_urma_dev(&info->dev_info, &urma_dev, &eid_index);
    if (eid_cnt == 0) {
        UMQ_VLOG_ERR("failed to get urma dev, dev: %s\n", dev_str);
        return -UMQ_ERR_ENODEV;
    }

    ub_ctx->trans_info.trans_mode = info->trans_mode;
    ret = umq_ub_get_eid_dev_info(urma_dev, eid_index, &ub_ctx->trans_info.dev_info);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get eid trans info failed, dev: %s\n", dev_str);
        return ret;
    }

    ret = umq_ub_create_urma_ctx(urma_dev, eid_index, ub_ctx);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get urma ctx failed, dev: %s\n", dev_str);
        return ret;
    }
    UMQ_VLOG_INFO("umq_find_ub_device success, dev: %s\n", dev_str);

    return UMQ_SUCCESS;
}

uint8_t *umq_ub_ctx_init_impl(umq_init_cfg_t *cfg)
{
    if (g_ub_ctx_count > 0) {
        UMQ_VLOG_WARN("umq ub ctx already inited\n");
        return (uint8_t *)g_ub_ctx;
    }

    if (umq_ub_id_allocator_init() != 0) {
        UMQ_VLOG_ERR("id allocator init failed\n");
        return NULL;
    }

    g_ub_ctx = (umq_ub_ctx_t *)calloc(MAX_UMQ_TRANS_INFO_NUM, sizeof(umq_ub_ctx_t));
    if (g_ub_ctx == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        goto UNINIT_ALLOCATOR;
    }

    urma_init_attr_t init_attr = {0};
    if (urma_init(&init_attr) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("urma init failed\n");
        goto FREE_CTX;
    }

    uint64_t total_io_buf_size = 0;
    for (uint32_t i = 0; i < cfg->trans_info_num; i++) {
        umq_trans_info_t *info = &cfg->trans_info[i];
        if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
            info->trans_mode != UMQ_TRANS_MODE_UBMM && info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
            UMQ_VLOG_INFO("trans init mode: %d not UB, skip it\n", info->trans_mode);
            continue;
        }

        g_ub_ctx[g_ub_ctx_count].remote_imported_info = umq_ub_ctx_imported_info_create();
        if (g_ub_ctx[g_ub_ctx_count].remote_imported_info == NULL) {
            UMQ_VLOG_ERR("imported info create failed\n");
            goto ROLLBACL_UB_CTX;
        }

        if (umq_find_ub_device(info, &g_ub_ctx[g_ub_ctx_count]) != UMQ_SUCCESS) {
            UMQ_VLOG_INFO("find ub device failed\n");
            umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);
            goto ROLLBACL_UB_CTX;
        }

        if (total_io_buf_size == 0) {
            total_io_buf_size = info->mem_cfg.total_size;
        }

        g_ub_ctx[g_ub_ctx_count].io_lock_free = cfg->io_lock_free;
        g_ub_ctx[g_ub_ctx_count].feature = cfg->feature;
        g_ub_ctx[g_ub_ctx_count].flow_control = cfg->flow_control;
        g_ub_ctx[g_ub_ctx_count].order_type = URMA_DEF_ORDER;
        g_ub_ctx[g_ub_ctx_count].ref_cnt = 1;
        ++g_ub_ctx_count;
    }
    if (g_ub_ctx_count == 0) {
        goto ROLLBACL_UB_CTX;
    }

    if (umq_io_buf_malloc(cfg->buf_mode, total_io_buf_size) == NULL) {
        goto ROLLBACL_UB_CTX;
    }

    qbuf_pool_cfg_t qbuf_cfg = {
        .buf_addr = umq_io_buf_addr(),
        .total_size = umq_io_buf_size(),
        .data_size = umq_buf_size_small(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
    };
    int ret = umq_qbuf_pool_init(&qbuf_cfg);
    if (ret != UMQ_SUCCESS && ret != -UMQ_ERR_EEXIST) {
        UMQ_VLOG_ERR("qbuf poll init failed\n");
        goto IO_BUF_FREE;
    }
    umq_ub_queue_ctx_list_init();

    return (uint8_t *)(uintptr_t)g_ub_ctx;

IO_BUF_FREE:
    umq_io_buf_free();

ROLLBACL_UB_CTX:
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        umq_ub_ctx_imported_info_destroy(&g_ub_ctx[i]);
        umq_ub_delete_urma_ctx(&g_ub_ctx[i]);
    }
    g_ub_ctx_count = 0;
    (void)urma_uninit();

FREE_CTX:
    free(g_ub_ctx);
    g_ub_ctx = NULL;

UNINIT_ALLOCATOR:
    umq_ub_id_allocator_uninit();
    return NULL;
}

void umq_ub_ctx_uninit_impl(uint8_t *ctx)
{
    umq_ub_queue_ctx_list_uninit();
    umq_ub_ctx_t *context = (umq_ub_ctx_t *)ctx;
    if (context != g_ub_ctx) {
        UMQ_VLOG_ERR("uninit failed, ub_ctx is invalid\n");
        return;
    }
    g_ub_ctx = NULL;
    for (uint32_t i = 0; i < g_ub_ctx_count; ++i) {
        if (umq_fetch_ref(context[i].io_lock_free, &context[i].ref_cnt) > 1) {
            UMQ_VLOG_ERR("device ref cnt not cleared\n");
            g_ub_ctx = context;
            return;
        }
    }

    for (uint32_t i = 0; i < g_ub_ctx_count; ++i) {
        umq_ub_ctx_imported_info_destroy(&context[i]);
        umq_dec_ref(context[i].io_lock_free, &context[i].ref_cnt, 1);
        urma_delete_context(context[i].urma_ctx);
    }

    umq_qbuf_pool_uninit();
    umq_io_buf_free();
    umq_ub_id_allocator_uninit();
    free(context);
    g_ub_ctx_count = 0;
    urma_uninit();
}

uint64_t umq_ub_create_impl(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option)
{
    umq_ub_ctx_t *ub_ctx = (umq_ub_ctx_t *)ctx;
    umq_ub_ctx_t *dev_ctx = umq_ub_get_ub_ctx_by_dev_info(ub_ctx, g_ub_ctx_count, &option->dev_info);
    if (dev_ctx == NULL) {
        UMQ_VLOG_ERR("device ctx find failed\n");
        return UMQ_INVALID_HANDLE;
    }

    bool enable_token = (dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t jetty_token;
    if (umq_ub_token_generate(enable_token, &jetty_token) != 0) {
        UMQ_VLOG_ERR("generate jetty token failed\n");
        return UMQ_INVALID_HANDLE;
    }

    umq_inc_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
    ub_queue_t *queue = (ub_queue_t *)calloc(1, sizeof(ub_queue_t));
    if (queue == NULL) {
        umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
        UMQ_VLOG_ERR("umq create failed, calloc queue failed\n");
        return UMQ_INVALID_HANDLE;
    }

    if (check_and_set_param(dev_ctx, option, queue) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("option param invalid\n");
        goto FREE_QUEUE;
    }

    if (umq_ub_flow_control_init(&queue->flow_control, queue, dev_ctx->feature, &dev_ctx->flow_control) !=
        UMQ_SUCCESS) {
        goto FREE_QUEUE;
    }

    queue->jfs_jfce = NULL;
    queue->jfr_jfce = NULL;
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        queue->jfs_jfce = urma_create_jfce(dev_ctx->urma_ctx);
        if (queue->jfs_jfce == NULL) {
            UMQ_VLOG_ERR("create jfs_jfce failed\n");
            goto UNINIT_FLOW_CONTROL;
        }
        queue->jfr_jfce = urma_create_jfce(dev_ctx->urma_ctx);
        if (queue->jfr_jfce == NULL) {
            UMQ_VLOG_ERR("create jfr_jfce failed\n");
            goto UNINIT_FLOW_CONTROL;
        }
    }

    urma_jfc_cfg_t jfc_cfg = {
        .depth = queue->tx_depth,
        .jfce = queue->jfs_jfce
    };
    queue->jfs_jfc = urma_create_jfc(dev_ctx->urma_ctx, &jfc_cfg);
    if (queue->jfs_jfc == NULL) {
        UMQ_VLOG_ERR("urma create jfs_jfc failed\n");
        goto DELETE_JFCE;
    }

    jfc_cfg.depth = queue->rx_depth;
    urma_jfc_cfg_t jfr_jfc_cfg = {
        .depth = queue->rx_depth,
        .jfce = queue->jfr_jfce
    };
    queue->jfr_jfc = urma_create_jfc(dev_ctx->urma_ctx, &jfr_jfc_cfg);
    if (queue->jfr_jfc == NULL) {
        UMQ_VLOG_ERR("urma create jfr_jfc failed\n");
        goto DELETE_JFS_JFC;
    }

    urma_jfr_cfg_t jfr_cfg = {
        .flag.bs.token_policy = token_policy_get(enable_token),
        .trans_mode = URMA_TM_RC,
        .depth = queue->rx_depth,
        .max_sge = queue->max_rx_sge,
        .min_rnr_timer = queue->min_rnr_timer,
        .jfc = queue->jfr_jfc,
        .token_value = { .token = jetty_token }
    };
    jfr_cfg.flag.bs.order_type = dev_ctx->order_type;
    queue->jfr = urma_create_jfr(dev_ctx->urma_ctx, &jfr_cfg);
    if (queue->jfr == NULL) {
        UMQ_VLOG_ERR("urma create jfr failed\n");
        goto DELETE_JFR_JFC;
    }

    queue->jetty = umq_create_jetty(queue, dev_ctx);
    if (queue->jetty == NULL) {
        goto DELETE_JFR;
    }

    if (rx_buf_ctx_list_init(queue) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("rx buf ctx list init failed\n");
        goto DELETE_JETTY;
    }

    queue->notify_buf = umq_buf_alloc(umq_buf_size_small(), 1, UMQ_INVALID_HANDLE, NULL);
    if (queue->notify_buf == NULL) {
        UMQ_VLOG_ERR("buf alloc failed\n");
        goto UNINIT_RX_CTX_LIST;
    }
    memset(queue->notify_buf->buf_data, 0, queue->notify_buf->data_size);

    UMQ_VLOG_INFO("umq create success\n");
    atomic_init(&queue->require_rx_count, 0);
    queue->ref_cnt = 1;
    queue->tx_outstanding = 0;
    queue->state = queue->flow_control.enabled ? QUEUE_STATE_IDLE : QUEUE_STATE_READY;
    queue->umqh = umqh;
    umq_ub_queue_ctx_list_push(&queue->qctx_node);
    return (uint64_t)(uintptr_t)queue;
UNINIT_RX_CTX_LIST:
    (void)rx_buf_ctx_list_uninit(&queue->rx_buf_ctx_list);
DELETE_JETTY:
    (void)urma_delete_jetty(queue->jetty);
DELETE_JFR:
    (void)urma_delete_jfr(queue->jfr);
DELETE_JFR_JFC:
    (void)urma_delete_jfc(queue->jfr_jfc);
DELETE_JFS_JFC:
    (void)urma_delete_jfc(queue->jfs_jfc);
DELETE_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        (void)urma_delete_jfce(queue->jfs_jfce);
        (void)urma_delete_jfce(queue->jfr_jfce);
    }
UNINIT_FLOW_CONTROL:
    umq_ub_flow_control_uninit(&queue->flow_control);
FREE_QUEUE:
    umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
    free(queue);
    return UMQ_INVALID_HANDLE;
}

int32_t umq_ub_destroy_impl(uint64_t umqh)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    if (queue->umq_trans_mode != UMQ_TRANS_MODE_UB && queue->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        queue->umq_trans_mode != UMQ_TRANS_MODE_UBMM && queue->umq_trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_ERR("destroy umq failed, trans mode %d is not UB\n", queue->umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }
    if (umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt) != 1) {
        UMQ_VLOG_ERR("umqh ref cnt is not 0\n");
        return -UMQ_ERR_EBUSY;
    }

    if (queue->bind_ctx != NULL) {
        UMQ_VLOG_ERR("umqh has not been unbinded\n");
        return -UMQ_ERR_EBUSY;
    }
    umq_buf_free(queue->notify_buf);

    umq_ub_flow_control_uninit(&queue->flow_control);
    rx_buf_ctx_list_uninit(&queue->rx_buf_ctx_list);

    UMQ_VLOG_INFO("delete jetty, eid: " EID_FMT ", jetty_id: %u\n",
                  EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id);
    if (urma_delete_jetty(queue->jetty) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete jetty failed\n");
    }
    if (queue->jfr != NULL) {
        if (urma_delete_jfr(queue->jfr) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("delete jfr failed\n");
        }
    }
    if (urma_delete_jfc(queue->jfr_jfc) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete jfr_jfc failed\n");
    }
    if (urma_delete_jfc(queue->jfs_jfc) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete jfs_jfc failed\n");
    }
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        if (urma_delete_jfce(queue->jfs_jfce) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("delete jfs_jfce failed\n");
        }
        if (urma_delete_jfce(queue->jfr_jfce) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("delete jfr_jfce failed\n");
        }
    }
    umq_ub_queue_ctx_list_remove(&queue->qctx_node);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->dev_ctx->ref_cnt, 1);
    free(queue);
    return UMQ_SUCCESS;
}

void umq_ub_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option not valid\n");
        return;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)(umqh_tp);
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return;
    }
    if (option->direction == UMQ_IO_RX) {
        urma_ack_jfc(&queue->jfr_jfc, &nevents, 1);
    } else {
        urma_ack_jfc(&queue->jfs_jfc, &nevents, 1);
    }
}

int umq_ub_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ub_wait_interrupt_impl(umqh_tp, -1, option);
}

int umq_ub_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option not valid\n");
        return -UMQ_ERR_EINVAL;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)(wait_umqh_tp);
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_jfc_t *jfc;
    int cnt = 0;
    if (option->direction == UMQ_IO_RX) {
        cnt = urma_wait_jfc(queue->jfr_jfce, 1, time_out, &jfc);
    } else {
        cnt = urma_wait_jfc(queue->jfs_jfce, 1, time_out, &jfc);
    }
    if (cnt < 0) {
        if (errno != EAGAIN) {
            UMQ_LIMIT_VLOG_ERR("urma_wait_jfc failed\n");
            return -1;
        }
        return 0;
    } else if (cnt == 0) {
        return 0;
    }
    return 1;
}

int umq_ub_interrupt_fd_get_impl(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_VLOG_ERR("option not valid\n");
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->jfs_jfce == NULL || queue->jfr_jfce == NULL) {
        UMQ_VLOG_ERR("get interrupt fd error, jfce is NULL\n");
        return -UMQ_ERR_EINVAL;
    }
    if (option->direction == UMQ_IO_TX) {
        return queue->jfs_jfce->fd;
    } else {
        return queue->jfr_jfce->fd;
    }
}

int umq_ub_rearm_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR("option not valid\n");
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR("queue mode is not interrupt\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_jfc_t *jfc = option->direction == UMQ_IO_RX ? queue->jfr_jfc : queue->jfs_jfc;
    urma_status_t status = urma_rearm_jfc(jfc, solicated);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR("rearm jfc failed\n");
        return -status;
    }

    return UMQ_SUCCESS;
}

int umq_ub_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf)
{
    if (io_direction == UMQ_IO_TX) {
        return umq_ub_post_tx(umqh_tp, qbuf, bad_qbuf);
    } else if (io_direction == UMQ_IO_RX) {
        return umq_ub_post_rx(umqh_tp, qbuf, bad_qbuf);
    }
    UMQ_LIMIT_VLOG_ERR("io_direction[%d] is not supported when post\n", io_direction);
    return -UMQ_ERR_EINVAL;
}

int umq_ub_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count)
{
    if (io_direction == UMQ_IO_RX) {
        return umq_ub_poll_rx(umqh_tp, buf, max_buf_count);
    } else if (io_direction == UMQ_IO_TX) {
        return umq_ub_poll_tx(umqh_tp, buf, max_buf_count);
    } else if (io_direction == UMQ_IO_ALL) {
        uint32_t tx_max_cnt = max_buf_count > 1 ? max_buf_count >> 1 : 1;
        int32_t tx_cnt = umq_ub_poll_tx(umqh_tp, buf, tx_max_cnt);
        if (tx_cnt < 0) {
            UMQ_LIMIT_VLOG_ERR("poll tx failed\n");
            return -UMQ_ERR_EAGAIN;
        }

        int32_t rx_cnt = umq_ub_poll_rx(umqh_tp, &buf[tx_cnt], max_buf_count - tx_cnt);
        if (rx_cnt < 0) {
            UMQ_LIMIT_VLOG_ERR("poll rx failed\n");
            return tx_cnt;
        }

        return tx_cnt + rx_cnt;
    }
    UMQ_LIMIT_VLOG_ERR("invalid io direction[%d]\n", io_direction);
    return -UMQ_ERR_EINVAL;
}

int umq_ub_unbind_impl(uint64_t umqh)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    ub_bind_ctx_t *bind_ctx = queue->bind_ctx;
    if (bind_ctx == NULL) {
        UMQ_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    urma_target_jetty_t *tjetty = bind_ctx->tjetty;
    (void)umq_ub_eid_id_release(queue->dev_ctx->remote_imported_info, bind_ctx);
    UMQ_VLOG_INFO("unbind jetty, local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                  "remote jetty_id: %u\n", EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                  EID_ARGS(tjetty->id.eid), tjetty->id.id);
    (void)urma_unbind_jetty(queue->jetty);
    (void)urma_unimport_jetty(tjetty);
    umq_modify_ubq_to_err(queue);

    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        umq_flush_tx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
        umq_flush_rx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
    }

    free(queue->bind_ctx);
    queue->bind_ctx = NULL;
    return UMQ_SUCCESS;
}

int32_t umq_ub_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    umq_ub_enqueue_with_poll_tx(queue, buf);

    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    *bad_qbuf = NULL;

    int ret = UMQ_SUCCESS;
    uint32_t tx_outstanding = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding);
    int remain_tx = queue->tx_depth - tx_outstanding;
    if (remain_tx <= 0) {
        ret = -UMQ_ERR_EAGAIN;
        goto ERROR;
    }
    int wr_num = umq_ub_fill_wr_impl(qbuf, queue, urma_wr, (uint32_t)remain_tx);
    if (wr_num < 0) {
        *bad_qbuf = qbuf;
        ret = wr_num;
        goto ERROR;
    }
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        if (bad_wr != NULL) {
            process_bad_qbuf(bad_wr, bad_qbuf, qbuf, queue);
        }
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
        ret = -status;
        goto ERROR;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, wr_num);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;

ERROR:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

int32_t umq_ub_enqueue_impl_plus(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    int ret = UMQ_SUCCESS;

    *bad_qbuf = NULL;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    umq_ub_enqueue_plus_with_poll_tx(queue, buf);
    uint32_t tx_outstanding = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding);
    int remain_tx = queue->tx_depth - tx_outstanding;
    if (remain_tx <= 0) {
        ret = -UMQ_ERR_EAGAIN;
        goto DEC_REF;
    }

    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    int wr_num = umq_ub_plus_fill_wr_impl(qbuf, queue, urma_wr, (uint32_t)remain_tx);
    if (wr_num < 0) {
        *bad_qbuf = qbuf;
        ret = wr_num;
        goto DEC_REF;
    } else if (wr_num == 0) {
        ret = UMQ_SUCCESS;
        goto DEC_REF;
    }
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        if (bad_wr != NULL) {
            process_bad_qbuf(bad_wr, bad_qbuf, qbuf, queue);
        }
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
        ret = -status;
        goto DEC_REF;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, wr_num);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;

DEC_REF:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

umq_buf_t *umq_ub_dequeue_impl(uint64_t umqh_tp)
{
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return NULL;
    }
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    int rx_cnt = umq_ub_dequeue_with_poll_rx(queue, cr, buf);
    if (rx_cnt <= 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        return NULL;
    }
    // small io not process poll tx
    // fill rx buffer if not enough
    umq_ub_fill_rx_buffer(queue, rx_cnt);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return buf[0];
}

umq_buf_t *umq_ub_dequeue_impl_plus(uint64_t umqh_tp)
{
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return NULL;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    int return_rx_cnt;
    int rx_cnt = umq_ub_dequeue_plus_with_poll_rx(umqh_tp, cr, buf);
    if (rx_cnt < 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        return NULL;
    } else if (rx_cnt == 0) {
        return_rx_cnt = umq_ub_dequeue_plus_with_poll_tx(queue, cr, buf, rx_cnt);
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        return return_rx_cnt > 0 ? buf[0] : NULL;
    }
    return_rx_cnt = umq_ub_dequeue_plus_with_poll_tx(queue, cr, buf, rx_cnt);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return buf[0];
}

void umq_ub_record_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id, umq_buf_t *buf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    queue->addr_list[msg_id] = (uint64_t)(uintptr_t)buf;
}

void umq_ub_remove_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    queue->addr_list[msg_id] = 0;
}

util_id_allocator_t *umq_ub_get_msg_id_generator(uint64_t umqh_tp)
{
    return umq_ub_id_allocator_get();
}

umq_state_t umq_ub_state_get_impl(uint64_t umqh_tp)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    return queue->state;
}

int umq_ub_async_event_fd_get(umq_trans_info_t *trans_info)
{
    umq_ub_ctx_t *dev_ctx = umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &trans_info->dev_info);
    if (dev_ctx == NULL || dev_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR("dev_ctx invalid\n");
        return UMQ_INVALID_FD;
    }
    return dev_ctx->urma_ctx->async_fd;
}

int umq_ub_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
    umq_ub_ctx_t *dev_ctx = umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &trans_info->dev_info);
    if (dev_ctx == NULL || dev_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR("dev_ctx invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_context_t *urma_ctx = dev_ctx->urma_ctx;

    urma_async_event_t *urma_event = (urma_async_event_t *)calloc(1, sizeof(urma_async_event_t));
    if (urma_event == NULL) {
        UMQ_VLOG_ERR("umq calloc async event failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    urma_status_t status = urma_get_async_event(urma_ctx, urma_event);
    if (status != URMA_SUCCESS) {
        free(urma_event);
        return -status;
    }
    event->priv = (void *)urma_event;
    memcpy(&event->trans_info, trans_info, sizeof(umq_trans_info_t));
    event->original_code = urma_event->event_type;

    switch (urma_event->event_type) {
        case URMA_EVENT_JFC_ERR:
            handle_async_event_jfc_err(urma_event, event);
            break;
        case URMA_EVENT_JFR_ERR:
            handle_async_event_jfr_err(urma_event, event);
            break;
        case URMA_EVENT_JETTY_ERR:
            handle_async_event_jetty_err(urma_event, event);
            break;
        case URMA_EVENT_JFR_LIMIT:
            handle_async_event_jfr_limit(urma_event, event);
            break;
        case URMA_EVENT_JETTY_LIMIT:
            handle_async_event_jetty_limit(urma_event, event);
            break;
        case URMA_EVENT_PORT_ACTIVE:
            event->event_type = UMQ_EVENT_PORT_ACTIVE;
            event->element.port_id = urma_event->element.port_id;
            UMQ_LIMIT_VLOG_WARN("port active, port_id[%u]\n", event->element.port_id);
            break;
        case URMA_EVENT_PORT_DOWN:
            event->event_type = UMQ_EVENT_PORT_DOWN;
            event->element.port_id = urma_event->element.port_id;
            UMQ_LIMIT_VLOG_WARN("port down, port_id[%u]\n", event->element.port_id);
            break;
        case URMA_EVENT_DEV_FATAL:
            event->event_type = UMQ_EVENT_DEV_FATAL;
            UMQ_LIMIT_VLOG_WARN("dev fatal\n");
            break;
        case URMA_EVENT_EID_CHANGE:
            event->event_type = UMQ_EVENT_EID_CHANGE;
            UMQ_LIMIT_VLOG_WARN("eid change\n");
            break;
        case URMA_EVENT_ELR_ERR:
            event->event_type = UMQ_EVENT_ELR_ERR;
            UMQ_LIMIT_VLOG_WARN("entity level error\n");
            break;
        case URMA_EVENT_ELR_DONE:
            event->event_type = UMQ_EVENT_ELR_DONE;
            UMQ_LIMIT_VLOG_WARN("entity flush done\n");
            break;
        default:
            event->event_type = UMQ_EVENT_OTHER;
            UMQ_LIMIT_VLOG_WARN("unrecognized urma event[%d]\n", urma_event->event_type);
            break;
    }
    return URMA_SUCCESS;
}

void umq_ub_async_event_ack(umq_async_event_t *event)
{
    urma_async_event_t *urma_event = (urma_async_event_t *)event->priv;
    if (urma_event == NULL) {
        UMQ_LIMIT_VLOG_ERR("urma event invalid\n");
        return;
    }
    urma_ack_async_event(urma_event);
    free(urma_event);
    event->priv = NULL;
}

static int umq_ub_register_seg_callback(uint8_t *ctx, uint8_t mempool_id, void *addr, uint64_t size)
{
    if (ctx == NULL || addr == NULL || size == 0) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq_ub_register_seg((umq_ub_ctx_t *)(uintptr_t)ctx, mempool_id, addr, size);
}

static int umq_ub_unregister_seg_callback(uint8_t *ctx, uint8_t mempool_id)
{
    if (ctx == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    umq_ub_unregister_seg((umq_ub_ctx_t *)(uintptr_t)ctx, 1, mempool_id);
    return UMQ_SUCCESS;
}

int umq_ub_dev_add_impl(umq_trans_info_t *info, umq_init_cfg_t *cfg)
{
    if (info == NULL || cfg == NULL) {
        UMQ_VLOG_ERR("invalid paramete\n");
        return -UMQ_ERR_EINVAL;
    }

    if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        info->trans_mode != UMQ_TRANS_MODE_UBMM && info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_INFO("trans init mode: %d not UB\n", info->trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    // create ub ctx
    g_ub_ctx[g_ub_ctx_count].remote_imported_info = umq_ub_ctx_imported_info_create();
    if (g_ub_ctx[g_ub_ctx_count].remote_imported_info == NULL) {
        UMQ_VLOG_ERR("imported info create failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    int ret = umq_find_ub_device(info, &g_ub_ctx[g_ub_ctx_count]);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("find ub device failed\n");
        goto DELETE_IMPORT_INFO;
    }

    // register seg
    ret = umq_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], umq_ub_register_seg_callback);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("qbuf register seg failed\n");
        goto DELETE_URMA_CTX;
    }

    ret = umq_huge_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count],
        umq_ub_register_seg_callback, umq_ub_unregister_seg_callback);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("huge qbuf register seg failed\n");
        goto UNREGISTER_MEM;
    }

    g_ub_ctx[g_ub_ctx_count].io_lock_free = cfg->io_lock_free;
    g_ub_ctx[g_ub_ctx_count].feature = cfg->feature;
    g_ub_ctx[g_ub_ctx_count].flow_control = cfg->flow_control;
    g_ub_ctx[g_ub_ctx_count].order_type = URMA_DEF_ORDER;
    g_ub_ctx[g_ub_ctx_count].ref_cnt = 1;
    g_ub_ctx_count++;

    return UMQ_SUCCESS;

UNREGISTER_MEM:
    (void)umq_qbuf_unregister_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], umq_ub_unregister_seg_callback);

DELETE_URMA_CTX:
    (void)umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);

DELETE_IMPORT_INFO:
    (void)umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);

    return ret;
}

int ubmm_fill_ref_sge_info(uint64_t umqh_tp, umq_buf_t *qbuf, char *ub_ref_info, uint32_t ub_ref_info_size)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    uint32_t max_ref_sge_num = (ub_ref_info_size - sizeof(umq_imm_head_t)) / sizeof(ub_ref_sge_t);
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)ub_ref_info;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(ub_ref_info + sizeof(umq_imm_head_t));
    ub_fill_umq_imm_head(umq_imm_head, qbuf);

    ub_import_mempool_info_t import_mempool_info[UMQ_MAX_TSEG_NUM];
    umq_buf_t *tmp_buf = qbuf;
    uint32_t idx = 0;
    while (tmp_buf != NULL) {
        if (idx >= max_ref_sge_num) {
            UMQ_LIMIT_VLOG_ERR("rendezvoud buf count exceed max support count[%u]\n", max_ref_sge_num);
            return UMQ_FAIL;
        }

        fill_big_data_ref_sge(
            queue, ref_sge, tmp_buf, &import_mempool_info[umq_imm_head->mempool_num], umq_imm_head);
        tmp_buf = tmp_buf->qbuf_next;
        ref_sge = ref_sge + 1;
        idx++;
    }

    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_IMPORT_MEM) {
        if ((sizeof(umq_imm_head_t) + sizeof(ub_ref_sge_t) * idx +
            sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num) > umq_buf_size_small()) {
            UMQ_LIMIT_VLOG_ERR("import mempool info is not enough\n");
            return UMQ_FAIL;
        }
        (void)memcpy(ref_sge,
            import_mempool_info, sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num);
    }
    return UMQ_SUCCESS;
}

int umq_ub_get_route_list_impl(const umq_route_t *route, umq_route_list_t *route_list)
{
    if (route == NULL || route_list == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    uvs_route_t uvs_route = {.flag.value = route->flag.value, .hops = route->hops};
    uvs_route_list_t uvs_route_list = {0};
    (void)memcpy(&uvs_route.src, &route->src, sizeof(umq_eid_t));
    (void)memcpy(&uvs_route.dst, &route->dst, sizeof(umq_eid_t));

    int ret = uvs_get_route_list(&uvs_route, &uvs_route_list);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("get route list failed\n");
        return ret;
    }

    if (uvs_route_list.len > UMQ_MAX_ROUTES || uvs_route_list.len > UVS_MAX_ROUTES) {
        UMQ_VLOG_ERR("number of routes exceeds the maximum limit\n");
        return -UMQ_ERR_ENOMEM;
    }

    for (uint32_t i = 0; i < uvs_route_list.len; i++) {
        (void)memcpy(&route_list->buf[i].src, &uvs_route_list.buf[i].src, sizeof(umq_eid_t));
        (void)memcpy(&route_list->buf[i].dst, &uvs_route_list.buf[i].dst, sizeof(umq_eid_t));
        route_list->buf[i].flag.value = uvs_route_list.buf[i].flag.value;
        route_list->buf[i].hops = uvs_route_list.buf[i].hops;
    }
    route_list->len = uvs_route_list.len;
    return UMQ_SUCCESS;
}

int umq_ub_user_ctl_impl(uint64_t umqh_tp, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (in->opcode != UMQ_OPCODE_FLOW_CONTROL_STATS_QUERY || out->addr == 0 ||
        out->len != sizeof(umq_flow_control_stats_t)) {
        UMQ_VLOG_ERR("umq ub user ctl parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_flow_control_stats_t *stats = (umq_flow_control_stats_t *)(uintptr_t)out->addr;
    queue->flow_control.ops.stats_query(&queue->flow_control, stats);
    return UMQ_SUCCESS;
}

int umq_ub_mempool_state_get_impl(uint64_t umqh_tp, uint32_t mempool_id, umq_mempool_state_t *mempool_state)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->dev_ctx == NULL || queue->dev_ctx->remote_imported_info == NULL || queue->bind_ctx == NULL ||
        mempool_id >= UMQ_MAX_TSEG_NUM) {
        UMQ_VLOG_ERR("umq ub get mempool state parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    if (queue->dev_ctx->remote_imported_info->tesg_imported[queue->bind_ctx->remote_eid_id][mempool_id]) {
        mempool_state->import_state = MEMPOOL_STATE_IMPORTED;
    } else {
        mempool_state->import_state = MEMPOOL_STATE_NON_IMPORTED;
    }
    return UMQ_SUCCESS;
}

int umq_ub_mempool_state_refresh_impl(uint64_t umqh_tp, uint32_t mempool_id)
{
    umq_mempool_state_t mempool_state;
    if (umq_ub_mempool_state_get_impl(umqh_tp, mempool_id, &mempool_state) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("get mempool state failed\n");
        return -UMQ_ERR_EINVAL;
    }

    if (mempool_state.import_state == MEMPOOL_STATE_IMPORTED) {
        UMQ_VLOG_INFO("mempool %u is imported\n", mempool_id);
        return UMQ_SUCCESS;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];
    if (tseg == NULL) {
        UMQ_VLOG_ERR("mempool %u tseg not exist\n", mempool_id);
        return -UMQ_ERR_ENODEV;
    }
    urma_seg_t *seg = &tseg->seg;

    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), 1, queue->umqh, NULL);
    if (send_buf == NULL) {
        UMQ_VLOG_ERR("umq malloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)send_buf->qbuf_ext;
    umq_ub_imm_t imm = {.mem_import = {
        .umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_MEM, .sub_type = IMM_TYPE_MEM_IMPORT}};
    buf_pro->imm_data = imm.value;
    buf_pro->opcode = UMQ_OPC_SEND_IMM;

    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)send_buf->buf_data;
    umq_imm_head->version = UMQ_IMM_VERSION;
    umq_imm_head->type = IMM_PROTOCAL_TYPE_IMPORT_MEM;
    umq_imm_head->mempool_num = 1;
    umq_imm_head->mem_interval = UMQ_SIZE_INVALID_INTERVAL;

    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)(umq_imm_head + 1);
    import_mempool_info->mempool_seg_flag = seg->attr.value;
    import_mempool_info->mempool_length = seg->len,
    import_mempool_info->mempool_token_id = seg->token_id;
    import_mempool_info->mempool_id = mempool_id;
    import_mempool_info->mempool_token_value = tseg->user_ctx;
    (void)memcpy(import_mempool_info->mempool_ubva, &seg->ubva, sizeof(urma_ubva_t));

    urma_sge_t sge = {
        .addr = (uint64_t)(uintptr_t)send_buf->buf_data,
        .len = sizeof(umq_imm_head_t) + sizeof(ub_import_mempool_info_t),
        .user_tseg = NULL,
        .tseg = queue->dev_ctx->tseg_list[send_buf->mempool_id],
    };
    int ret = 0;
    uint16_t max_tx = umq_ub_window_dec(&queue->flow_control, queue, 1);
    if (max_tx == 0) {
        ret = -UMQ_ERR_EAGAIN;
        goto FREE_BUF;
    }

    ret = umq_ub_send_imm(queue, imm.value, &sge, (uint64_t)(uintptr_t)send_buf);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq ub send imm failed\n");
        goto INC_FC_WIN;
    }
    return UMQ_SUCCESS;

INC_FC_WIN:
    umq_ub_window_inc(&queue->flow_control, 1);

FREE_BUF:
    umq_buf_free(send_buf);
    return ret;
}
