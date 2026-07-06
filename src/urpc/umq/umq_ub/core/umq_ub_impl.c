/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB implementation
 * Create: 2025-7-19
 * Note:
 * History: 2025-7-19
 */

#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/queue.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>

#include "urpc_framework_errno.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "uvs_api.h"
#include "perf.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "urpc_timer.h"
#include "urpc_id_generator.h"
#include "urma_api.h"
#include "urma_perf.h"
#include "umq_symbol_private.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_qbuf_pool_helper.h"
#include "umq_tiny_qbuf_pool.h"
#include "umq_inner.h"
#include "umq_huge_qbuf_pool.h"
#include "util_id_generator.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_imm_data.h"
#include "umq_ub_private.h"
#include "umq_ub_impl.h"

#define UMQ_FLUSH_MAX_RETRY_TIMES 10000
#define UMQ_UB_DEFAULT_SLOT_NUM 10
#define UMQ_UB_EVENT_QUEUE_IDLE 1
#define UMQ_PORT_STR_SIZE 512

#define UMQ_ALIGN_64K(__size)    (((__size) + 65535) & ~65535)

static umq_ub_ctx_t *g_ub_ctx = NULL;
static uint32_t g_ub_ctx_count = 0;
static bool g_umq_ub_inited = false;

typedef struct umq_ub_monitor_slot {
    urpc_list_t monitored_links;
    uint32_t slot_id;
    util_external_mutex_lock *lock;
} umq_ub_monitor_slot_t;

typedef struct umq_ub_monitor_slots_array {
    umq_ub_monitor_slot_t *monitor_slots;
    volatile uint32_t current_slot;
    uint32_t slot_num;
    uint32_t timeout_us;
    uint32_t interval_us;
    urpc_timer_t *timer;
} umq_ub_monitor_slots_array_t;

static umq_ub_monitor_slots_array_t g_umq_monitor_slots = {0};
static urpc_id_generator_t g_umq_id_allocator;

static int huge_qbuf_pool_memory_init(uint16_t mempool_id, huge_qbuf_pool_size_type_t type, void **buffer_addr)
{
    uint32_t blk_size = umq_huge_qbuf_get_size_by_type(type);
    uint32_t total_len = blk_size * HUGE_QBUF_BUFFER_INC_BATCH;
    void *addr = (void *)memalign(UMQ_QBUF_ALIGN_SIZE, total_len);
    if (addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "memalign for huge qbuf pool failed, errno: %d\n", errno);
        return -UMQ_ERR_ENOMEM;
    }

    uint32_t failed_idx = 0;
    int ret = 0;
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        ret = umq_ub_register_seg(&g_ub_ctx[i], mempool_id, addr, total_len);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR(VLOG_UMQ, "ub ctx[%u] register segment failed, status: %d\n", i, ret);
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

static void huge_qbuf_pool_memory_uninit(uint16_t mempool_id, void *buf_addr)
{
    umq_ub_unregister_seg(g_ub_ctx, g_ub_ctx_count, mempool_id);
    free(buf_addr);
}

int umq_ub_log_config_set_impl(umq_log_config_t *config)
{
    if (config->log_flag & UMQ_LOG_FLAG_LEVEL) {
        umq_symbol_urma()->urma_log_set_level((urma_vlog_level_t)config->level);
    }

    if (((config->log_flag & UMQ_LOG_FLAG_FUNC) && config->func == NULL) ||
        ((config->log_flag & UMQ_LOG_FLAG_EXT_FUNC) && config->ext_func == NULL)) {
        return umq_symbol_urma()->urma_unregister_log_func();
    }

    if (config->log_flag & UMQ_LOG_FLAG_EXT_FUNC) {
        return umq_symbol_urma()->urma_register_loc_log_func(config->ext_func);
    }
    if (config->log_flag & UMQ_LOG_FLAG_FUNC) {
        return umq_symbol_urma()->urma_register_log_func(config->func);
    }
    return UMQ_SUCCESS;
}

int umq_ub_log_config_reset_impl(void)
{
    umq_symbol_urma()->urma_log_set_level(URMA_VLOG_LEVEL_INFO);
    return umq_symbol_urma()->urma_unregister_log_func();
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
            UMQ_VLOG_ERR(VLOG_UMQ, "initialize configuration for huge qbuf pool type(%d) failed, status: %d\n",
                i, ret);
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

uint32_t umq_ub_bind_info_get_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    if (bind_info_size < sizeof(umq_ub_bind_info_t)) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "bind_info_size[%u] is less than required size[%u], errno: %d\n", bind_info_size,
            sizeof(umq_ub_bind_info_t), errno);
        return 0;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    return umq_ub_bind_info_serialize(queue, bind_info, bind_info_size);
}

int umq_ub_bind_impl(uint64_t umqh, uint8_t *bind_info_buf, uint32_t bind_info_size)
{
    umq_ub_bind_info_t bind_info = {0};
    int ret = umq_ub_bind_info_deserialize(bind_info_buf, bind_info_size, &bind_info);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "deserialize bind info failed, status: %d\n", ret);
        return ret;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    ret = umq_ub_bind_info_check(queue, &bind_info);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    if (umq_ub_window_init(&queue->flow_control, &bind_info) != UMQ_SUCCESS) {
        return -UMQ_ERR_EINVAL;
    }
    return umq_ub_bind_inner_impl(queue, &bind_info);
}

static int32_t umq_ub_register_memory_with_id(uint16_t mempool_id, void *buf, uint64_t size)
{
    if (g_ub_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "no device is available to register memory\n");
        return -UMQ_ERR_ENODEV;
    }

    if (buf == NULL || size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid addr or size\n");
        return -UMQ_ERR_EINVAL;
    }

    uint32_t failed_idx;
    int ret = 0;
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        ret = umq_ub_register_seg(&g_ub_ctx[i], mempool_id, buf, size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR(VLOG_UMQ, "ub ctx[%u] register segment failed, status: %d\n", i, ret);
            goto UNREGISTER_MEM;
        }
    }
    return UMQ_SUCCESS;

UNREGISTER_MEM:
    umq_ub_unregister_seg(g_ub_ctx, failed_idx, mempool_id);
    return ret;
}

int32_t umq_ub_register_memory_impl(void *buf, uint64_t size)
{
    return umq_ub_register_memory_with_id(UMQ_QBUF_DEFAULT_MEMPOOL_ID, buf, size);
}

int32_t umq_ub_register_tiny_memory_impl(void)
{
    return umq_ub_register_memory_with_id(UMQ_TINY_QBUF_MEMPOOL_ID, umq_tiny_io_buf_addr(), umq_tiny_io_buf_size());
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
    (void)umqh_tp;
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
    (void)umqh_tp;
    umq_buf_list_t head;
    QBUF_LIST_INIT(&head);
    if (umq_qbuf_alloc(request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
        return NULL;
    }
    return QBUF_LIST_FIRST(&head);
}

void umq_ub_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    umq_invalid_handle_buf_free(&head, umq_pool_type_get(qbuf->mempool_id));
}

void umq_ub_plus_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    if (QBUF_LIST_NEXT(qbuf) == NULL) {
        umq_invalid_handle_buf_free(&head, umq_pool_type_get(qbuf->mempool_id));
        return;
    }

    /* Here, the free list will be traversed, and an attempt will be made to scan each qbuf object.
    * If there exist n consecutive qbuf objects that belong to the same memory pool, they will be
    * released in batch. */
    umq_buf_t *cur_node = NULL;
    umq_buf_t *next_node = NULL;
    umq_buf_list_t free_head;
    umq_buf_t *last_node = qbuf;
    umq_buf_t *free_node = qbuf; // head of the list to be released
    umq_pool_type_t type = umq_pool_type_get(qbuf->mempool_id);
    QBUF_LIST_FIRST(&head) = QBUF_LIST_NEXT(qbuf);

    QBUF_LIST_FOR_EACH_SAFE(cur_node, &head, next_node)
    {
        if (type == umq_pool_type_get(cur_node->mempool_id)) {
            // current qbuf is in the same pool, scan the next one directly
            last_node = cur_node;
            continue;
        }

        // free qbuf list in the same pool
        QBUF_LIST_NEXT(last_node) = NULL;
        QBUF_LIST_FIRST(&free_head) = free_node;
        umq_invalid_handle_buf_free(&free_head, type);

        // update variables
        free_node = cur_node;
        last_node = cur_node;
        type = umq_pool_type_get(cur_node->mempool_id);
    }

    QBUF_LIST_FIRST(&free_head) = free_node;
    umq_invalid_handle_buf_free(&free_head, type);
    return;
}

static int umq_find_ub_device(umq_trans_info_t *info, umq_ub_ctx_t *ub_ctx)
{
    char dev_str[UMQ_UB_DEV_STR_LENGTH] = {0};
    int ret = umq_ub_dev_str_get(&info->dev_info, dev_str, UMQ_UB_DEV_STR_LENGTH);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    if (g_ub_ctx_count >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ub ctx cnt exceeded the maximum limit %u\n", MAX_UMQ_TRANS_INFO_NUM);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &info->dev_info) != NULL) {
        UMQ_VLOG_WARN(VLOG_UMQ, "ub ctx already exists, dev: %s\n", dev_str);
        return -UMQ_ERR_EEXIST;
    }

    urma_device_t *urma_dev;
    uint32_t eid_index = 0;
    ub_ctx->trans_info.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
    ub_ctx->trans_info.trans_mode = info->trans_mode;

    ret = umq_ub_get_urma_dev(&info->dev_info, &urma_dev, &ub_ctx->trans_info.dev_info.eid.eid, &eid_index);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to get urma dev, dev: %s, status: %d\n", dev_str, ret);
        return -UMQ_ERR_ENODEV;
    }

    ret = umq_ub_create_urma_ctx(urma_dev, eid_index, ub_ctx);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq get urma ctx failed, dev: %s, status: %d\n", dev_str, ret);
        return ret;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "umq_find_ub_device success, dev: %s\n", dev_str);

    return UMQ_SUCCESS;
}

uint32_t current_get_and_next_update(void)
{
    uint32_t old_val, new_val;
    do {
        old_val = __atomic_load_n(&g_umq_monitor_slots.current_slot, __ATOMIC_ACQUIRE);
        // next slot id
        new_val = old_val + 1;
        if (new_val >= g_umq_monitor_slots.slot_num) {
            new_val = 0;
        }
    } while (!__atomic_compare_exchange_n(
        &g_umq_monitor_slots.current_slot, &old_val, new_val, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    return old_val;
}

static uint32_t target_slot_id_calcuate(uint64_t expire_time, uint64_t current_time, uint32_t current_slot_id)
{
    uint32_t slot_num = g_umq_monitor_slots.slot_num;
    uint32_t interval_us = g_umq_monitor_slots.interval_us;
    uint32_t target_slot_id;
    if (expire_time <= current_time) {
        target_slot_id = current_slot_id;
        return target_slot_id;
    }

    uint64_t delay_time = expire_time - current_time;
    uint32_t delay_slots = (delay_time + interval_us - 1) / interval_us;
    target_slot_id = (current_slot_id + delay_slots) % slot_num;
    return target_slot_id;
}

/* this function can be called only umq_ub_idle_queue_check or umq_ub_monitor_slots_uninit function */
static void umq_ub_idle_checker_uninit(ub_queue_idle_check_t *checker)
{
    checker->umq = NULL;
    close(checker->event_fd);
    checker->event_fd = UMQ_INVALID_FD;
    (void)util_mutex_lock_destroy(checker->lock);
    checker->lock = NULL;
    free(checker);
}

void umq_ub_idle_queue_check(void *args)
{
    uint32_t current_slot_id = current_get_and_next_update();
    umq_ub_monitor_slot_t *current_slot_obj = &g_umq_monitor_slots.monitor_slots[current_slot_id];
    ub_queue_idle_check_t *cur_node, *next_node;
    urpc_list_t temp_list;
    urpc_list_init(&temp_list);
    uint64_t value = UMQ_UB_EVENT_QUEUE_IDLE;
    uint64_t current_timestamp = get_timestamp_us();
    uint64_t timeout_us = g_umq_monitor_slots.timeout_us;
    (void)util_mutex_lock(current_slot_obj->lock);
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &current_slot_obj->monitored_links) {
        (void)util_mutex_lock(cur_node->lock);
        ub_queue_t *queue = cur_node->umq;
        if (queue == NULL) {
            urpc_list_remove(&cur_node->node);
            (void)util_mutex_unlock(cur_node->lock);
            umq_ub_idle_checker_uninit(cur_node);
            continue;
        }
        ub_flow_control_t *fc = &queue->flow_control;
        uint16_t remote_credit = fc->ops.remote_rx_window_load(fc);
        uint16_t return_threshold = 0;
        if (fc->peer_ratio == 0) {
            return_threshold = 0;
        } else {
            return_threshold = umq_ub_flow_control_threashold_modify((uint16_t)fc->min_reserved_credit, fc->peer_ratio);
        }
        if (remote_credit <= return_threshold) {
            (void)util_mutex_unlock(cur_node->lock);
            continue;
        }
        uint64_t last_send = __atomic_load_n(&cur_node->last_send, __ATOMIC_ACQUIRE);
        if (current_timestamp >= last_send) {
            uint64_t diff = (current_timestamp - last_send);
            if (diff >= timeout_us) {
                __atomic_store_n(&cur_node->need_return_credit, true, __ATOMIC_RELEASE);
                if (eventfd_write(cur_node->event_fd, value) == -1) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "umq write event failed, err: %s\n", strerror(errno));
                }
            }
        }
        uint64_t expire_time = last_send + timeout_us;
        uint32_t target_slot_id = target_slot_id_calcuate(expire_time, current_timestamp, current_slot_id);
        if (target_slot_id != current_slot_id) {
            urpc_list_remove(&cur_node->node);
            urpc_list_push_back(&temp_list, &cur_node->node);
            __atomic_store_n(&cur_node->target_slot_id, target_slot_id, __ATOMIC_RELEASE);
        }
        (void)util_mutex_unlock(cur_node->lock);
    }
    (void)util_mutex_unlock(current_slot_obj->lock);
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &temp_list) {
        uint32_t target_slot_id = cur_node->target_slot_id;
        (void)util_mutex_lock(g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
        urpc_list_remove(&cur_node->node);
        urpc_list_push_back(&g_umq_monitor_slots.monitor_slots[target_slot_id].monitored_links, &cur_node->node);
        (void)util_mutex_unlock(g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
    }
    return;
}

static int umq_ub_monitor_slots_init(umq_init_cfg_t *cfg)
{
    g_umq_monitor_slots.slot_num = UMQ_UB_DEFAULT_SLOT_NUM;
    if (cfg->flow_control.timeout_ms == 0 || cfg->flow_control.timeout_ms % g_umq_monitor_slots.slot_num != 0) {
        g_umq_monitor_slots.timeout_us = US_PER_MS * UMQ_UB_DEFAULT_SLOT_NUM;
        g_umq_monitor_slots.interval_us = US_PER_MS;
    } else {
        g_umq_monitor_slots.timeout_us = cfg->flow_control.timeout_ms * US_PER_MS;
        g_umq_monitor_slots.interval_us = (g_umq_monitor_slots.timeout_us / g_umq_monitor_slots.slot_num);
    }
    g_umq_monitor_slots.monitor_slots =
        (umq_ub_monitor_slot_t *)calloc(g_umq_monitor_slots.slot_num, sizeof(umq_ub_monitor_slot_t));
    if (g_umq_monitor_slots.monitor_slots == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq monitor_slots calloc failed\n");
        return UMQ_FAIL;
    }
    uint32_t i = 0;
    for (; i < g_umq_monitor_slots.slot_num; i++) {
        urpc_list_init(&g_umq_monitor_slots.monitor_slots[i].monitored_links);
        g_umq_monitor_slots.monitor_slots[i].slot_id = i;
        g_umq_monitor_slots.monitor_slots[i].lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
        if (g_umq_monitor_slots.monitor_slots[i].lock == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq monitor slots mutex create failed\n");
            goto LOCK_DESTROY;
        }
    }
    return UMQ_SUCCESS;

LOCK_DESTROY:
    for (uint32_t j = 0; j < i; j++) {
        (void)util_mutex_lock_destroy(g_umq_monitor_slots.monitor_slots[j].lock);
        g_umq_monitor_slots.monitor_slots[j].lock = NULL;
    }
    free(g_umq_monitor_slots.monitor_slots);
    return -UMQ_ERR_ENOMEM;
}

static ALWAYS_INLINE void umq_ub_monitor_slots_uninit(void)
{
    ub_queue_idle_check_t *cur_node, *next_node;
    for (uint32_t i  = 0; i < g_umq_monitor_slots.slot_num; i++) {
        umq_ub_monitor_slot_t *current_slot_obj = &g_umq_monitor_slots.monitor_slots[i];
        URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &current_slot_obj->monitored_links) {
            urpc_list_remove(&cur_node->node);
            umq_ub_idle_checker_uninit(cur_node);
        }
        (void)util_mutex_lock_destroy(current_slot_obj->lock);
        current_slot_obj->lock = NULL;
    }
    if (g_umq_monitor_slots.monitor_slots != NULL) {
        free(g_umq_monitor_slots.monitor_slots);
    }
    g_umq_monitor_slots.monitor_slots = NULL;
    g_umq_monitor_slots.slot_num = 0;
}

static int umq_ub_check_idle_queue_timer_create(umq_init_cfg_t *cfg)
{
    if ((cfg->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) == 0) {
        return UMQ_SUCCESS;
    }

    if (umq_ub_monitor_slots_init(cfg) != UMQ_SUCCESS) {
        return UMQ_FAIL;
    }

    g_umq_monitor_slots.timer = urpc_timer_create(URPC_INVALID_ID_U32, false);
    if (URPC_UNLIKELY(g_umq_monitor_slots.timer == NULL)) {
        goto MONITOR_UNINIT;
    }
    void *args = NULL;
    int ret = urpc_timer_start(
        g_umq_monitor_slots.timer, g_umq_monitor_slots.interval_us / US_PER_MS, umq_ub_idle_queue_check, args, true);
    if (URPC_UNLIKELY(ret != UMQ_SUCCESS)) {
        goto TIMER_DESTROY;
    }
    return UMQ_SUCCESS;

TIMER_DESTROY:
    urpc_timer_destroy(g_umq_monitor_slots.timer);
    g_umq_monitor_slots.timer = NULL;

MONITOR_UNINIT:
    umq_ub_monitor_slots_uninit();

    return UMQ_FAIL;
}

static void umq_ub_check_idle_queue_timer_delete(void)
{
    if (g_umq_monitor_slots.timer != NULL) {
        urpc_timer_destroy(g_umq_monitor_slots.timer);
        g_umq_monitor_slots.timer = NULL;
    }
    umq_ub_monitor_slots_uninit();
}

uint32_t umq_ub_timer_timeout_get(void)
{
    return g_umq_monitor_slots.timeout_us;
}

static int umq_ub_register_seg_callback(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size);
static void umq_ub_unregister_seg_callback(uint8_t *ctx, uint16_t mempool_id);

static int umq_ub_ctx_init_one(umq_ub_ctx_t *ctx, umq_trans_info_t *info, umq_init_cfg_t *cfg)
{
    ctx->remote_imported_info = umq_ub_ctx_imported_info_create();
    if (ctx->remote_imported_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "imported info create failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    int ret = umq_find_ub_device(info, ctx);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "find ub device failed, status: %d\n", ret);
        goto DESTROY_IMPORTED_INFO;
    }

    ctx->umq_ctx_table = (volatile uint64_t *)calloc(UMQ_ID_ALLOC_SIZE, sizeof(uint64_t));
    if (ctx->umq_ctx_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc umq_ctx_table failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto DELETE_URMA;
    }

    ctx->rx_consumed_jetty_table = (volatile uint64_t *)calloc(UMQ_ID_ALLOC_SIZE, sizeof(uint64_t));
    if (ctx->rx_consumed_jetty_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc rx_consumed_jetty_table failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_CTX_TABLE;
    }

    ctx->io_lock_free = cfg->io_lock_free;
    ctx->rq_lock_free = cfg->rq_lock_free;
    ctx->feature = cfg->feature;
    ctx->flow_control = cfg->flow_control;
    ctx->ref_cnt = 1;
    (void)pthread_spin_init(&ctx->tseg_list_lock, PTHREAD_PROCESS_PRIVATE);

    return UMQ_SUCCESS;

FREE_CTX_TABLE:
    free((void *)ctx->umq_ctx_table);
    ctx->umq_ctx_table = NULL;

DELETE_URMA:
    umq_ub_delete_urma_ctx(ctx);

DESTROY_IMPORTED_INFO:
    umq_ub_ctx_imported_info_destroy(ctx);
    return ret;
}

uint8_t *umq_ub_ctx_init_impl(umq_init_cfg_t *cfg)
{
    if (g_umq_ub_inited) {
        UMQ_VLOG_WARN(VLOG_UMQ, "umq ub ctx already inited\n");
        return (uint8_t *)g_ub_ctx;
    }

    int ret = umq_ub_id_allocator_init();
    if (ret != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "id allocator init failed, status: %d\n", ret);
        return NULL;
    }

    ret = urpc_id_generator_init(&g_umq_id_allocator, URPC_ID_GENERATOR_TYPE_BITMAP_AUTO_INC, UMQ_ID_ALLOC_SIZE);
    if (ret != URPC_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "id generator init failed, status: %d\n", ret);
        goto UNINIT_ALLOCATOR;
    }

    g_ub_ctx = (umq_ub_ctx_t *)calloc(MAX_UMQ_TRANS_INFO_NUM, sizeof(umq_ub_ctx_t));
    if (g_ub_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "memory alloc failed\n");
        goto UNINIT_UMQ_ID_ALLOCATOR;
    }

    urma_init_attr_t init_attr = {0};
    ret = umq_symbol_urma()->urma_init(&init_attr);
    if (ret != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_init failed, status: %d\n", ret);
        goto FREE_CTX;
    }

    if (umq_ub_dev_info_init() != UMQ_SUCCESS) {
        goto URMA_UNINIT;
    }

    for (uint32_t i = 0; i < cfg->trans_info_num; i++) {
        umq_trans_info_t *info = &cfg->trans_info[i];
        if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
            UMQ_VLOG_INFO(VLOG_UMQ, "trans init mode: %d not UB, skip it\n", info->trans_mode);
            continue;
        }

        if (info->dev_info.assign_mode == UMQ_DEV_ASSIGN_MODE_DUMMY) {
            UMQ_VLOG_INFO(VLOG_UMQ, "device info assign_mode is dummy, skip it\n");
            continue;
        }

        ret = umq_ub_ctx_init_one(&g_ub_ctx[g_ub_ctx_count], info, cfg);
        if (ret != UMQ_SUCCESS) {
            goto ROLLBACK_UB_CTX;
        }
        ++g_ub_ctx_count;
    }

    umq_qbuf_pool_plan_t buf_pool_plan;
    ret = umq_qbuf_pool_cfg_check(cfg, &buf_pool_plan);
    if (ret != UMQ_SUCCESS) {
        goto ROLLBACK_UB_CTX;
    }

    if (umq_io_buf_malloc(cfg->buf_mode, buf_pool_plan.normal_io_buf_size) == NULL) {
        goto ROLLBACK_UB_CTX;
    }

    qbuf_pool_cfg_t qbuf_cfg = {
        .buf_addr = umq_io_buf_addr(),
        .total_size = umq_io_buf_size(),
        .data_size = umq_buf_size_small(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
        .umq_buf_pool_max_size = buf_pool_plan.normal_pool_budget_size,
        .expansion_block_count = cfg->buf_pool_cfg.expansion_block_count,
        .seg_ops = {
            .register_seg_callback = umq_ub_register_seg_callback,
            .unregister_seg_callback = umq_ub_unregister_seg_callback,
        },
        .disable_scale_cap = cfg->buf_pool_cfg.disable_scale_cap,
        .expansion_pool_id_min = HUGE_QBUF_POOL_MEMPOOL_ID_MAX,
        .expansion_pool_cnt_max = UMQ_EXPANSION_POOL_CNT_MAX,
        .tls_qbuf_pool_depth = cfg->buf_pool_cfg.tls_qbuf_pool_depth,
        .tls_expand_qbuf_pool_depth = cfg->buf_pool_cfg.tls_expand_qbuf_pool_depth,
        .disable_malloc_escape = cfg->buf_pool_cfg.disable_malloc_escape,
    };
    ret = umq_qbuf_pool_init(&qbuf_cfg);
    if (ret != UMQ_SUCCESS && ret != -UMQ_ERR_EEXIST) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool init failed, status: %d\n", ret);
        goto IO_BUF_FREE;
    }

    if (cfg->buf_pool_cfg.enable_tiny_pool) {
        if (umq_tiny_io_buf_malloc(cfg->buf_mode, buf_pool_plan.tiny_io_buf_size) == NULL) {
            goto QBUF_POOL_UNINIT;
        }

        qbuf_pool_cfg_t tiny_qbuf_cfg = qbuf_cfg;
        tiny_qbuf_cfg.buf_addr = umq_tiny_io_buf_addr();
        tiny_qbuf_cfg.total_size = umq_tiny_io_buf_size();
        tiny_qbuf_cfg.data_size = buf_pool_plan.tiny_block_size;
        tiny_qbuf_cfg.tls_qbuf_pool_depth = cfg->buf_pool_cfg.tls_tiny_pool_depth;
        tiny_qbuf_cfg.tls_expand_qbuf_pool_depth = cfg->buf_pool_cfg.tls_expand_tiny_pool_depth;
        ret = umq_tiny_qbuf_pool_init(&tiny_qbuf_cfg);
        if (ret != UMQ_SUCCESS && ret != -UMQ_ERR_EEXIST) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tiny qbuf pool init failed, status: %d\n", ret);
            goto TINY_IO_BUF_FREE;
        }
    }

    ret = umq_ub_queue_ctx_list_init();
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ub queue ctx list init failed, status: %d\n", ret);
        goto TINY_QBUF_POOL_UNINIT;
    }
    if (umq_ub_check_idle_queue_timer_create(cfg) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq check idle queue timer create failed\n");
        goto QUEUE_CTX_LIST_UNINIT;
    }

    jetty_pool_config_t config = {
        .notify_threshold = cfg->tp_pool_cfg.notify_threshold,
    };
    ret = umq_ub_jetty_pool_init(&config);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty pool init failed, status: %d\n", ret);
        goto DELETE_TIMER;
    }

    g_umq_ub_inited = true;
    return (uint8_t *)(uintptr_t)g_ub_ctx;

DELETE_TIMER:
    umq_ub_check_idle_queue_timer_delete();

QUEUE_CTX_LIST_UNINIT:
    umq_ub_queue_ctx_list_uninit();

TINY_QBUF_POOL_UNINIT:
    umq_tiny_qbuf_pool_uninit();

TINY_IO_BUF_FREE:
    umq_tiny_io_buf_free();

QBUF_POOL_UNINIT:
    umq_qbuf_pool_uninit();

IO_BUF_FREE:
    umq_io_buf_free();

ROLLBACK_UB_CTX:
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        umq_ub_ctx_imported_info_destroy(&g_ub_ctx[i]);
        umq_ub_delete_urma_ctx(&g_ub_ctx[i]);
        free((void*)g_ub_ctx[i].umq_ctx_table);
        g_ub_ctx[i].umq_ctx_table = NULL;
        free((void*)g_ub_ctx[i].rx_consumed_jetty_table);
        g_ub_ctx[i].rx_consumed_jetty_table = NULL;
        (void)pthread_spin_destroy(&g_ub_ctx[i].tseg_list_lock);
    }
    g_ub_ctx_count = 0;
    umq_ub_dev_info_uninit();

URMA_UNINIT:
    (void)umq_symbol_urma()->urma_uninit();

FREE_CTX:
    free(g_ub_ctx);
    g_ub_ctx = NULL;

UNINIT_UMQ_ID_ALLOCATOR:
    urpc_id_generator_uninit(&g_umq_id_allocator);

UNINIT_ALLOCATOR:
    umq_ub_id_allocator_uninit();
    return NULL;
}

void umq_ub_ctx_uninit_impl(uint8_t *ctx)
{
    umq_ub_ctx_t *context = (umq_ub_ctx_t *)ctx;
    if (context != g_ub_ctx) {
        UMQ_VLOG_ERR(VLOG_UMQ, "uninit failed, ub_ctx is invalid\n");
        return;
    }
    g_ub_ctx = NULL;
    for (uint32_t i = 0; i < g_ub_ctx_count; ++i) {
        if (umq_fetch_ref(context[i].io_lock_free, &context[i].ref_cnt) > 1) {
            UMQ_VLOG_ERR(VLOG_UMQ, "device ref cnt not cleared\n");
            g_ub_ctx = context;
            return;
        }
    }

    umq_ub_jetty_pool_uninit();
    umq_ub_check_idle_queue_timer_delete();
    umq_ub_queue_ctx_list_uninit();
    umq_tiny_qbuf_pool_uninit();
    umq_qbuf_pool_uninit();

    for (uint32_t i = 0; i < g_ub_ctx_count; ++i) {
        umq_ub_ctx_imported_info_destroy(&context[i]);
        umq_dec_ref(context[i].io_lock_free, &context[i].ref_cnt, 1);
        umq_symbol_urma()->urma_delete_context(context[i].urma_ctx);
        free((void*)context[i].umq_ctx_table);
        context[i].umq_ctx_table = NULL;
        free((void*)context[i].rx_consumed_jetty_table);
        context[i].rx_consumed_jetty_table = NULL;
        (void)pthread_spin_destroy(&context[i].tseg_list_lock);
    }

    umq_tiny_io_buf_free();
    umq_io_buf_free();
    umq_ub_id_allocator_uninit();
    umq_ub_dev_info_uninit();

    free(context);
    g_ub_ctx_count = 0;
    g_umq_ub_inited = false;
    umq_symbol_urma()->urma_uninit();
    urpc_id_generator_uninit(&g_umq_id_allocator);
}

static int umq_ub_idle_checker_init(ub_queue_t *queue)
{
    ub_queue_idle_check_t *checker = (ub_queue_idle_check_t *)calloc(1, sizeof(ub_queue_idle_check_t));
    if (checker == NULL) {
        queue->checker = NULL;
        return UMQ_FAIL;
    }
    queue->checker = checker;
    checker->lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    int ret = UMQ_SUCCESS;
    if (checker->lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "checker mutex create failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_CHECKER;
    }
    checker->umq = queue;
    checker->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (checker->event_fd == UMQ_INVALID_FD) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create eventfd failed, err: %s\n", strerror(errno));
        ret = UMQ_FAIL;
        goto CHECKER_LOCK_DESTROY;
    }
    uint64_t current_time = get_timestamp_us();
    checker->last_send = current_time;
    uint64_t expire_time = current_time + g_umq_monitor_slots.timeout_us;
    uint32_t current_slot_id = __atomic_load_n(&g_umq_monitor_slots.current_slot, __ATOMIC_RELAXED);
    uint32_t target_slot_id = target_slot_id_calcuate(expire_time, current_time, current_slot_id);
    checker->target_slot_id = target_slot_id;
    (void)util_mutex_lock(g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
    urpc_list_push_back(&g_umq_monitor_slots.monitor_slots[target_slot_id].monitored_links, &checker->node);
    (void)util_mutex_unlock(g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
    return UMQ_SUCCESS;

CHECKER_LOCK_DESTROY:
    (void)util_mutex_lock_destroy(checker->lock);
    checker->lock = NULL;

FREE_CHECKER:
    free(checker);
    queue->checker = NULL;
    return ret;
}

static int umq_ub_create_flow_control_resource(ub_queue_t *queue, ub_queue_t *share_queue, umq_create_option_t *option,
    const char *port_str)
{
    uint64_t start_timestamp;
    if (!queue->flow_control.enabled) {
        return UMQ_SUCCESS;
    }
    bondp_jfc_cfg_t bondp_jfc_cfg = {
        .base = {
            .depth = UMQ_UB_FLOW_CONTORL_JETTY_DEPTH, // jfs_jfce is shared between fc jfs_jfc and io jfs_jfc
            .jfce = queue->jfs_jfce,
            .flag.bs.has_drv_ext = ((queue->create_flag & UMQ_CREATE_FLAG_USED_PORTS) != 0)
        },
        .port_ids = queue->used_port,
        .port_count = queue->used_port_num,
    };

    umq_ub_ctx_t *dev_ctx = queue->dev_ctx;
    if (umq_ub_jfr_ctx_get(queue, dev_ctx, option, share_queue, UB_QUEUE_JETTY_FLOW_CONTROL) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get flow control jfr ctx failed\n");
        return UMQ_FAIL;
    }
    umq_ub_rx_consumed_exchange(dev_ctx->io_lock_free, &dev_ctx->rx_consumed_jetty_table[queue->umq_id], 0);

    if (!is_umq_ub_logic_queue(option->create_flag)) {
        start_timestamp = umq_perf_get_start_timestamp();
        queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] =
            umq_symbol_urma()->urma_create_jfc(dev_ctx->urma_ctx, &bondp_jfc_cfg.base);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFC, start_timestamp);
        if (queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for flowcontrol jfs_jfc failed, errno: %d\n", errno);
            goto DESTROY_FC_JFR_CTX;
        }

        umq_create_jetty_config_t create_fc_jetty_config = {
            .jetty_idx = UB_QUEUE_JETTY_FLOW_CONTROL,
            .jfs_jfc = queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL],
            .port_str = port_str,
            .used_port = queue->used_port,
            .used_port_num = queue->used_port_num,
        };
        queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] = umq_create_jetty(queue, dev_ctx, &create_fc_jetty_config);
        if (queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
            goto DELETE_FC_JFS_JFC;
        }

        if (queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id >=
            UMQ_ALIGN_64K(queue->dev_ctx->dev_attr.dev_cap.max_jetty)) {
            UMQ_VLOG_ERR(VLOG_UMQ, "jetty id %u exceed max jetty %u\n",
                queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id,
                UMQ_ALIGN_64K(queue->dev_ctx->dev_attr.dev_cap.max_jetty));
            goto DELETE_FC_JETTY;
        }
    }

    uint8_t rqe_post_factor = queue->used_port_num == 0 ? 1 : queue->used_port_num;
    if (UMQ_UB_ENABLE_SHARE_FC_JFR && (option->create_flag & UMQ_CREATE_FLAG_MAIN_UMQ) != 0) {
        // the coefficient for the number of main umq post flow control rx operations uses rqe_post_factor
        rqe_post_factor = queue->rqe_post_factor;
    }

    if (UMQ_UB_ENABLE_SHARE_FC_JFR && (option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0) {
        // sub umq does not need to post flow control rx
        rqe_post_factor = 0;
    }

    if (umq_ub_fill_fc_rx_buf_batch(queue, rqe_post_factor) != UMQ_SUCCESS) {
        goto DELETE_FC_JETTY;
    }

    /* if step A after umq_ub_idle_checker_init, step A fails,
     * umq_ub_idle_checker_uninit can not be called, need to lock checker, setting checker->umq to NULL,
     * umq_ub_idle_queue_check or umq_ub_monitor_slots_uninit free resoures */
    if ((queue->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0) {
        if (umq_ub_idle_checker_init(queue) != UMQ_SUCCESS) {
            goto DELETE_FC_JETTY;
        }
    }

    return UMQ_SUCCESS;

DELETE_FC_JETTY:
    if (!is_umq_ub_logic_queue(option->create_flag)) {
        (void)umq_symbol_urma()->urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
    }

DELETE_FC_JFS_JFC:
    if (!is_umq_ub_logic_queue(option->create_flag)) {
        (void)umq_symbol_urma()->urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]);
    }

DESTROY_FC_JFR_CTX:
    umq_ub_jfr_ctx_put(queue, UB_QUEUE_JETTY_FLOW_CONTROL);

    return UMQ_FAIL;
}

static void umq_jetty_port_info(char *buf, int size, ub_queue_t *queue)
{
    int ret;
    int offset = 0;
    int remain = size;

    for (uint8_t i = 0; i < queue->used_port_num; i++) {
        ret = snprintf(buf + offset, remain, " [chip: %hhu, die: %hhu, port: %hhu]", queue->used_port[i].chip_id,
                       queue->used_port[i].die_id, queue->used_port[i].port_idx);
        if (ret < 0 || ret >= remain) {
            buf[0] = 0;
            UMQ_VLOG_ERR(VLOG_UMQ, "format jetty port info failed, port_num %d, error %d\n", queue->used_port_num, ret);
            return;
        }

        offset += ret;
        remain -= ret;
    }
}

static int umq_ub_create_jetty_node(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx,
    umq_tp_resource_create_option_t *option, jetty_pool_node_t **node)
{
    uint64_t start_timestamp;
    int ret = UMQ_FAIL;
    uint8_t used_port_num = option->used_ports.num;
    bondp_port_id_t used_port[used_port_num > 0 ? used_port_num : 1];
    bool option_with_used_ports = ((option->create_flag & UMQ_TP_CREATE_FLAG_USED_PORTS) != 0);
    bool queue_with_used_ports = ((queue->create_flag & UMQ_CREATE_FLAG_USED_PORTS) != 0);
    if (option_with_used_ports != queue_with_used_ports) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tp handle %s used port, but main umq %s used port\n",
            option_with_used_ports ? "with" : "without", queue_with_used_ports ? "with" : "without");
        return -UMQ_ERR_EINVAL;
    }

    jetty_pool_node_t *jetty_node = umq_ub_jetty_pool_get_free_node();
    if (jetty_node == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get free jetty node failed, errno %d\n", errno);
        return -UMQ_ERR_ENOMEM;
    }

    if (queue->mode == UMQ_MODE_INTERRUPT) {
        start_timestamp = umq_perf_get_start_timestamp();
        jetty_node->jfs_jfce = umq_symbol_urma()->urma_create_jfce(dev_ctx->urma_ctx);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFCE, start_timestamp);
        if (jetty_node->jfs_jfce == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfce for jfs_jfce failed, errno: %d\n", errno);
            goto PUT_FREE_NODE;
        }
    }

    if ((option->create_flag & UMQ_TP_CREATE_FLAG_USED_PORTS) != 0) {
        if (umq_bondp_port_id_set(&option->used_ports, used_port, used_port_num) != UMQ_SUCCESS) {
            ret = -UMQ_ERR_EINVAL;
            goto DELETE_JFCE;
        }
    }

    bondp_jfc_cfg_t bondp_jfc_cfg = {
        .base = {
            .depth = queue->tx_depth + 1, // flush done consumes one cqe
            .jfce = jetty_node->jfs_jfce,
            .flag.bs.has_drv_ext = ((option->create_flag & UMQ_TP_CREATE_FLAG_USED_PORTS) != 0)
        },
        .port_ids = used_port,
        .port_count = used_port_num,
    };
    start_timestamp = umq_perf_get_start_timestamp();
    jetty_node->jfs_jfc[UB_QUEUE_JETTY_IO] = umq_symbol_urma()->urma_create_jfc(dev_ctx->urma_ctx, &bondp_jfc_cfg.base);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFC, start_timestamp);
    if (jetty_node->jfs_jfc[UB_QUEUE_JETTY_IO] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for jfs_jfc failed, errno: %d\n", errno);
        goto DELETE_JFCE;
    }

    char port_str[UMQ_PORT_STR_SIZE] = {0};
    umq_jetty_port_info(port_str, UMQ_PORT_STR_SIZE, queue);

    umq_create_jetty_config_t create_io_jetty_config = {
        .jetty_idx = UB_QUEUE_JETTY_IO,
        .jfs_jfc = jetty_node->jfs_jfc[UB_QUEUE_JETTY_IO],
        .port_str = port_str,
        .used_port = used_port,
        .used_port_num = used_port_num,
    };
    jetty_node->jetty[UB_QUEUE_JETTY_IO] = umq_create_jetty(queue, dev_ctx, &create_io_jetty_config);
    if (jetty_node->jetty[UB_QUEUE_JETTY_IO] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "umq_create_jetty for io jetty failed, errno: %d\n", errno);
        goto DELETE_JFS_JFC;
    }

    if (queue->flow_control.enabled) {
        start_timestamp = umq_perf_get_start_timestamp();
        jetty_node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] =
        umq_symbol_urma()->urma_create_jfc(dev_ctx->urma_ctx, &bondp_jfc_cfg.base);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFC, start_timestamp);
        if (jetty_node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for flowcontrol jfs_jfc failed, errno: %d\n", errno);
            goto DELETE_JETTY;
        }

        umq_create_jetty_config_t create_fc_jetty_config = {
            .jetty_idx = UB_QUEUE_JETTY_FLOW_CONTROL,
            .jfs_jfc = jetty_node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL],
            .port_str = port_str,
            .used_port = used_port,
            .used_port_num = used_port_num,
        };
        jetty_node->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] = umq_create_jetty(queue, dev_ctx, &create_fc_jetty_config);
        if (jetty_node->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "umq_create_jetty for flow flowcontrol jetty failed, errno: %d\n", errno);
            goto DELETE_FC_JFS_JFC;
        }
    }

    ret = umq_ub_jetty_node_add(jetty_node);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "jetty node add failed, ret: %d\n", ret);
        goto DELETE_FC_JETTY;
    }

    *node = jetty_node;
    return UMQ_SUCCESS;

DELETE_FC_JETTY:
    if (queue->flow_control.enabled) {
        (void)umq_symbol_urma()->urma_delete_jetty(jetty_node->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
    }

DELETE_FC_JFS_JFC:
    if (queue->flow_control.enabled) {
        (void)umq_symbol_urma()->urma_delete_jfc(jetty_node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]);
    }

DELETE_JETTY:
    (void)umq_symbol_urma()->urma_delete_jetty(jetty_node->jetty[UB_QUEUE_JETTY_IO]);
DELETE_JFS_JFC:
    (void)umq_symbol_urma()->urma_delete_jfc(jetty_node->jfs_jfc[UB_QUEUE_JETTY_IO]);
DELETE_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        (void)umq_symbol_urma()->urma_delete_jfce(jetty_node->jfs_jfce);
    }
PUT_FREE_NODE:
    umq_ub_jetty_pool_put_free_node(jetty_node);

    return ret;
}

static int umq_ub_destroy_jetty_node(ub_queue_t *queue, jetty_pool_node_t *jetty_node)
{
    uint64_t start_timestamp;
    urma_jetty_t *fc_jetty = jetty_node->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_jetty_t *io_jetty = jetty_node->jetty[UB_QUEUE_JETTY_IO];
    urma_jfc_t *fc_jfs_jfc = jetty_node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_jfc_t *io_jfs_jfc = jetty_node->jfs_jfc[UB_QUEUE_JETTY_IO];
    urma_jfce_t *jfs_jfce = jetty_node->jfs_jfce;
    int ret = umq_ub_jetty_node_remove(jetty_node);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "remove jetty node failed\n");
        return ret;
    }

    if (queue->flow_control.enabled) {
        start_timestamp = umq_perf_get_start_timestamp();
        (void)umq_symbol_urma()->urma_delete_jetty(fc_jetty);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JETTY, start_timestamp);
        start_timestamp = umq_perf_get_start_timestamp();
        (void)umq_symbol_urma()->urma_delete_jfc(fc_jfs_jfc);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFC, start_timestamp);
    }

    start_timestamp = umq_perf_get_start_timestamp();
    (void)umq_symbol_urma()->urma_delete_jetty(io_jetty);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JETTY, start_timestamp);

    start_timestamp = umq_perf_get_start_timestamp();
    (void)umq_symbol_urma()->urma_delete_jfc(io_jfs_jfc);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFC, start_timestamp);

    if (queue->mode == UMQ_MODE_INTERRUPT) {
        start_timestamp = umq_perf_get_start_timestamp();
        (void)umq_symbol_urma()->urma_delete_jfce(jfs_jfce);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFCE, start_timestamp);
    }
    return UMQ_SUCCESS;
}

uint32_t umq_ub_transport_pool_resource_create_impl(uint64_t umqh_tp, umq_tp_resource_create_option_t *option)
{
    if (umqh_tp == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh_tp is invalid\n");
        errno = -UMQ_ERR_EINVAL;
        return UINT32_MAX;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (!is_umq_ub_main_queue(queue->create_flag) || !is_umq_ub_share_transport(queue->create_flag)) {
        UMQ_VLOG_ERR(VLOG_UMQ,
            "transport resources can be expanded only if both main umq and share transport are available\n");
        errno = -UMQ_ERR_EINVAL;
        return UINT32_MAX;
    }

    umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
    umq_ub_ctx_t *dev_ctx = queue->dev_ctx;
    int ret = 0;
    (void)util_mutex_lock(jetty_node_list->lock);
    unsigned long offset = urpc_bitmap_find_next_zero_bit(jetty_node_list->bitmap, jetty_node_list->list_len, 0);
    if (offset >= jetty_node_list->list_len) {
        (void)util_mutex_unlock(jetty_node_list->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "node list is full, no more jetty nodes can be added\n");
        errno = -UMQ_ERR_EINVAL;
        return UINT32_MAX;
    }
    ret = umq_ub_create_jetty_node(queue, dev_ctx, option, &jetty_node_list->node_list[offset]);
    if (ret != UMQ_SUCCESS) {
        (void)util_mutex_unlock(jetty_node_list->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "create jetty node failed, ret %d\n", ret);
        return UINT32_MAX;
    }
    urpc_bitmap_set1(jetty_node_list->bitmap, offset);
    (void)util_mutex_unlock(jetty_node_list->lock);

    return (uint32_t)offset;
}

int umq_ub_transport_pool_resource_destroy_impl(uint64_t umqh_tp, uint32_t tp_handle_idx)
{
    if (umqh_tp == UMQ_INVALID_HANDLE) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh_tp is invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (!is_umq_ub_main_queue(queue->create_flag) || !is_umq_ub_share_transport(queue->create_flag)) {
        UMQ_VLOG_ERR(VLOG_UMQ,
            "transport resources can be destroy only if both main umq and share transport are available\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
    if (tp_handle_idx >= jetty_node_list->list_len) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                     tp_handle_idx, jetty_node_list->list_len);
        return -UMQ_ERR_EINVAL;
    }

    (void)util_mutex_lock(jetty_node_list->lock);
    if (!urpc_bitmap_is_set(jetty_node_list->bitmap, tp_handle_idx)) {
        (void)util_mutex_unlock(jetty_node_list->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty node index %u has already been destroyed\n", tp_handle_idx);
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_ub_destroy_jetty_node(queue, jetty_node_list->node_list[tp_handle_idx]);
    if (ret != UMQ_SUCCESS) {
        (void)util_mutex_unlock(jetty_node_list->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "destroy jetty node failed, index %u\n", tp_handle_idx);
        return ret;
    }

    urpc_bitmap_set0(jetty_node_list->bitmap, tp_handle_idx);
    (void)util_mutex_unlock(jetty_node_list->lock);
    return UMQ_SUCCESS;
}

uint64_t umq_ub_create_impl(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option)
{
    uint64_t start_timestamp;
    umq_ub_ctx_t *ub_ctx = (umq_ub_ctx_t *)ctx;
    umq_ub_ctx_t *dev_ctx = umq_ub_get_ub_ctx_by_dev_info(ub_ctx, g_ub_ctx_count, &option->dev_info);
    if (dev_ctx == NULL) {
        char dev_str[UMQ_UB_DEV_STR_LENGTH] = {0};
        (void)umq_ub_dev_str_get(&option->dev_info, dev_str, UMQ_UB_DEV_STR_LENGTH);
        UMQ_VLOG_ERR(VLOG_UMQ, "device ctx %s find failed\n", dev_str);
        return UMQ_INVALID_HANDLE;
    }

    umq_inc_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);
    ub_queue_t *queue = (ub_queue_t *)calloc(1, sizeof(ub_queue_t));
    if (queue == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq create failed, calloc queue failed\n");
        goto DEC_REF;
    }

    int ret = check_and_set_param(dev_ctx, option, queue);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "option param invalid, status: %d\n", ret);
        goto FREE_QUEUE;
    }

    ub_queue_t *share_rq = NULL;
    if ((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0) {
        if (option->share_rq_umqh == UMQ_INVALID_HANDLE) {
            UMQ_VLOG_ERR(VLOG_UMQ, "the share_rq_umqh is invalid\n");
            goto FREE_QUEUE;
        }
        umq_t *umq = (umq_t *)(uintptr_t)option->share_rq_umqh;
        share_rq = (ub_queue_t *)(uintptr_t)umq->umqh_tp;
        if (share_rq_param_check(queue, share_rq) != UMQ_SUCCESS) {
            goto FREE_QUEUE;
        }
        queue->share_rq_umqh = option->share_rq_umqh;
    }

    ret = urpc_id_generator_alloc(&g_umq_id_allocator, 0, &queue->umq_id);
    if (ret != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq create failed, umq id allocator failed. error code=%d\n", ret);
        goto FREE_QUEUE;
    }

    if (umq_ub_jfr_ctx_get(queue, dev_ctx, option, share_rq, UB_QUEUE_JETTY_IO) != UMQ_SUCCESS) {
        goto FREE_QUEUE_ID;
    }

    if (umq_ub_flow_control_init(&queue->flow_control, queue, dev_ctx->feature, &dev_ctx->flow_control) !=
        UMQ_SUCCESS) {
        goto DESTROY_JFR_CTX;
    }
    if (!is_umq_ub_logic_queue(queue->create_flag)) {
        if (queue->mode == UMQ_MODE_INTERRUPT) {
            start_timestamp = umq_perf_get_start_timestamp();
            queue->jfs_jfce = umq_symbol_urma()->urma_create_jfce(dev_ctx->urma_ctx);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFCE, start_timestamp);
            if (queue->jfs_jfce == NULL) {
                UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfce for jfs_jfce failed, errno: %d\n", errno);
                goto UNINIT_FLOW_CONTROL;
            }
        }

        bondp_jfc_cfg_t bondp_jfc_cfg = {
            .base = {
                .depth = queue->tx_depth + 1, // flush done consumes one cqe
                .jfce = queue->jfs_jfce,
                .flag.bs.has_drv_ext = ((queue->create_flag & UMQ_CREATE_FLAG_USED_PORTS) != 0)
            },
            .port_ids = queue->used_port,
            .port_count = queue->used_port_num,
        };
        start_timestamp = umq_perf_get_start_timestamp();
        queue->jfs_jfc[UB_QUEUE_JETTY_IO] = umq_symbol_urma()->urma_create_jfc(dev_ctx->urma_ctx, &bondp_jfc_cfg.base);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_CREATE_JFC, start_timestamp);
        if (queue->jfs_jfc[UB_QUEUE_JETTY_IO] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for jfs_jfc failed, errno: %d\n", errno);
            goto DELETE_JFCE;
        }

        char port_str[UMQ_PORT_STR_SIZE] = {0};
        umq_jetty_port_info(port_str, UMQ_PORT_STR_SIZE, queue);
        umq_create_jetty_config_t create_io_jetty_config = {
            .jetty_idx = UB_QUEUE_JETTY_IO,
            .jfs_jfc = queue->jfs_jfc[UB_QUEUE_JETTY_IO],
            .port_str = port_str,
            .used_port = queue->used_port,
            .used_port_num = queue->used_port_num,
        };
        queue->jetty[UB_QUEUE_JETTY_IO] = umq_create_jetty(queue, dev_ctx, &create_io_jetty_config);
        if (queue->jetty[UB_QUEUE_JETTY_IO] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "umq_create_jetty for io jetty failed, errno: %d\n", errno);
            goto DELETE_JFS_JFC;
        }

        if (queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id >= UMQ_ALIGN_64K(queue->dev_ctx->dev_attr.dev_cap.max_jetty)) {
            UMQ_VLOG_ERR(VLOG_UMQ, "jetty id %u exceed max jetty %u\n", queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
                UMQ_ALIGN_64K(queue->dev_ctx->dev_attr.dev_cap.max_jetty));
            goto DELETE_JETTY;
        }
    }

    if ((option->create_flag & UMQ_CREATE_FLAG_UMQ_CTX) != 0) {
        queue->umq_ctx = option->umq_ctx;
    }
    dev_ctx->umq_ctx_table[queue->umq_id] = (uint64_t)(uintptr_t)queue;

    queue->wait_ack_import.lock = util_rwlock_create();
    if (queue->wait_ack_import.lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue wait_ack_import lock create failed\n");
        if (is_umq_ub_logic_queue(queue->create_flag)) {
            goto DESTROY_JFR_CTX;
        }
        goto CLEAR_TABLE;
    }

    char port_str[UMQ_PORT_STR_SIZE] = {0};
    umq_jetty_port_info(port_str, UMQ_PORT_STR_SIZE, queue);
    if (umq_ub_create_flow_control_resource(queue, share_rq, option, port_str) != UMQ_SUCCESS) {
        goto LOCK_DESTROY;
    }

    if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
        queue->jetty_node_list = umq_ub_jetty_pool_get_jetty_node_list();
    }

    queue->require_rx_count = 0;
    queue->ref_cnt = 1;
    queue->tx_outstanding = 0;
    queue->state = queue->flow_control.enabled ? QUEUE_STATE_IDLE : QUEUE_STATE_READY;
    queue->umqh = umqh;
    (void)pthread_spin_init(&queue->get_jetty_node_lock, PTHREAD_PROCESS_PRIVATE);
    umq_ub_queue_ctx_list_push(&queue->qctx_node);
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        UMQ_VLOG_INFO(VLOG_UMQ, "create Logic UMQ(ID:%u) success, tp_mode %d, flowcontrol use %s window\n",
            queue->umq_id, queue->tp_mode, dev_ctx->flow_control.use_atomic_window ? "atomic" : "non-atomic");
    } else if (queue->flow_control.enabled) {
        UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id[0]: %u, jetty_id[1]: %u,%s create UMQ(ID:%u)"
            "success, jfr_id[0]: %u, jfr_id[1]: %u, urma transmode %d, tp_type %d, priority %d, rnr_retry %d, "
            "err_timeout %d, flowcontrol use %s window\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id, queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id,
            port_str, queue->umq_id, queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr->jfr_id.id,
            queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr->jfr_id.id, queue->tp_mode, queue->tp_type,
            queue->priority, queue->rnr_retry, queue->err_timeout,
            dev_ctx->flow_control.use_atomic_window ? "atomic" : "non-atomic");
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id[0]: %u,%s create UMQ(ID:%u) success, jfr_id[0]: %u, "
            "urma transmode %d, tp_type %d, priority %d, rnr_retry %d, err_timeout %d\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
            port_str, queue->umq_id, queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr->jfr_id.id, queue->tp_mode, queue->tp_type,
            queue->priority, queue->rnr_retry, queue->err_timeout);
    }
    return (uint64_t)(uintptr_t)queue;

LOCK_DESTROY:
    (void)util_rwlock_destroy(queue->wait_ack_import.lock);
    queue->wait_ack_import.lock = NULL;
CLEAR_TABLE:
    dev_ctx->umq_ctx_table[queue->umq_id] = 0;
DELETE_JETTY:
    (void)umq_symbol_urma()->urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
DELETE_JFS_JFC:
    (void)umq_symbol_urma()->urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO]);
DELETE_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        (void)umq_symbol_urma()->urma_delete_jfce(queue->jfs_jfce);
    }
UNINIT_FLOW_CONTROL:
    umq_ub_flow_control_uninit(&queue->flow_control);
DESTROY_JFR_CTX:
    umq_ub_jfr_ctx_put(queue, UB_QUEUE_JETTY_IO);
FREE_QUEUE_ID:
    urpc_id_generator_free(&g_umq_id_allocator, queue->umq_id);
FREE_QUEUE:
    if (queue->used_port != NULL) {
        free(queue->used_port);
    }
    free(queue);
DEC_REF:
    umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);

    return UMQ_INVALID_HANDLE;
}

int32_t umq_ub_destroy_impl(uint64_t umqh)
{
    uint64_t start_timestamp;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    // For Logic UMQ, use share_rq's IO jetty for logging (no own IO jetty)
    urma_eid_t *io_eid;
    uint32_t io_id;
    int ret = UMQ_SUCCESS;
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        ub_queue_t *share_rq = (ub_queue_t *)(uintptr_t)((umq_t *)(uintptr_t)queue->share_rq_umqh)->umqh_tp;
        io_eid = &share_rq->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
        io_id = share_rq->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    } else {
        io_eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
        io_id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    }

    if (queue->umq_trans_mode != UMQ_TRANS_MODE_UB && queue->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, destroy umq failed, trans mode %d is not UB\n",
            EID_ARGS(*io_eid), io_id, queue->umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }
    uint32_t ref_cnt = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt);
    if (!queue->dev_ctx->io_lock_free && ref_cnt != 1) {
        UMQ_VLOG_WARN(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umqh ref cnt %u is not 0\n", EID_ARGS(*io_eid),
            io_id, ref_cnt);
        return -UMQ_ERR_EBUSY;
    }

    if (!is_umq_ub_logic_queue(queue->create_flag) && !is_umq_ub_sub_queue(queue->create_flag) &&
        __atomic_load_n(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->ref_cnt, __ATOMIC_ACQUIRE) != 1) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, jfr_ctx ref_cnt not cleared, cannot destroy main "
            "queue\n", EID_ARGS(*io_eid), io_id);
        return -UMQ_ERR_EBUSY;
    }

    if (queue->bind_ctx != NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umqh has not been unbinded\n",
            EID_ARGS(*io_eid), io_id);
        return -UMQ_ERR_EBUSY;
    }

    if (queue->flow_control.enabled && !is_umq_ub_logic_queue(queue->create_flag)) {
        ub_queue_t *real_queue = umq_ub_get_real_queue_by_umq_id(queue, queue->umq_id);
        if (real_queue == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq_id: %u queue is in use, cannot destroy\n",
                EID_ARGS(*io_eid), io_id, queue->umq_id);
            return -UMQ_ERR_EBUSY;
        }

        urma_eid_t *fc_eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
        uint32_t fc_id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
        umq_ub_credit_clean_up(queue);
        UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, delete flowcontrol jetty\n",
            EID_ARGS(*fc_eid), fc_id);

        start_timestamp = umq_perf_get_start_timestamp();
        ret = umq_symbol_urma()->urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JETTY, start_timestamp);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jetty for flowcontrol jetty "
                "failed, status: %d\n", EID_ARGS(*fc_eid), fc_id, ret);
        }

        start_timestamp = umq_perf_get_start_timestamp();
        ret = umq_symbol_urma()->urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFC, start_timestamp);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfc for flowcontrol jfs_jfc "
                "failed, status: %d\n", EID_ARGS(*fc_eid), fc_id, ret);
        }
        umq_ub_jfr_ctx_put(queue, UB_QUEUE_JETTY_FLOW_CONTROL);
    } else if (queue->flow_control.enabled && is_umq_ub_logic_queue(queue->create_flag)) {
        umq_ub_jfr_ctx_put(queue, UB_QUEUE_JETTY_FLOW_CONTROL);
    }

    // destroy all tp handle
    if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (umq_ub_jetty_pool_put_jetty_node_list(jetty_node_list) == 0) {
            uint32_t idx;
            URPC_BITMAP_FOR_EACH_1(idx, jetty_node_list->list_len, jetty_node_list->bitmap) {
                (void)umq_ub_transport_pool_resource_destroy_impl(umqh, idx);
            }
        }
    }

    umq_buf_free(queue->addr_list);
    umq_ub_flow_control_uninit(&queue->flow_control);

    if (!is_umq_ub_logic_queue(queue->create_flag)) {
        start_timestamp = umq_perf_get_start_timestamp();
        ret = umq_symbol_urma()->urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JETTY, start_timestamp);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jetty failed, status: %d\n",
                EID_ARGS(*io_eid), io_id, ret);
        }
        start_timestamp = umq_perf_get_start_timestamp();
        ret = umq_symbol_urma()->urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO]);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFC, start_timestamp);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfc failed, status: %d\n",
                EID_ARGS(*io_eid), io_id, ret);
        }
        if (queue->mode == UMQ_MODE_INTERRUPT) {
            start_timestamp = umq_perf_get_start_timestamp();
            ret = umq_symbol_urma()->urma_delete_jfce(queue->jfs_jfce);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFCE, start_timestamp);
            if (ret != URMA_SUCCESS) {
                UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfc failed, status: %d\n",
                    EID_ARGS(*io_eid), io_id, ret);
            }
        }
    }

    if (queue->wait_ack_import.wait_ack_pool_id != NULL) {
        free(queue->wait_ack_import.wait_ack_pool_id);
    }
    (void)util_rwlock_destroy(queue->wait_ack_import.lock);
    queue->wait_ack_import.lock = NULL;
    (void)pthread_spin_destroy(&queue->get_jetty_node_lock);
    umq_ub_jfr_ctx_put(queue, UB_QUEUE_JETTY_IO);
    umq_ub_queue_ctx_list_remove(&queue->qctx_node);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->dev_ctx->ref_cnt, 1);
    if (queue->checker != NULL) {
        (void)util_mutex_lock(queue->checker->lock);
        queue->checker->umq = NULL;
        (void)util_mutex_unlock(queue->checker->lock);
    }
    if (queue->used_port != NULL) {
        free(queue->used_port);
    }

    queue->dev_ctx->umq_ctx_table[queue->umq_id] = 0;
    urpc_id_generator_free(&g_umq_id_allocator, queue->umq_id);
    free(queue);
    return UMQ_SUCCESS;
}

void umq_ub_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    return;
}

int umq_ub_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ub_wait_interrupt_impl(umqh_tp, -1, option);
}

int umq_ub_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    uint64_t wait_start = umq_trace_start_timestamp_get();
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option not valid\n");
        return -UMQ_ERR_EINVAL;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)(wait_umqh_tp);
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), logic umq not support wait interrupt\n");
        return -UMQ_ERR_EINVAL;
    }

    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue mode is not interrupt\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    /* record start before URMA calls so sub_time can be captured */
    uint64_t interrupt_timestamp = (option->flag & UMQ_INTERRUPT_FLAG_TIMESTAMP) == 0 ? 0 : option->timestamp;
    umq_trace_start_record(UMQ_TRACE_TYPE_WAIT, wait_start, interrupt_timestamp);
    umq_trace_item_record(0, 0, queue->umq_id);

    int cnt = 0;
    urma_jfc_t *jfc[UB_QUEUE_JETTY_NUM];
    if ((option->flag & UMQ_INTERRUPT_FLAG_TP_HANDLE_IDX) != 0) {
        if (!(is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag) &&
            (option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) != 0 && option->direction == UMQ_IO_TX)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "enable tp handle idx only obtaining the tx fd of tp resources\n");
            umq_trace_end_record(UMQ_TRACE_TYPE_WAIT, umq_trace_timestamp_get());
            return -UMQ_ERR_EINVAL;
        }

        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (option->tp_handle_idx >= jetty_node_list->list_len) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                               option->tp_handle_idx, jetty_node_list->list_len);
            umq_trace_end_record(UMQ_TRACE_TYPE_WAIT, umq_trace_timestamp_get());
            return -UMQ_ERR_EINVAL;
        }
        if (!urpc_bitmap_is_set(jetty_node_list->bitmap, option->tp_handle_idx)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tx_handel_idx %u not exist\n", option->tp_handle_idx);
            umq_trace_end_record(UMQ_TRACE_TYPE_WAIT, umq_trace_timestamp_get());
            return -UMQ_ERR_EINVAL;
        }

        cnt = umq_ub_wait_tp_handle_tx_interrupt(jetty_node_list->node_list[option->tp_handle_idx]->jfs_jfce,
            time_out, jfc, queue->flow_control.enabled);
    } else if (option->direction == UMQ_IO_RX) {
        cnt = umq_ub_wait_rx_interrupt(queue, time_out, jfc);
    } else {
        cnt = umq_ub_wait_tx_interrupt(queue, time_out, jfc);
    }
    umq_trace_end_record(UMQ_TRACE_TYPE_WAIT, umq_trace_timestamp_get());
    if (cnt < 0) {
        if (errno != EAGAIN) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_wait_jfc failed, direction %u,"
                " errno: %d, status: %d\n", EID_ARGS(*eid), id, option->direction, errno, cnt);
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
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (option->fd_type == UMQ_FD_EVENT) {
        if (queue->checker == NULL) {
            return UMQ_INVALID_FD;
        }
        return queue->checker->event_fd;
    }

    if (is_umq_ub_logic_queue(queue->create_flag)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), logic umq not have io interrupt fd\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    if ((option->flag & UMQ_INTERRUPT_FLAG_TP_HANDLE_IDX) != 0) {
        if (!(is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag) &&
            (option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) != 0 && option->direction == UMQ_IO_TX)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "enable tp handle idx only obtaining the tx fd of tp resources\n");
            return UMQ_INVALID_FD;
        }
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (option->tp_handle_idx >= jetty_node_list->list_len) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                               option->tp_handle_idx, jetty_node_list->list_len);
            return -UMQ_ERR_EINVAL;
        }

        if (!urpc_bitmap_is_set(jetty_node_list->bitmap, option->tp_handle_idx)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tx_handel_idx %u not exist\n", option->tp_handle_idx);
            return UMQ_INVALID_FD;
        }
        return jetty_node_list->node_list[option->tp_handle_idx]->jfs_jfce->fd;
    }

    if (queue->jfs_jfce == NULL || queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get interrupt fd error, jfce is NULL\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_EINVAL;
    }
    if (option->direction == UMQ_IO_TX) {
        return queue->jfs_jfce->fd;
    } else if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        return queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce->fd;
    } else if (!UMQ_UB_ENABLE_SHARE_FC_JFR && queue->flow_control.enabled) {
        return queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfce->fd;
    }
    return -1;
}

static int umq_ub_get_fd_list(umq_ub_ctx_t *dev_ctx, urma_jfce_t *jfce, umq_interrupt_fd_list_t *fd_list)
{
    if (!is_umq_ub_bonding_dev(dev_ctx->urma_ctx->dev->name)) {
        fd_list->fd[0] = jfce->fd;
        fd_list->fd_num = 1;
        return UMQ_SUCCESS;
    }

    bondp_get_jfce_fd_list_in_t bond_in = {
        .jfce = jfce,
    };
    urma_user_ctl_in_t in = {
        .addr = (uint64_t)(uintptr_t)&bond_in,
        .len = sizeof(bond_in),
        .opcode = BONDP_USER_CTL_GET_JFCE_FD_LIST};
    bondp_get_jfce_fd_list_out_t bond_out = {0};
    urma_user_ctl_out_t out = {
        .addr = (uint64_t)(uintptr_t)&bond_out,
        .len = sizeof(bond_out),
    };
    urma_status_t status = umq_symbol_urma()->urma_user_ctl(dev_ctx->urma_ctx, &in, &out);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_user_ctl query fd list for device %s failed, status: %d\n",
                     dev_ctx->urma_ctx->dev->name, (int)status);
        return umq_status_convert(status);
    }

    uint32_t valid_cnt = 0;
    for (uint32_t i = 0; valid_cnt < bond_out.count; i++) {
        if (bond_out.fd_list[i] < 0) {
            continue;
        }
        fd_list->fd[valid_cnt] = bond_out.fd_list[i];
        valid_cnt++;
    }
    fd_list->fd_num = valid_cnt;
    return UMQ_SUCCESS;
}

int umq_ub_interrupt_fd_list_get_impl(uint64_t umqh_tp,
    umq_interrupt_option_t *option, umq_interrupt_fd_list_t *fd_list)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (option->fd_type == UMQ_FD_EVENT) {
        if (queue->checker == NULL) {
            return -UMQ_ERR_EINVAL;
        }

        fd_list->fd[0] = queue->checker->event_fd;
        fd_list->fd_num = 1;
        return UMQ_SUCCESS;
    }

    if (is_umq_ub_logic_queue(queue->create_flag)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), logic umq not have io interrupt fd\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    if ((option->flag & UMQ_INTERRUPT_FLAG_TP_HANDLE_IDX) != 0) {
        if (!(is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag) &&
            (option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) != 0 && option->direction == UMQ_IO_TX)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "enable tp handle idx only obtaining the tx fd of tp resources\n");
            return UMQ_INVALID_FD;
        }
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (option->tp_handle_idx >= jetty_node_list->list_len) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                               option->tp_handle_idx, jetty_node_list->list_len);
            return -UMQ_ERR_EINVAL;
        }

        if (!urpc_bitmap_is_set(jetty_node_list->bitmap, option->tp_handle_idx)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tx_handel_idx %u not exist\n", option->tp_handle_idx);
            return UMQ_INVALID_FD;
        }
        return umq_ub_get_fd_list(queue->dev_ctx,
            jetty_node_list->node_list[option->tp_handle_idx]->jfs_jfce, fd_list);
    }

    if (queue->jfs_jfce == NULL || queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get interrupt fd error, jfce is NULL\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_EINVAL;
    }

    urma_jfce_t *jfce = NULL;
    if (option->direction == UMQ_IO_TX) {
        jfce = queue->jfs_jfce;
    } else if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        jfce = queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce;
    } else if (!UMQ_UB_ENABLE_SHARE_FC_JFR && queue->flow_control.enabled) {
        jfce = queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfce;
    }

    if (jfce == NULL) {
        return -UMQ_ERR_EINVAL;
    }

    return umq_ub_get_fd_list(queue->dev_ctx, jfce, fd_list);
}

int umq_ub_rearm_impl(uint64_t umqh_tp, bool solicited, umq_interrupt_option_t *option)
{
    uint64_t start_timestamp;
    uint64_t rearm_start = umq_trace_start_timestamp_get();
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), logic umq not support rearm jfc\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue mode is not interrupt\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    /* record start */
    uint64_t interrupt_timestamp = (option->flag & UMQ_INTERRUPT_FLAG_TIMESTAMP) == 0 ? 0 : option->timestamp;
    umq_trace_start_record(UMQ_TRACE_TYPE_REARM, rearm_start, interrupt_timestamp);
    umq_trace_item_record(0, 0, queue->umq_id);

    urma_status_t status = URMA_SUCCESS;
    if ((option->flag & UMQ_INTERRUPT_FLAG_TP_HANDLE_IDX) != 0) {
        if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag) &&
            (option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) != 0 && option->direction == UMQ_IO_TX) {
            umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
            if (option->tp_handle_idx >= jetty_node_list->list_len) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                                   option->tp_handle_idx, jetty_node_list->list_len);
                umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
                return -UMQ_ERR_EINVAL;
            }

            if (!urpc_bitmap_is_set(jetty_node_list->bitmap, option->tp_handle_idx)) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "tx_handel_idx %u not exist\n", option->tp_handle_idx);
                umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
                return -UMQ_ERR_EINVAL;
            }

            /* URMA rearm — io jetty (tp_handle path) */
            uint64_t tp_rearm_start = umq_trace_timestamp_get();
            status = umq_symbol_urma()->urma_rearm_jfc(
                jetty_node_list->node_list[option->tp_handle_idx]->jfs_jfc[UB_QUEUE_JETTY_IO], solicited);
            uint64_t rearm_delta = umq_trace_write_delta(tp_rearm_start);
            umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_REARM_JFC, tp_rearm_start, rearm_delta);
            if (status != URMA_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, "
                "urma_rearm_jfc for io jfc failed, status: %d\n", EID_ARGS(*eid), id, (int)status);
                umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
                return umq_status_convert(status);
            }

            if (queue->flow_control.enabled) {
                uint64_t fc_rearm_start = umq_trace_timestamp_get();
                status = umq_symbol_urma()->urma_rearm_jfc(jetty_node_list->node_list[
                    option->tp_handle_idx]->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL], solicited);
                rearm_delta = umq_trace_write_delta(fc_rearm_start);
                umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_FC_REARM_JFC, fc_rearm_start, rearm_delta);
                if (status != URMA_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, "
                    "urma_rearm_jfc for io jfc failed, status: %d\n", EID_ARGS(*eid), id, (int)status);
                    umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
                    return umq_status_convert(status);
                }
            }

            umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
            return UMQ_SUCCESS;
        }
        UMQ_VLOG_ERR(VLOG_UMQ, "enable tp handle idx only rearm tp resources tx\n");
        umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
        return -UMQ_ERR_EINVAL;
    }

    start_timestamp = umq_perf_get_start_timestamp();
    /* URMA rearm — io jetty */
    uint64_t tp_rearm_start = umq_trace_timestamp_get();
    uint64_t rearm_delta = 0;
    if (option->direction == UMQ_IO_TX) {
        status = umq_symbol_urma()->urma_rearm_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], solicited);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_TX, start_timestamp);
        rearm_delta = umq_trace_write_delta(tp_rearm_start);
        umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_REARM_JFC, tp_rearm_start, rearm_delta);
    } else if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        status = umq_symbol_urma()->urma_rearm_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, solicited);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_RX, start_timestamp);
        rearm_delta = umq_trace_write_delta(tp_rearm_start);
        umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_REARM_JFC, tp_rearm_start, rearm_delta);
    }
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_rearm_jfc for io jfc failed, "
            "status: %d\n", EID_ARGS(*eid), id, (int)status);
        umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
        return umq_status_convert(status);
    }

    /* URMA rearm — fc jetty (if enabled) */
    if (queue->flow_control.enabled) {
        uint64_t fc_rearm_start = umq_trace_timestamp_get();
        start_timestamp = umq_perf_get_start_timestamp();
        if (option->direction == UMQ_IO_TX) {
            status = umq_symbol_urma()->urma_rearm_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL], solicited);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_TX, start_timestamp);
            rearm_delta = umq_trace_write_delta(fc_rearm_start);
            umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_FC_REARM_JFC, fc_rearm_start, rearm_delta);
        } else if (!UMQ_UB_ENABLE_SHARE_FC_JFR || (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
            status = umq_symbol_urma()->urma_rearm_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc, solicited);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_RX, start_timestamp);
            rearm_delta = umq_trace_write_delta(fc_rearm_start);
            umq_trace_sub_record(UMQ_TRACE_TYPE_REARM, UMQ_URMA_FUNC_FC_REARM_JFC, fc_rearm_start, rearm_delta);
        }
        if (status != URMA_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_rearm_jfc for flowcontrol jfc"
                " failed, status: %d\n", EID_ARGS(*eid), id, (int)status);
            umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
            return umq_status_convert(status);
        }
    }

    umq_trace_end_record(UMQ_TRACE_TYPE_REARM, umq_trace_timestamp_get());
    return UMQ_SUCCESS;
}

int umq_ub_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_option_t *option, umq_buf_t **bad_qbuf)
{
    int ret;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    if (option->io_direction == UMQ_IO_TX) {
        ret = umq_ub_post_tx(umqh_tp, qbuf, bad_qbuf);
    } else if (option->io_direction == UMQ_IO_RX) {
        ret = umq_ub_post_rx(umqh_tp, qbuf, bad_qbuf);
    } else {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, io_direction[%d] is not supported when post\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
            option->io_direction);
        ret = -UMQ_ERR_EINVAL;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    return ret;
}

int umq_ub_poll_impl(uint64_t umqh_tp, umq_io_option_t *option, umq_buf_t **buf, uint32_t max_buf_count)
{
    int ret;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    if (option->io_direction == UMQ_IO_RX) {
        ret = umq_ub_poll_rx(umqh_tp, buf, max_buf_count);
    } else if (option->io_direction == UMQ_IO_TX) {
        ret = umq_ub_poll_tx(umqh_tp, buf, max_buf_count, option);
    } else if (option->io_direction == UMQ_IO_ALL) {
        uint32_t tx_max_cnt = max_buf_count > 1 ? max_buf_count >> 1 : 1;
        int32_t tx_cnt = umq_ub_poll_tx(umqh_tp, buf, tx_max_cnt, option);
        if (tx_cnt < 0) {
            ret = tx_cnt;
            goto OUT;
        }

        int32_t rx_cnt = umq_ub_poll_rx(umqh_tp, &buf[tx_cnt], max_buf_count - tx_cnt);
        if (rx_cnt < 0) {
            // notice: only report tx cqe qbuf in case of failure
            ret = tx_cnt;
            goto OUT;
        }

        ret = tx_cnt + rx_cnt;
    } else {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, invalid io direction[%d]\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
            option->io_direction);
        ret = -UMQ_ERR_EINVAL;
    }

OUT:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

int umq_ub_unbind_impl(uint64_t umqh)
{
    uint64_t start_timestamp;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    ub_bind_ctx_t *bind_ctx = queue->bind_ctx;
    if (bind_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), umq has not been binded\n", queue->umq_id);
        return -UMQ_ERR_ENODEV;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    if (queue->flow_control.enabled) {
        urma_target_jetty_t *tjetty = bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
        UMQ_VLOG_INFO(VLOG_UMQ, "UMQ(ID:%u), remote eid: " EID_FMT ", remote jetty_id: %u, unbind flowcontrol jetty\n",
            queue->umq_id, EID_ARGS(tjetty->id.eid), tjetty->id.id);
        if (queue->tp_mode == URMA_TM_RC) {
            start_timestamp = umq_perf_get_start_timestamp();
            (void)umq_symbol_urma()->urma_unbind_jetty(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_UNBIND_JETTY, start_timestamp);
        }
        start_timestamp = umq_perf_get_start_timestamp();
        (void)umq_symbol_urma()->urma_unimport_jetty(tjetty);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_UNIMPORT_JETTY, start_timestamp);
        if (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
            umq_modify_ubq_to_err(queue, UMQ_IO_TX, UB_QUEUE_JETTY_FLOW_CONTROL);
        } else {
            umq_modify_ubq_to_err(queue, UMQ_IO_ALL, UB_QUEUE_JETTY_FLOW_CONTROL);
        }
    }

    urma_target_jetty_t *tjetty = bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
    (void)umq_ub_remote_tseg_info_release(queue->dev_ctx->remote_imported_info, bind_ctx);
    UMQ_VLOG_INFO(VLOG_UMQ, "UMQ(ID:%u), remote eid: " EID_FMT ", remote jetty_id: %u, unbind jetty\n",
        queue->umq_id, EID_ARGS(tjetty->id.eid), tjetty->id.id);
    if (queue->tp_mode == URMA_TM_RC) {
        start_timestamp = umq_perf_get_start_timestamp();
        (void)umq_symbol_urma()->urma_unbind_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_UNBIND_JETTY, start_timestamp);
    }

    start_timestamp = umq_perf_get_start_timestamp();
    (void)umq_symbol_urma()->urma_unimport_jetty(tjetty);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_UNIMPORT_JETTY, start_timestamp);
    if (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
        UMQ_VLOG_DEBUG(VLOG_UMQ, "UMQ(ID:%u), sub umq only need set tx res error\n", queue->umq_id);
        umq_modify_ubq_to_err(queue, UMQ_IO_TX, UB_QUEUE_JETTY_IO);
    } else {
        umq_modify_ubq_to_err(queue, UMQ_IO_ALL, UB_QUEUE_JETTY_IO);
    }

    free(queue->bind_ctx);
    queue->bind_ctx = NULL;
    /* The `flush tx` and `flush rx` directives should be placed after `bind_ctx` is set to null,
     * preventing requests from being sent under flow control. */
    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        umq_flush_tx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
        if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
            umq_flush_rx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
        }
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    return UMQ_SUCCESS;
}

int32_t umq_ub_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    umq_buf_t *buf[UMQ_BATCH_SIZE];
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    umq_ub_enqueue_with_poll_tx(queue, buf);

    urma_jfs_wr_t urma_wr[UMQ_BATCH_SIZE];
    urma_sge_t sges[UMQ_BATCH_SIZE][queue->max_tx_sge];
    *bad_qbuf = NULL;

    int ret = UMQ_SUCCESS;
    uint32_t tx_outstanding = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding);
    if (queue->tx_depth <= tx_outstanding) {
        ret = -UMQ_ERR_EAGAIN;
        goto DEC_REF;
    }
    uint32_t remain_tx = queue->tx_depth - tx_outstanding;
    /* sges is defined as two-dimensional array, cast to a one-dimensional array for passing, and within the
     * `umq_ub_fill_wr_impl`, it is assigned by jumping in groups of max_tx_sge. */
    int wr_num = umq_ub_fill_wr_impl(qbuf, queue, urma_wr, (urma_sge_t *)(uintptr_t)sges, remain_tx);
    if (wr_num < 0) {
        *bad_qbuf = qbuf;
        ret = wr_num;
        goto DEC_REF;
    }
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO],
        urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status != URMA_SUCCESS) {
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
            process_bad_qbuf(*bad_qbuf, qbuf, queue);
        } else {
            *bad_qbuf = qbuf;
        }
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_send_wr failed, "
            "status: %d\n", EID_ARGS(*eid), id, status);
        ret = umq_status_convert(status);
        goto DEC_REF;
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, wr_num, queue->dev_ctx->io_lock_free);
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, wr_num);

DEC_REF:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

int32_t umq_ub_enqueue_impl_plus(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    umq_buf_t *buf[UMQ_BATCH_SIZE];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int ret = UMQ_SUCCESS;

    *bad_qbuf = NULL;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    umq_ub_enqueue_plus_with_poll_tx(queue, buf);
    urma_sge_t sges[UMQ_BATCH_SIZE][queue->max_tx_sge];
    uint32_t tx_outstanding = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding);
    if (queue->tx_depth <= tx_outstanding) {
        ret = -UMQ_ERR_EAGAIN;
        goto DEC_REF;
    }

    uint32_t remain_tx = queue->tx_depth - tx_outstanding;
    urma_jfs_wr_t urma_wr[UMQ_BATCH_SIZE];
    /* sges is defined as two-dimensional array, cast to a one-dimensional array for passing, and within the
     * `umq_ub_plus_fill_wr_impl`, it is assigned by jumping in groups of max_tx_sge. */
    int wr_num = umq_ub_plus_fill_wr_impl(qbuf, queue, urma_wr, (urma_sge_t *)(uintptr_t)sges, (uint32_t)remain_tx);
    if (wr_num < 0) {
        *bad_qbuf = qbuf;
        ret = wr_num;
        goto DEC_REF;
    } else if (wr_num == 0) {
        ret = UMQ_SUCCESS;
        goto DEC_REF;
    }
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO],
        urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status != URMA_SUCCESS) {
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
            process_bad_qbuf(*bad_qbuf, qbuf, queue);
        } else {
            *bad_qbuf = qbuf;
        }
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_send_wr failed, status"
            " %d\n", EID_ARGS(*eid), id, status);
        ret = umq_status_convert(status);
        goto DEC_REF;
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, wr_num, queue->dev_ctx->io_lock_free);
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, wr_num);

DEC_REF:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

umq_buf_t *umq_ub_dequeue_impl(uint64_t umqh_tp)
{
    umq_buf_t *buf[UMQ_BATCH_SIZE];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return NULL;
    }
    urma_cr_t cr[UMQ_BATCH_SIZE];
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
    umq_buf_t *buf[UMQ_BATCH_SIZE];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return NULL;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    urma_cr_t cr[UMQ_BATCH_SIZE];
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

int umq_ub_queue_addr_list_alloc(ub_queue_t *queue)
{
    if (queue->addr_list != NULL) {
        return UMQ_SUCCESS;
    }

    queue->addr_list = umq_buf_alloc(UMQ_MAX_MSG_ID_NUM * sizeof(uint64_t), 1, UMQ_INVALID_HANDLE, NULL);
    if (queue->addr_list == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq_buf_alloc for addr_list failed\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_ENOMEM;
    }

    return UMQ_SUCCESS;
}

void umq_ub_queue_addr_list_record(umq_buf_t *addr_list, uint16_t msg_id, umq_buf_t *buf)
{
    uint64_t *dst = (uint64_t *)(uintptr_t)addr_list->buf_data;
    dst[msg_id] = (uint64_t)(uintptr_t)buf;
}

umq_buf_t *umq_ub_queue_addr_list_remove(umq_buf_t *addr_list, uint16_t msg_id)
{
    uint64_t *dst = (uint64_t *)(uintptr_t)addr_list->buf_data;
    umq_buf_t *buf = (umq_buf_t *)(uintptr_t)dst[msg_id];
    dst[msg_id] = 0;
    return buf;
}

int umq_ub_state_set_impl(uint64_t umqh_tp, umq_state_t state)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (!is_umq_ub_main_queue(queue->create_flag)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u) set state only support main umq\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    if (state != QUEUE_STATE_ERR) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), set state only support error state\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->state == QUEUE_STATE_ERR) {
        UMQ_VLOG_INFO(VLOG_UMQ, "UMQ(ID:%u), queue state already in error state\n", queue->umq_id);
        return UMQ_SUCCESS;
    }

    int ret = umq_modify_ubq_to_err(queue, UMQ_IO_ALL, UB_QUEUE_JETTY_IO);
    if (ret) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), modify queue state failed, status: %d\n", queue->umq_id, ret);
        return ret;
    }

    UMQ_VLOG_INFO(VLOG_UMQ, "UMQ(ID:%u), modify queue state %d success\n", queue->umq_id, state);
    return UMQ_SUCCESS;
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
        UMQ_VLOG_ERR(VLOG_UMQ, "dev_ctx invalid\n");
        return UMQ_INVALID_FD;
    }
    return dev_ctx->urma_ctx->async_fd;
}

int umq_ub_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
    umq_ub_ctx_t *dev_ctx = umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &trans_info->dev_info);
    if (dev_ctx == NULL || dev_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "dev_ctx invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_context_t *urma_ctx = dev_ctx->urma_ctx;

    urma_async_event_t *urma_event = (urma_async_event_t *)calloc(1, sizeof(urma_async_event_t));
    if (urma_event == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq calloc async event failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    urma_status_t status = umq_symbol_urma()->urma_get_async_event(urma_ctx, urma_event);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_get_async_event failed, status: %d\n", status);
        free(urma_event);
        return umq_status_convert(status);
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
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "port active, port_id[%u]\n", event->element.port_id);
            break;
        case URMA_EVENT_PORT_DOWN:
            event->event_type = UMQ_EVENT_PORT_DOWN;
            event->element.port_id = urma_event->element.port_id;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "port down, port_id[%u]\n", event->element.port_id);
            break;
        case URMA_EVENT_DEV_FATAL:
            event->event_type = UMQ_EVENT_DEV_FATAL;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "dev fatal\n");
            break;
        case URMA_EVENT_EID_CHANGE:
            event->event_type = UMQ_EVENT_EID_CHANGE;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "eid change\n");
            break;
        case URMA_EVENT_ELR_ERR:
            event->event_type = UMQ_EVENT_ELR_ERR;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "entity level error\n");
            break;
        case URMA_EVENT_ELR_DONE:
            event->event_type = UMQ_EVENT_ELR_DONE;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "entity flush done\n");
            break;
        default:
            event->event_type = UMQ_EVENT_OTHER;
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ_URMA_AE, "unrecognized urma event_type: %d\n", urma_event->event_type);
            break;
    }
    return URMA_SUCCESS;
}

void umq_ub_async_event_ack(umq_async_event_t *event)
{
    urma_async_event_t *urma_event = (urma_async_event_t *)event->priv;
    if (urma_event == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_AE, "urma event invalid\n");
        return;
    }
    umq_symbol_urma()->urma_ack_async_event(urma_event);
    free(urma_event);
    event->priv = NULL;
}

static int umq_ub_register_seg_callback(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size)
{
    if (addr == NULL || size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    if (ctx != NULL) {
        return umq_ub_register_seg((umq_ub_ctx_t *)(uintptr_t)ctx, mempool_id, addr, size);
    }

    if (g_ub_ctx == NULL || g_ub_ctx_count == 0) {
        UMQ_VLOG_DEBUG(VLOG_UMQ, "no device need register memory\n");
        return UMQ_SUCCESS;
    }

    int ret;
    uint32_t idx = 0;
    for (idx = 0; idx < g_ub_ctx_count; idx++) {
        ret = umq_ub_register_seg(&g_ub_ctx[idx], mempool_id, addr, size);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "register sge failed, status: %d, dev idx %u, eid: " EID_FMT "\n",
                ret, idx, EID_ARGS(g_ub_ctx[idx].dev_info.eid.eid));
            goto ROLLBACK;
        }
    }
    return UMQ_SUCCESS;

ROLLBACK:
    for (uint32_t i = 0; i < idx; i++) {
        umq_ub_unregister_seg(&g_ub_ctx[i], 1, mempool_id);
    }
    return ret;
}

static void umq_ub_unregister_seg_callback(uint8_t *ctx, uint16_t mempool_id)
{
    if (ctx != NULL) {
        umq_ub_unregister_seg((umq_ub_ctx_t *)(uintptr_t)ctx, 1, mempool_id);
        return;
    }

    if (g_ub_ctx == NULL || g_ub_ctx_count == 0) {
        UMQ_VLOG_INFO(VLOG_UMQ, "no device need unregister memory\n");
        return;
    }

    umq_ub_unregister_seg(g_ub_ctx, g_ub_ctx_count, mempool_id);
}

int umq_ub_dev_add_impl(umq_trans_info_t *info, umq_init_cfg_t *cfg)
{
    if (info == NULL || cfg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_INFO(VLOG_UMQ, "trans init mode: %d not UB\n", info->trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    // create ub ctx
    g_ub_ctx[g_ub_ctx_count].remote_imported_info = umq_ub_ctx_imported_info_create();
    if (g_ub_ctx[g_ub_ctx_count].remote_imported_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "imported info create failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    int ret = umq_find_ub_device(info, &g_ub_ctx[g_ub_ctx_count]);
    if (ret != UMQ_SUCCESS) {
        goto DELETE_IMPORT_INFO;
    }

    g_ub_ctx[g_ub_ctx_count].umq_ctx_table = (volatile uint64_t *)calloc(UMQ_ID_ALLOC_SIZE, sizeof(uint64_t));
    if (g_ub_ctx[g_ub_ctx_count].umq_ctx_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc umq_ctx_table failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto DELETE_URMA_CTX;
    }
    g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table = (volatile uint64_t *)calloc(UMQ_ID_ALLOC_SIZE, sizeof(uint64_t));
    if (g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc rx_consumed_jetty_table failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_UMQ_CTX_TBL;
    }

    g_ub_ctx[g_ub_ctx_count].io_lock_free = cfg->io_lock_free;
    g_ub_ctx[g_ub_ctx_count].rq_lock_free = cfg->rq_lock_free;
    g_ub_ctx[g_ub_ctx_count].feature = cfg->feature;
    g_ub_ctx[g_ub_ctx_count].flow_control = cfg->flow_control;

    mempool_segment_ops_t sge_ops = {
        .register_seg_callback = umq_ub_register_seg_callback,
        .unregister_seg_callback = umq_ub_unregister_seg_callback
    };
    // register seg
    ret = umq_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], &sge_ops);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf register seg failed\n");
        goto FREE_UMQ_CTX_RX_CONSUMED_TBL;
    }

    ret = umq_huge_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], &sge_ops);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "huge qbuf register seg failed, status: %d\n", ret);
        goto UNREGISTER_MEM;
    }
    if (cfg->buf_pool_cfg.enable_tiny_pool) {
        ret = umq_tiny_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], &sge_ops);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tiny qbuf register seg failed, status: %d\n", ret);
            goto UNREGISTER_HUGE_MEM;
        }
    }
    g_ub_ctx[g_ub_ctx_count].ref_cnt = 1;
    (void)pthread_spin_init(&g_ub_ctx[g_ub_ctx_count].tseg_list_lock, PTHREAD_PROCESS_PRIVATE);

    g_ub_ctx_count++;

    return UMQ_SUCCESS;

UNREGISTER_HUGE_MEM:
    umq_huge_qbuf_unregister_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], &sge_ops);

UNREGISTER_MEM:
    umq_qbuf_unregister_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], &sge_ops);

FREE_UMQ_CTX_RX_CONSUMED_TBL:
    free((void*)g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table);
    g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table = NULL;

FREE_UMQ_CTX_TBL:
    free((void*)g_ub_ctx[g_ub_ctx_count].umq_ctx_table);
    g_ub_ctx[g_ub_ctx_count].umq_ctx_table = NULL;

DELETE_URMA_CTX:
    (void)umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);

DELETE_IMPORT_INFO:
    (void)umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);

    return ret;
}

static uvs_tp_type_t umq_tp_type_convert_to_uvs(umq_tp_type_t tp_type)
{
    switch (tp_type) {
        case UMQ_TP_TYPE_RTP:
            return UVS_RTP;
        case UMQ_TP_TYPE_CTP:
            return UVS_CTP;
        case UMQ_TP_TYPE_UTP:
            return UVS_UTP;
        default:
            return UVS_CTP;
    };
}

static void umq_port_id_set(union uvs_port_id *uvs_port_id, umq_port_id_t *umq_port_id)
{
    umq_port_id->bs.chip_id = uvs_port_id->chip_id;
    umq_port_id->bs.die_id = uvs_port_id->die_id;
    umq_port_id->bs.port_idx = uvs_port_id->port_idx;
}

int umq_ub_get_route_list_impl(const umq_route_key_t *route_key, umq_route_list_t *route_list)
{
    if (route_key == NULL || route_key->tp_type >= UMQ_TP_TYPE_UTP || route_list == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    uvs_path_set_t uvs_path_set;
    uvs_tp_type_t uvs_tp_type = umq_tp_type_convert_to_uvs(route_key->tp_type);
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    int ret = umq_symbol_urma()->uvs_get_path_set((uvs_eid_t *)(uintptr_t)&route_key->src_bonding_eid,
        (uvs_eid_t *)(uintptr_t)&route_key->dst_bonding_eid, uvs_tp_type, false, &uvs_path_set);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_PATH_GET, start_timestamp);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "uvs_get_path_set failed, status: %d\n", ret);
        return ret;
    }

    if (uvs_path_set.path_count > UMQ_MAX_ROUTES || uvs_path_set.path_count > UVS_MAX_ROUTES) {
        UMQ_VLOG_ERR(VLOG_UMQ, "number of routes %u exceeds the maximum limit\n", uvs_path_set.path_count);
        return -UMQ_ERR_ENOMEM;
    }

    memset(route_list, 0, sizeof(umq_route_list_t));
    for (uint32_t i = 0; i < uvs_path_set.path_count; i++) {
        (void)memcpy(&route_list->routes[i].src_eid, &uvs_path_set.paths[i].src_eid, sizeof(umq_eid_t));
        (void)memcpy(&route_list->routes[i].dst_eid, &uvs_path_set.paths[i].dst_eid, sizeof(umq_eid_t));
        umq_port_id_set(&uvs_path_set.paths[i].src_port, &route_list->routes[i].src_port);
        umq_port_id_set(&uvs_path_set.paths[i].dst_port, &route_list->routes[i].dst_port);
    }
    route_list->route_num = uvs_path_set.path_count;
    route_list->topo_type = (umq_topo_type_t)uvs_path_set.topo_type;
    route_list->chip_num = uvs_path_set.chip_count;
    route_list->die_num = uvs_path_set.die_count;
    route_list->src_node.super_node_id = uvs_path_set.src_node.super_node_id;
    route_list->src_node.node_id = uvs_path_set.src_node.node_id;
    route_list->dst_node.super_node_id = uvs_path_set.dst_node.super_node_id;
    route_list->dst_node.node_id = uvs_path_set.dst_node.node_id;

    return UMQ_SUCCESS;
}

int umq_ub_mempool_state_get_impl(uint64_t umqh_tp, uint32_t mempool_id, umq_mempool_state_t *mempool_state)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->dev_ctx == NULL || queue->dev_ctx->remote_imported_info == NULL || queue->bind_ctx == NULL ||
        mempool_id >= UMQ_MAX_TSEG_NUM) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub get mempool state parameter invalid\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_EINVAL;
    }

    if (urpc_bitmap_is_set(queue->bind_ctx->tseg_imported, mempool_id)) {
        mempool_state->import_state = MEMPOOL_STATE_IMPORTED;
    } else {
        mempool_state->import_state = MEMPOOL_STATE_NON_IMPORTED;
    }
    return UMQ_SUCCESS;
}

int umq_ub_mempool_state_refresh_impl(uint64_t umqh_tp, uint32_t mempool_id)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (!umq_ub_enable_import_remote_mem(queue->dev_ctx->feature)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, "
            "UMQ_FEATURE_ENABLE_REMOTE_MEM_ACCESS is not enabled, refresh mempool state is not supported\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EPERM;
    }

    umq_mempool_state_t mempool_state;
    int ret = umq_ub_mempool_state_get_impl(umqh_tp, mempool_id, &mempool_state);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "get mempool state failed, status: %d\n", ret);
        return ret;
    }

    if (mempool_state.import_state == MEMPOOL_STATE_IMPORTED) {
        UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "mempool %u is imported\n", mempool_id);
        return UMQ_SUCCESS;
    }

    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];
    if (tseg == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n", EID_ARGS(*eid),
            id, mempool_id);
        return -UMQ_ERR_ENODEV;
    }
    urma_seg_t *seg = &tseg->seg;

    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), 1, queue->umqh, NULL);
    if (send_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq malloc failed\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENOMEM;
    }

    if (send_buf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, send_buf is not a pooled memory\n",
            EID_ARGS(*eid), id);
        ret = -UMQ_ERR_EFAULT;
        goto FREE_BUF;
    }

    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)send_buf->qbuf_ext;
    umq_ub_imm_t imm = {.mem_import = {
        .type = IMM_TYPE_CONTROL_MSG,
        .umq_id = queue->remote_umq_id,
        .extend_type = IMM_TYPE_EXTEND_MEM_IMPORT
    }};
    buf_pro->imm_data = imm.value;
    buf_pro->opcode = UMQ_OPC_SEND_IMM;

    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)send_buf->buf_data;
    umq_imm_head->version = UMQ_IMM_VERSION;
    umq_imm_head->type = IMM_PROTOCAL_TYPE_IMPORT_MEM;
    umq_imm_head->mempool_num = 1;
    umq_imm_head->mem_interval = UMQ_SIZE_0K_SMALL_INTERVAL;

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
    uint16_t max_tx = umq_ub_window_dec(&queue->flow_control, queue, 1);
    if (max_tx == 0) {
        ret = -UMQ_ERR_EAGAIN;
        goto FREE_BUF;
    }

    ret = umq_ub_send_imm(queue, imm.value, &sge, (uint64_t)(uintptr_t)send_buf);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub send imm failed, status: %d\n",
            EID_ARGS(*eid), id, ret);
        goto INC_FC_WIN;
    }
    return UMQ_SUCCESS;

INC_FC_WIN:
    umq_ub_window_inc(&queue->flow_control, 1);

FREE_BUF:
    umq_buf_free(send_buf);
    return ret;
}

int umq_ub_dev_info_get_impl(char *dev_name, umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info)
{
    if (dev_name == NULL || strnlen(dev_name, UMQ_DEV_NAME_SIZE) >= UMQ_DEV_NAME_SIZE || umq_dev_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq_ub_dev_info_dump_by_name(dev_name, umq_trans_mode, umq_dev_info);
}

umq_dev_info_t *umq_ub_dev_info_list_get_impl(umq_trans_mode_t umq_trans_mode, int *dev_num)
{
    if (dev_num == NULL) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter, errno: %d\n", errno);
        return NULL;
    }

    int urma_dev_num = umq_ub_dev_num_get();
    if (urma_dev_num == 0) {
        errno = UMQ_ERR_ENODEV;
        return NULL;
    }

    umq_dev_info_t *umq_dev_info = calloc(urma_dev_num, sizeof(umq_dev_info_t));
    if (umq_dev_info == NULL) {
        errno = UMQ_ERR_ENOMEM;
        return NULL;
    }

    *dev_num = urma_dev_num;
    umq_ub_dev_info_dump(umq_trans_mode, urma_dev_num, umq_dev_info);

    return umq_dev_info;
}

void umq_ub_dev_info_list_free_impl(umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info)
{
    if (umq_dev_info != NULL) {
        free(umq_dev_info);
    }
}

int umq_ub_cfg_get_impl(uint64_t umqh_tp, umq_cfg_get_t *cfg)
{
    if (cfg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq cfg is invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    cfg->create_flag = queue->create_flag;
    cfg->max_rx_sge = queue->max_rx_sge;
    cfg->max_tx_sge = queue->max_tx_sge;
    cfg->rx_buf_size = queue->rx_buf_size;
    cfg->tx_buf_size = queue->tx_buf_size;
    cfg->rx_depth = queue->rx_depth;
    cfg->tx_depth = queue->tx_depth;
    cfg->umq_ctx = queue->umq_ctx;
    cfg->share_rq_umqh = queue->share_rq_umqh;
    cfg->trans_mode = queue->umq_trans_mode;
    cfg->mode = queue->mode;
    cfg->state = queue->state;
    cfg->priority = queue->priority;
    cfg->rqe_post_factor = queue->rqe_post_factor;
    cfg->tp_mode = umq_tp_mode_convert(queue->tp_mode);
    cfg->tp_type = umq_tp_type_convert(queue->tp_type);
    return UMQ_SUCCESS;
}

int umq_ub_plus_stats_flow_control_get_impl(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats)
{
    return umq_flow_control_stats_get(umqh_tp, flow_control_stats);
}

int umq_ub_stats_qbuf_pool_get_impl(uint64_t umqh_tp, umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    qbuf_pool_stats->num = 0;
    int ret = umq_qbuf_pool_info_get(qbuf_pool_stats);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq_qbuf pool info get failed\n");
        return ret;
    }

    ret = umq_huge_qbuf_pool_info_get(qbuf_pool_stats);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq huge qbuf pool info get failed\n");
        return ret;
    }
    ret = umq_tiny_qbuf_pool_info_get(qbuf_pool_stats);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq tiny qbuf pool info get failed\n");
        return ret;
    }
    return UMQ_SUCCESS;
}

int umq_ub_info_get_impl(uint64_t umqh_tp, umq_info_t *umq_info)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->jetty[UB_QUEUE_JETTY_IO] != NULL) {
        umq_info->ub.local_io_jetty_id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    } else {
        umq_info->ub.local_io_jetty_id = 0;
    }

    if (queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] != NULL) {
        umq_info->ub.local_fc_jetty_id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    } else {
        umq_info->ub.local_fc_jetty_id = 0;
    }

    if (queue->bind_ctx != NULL && queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO] != NULL) {
        umq_info->ub.remote_io_jetty_id = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id;
    } else {
        umq_info->ub.remote_io_jetty_id = 0;
    }

    if (queue->bind_ctx != NULL && queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL] != NULL) {
        umq_info->ub.remote_fc_jetty_id = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL]->id.id;
    } else {
        umq_info->ub.remote_fc_jetty_id = 0;
    }

    umq_info->trans_mode = queue->dev_ctx->trans_info.trans_mode;
    (void)memcpy(&umq_info->ub.eid, &queue->dev_ctx->urma_ctx->eid, sizeof(urma_eid_t));
    (void)memcpy(umq_info->ub.dev_name, queue->dev_ctx->urma_ctx->dev->name, URMA_MAX_NAME);
    return UMQ_SUCCESS;
}

int umq_ub_stats_io_get_impl(uint64_t umqh_tp, umq_packet_stats_t *packet_stats)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    packet_stats->send_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_SEND];
    packet_stats->send_success = queue->packet_stats[UB_PACKET_STATS_TYPE_SEND_SUCCESS];
    packet_stats->recv_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_RECV];
    packet_stats->send_eagain_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_SEND_EAGAIN];
    packet_stats->send_error_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_SEND_ERROR];
    packet_stats->recv_error_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_RECV_ERROR];
    packet_stats->recv_duplicate_req_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_RECV_DUPLICATE_REQ];
    packet_stats->recv_duplicate_rsp_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_RECV_DUPLICATE_RSP];

    return UMQ_SUCCESS;
}

int umq_ub_stats_io_reset_impl(uint64_t umqh_tp)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;

    if (queue->dev_ctx != NULL && queue->dev_ctx->io_lock_free) {
        for (uint32_t i = 0; i < UB_PACKET_STATS_TYPE_MAX; i++) {
            queue->packet_stats[i] = 0;
        }
        return UMQ_SUCCESS;
    }

    for (uint32_t i = 0; i < UB_PACKET_STATS_TYPE_MAX; i++) {
        (void)__atomic_exchange_n(&queue->packet_stats[i], 0, __ATOMIC_ACQ_REL);
    }
    return UMQ_SUCCESS;
}

int umq_ub_stats_tp_perf_start_impl(void)
{
    return umq_symbol_urma()->urma_start_perf();
}

int umq_ub_stats_tp_perf_stop_impl(void)
{
    return umq_symbol_urma()->urma_stop_perf();
}

int umq_ub_stats_tp_perf_info_get_impl(char *perf_buf, uint32_t *length)
{
    return umq_symbol_urma()->urma_get_perf_info(perf_buf, length);
}

int umq_ub_transport_pool_resource_modify_impl(uint64_t umqh_tp, uint32_t tp_handle_idx)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "modify to err failed, queue is NULL\n");
        return -UMQ_ERR_EINVAL;
    }

    if (!is_umq_ub_main_queue(queue->create_flag) || !is_umq_ub_share_transport(queue->create_flag)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u) is not share transport main umq\n", queue->umq_id);
        return -UMQ_ERR_EINVAL;
    }

    umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
    if (tp_handle_idx >= jetty_node_list->list_len) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tp handle idx %u exceeds the jetty node list len %u\n",
                     tp_handle_idx, jetty_node_list->list_len);
        return -UMQ_ERR_EINVAL;
    }

    if (!urpc_bitmap_is_set(jetty_node_list->bitmap, tp_handle_idx)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u) tp_handle_idx %u tp handle not exist\n", queue->umq_id, tp_handle_idx);
        return -UMQ_ERR_EINVAL;
    }

    urma_jetty_t *jetty = jetty_node_list->node_list[tp_handle_idx]->jetty[UB_QUEUE_JETTY_IO];
    urma_jetty_attr_t jetty_attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_ERROR,
    };
    urma_status_t urma_status = umq_symbol_urma()->urma_modify_jetty(jetty, &jetty_attr);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_modify_jetty to "
            "URMA_JETTY_STATE_ERROR failed, status: %u\n",  EID_ARGS(jetty->jetty_id.eid),
            jetty->jetty_id.id, (int)urma_status);
    }

    if (queue->flow_control.enabled) {
        jetty = jetty_node_list->node_list[tp_handle_idx]->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
        urma_status = umq_symbol_urma()->urma_modify_jetty(jetty, &jetty_attr);
        if (urma_status != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_modify_jetty to "
                "URMA_JETTY_STATE_ERROR failed, status: %u\n",  EID_ARGS(jetty->jetty_id.eid),
                jetty->jetty_id.id, (int)urma_status);
        }
    }
    umq_ub_jetty_node_mark_err(jetty_node_list->node_list[tp_handle_idx]);
    return umq_status_convert(urma_status);
}

int umq_ub_transport_pool_eventfd_get_impl(void)
{
    return umq_ub_jetty_pool_get_eventfd();
}

int umq_ub_transport_pool_stats_get_impl(umq_transport_pool_stats_t *stats)
{
    if (stats == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "transport pool stats is NULL\n");
        return -UMQ_ERR_EINVAL;
    }
    umq_ub_jetty_pool_stats_t pool_stats;
    int ret = umq_ub_jetty_pool_stats_get(&pool_stats);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    stats->total_num = pool_stats.total_num;
    stats->global_num = pool_stats.global_num;
    stats->cache_num = pool_stats.cache_num;
    stats->in_use_num = pool_stats.in_use_num;
    stats->error_num = pool_stats.err_num;
    stats->acc_alloc_num = pool_stats.acc_alloc_num;
    stats->acc_free_num = pool_stats.acc_free_num;
    stats->acc_miss_num = pool_stats.acc_miss_num;
    return UMQ_SUCCESS;
}
