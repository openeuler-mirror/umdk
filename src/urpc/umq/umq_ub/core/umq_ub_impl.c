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
#define UMQ_UB_DEFAULT_SLOT_NUM 10
#define UMQ_UB_EVENT_QUEUE_IDLE 1

static umq_ub_ctx_t *g_ub_ctx = NULL;
static uint32_t g_ub_ctx_count = 0;
static bool g_umq_ub_inited = false;

typedef struct umq_ub_monitor_slot {
    urpc_list_t monitored_links;
    uint32_t slot_id;
    pthread_mutex_t lock;
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

int32_t umq_ub_register_memory_impl(void *buf, uint64_t size)
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
        ret = umq_ub_register_seg(&g_ub_ctx[i], UMQ_QBUF_DEFAULT_MEMPOOL_ID, buf, size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR(VLOG_UMQ, "ub ctx[%u] register segment failed, status: %d\n", i, ret);
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

    if (buf_size < umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID)) {
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
        old_val = __atomic_load_n(&g_umq_monitor_slots.current_slot, __ATOMIC_RELAXED);
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
    (void)pthread_mutex_destroy(&checker->lock);
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
    (void)pthread_mutex_lock(&current_slot_obj->lock);
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &current_slot_obj->monitored_links) {
        (void)pthread_mutex_lock(&cur_node->lock);
        ub_queue_t *queue = cur_node->umq;
        if (queue == NULL) {
            urpc_list_remove(&cur_node->node);
            (void)pthread_mutex_unlock(&cur_node->lock);
            umq_ub_idle_checker_uninit(cur_node);
            continue;
        }
        ub_flow_control_t *fc = &queue->flow_control;
        uint16_t remote_credit = fc->ops.remote_rx_window_load(fc);
        if (remote_credit <= fc->min_reserved_credit) {
            (void)pthread_mutex_unlock(&cur_node->lock);
            continue;
        }
        uint64_t last_send = __atomic_load_n(&cur_node->last_send, __ATOMIC_RELAXED);
        if (current_timestamp >= last_send) {
            uint64_t diff = (current_timestamp - last_send);
            if (diff >= timeout_us) {
                __atomic_store_n(&cur_node->need_return_credit, true, __ATOMIC_RELAXED);
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
            __atomic_store_n(&cur_node->target_slot_id, target_slot_id, __ATOMIC_RELAXED);
        }
        (void)pthread_mutex_unlock(&cur_node->lock);
    }
    (void)pthread_mutex_unlock(&current_slot_obj->lock);
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &temp_list) {
        uint32_t target_slot_id = cur_node->target_slot_id;
        (void)pthread_mutex_lock(&g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
        urpc_list_remove(&cur_node->node);
        urpc_list_push_back(&g_umq_monitor_slots.monitor_slots[target_slot_id].monitored_links, &cur_node->node);
        (void)pthread_mutex_unlock(&g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
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
    for (uint32_t i = 0; i < g_umq_monitor_slots.slot_num; i++) {
        urpc_list_init(&g_umq_monitor_slots.monitor_slots[i].monitored_links);
        g_umq_monitor_slots.monitor_slots[i].slot_id = i;
        pthread_mutex_init(&g_umq_monitor_slots.monitor_slots[i].lock, NULL);
    }
    return UMQ_SUCCESS;
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
        pthread_mutex_destroy(&current_slot_obj->lock);
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

    g_ub_ctx = (umq_ub_ctx_t *)calloc(MAX_UMQ_TRANS_INFO_NUM, sizeof(umq_ub_ctx_t));
    if (g_ub_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "memory alloc failed\n");
        goto UNINIT_ALLOCATOR;
    }

    urma_init_attr_t init_attr = {0};
    ret = urma_init(&init_attr);
    if (ret != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_init failed, status: %d\n", ret);
        goto FREE_CTX;
    }

    if (umq_ub_dev_info_init() != UMQ_SUCCESS) {
        goto URMA_UNINIT;
    }

    uint64_t total_io_buf_size = 0;
    for (uint32_t i = 0; i < cfg->trans_info_num; i++) {
        umq_trans_info_t *info = &cfg->trans_info[i];
        if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
            info->trans_mode != UMQ_TRANS_MODE_UBMM && info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
            UMQ_VLOG_INFO(VLOG_UMQ, "trans init mode: %d not UB, skip it\n", info->trans_mode);
            continue;
        }

        if (total_io_buf_size == 0) {
            total_io_buf_size = info->mem_cfg.total_size;
        }

        if (info->dev_info.assign_mode == UMQ_DEV_ASSIGN_MODE_DUMMY) {
            UMQ_VLOG_INFO(VLOG_UMQ, "device info assign_mode is dummy, skip it\n");
            continue;
        }

        g_ub_ctx[g_ub_ctx_count].remote_imported_info = umq_ub_ctx_imported_info_create();
        if (g_ub_ctx[g_ub_ctx_count].remote_imported_info == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "imported info create failed\n");
            goto ROLLBACK_UB_CTX;
        }

        ret = umq_find_ub_device(info, &g_ub_ctx[g_ub_ctx_count]);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "find ub device failed, status: %d\n", ret);
            umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);
            goto ROLLBACK_UB_CTX;
        }

        g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table = (uint64_t *)calloc(
            g_ub_ctx[g_ub_ctx_count].dev_attr.dev_cap.max_jetty, sizeof(uint64_t));
        if (g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "calloc umq_ctx_jetty_table failed\n");
            umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);
            umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);
            goto ROLLBACK_UB_CTX;
        }

        g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table = (volatile uint64_t *)calloc(
            g_ub_ctx[g_ub_ctx_count].dev_attr.dev_cap.max_jetty, sizeof(uint64_t));
        if (g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "calloc rx_consumed_jetty_table failed\n");
            umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);
            umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);
            free(g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table);
            g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table = NULL;
            goto ROLLBACK_UB_CTX;
        }

        g_ub_ctx[g_ub_ctx_count].io_lock_free = cfg->io_lock_free;
        g_ub_ctx[g_ub_ctx_count].feature = cfg->feature;
        g_ub_ctx[g_ub_ctx_count].flow_control = cfg->flow_control;
        g_ub_ctx[g_ub_ctx_count].ref_cnt = 1;
        ++g_ub_ctx_count;
    }

    if (umq_io_buf_malloc(cfg->buf_mode, total_io_buf_size) == NULL) {
        goto ROLLBACK_UB_CTX;
    }

    qbuf_pool_cfg_t qbuf_cfg = {
        .buf_addr = umq_io_buf_addr(),
        .total_size = umq_io_buf_size(),
        .data_size = umq_buf_size_small(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
    };
    ret = umq_qbuf_pool_init(&qbuf_cfg);
    if (ret != UMQ_SUCCESS && ret != -UMQ_ERR_EEXIST) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf poll init failed, status: %d\n", ret);
        goto IO_BUF_FREE;
    }
    umq_ub_queue_ctx_list_init();
    if (umq_ub_check_idle_queue_timer_create(cfg) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq check idle queue timer create failed\n");
        goto QUEUE_CTX_LIST_UNINIT;
    }

    g_umq_ub_inited = true;

    return (uint8_t *)(uintptr_t)g_ub_ctx;

QUEUE_CTX_LIST_UNINIT:
    umq_ub_queue_ctx_list_uninit();

IO_BUF_FREE:
    umq_io_buf_free();

ROLLBACK_UB_CTX:
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        umq_ub_ctx_imported_info_destroy(&g_ub_ctx[i]);
        umq_ub_delete_urma_ctx(&g_ub_ctx[i]);
        free(g_ub_ctx[i].umq_ctx_jetty_table);
        g_ub_ctx[i].umq_ctx_jetty_table = NULL;
        free((void*)g_ub_ctx[i].rx_consumed_jetty_table);
        g_ub_ctx[i].rx_consumed_jetty_table = NULL;
    }
    g_ub_ctx_count = 0;
    umq_ub_dev_info_uninit();

URMA_UNINIT:
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
    umq_ub_check_idle_queue_timer_delete();
    umq_ub_queue_ctx_list_uninit();
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

    for (uint32_t i = 0; i < g_ub_ctx_count; ++i) {
        umq_ub_ctx_imported_info_destroy(&context[i]);
        umq_dec_ref(context[i].io_lock_free, &context[i].ref_cnt, 1);
        urma_delete_context(context[i].urma_ctx);
        free(context[i].umq_ctx_jetty_table);
        context[i].umq_ctx_jetty_table = NULL;
        free((void*)context[i].rx_consumed_jetty_table);
        context[i].rx_consumed_jetty_table = NULL;
    }

    umq_qbuf_pool_uninit();
    umq_io_buf_free();
    umq_ub_id_allocator_uninit();
    umq_ub_dev_info_uninit();

    free(context);
    g_ub_ctx_count = 0;
    g_umq_ub_inited = false;
    urma_uninit();
}

static int umq_ub_idle_checker_init(ub_queue_t *queue)
{
    ub_queue_idle_check_t *checker = (ub_queue_idle_check_t *)calloc(1, sizeof(ub_queue_idle_check_t));
    if (checker == NULL) {
        queue->checker = NULL;
        return UMQ_FAIL;
    }
    queue->checker = checker;
    checker->umq = queue;
    checker->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (checker->event_fd == UMQ_INVALID_FD) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create eventfd failed, err: %s\n", strerror(errno))
        free(checker);
        queue->checker = NULL;
        return UMQ_FAIL;
    }
    uint64_t current_time = get_timestamp_us();
    checker->last_send = current_time;
    uint64_t expire_time = current_time + g_umq_monitor_slots.timeout_us;
    uint32_t current_slot_id = __atomic_load_n(&g_umq_monitor_slots.current_slot, __ATOMIC_RELAXED);
    uint32_t target_slot_id = target_slot_id_calcuate(expire_time, current_time, current_slot_id);
    checker->target_slot_id = target_slot_id;
    pthread_mutex_init(&checker->lock, NULL);
    (void)pthread_mutex_lock(&g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
    urpc_list_push_back(&g_umq_monitor_slots.monitor_slots[target_slot_id].monitored_links, &checker->node);
    (void)pthread_mutex_unlock(&g_umq_monitor_slots.monitor_slots[target_slot_id].lock);
    return UMQ_SUCCESS;
}

static int umq_ub_create_flow_control_resource(ub_queue_t *queue, umq_create_option_t *option)
{
    if (!queue->flow_control.enabled) {
        return UMQ_SUCCESS;
    }
    urma_jfc_cfg_t jfc_cfg = {
        .depth = UMQ_UB_FLOW_CONTORL_JETTY_DEPTH, // jfs_jfce is shared between fc jfs_jfc and io jfs_jfc
        .jfce = queue->jfs_jfce};
    umq_ub_ctx_t *dev_ctx = queue->dev_ctx;
    // fc jetty
    umq_ub_rx_consumed_exchange(dev_ctx->io_lock_free,
                                &dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id], 0);
    queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL] = umq_ub_jfr_ctx_create(queue, dev_ctx, UB_QUEUE_JETTY_FLOW_CONTROL);
    if (queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create flow control jfr ctx failed\n")
        return UMQ_FAIL;
    }

    queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] = urma_create_jfc(dev_ctx->urma_ctx, &jfc_cfg);
    if (queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for flowcontrol jfs_jfc failed, errno: %d\n", errno);
        goto DESTROY_FC_JFR_CTX;
    }

    queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] = umq_create_jetty(queue, dev_ctx, UB_QUEUE_JETTY_FLOW_CONTROL);
    if (queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
        goto DELETE_FC_JFS_JFC;
    }

    dev_ctx->umq_ctx_jetty_table[queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id] =
        (uint64_t)(uintptr_t)queue;

    umq_ub_rx_consumed_exchange(
        dev_ctx->io_lock_free,
        &dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id], 0);

    /* if step A after umq_ub_idle_checker_init, step A fails,
     * umq_ub_idle_checker_uninit can not be called, need to lock checker, setting checker->umq to NULL,
     * umq_ub_idle_queue_check or umq_ub_monitor_slots_uninit free resoures */
    if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0) {
        if (umq_ub_idle_checker_init(queue) != UMQ_SUCCESS) {
            goto DELETE_FC_JFS_JFC;
        }
    }

    return UMQ_SUCCESS;

DELETE_FC_JFS_JFC:
    (void)urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]);

DESTROY_FC_JFR_CTX:
    umq_ub_jfr_ctx_destroy(queue, UB_QUEUE_JETTY_FLOW_CONTROL);

    return UMQ_FAIL;
}

uint64_t umq_ub_create_impl(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option)
{
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

    if (umq_ub_jfr_ctx_get(queue, dev_ctx, option, share_rq) != UMQ_SUCCESS) {
        goto FREE_QUEUE;
    }

    if (umq_ub_flow_control_init(&queue->flow_control, queue, dev_ctx->feature, &dev_ctx->flow_control) !=
        UMQ_SUCCESS) {
        goto DESTROY_JFR_CTX;
    }
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        queue->jfs_jfce = urma_create_jfce(dev_ctx->urma_ctx);
        if (queue->jfs_jfce == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfce for jfs_jfce failed, errno: %d\n", errno);
            goto UNINIT_FLOW_CONTROL;
        }
    }

    urma_jfc_cfg_t jfc_cfg = {
        .depth = queue->tx_depth + 1, // flush done consumes one cqe
        .jfce = queue->jfs_jfce
    };
    queue->jfs_jfc[UB_QUEUE_JETTY_IO] = urma_create_jfc(dev_ctx->urma_ctx, &jfc_cfg);
    if (queue->jfs_jfc[UB_QUEUE_JETTY_IO] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc for jfs_jfc failed, errno: %d\n", errno);
        goto DELETE_JFCE;
    }

    queue->jetty[UB_QUEUE_JETTY_IO] = umq_create_jetty(queue, dev_ctx, UB_QUEUE_JETTY_IO);
    if (queue->jetty[UB_QUEUE_JETTY_IO] == NULL) {
        goto DELETE_JFS_JFC;
    }
    if ((option->create_flag & UMQ_CREATE_FLAG_UMQ_CTX) != 0) {
        queue->umq_ctx = option->umq_ctx;
    }
    dev_ctx->umq_ctx_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id] = (uint64_t)(uintptr_t)queue;

    queue->notify_buf = umq_buf_alloc(umq_buf_size_small(), 1, UMQ_INVALID_HANDLE, NULL);
    if (queue->notify_buf == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, buf alloc failed\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        goto DELETE_JETTY;
    }
    memset(queue->notify_buf->buf_data, 0, queue->notify_buf->data_size);

    if (umq_ub_create_flow_control_resource(queue, option) != UMQ_SUCCESS) {
        goto FREE_NOTIFY_BUF;
    }

    queue->require_rx_count = 0;
    queue->ref_cnt = 1;
    queue->tx_outstanding = 0;
    queue->state = queue->flow_control.enabled ? QUEUE_STATE_IDLE : QUEUE_STATE_READY;
    queue->umqh = umqh;
    (void)pthread_rwlock_init(&queue->wait_ack_import.lock, NULL);
    umq_ub_queue_ctx_list_push(&queue->qctx_node);
    return (uint64_t)(uintptr_t)queue;

FREE_NOTIFY_BUF:
    umq_buf_free(queue->notify_buf);

DELETE_JETTY:
    if ((option->create_flag & UMQ_CREATE_FLAG_UMQ_CTX) != 0) {
        dev_ctx->umq_ctx_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id] = 0;
    }
    (void)urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
DELETE_JFS_JFC:
    (void)urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO]);
DELETE_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        (void)urma_delete_jfce(queue->jfs_jfce);
    }
UNINIT_FLOW_CONTROL:
    umq_ub_flow_control_uninit(&queue->flow_control);
DESTROY_JFR_CTX:
    umq_ub_jfr_ctx_put(queue);
FREE_QUEUE:
    free(queue);
DEC_REF:
    umq_dec_ref(dev_ctx->io_lock_free, &dev_ctx->ref_cnt, 1);

    return UMQ_INVALID_HANDLE;
}

int32_t umq_ub_destroy_impl(uint64_t umqh)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    urma_eid_t *io_eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t io_id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int ret = UMQ_SUCCESS;
    if (queue->umq_trans_mode != UMQ_TRANS_MODE_UB && queue->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        queue->umq_trans_mode != UMQ_TRANS_MODE_UBMM && queue->umq_trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
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

    if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0 &&
        __atomic_load_n(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->ref_cnt, __ATOMIC_RELAXED) != 1) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, jfr_ctx ref_cnt not cleared, cannot destroy main "
            "queue\n", EID_ARGS(*io_eid), io_id);
        return -UMQ_ERR_EBUSY;
    }

    if (queue->bind_ctx != NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umqh has not been unbinded\n",
            EID_ARGS(*io_eid), io_id);
        return -UMQ_ERR_EBUSY;
    }

    if (queue->flow_control.enabled) {
        urma_eid_t *fc_eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
        uint32_t fc_id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
        umq_ub_credit_clean_up(queue);
        UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, delete flowcontrol jetty\n",
            EID_ARGS(*fc_eid), fc_id);
        if ((queue->create_flag & UMQ_CREATE_FLAG_UMQ_CTX) != 0) {
            queue->dev_ctx->umq_ctx_jetty_table[fc_id] = 0;
        }
        ret = urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jetty for flowcontrol jetty "
                "failed, status: %d\n", EID_ARGS(*fc_eid), fc_id, ret);
        }

        ret = urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfc for flowcontrol jfs_jfc "
                "failed, status: %d\n", EID_ARGS(*fc_eid), fc_id, ret);
        }

        umq_ub_jfr_ctx_destroy(queue, UB_QUEUE_JETTY_FLOW_CONTROL);
    }

    umq_buf_free(queue->notify_buf);
    umq_buf_free(queue->addr_list);

    umq_ub_flow_control_uninit(&queue->flow_control);
    UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, delete jetty\n", EID_ARGS(*io_eid), io_id);
    if ((queue->create_flag & UMQ_CREATE_FLAG_UMQ_CTX) != 0) {
        queue->dev_ctx->umq_ctx_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id] = 0;
    }
    ret = urma_delete_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
    if (ret != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jetty failed, status: %d\n",
            EID_ARGS(*io_eid), io_id, ret);
    }
    ret = urma_delete_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO]);
    if (ret != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfc failed, status: %d\n",
            EID_ARGS(*io_eid), io_id, ret);
    }
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        ret = urma_delete_jfce(queue->jfs_jfce);
        if (ret != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_delete_jfce for jfs_jfce failed, "
                "status: %d\n", EID_ARGS(*io_eid), io_id, ret);
        }
    }

    if (queue->wait_ack_import.wait_ack_pool_id != NULL) {
        free(queue->wait_ack_import.wait_ack_pool_id);
    }
    (void)pthread_rwlock_destroy(&queue->wait_ack_import.lock);

    umq_ub_jfr_ctx_put(queue);
    umq_ub_queue_ctx_list_remove(&queue->qctx_node);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->dev_ctx->ref_cnt, 1);
    if (queue->checker != NULL) {
        (void)pthread_mutex_lock(&queue->checker->lock);
        queue->checker->umq = NULL;
        (void)pthread_mutex_unlock(&queue->checker->lock);
    }
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
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option not valid\n");
        return -UMQ_ERR_EINVAL;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)(wait_umqh_tp);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue mode is not interrupt\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }
    urma_jfc_t *jfc[UB_QUEUE_JETTY_NUM];
    int cnt = 0;
    if (option->direction == UMQ_IO_RX) {
        cnt = umq_ub_wait_rx_interrupt(queue, time_out, jfc);
    } else {
        cnt = umq_ub_wait_tx_interrupt(queue, time_out, jfc);
    }
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
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "option invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    if (queue->jfs_jfce == NULL || queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get interrupt fd error, jfce is NULL\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_EINVAL;
    }
    if (option->direction == UMQ_IO_TX) {
        return queue->jfs_jfce->fd;
    } else if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        return queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce->fd;
    } else if (queue->flow_control.enabled) {
        return queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfce->fd;
    }
    return -1;
}

int umq_ub_rearm_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    if ((option->flag & UMQ_INTERRUPT_FLAG_IO_DIRECTION) == 0 || option->direction <= UMQ_IO_ALL ||
        option->direction >= UMQ_IO_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "option invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->mode != UMQ_MODE_INTERRUPT) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue mode is not interrupt\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    urma_status_t status = URMA_SUCCESS;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    if (option->direction == UMQ_IO_TX) {
        status = urma_rearm_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], solicated);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_TX, start_timestamp);
    } else if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        status = urma_rearm_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, solicated);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_RX, start_timestamp);
    }
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_rearm_jfc for io jfc failed, "
            "status: %d\n", EID_ARGS(*eid), id, (int)status);
        return umq_status_convert(status);
    }

    if (queue->flow_control.enabled) {
        uint64_t start_timestamp = umq_perf_get_start_timestamp();
        if (option->direction == UMQ_IO_RX) {
            status = urma_rearm_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc, solicated);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_RX, start_timestamp);
        } else {
            status = urma_rearm_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL], solicated);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_REARM_TX, start_timestamp);
        }
        if (status != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_rearm_jfc for flowcontrol jfc failed"
                ", status: %d\n", EID_ARGS(*eid), id, (int)status);
            return umq_status_convert(status);
        }
    }

    return UMQ_SUCCESS;
}

int umq_ub_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf)
{
    int ret;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    if (io_direction == UMQ_IO_TX) {
        ret = umq_ub_post_tx(umqh_tp, qbuf, bad_qbuf);
    } else if (io_direction == UMQ_IO_RX) {
        ret = umq_ub_post_rx(umqh_tp, qbuf, bad_qbuf);
    } else {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, io_direction[%d] is not supported when post\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
            io_direction);
        ret = -UMQ_ERR_EINVAL;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    return ret;
}

int umq_ub_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count)
{
    int ret;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    if (io_direction == UMQ_IO_RX) {
        ret = umq_ub_poll_rx(umqh_tp, buf, max_buf_count);
    } else if (io_direction == UMQ_IO_TX) {
        ret = umq_ub_poll_tx(umqh_tp, buf, max_buf_count);
    } else if (io_direction == UMQ_IO_ALL) {
        uint32_t tx_max_cnt = max_buf_count > 1 ? max_buf_count >> 1 : 1;
        int32_t tx_cnt = umq_ub_poll_tx(umqh_tp, buf, tx_max_cnt);
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
            io_direction);
        ret = -UMQ_ERR_EINVAL;
    }

OUT:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

int umq_ub_unbind_impl(uint64_t umqh)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    ub_bind_ctx_t *bind_ctx = queue->bind_ctx;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (bind_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    if (queue->flow_control.enabled) {
        urma_target_jetty_t *tjetty = bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
        UMQ_VLOG_INFO(VLOG_UMQ, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id:"
            " %u, unbind flowcontrol jetty\n", EID_ARGS(*eid), id, EID_ARGS(tjetty->id.eid), tjetty->id.id);
        (void)urma_unbind_jetty(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]);
        (void)urma_unimport_jetty(tjetty);
        umq_modify_ubq_to_err(queue, UMQ_IO_ALL, UB_QUEUE_JETTY_FLOW_CONTROL);
    }

    urma_target_jetty_t *tjetty = bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
    (void)umq_ub_eid_id_release(queue->dev_ctx->remote_imported_info, bind_ctx);
    UMQ_VLOG_INFO(VLOG_UMQ, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u"
        ", unbind jetty\n", EID_ARGS(*eid), id, EID_ARGS(tjetty->id.eid), tjetty->id.id);
    (void)urma_unbind_jetty(queue->jetty[UB_QUEUE_JETTY_IO]);
    (void)urma_unimport_jetty(tjetty);
    if (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
        UMQ_VLOG_DEBUG(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sub umq only need set tx res error\n",
            EID_ARGS(*eid), id);
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
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    umq_ub_enqueue_with_poll_tx(queue, buf);

    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    urma_sge_t sges[UMQ_POST_POLL_BATCH][queue->max_tx_sge];
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
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], urma_wr, &bad_wr);
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
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
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
    urma_sge_t sges[UMQ_POST_POLL_BATCH][queue->max_tx_sge];
    uint32_t tx_outstanding = umq_fetch_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding);
    if (queue->tx_depth <= tx_outstanding) {
        ret = -UMQ_ERR_EAGAIN;
        goto DEC_REF;
    }

    uint32_t remain_tx = queue->tx_depth - tx_outstanding;
    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
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
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], urma_wr, &bad_wr);
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
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
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
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
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

int umq_ub_queue_addr_list_alloc(ub_queue_t *queue)
{
    if (queue->addr_list != NULL) {
        return UMQ_SUCCESS;
    }

    queue->addr_list = umq_buf_alloc(UMQ_MAX_ID_NUM * sizeof(uint64_t), 1, UMQ_INVALID_HANDLE, NULL);
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

int umq_ub_record_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id, umq_buf_t *buf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (umq_ub_queue_addr_list_alloc(queue) != UMQ_SUCCESS) {
        return -UMQ_ERR_ENOMEM;
    }

    umq_ub_queue_addr_list_record(queue->addr_list, msg_id, buf);
    return UMQ_SUCCESS;
}

void umq_ub_remove_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->addr_list == NULL) {
        return;
    }
    (void)umq_ub_queue_addr_list_remove(queue->addr_list, msg_id);
}

util_id_allocator_t *umq_ub_get_msg_id_generator(uint64_t umqh_tp)
{
    return umq_ub_id_allocator_get();
}

int umq_ub_state_set_impl(uint64_t umqh_tp, umq_state_t state)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, set state only support main umq\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    if (state != QUEUE_STATE_ERR) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, set state only support error state\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->state == QUEUE_STATE_ERR) {
        UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue state already in error state\n",
            EID_ARGS(*eid), id);
        return UMQ_SUCCESS;
    }

    int ret = umq_modify_ubq_to_err(queue, UMQ_IO_ALL, UB_QUEUE_JETTY_IO);
    if (ret) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, modify queue state failed, status: %d\n",
            EID_ARGS(*eid), id, ret);
        return ret;
    }

    UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, modify queue state %d success\n",
        EID_ARGS(*eid), id, state);
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
    urma_status_t status = urma_get_async_event(urma_ctx, urma_event);
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
    urma_ack_async_event(urma_event);
    free(urma_event);
    event->priv = NULL;
}

static int umq_ub_register_seg_callback(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size)
{
    if (ctx == NULL || addr == NULL || size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq_ub_register_seg((umq_ub_ctx_t *)(uintptr_t)ctx, mempool_id, addr, size);
}

static int umq_ub_unregister_seg_callback(uint8_t *ctx, uint16_t mempool_id)
{
    if (ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    umq_ub_unregister_seg((umq_ub_ctx_t *)(uintptr_t)ctx, 1, mempool_id);
    return UMQ_SUCCESS;
}

int umq_ub_dev_add_impl(umq_trans_info_t *info, umq_init_cfg_t *cfg)
{
    if (info == NULL || cfg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        info->trans_mode != UMQ_TRANS_MODE_UBMM && info->trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
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

    g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table = (uint64_t *)calloc(
        g_ub_ctx[g_ub_ctx_count].dev_attr.dev_cap.max_jetty, sizeof(uint64_t));
    if (g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc umq_ctx_jetty_table failed\n");
        goto DELETE_URMA_CTX;
    }
    g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table = (volatile uint64_t *)calloc(
        g_ub_ctx[g_ub_ctx_count].dev_attr.dev_cap.max_jetty, sizeof(uint64_t));
    if (g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc rx_consumed_jetty_table failed\n");
        goto FREE_UMQ_CTX_TBL;
    }
    // register seg
    ret = umq_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], umq_ub_register_seg_callback);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf register seg failed\n");
        goto FREE_UMQ_CTX_RX_CONSUMED_TBL;
    }

    ret = umq_huge_qbuf_register_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count],
        umq_ub_register_seg_callback, umq_ub_unregister_seg_callback);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "huge qbuf register seg failed, status: %d\n", ret);
        goto UNREGISTER_MEM;
    }

    g_ub_ctx[g_ub_ctx_count].io_lock_free = cfg->io_lock_free;
    g_ub_ctx[g_ub_ctx_count].feature = cfg->feature;
    g_ub_ctx[g_ub_ctx_count].flow_control = cfg->flow_control;
    g_ub_ctx[g_ub_ctx_count].ref_cnt = 1;
    g_ub_ctx_count++;

    return UMQ_SUCCESS;

UNREGISTER_MEM:
    (void)umq_qbuf_unregister_seg((uint8_t *)&g_ub_ctx[g_ub_ctx_count], umq_ub_unregister_seg_callback);

FREE_UMQ_CTX_RX_CONSUMED_TBL:
    free((void*)g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table);
    g_ub_ctx[g_ub_ctx_count].rx_consumed_jetty_table = NULL;

FREE_UMQ_CTX_TBL:
    free(g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table);
    g_ub_ctx[g_ub_ctx_count].umq_ctx_jetty_table = NULL;

DELETE_URMA_CTX:
    (void)umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);

DELETE_IMPORT_INFO:
    (void)umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);

    return ret;
}

int ubmm_fill_ref_sge_info(uint64_t umqh_tp, umq_buf_t *qbuf, char *ub_ref_info, uint32_t ub_ref_info_size)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)ub_ref_info;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(ub_ref_info + sizeof(umq_imm_head_t));
    ub_fill_umq_imm_head(umq_imm_head, qbuf);

    uint32_t ref_sge_cnt = umq_ub_ref_sge_cnt(qbuf);
    if (ref_sge_cnt == 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get ref sge cnt failed\n", EID_ARGS(*eid), id);
        return UMQ_FAIL;
    }

    uint32_t ref_sge_size = ref_sge_cnt * sizeof(ub_ref_sge_t);
    if (ref_sge_size + (uint32_t)sizeof(umq_imm_head_t) > umq_buf_size_small()) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the buf num [%d] exceeds the maximum limit\n",
            EID_ARGS(*eid), id, ref_sge_cnt);
        return UMQ_FAIL;
    }
    uint32_t mempool_info_size = umq_buf_size_small() - ref_sge_size - (uint32_t)sizeof(umq_imm_head_t);
    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)(uintptr_t)(ub_ref_info +
        sizeof(umq_imm_head_t) + ref_sge_cnt * sizeof(ub_ref_sge_t));

    umq_buf_t *tmp_buf = qbuf;
    uint32_t idx = 0;
    mempool_info_ctx_t mempool_info_ctx = {
        .umq_imm_head = umq_imm_head,
    };
    while (tmp_buf != NULL) {
        if (mempool_info_size < (umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t))) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the buf num [%d] mempool info num [%u] "
                "exceeds the maximum limit [%u]\n", EID_ARGS(*eid), id, ref_sge_cnt, umq_imm_head->mempool_num);
            return UMQ_FAIL;
        }
        mempool_info_ctx.import_mempool_info = &import_mempool_info[umq_imm_head->mempool_num];
        if (fill_big_data_ref_sge(queue, ref_sge, tmp_buf, &mempool_info_ctx) != UMQ_SUCCESS) {
            return UMQ_FAIL;
        }
        tmp_buf = tmp_buf->qbuf_next;
        ref_sge = ref_sge + 1;
        idx++;
    }
    return UMQ_SUCCESS;
}

int umq_ub_get_route_list_impl(const umq_route_t *route, umq_route_list_t *route_list)
{
    if (route == NULL || route_list == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    uvs_route_t uvs_route = {.flag.value = route->flag.value, .hops = route->hops, .chip_id = route->chip_id};
    uvs_route_list_t uvs_route_list = {0};
    (void)memcpy(&uvs_route.src, &route->src, sizeof(umq_eid_t));
    (void)memcpy(&uvs_route.dst, &route->dst, sizeof(umq_eid_t));

    int ret = uvs_get_route_list(&uvs_route, &uvs_route_list);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get route list failed, status: %d\n", ret);
        return ret;
    }

    if (uvs_route_list.len > UMQ_MAX_ROUTES || uvs_route_list.len > UVS_MAX_ROUTES) {
        UMQ_VLOG_ERR(VLOG_UMQ, "number of routes exceeds the maximum limit\n");
        return -UMQ_ERR_ENOMEM;
    }

    for (uint32_t i = 0; i < uvs_route_list.len; i++) {
        (void)memcpy(&route_list->buf[i].src, &uvs_route_list.buf[i].src, sizeof(umq_eid_t));
        (void)memcpy(&route_list->buf[i].dst, &uvs_route_list.buf[i].dst, sizeof(umq_eid_t));
        route_list->buf[i].flag.value = uvs_route_list.buf[i].flag.value;
        route_list->buf[i].hops = uvs_route_list.buf[i].hops;
        route_list->buf[i].chip_id = uvs_route_list.buf[i].chip_id;
    }
    route_list->len = uvs_route_list.len;
    return UMQ_SUCCESS;
}

int umq_ub_mempool_state_get_impl(uint64_t umqh_tp, uint32_t mempool_id, umq_mempool_state_t *mempool_state)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->dev_ctx == NULL || queue->dev_ctx->remote_imported_info == NULL || queue->bind_ctx == NULL ||
        mempool_id >= UMQ_MAX_TSEG_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub get mempool state parameter invalid\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
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
    int ret = umq_ub_mempool_state_get_impl(umqh_tp, mempool_id, &mempool_state);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get mempool state failed, status: %d\n", ret);
        return ret;
    }

    if (mempool_state.import_state == MEMPOOL_STATE_IMPORTED) {
        UMQ_VLOG_INFO(VLOG_UMQ, "mempool %u is imported\n", mempool_id);
        return UMQ_SUCCESS;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];
    if (tseg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n", EID_ARGS(*eid),
            id, mempool_id);
        return -UMQ_ERR_ENODEV;
    }
    urma_seg_t *seg = &tseg->seg;

    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), 1, queue->umqh, NULL);
    if (send_buf == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq malloc failed\n", EID_ARGS(*eid), id);
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
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub send imm failed, status: %d\n",
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

static umq_tp_mode_t umq_tp_mode_convert(urma_transport_mode_t tp_mode)
{
    switch (tp_mode) {
        case URMA_TM_RC:
            return UMQ_TM_RC;
        case URMA_TM_RM:
            return UMQ_TM_RM;
        case URMA_TM_UM:
            return UMQ_TM_UM;
        default:
            return UMQ_TM_RC;
    };
}

static umq_tp_type_t umq_tp_type_convert(urma_tp_type_t tp_type)
{
    switch (tp_type) {
        case URMA_RTP:
            return UMQ_TP_TYPE_RTP;
        case URMA_CTP:
            return UMQ_TP_TYPE_CTP;
        case URMA_UTP:
            return UMQ_TP_TYPE_UTP;
        default:
            return UMQ_TP_TYPE_RTP;
    };
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
    packet_stats->send_error_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_SEND_ERROR];
    packet_stats->recv_error_cnt = queue->packet_stats[UB_PACKET_STATS_TYPE_RECV_ERROR];

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
        (void)__atomic_exchange_n(&queue->packet_stats[i], 0, __ATOMIC_RELAXED);
    }
    return UMQ_SUCCESS;
}