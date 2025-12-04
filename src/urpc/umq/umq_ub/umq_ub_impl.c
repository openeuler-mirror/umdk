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
#include "umq_ub_imm_data.h"
#include "umq_ub_impl.h"

#define UMQ_DEFAULT_BUF_SIZE 4096
#define UMQ_DEFAULT_DEPTH 1024
#define DEFAULT_PRIORITY 5
#define DEFAULT_RNR_RETRY 6      // Retry 6 times
#define DEFAULT_ERR_TIMEOUT 2
#define DEFAULT_MIN_RNR_TIMER 19 // RNR single retransmission time: 2us*2^19 = 1.049s
#define UMQ_MAX_SGE_NUM 6
#define UMQ_REV_PULL_DONE 1
#define UMQ_FLUSH_MAX_RETRY_TIMES 10000
#define UMQ_MAX_ID_NUM (1 << 16)
#define UMQ_CONTINUE_FLAG 1
#define UMQ_MAX_QBUF_NUM 1
#define UMQ_MAX_TSEG_NUM 255
#define HUGE_QBUF_BUFFER_INC_BATCH 64
#define UMQ_ENABLE_INLINE_LIMIT_SIZE 32
#define UMQ_INLINE_ENABLE 1
#define UMQ_UB_RW_SEGMENT_LEN 64 // ub_queue read/write buf splited 64B for each module, such as mem import/flow control
#define UMQ_UB_FLOW_CONTROL_NOTIFY_THR 4
#define UMQ_DATA_LIMIT_SIZE (8 * 1024) // 8KB

typedef enum umq_ub_rw_segment_offset {
    OFFSET_MEM_IMPORT = 0,
    OFFSET_FLOW_CONTROL, // 16bit local window, 16bit remote window
} umq_ub_rw_segment_offset_t;

static util_id_allocator_t g_umq_ub_id_allocator = {0};

#define UMQ_UB_MAX_REMOTE_EID_NUM 1024
#define UMQ_UB_MIN_EID_ID 0

typedef struct remote_eid_hmap_node {
    struct urpc_hmap_node node;
    urma_eid_t eid;
    uint32_t remote_eid_id;
    uint32_t ref_cnt;
} remote_eid_hmap_node_t;

typedef struct remote_imported_tseg_info {
    bool tesg_imported[UMQ_UB_MAX_REMOTE_EID_NUM][UMQ_MAX_TSEG_NUM];
    struct urpc_hmap remote_eid_id_table;
    pthread_mutex_t remote_eid_id_table_lock;
    util_id_allocator_t eid_id_allocator;
} remote_imported_tseg_info_t;

typedef struct umq_ub_ctx {
    bool io_lock_free;
    volatile uint32_t ref_cnt;
    uint32_t feature;
    urma_order_type_t order_type;
    umq_flow_control_cfg_t flow_control;
    urma_context_t *urma_ctx;
    urma_device_attr_t dev_attr;
    umq_dev_assign_t dev_info;
    urma_target_seg_t *tseg_list[UMQ_MAX_TSEG_NUM];
    remote_imported_tseg_info_t *remote_imported_info;
    urma_target_jetty_t *tjetty;
    umq_trans_info_t trans_info;
    uint64_t remote_notify_addr;
} umq_ub_ctx_t;

typedef struct rx_buf_ctx {
    urpc_list_t node;
    umq_buf_t *buffer;
} rx_buf_ctx_t;

typedef struct rx_buf_ctx_list {
    void *addr; // The starting address of the memory allocated to rx buf ctx list
    urpc_list_t idle_rx_buf_ctx_list;
    urpc_list_t used_rx_buf_ctx_list;
} rx_buf_ctx_list_t;

struct ub_flow_control;
typedef struct ub_flow_control_window_ops {
    // update tx window after receive IMM_TYPE_FLOW_CONTROL
    uint16_t (*remote_rx_window_inc)(struct ub_flow_control *fc, uint16_t new_win);
    // alloc tx window, may return [0, required_win]
    uint16_t (*remote_rx_window_dec)(struct ub_flow_control *fc, uint16_t required_win);
    // exchange current tx window to 0 and return current tx window
    uint16_t (*remote_rx_window_exchange)(struct ub_flow_control *fc);
    // load current tx window
    uint16_t (*remote_rx_window_load)(struct ub_flow_control *fc);

    // update rx_posted after post rx buffer
    uint16_t (*local_rx_posted_inc)(struct ub_flow_control *fc, uint16_t rx_posted);
    // load current rx_posted
    uint16_t (*local_rx_posted_load)(struct ub_flow_control *fc);
    // exchange current rx_posted to 0 and return rx_posted
    uint16_t (*local_rx_posted_exchange)(struct ub_flow_control *fc);

    void (*stats_query)(struct ub_flow_control *fc, umq_flowcontrol_stats_t *out);
} ub_flow_control_window_ops_t;

typedef struct ub_flow_control {
    ub_flow_control_window_ops_t ops;
    volatile uint64_t total_local_rx_posted;
    volatile uint64_t total_local_rx_notified;
    volatile uint64_t total_local_rx_posted_error;
    volatile uint64_t total_remote_rx_received;
    volatile uint64_t total_remote_rx_consumed;
    volatile uint64_t total_remote_rx_received_error;
    volatile uint64_t total_flow_controlled_wr;
    uint64_t remote_win_buf_addr;
    uint32_t remote_win_buf_len;
    volatile uint16_t local_rx_posted;
    volatile uint16_t remote_rx_window;
    uint16_t initial_window;
    uint16_t notify_interval;
    uint16_t local_tx_depth;
    uint16_t local_rx_depth;
    uint16_t remote_tx_depth;
    uint16_t remote_rx_depth;
    bool local_set;
    bool remote_get;
    bool need_notify;
    bool enabled;
} ub_flow_control_t;

struct ub_bind_ctx;
typedef struct ub_queue {
    urpc_list_t qctx_node;
    // queue param
    urma_jetty_t *jetty;
    urma_jfc_t *jfs_jfc;
    urma_jfc_t *jfr_jfc;
    urma_jfr_t *jfr;
    urma_jfce_t *jfs_jfce;
    urma_jfce_t *jfr_jfce;
    umq_ub_ctx_t *dev_ctx;
    struct ub_bind_ctx *bind_ctx;
    volatile uint32_t ref_cnt;
    atomic_uint require_rx_count;
    volatile uint32_t tx_outstanding;
    urma_target_seg_t *imported_tseg_list[UMQ_MAX_TSEG_NUM];
    pthread_mutex_t imported_tseg_list_mutex;
    uint64_t addr_list[UMQ_MAX_ID_NUM];

    // config param
    umq_trans_mode_t umq_trans_mode;
    ub_flow_control_t flow_control;
    char name[UMQ_NAME_MAX_LEN];
    uint32_t rx_buf_size;
    uint32_t tx_buf_size;
    uint32_t rx_depth;
    uint32_t tx_depth;
    uint32_t remote_rx_buf_size;

    uint8_t priority;           // priority of the queue
    uint8_t max_rx_sge;         // max sge number of receive array
    uint8_t max_tx_sge;         // max sge number of send array
    uint8_t err_timeout;        // jetty timeout before report error
    uint8_t rnr_retry;          // number of times that jfs will resend packets before report error, when remote (RNR)
    uint8_t min_rnr_timer;      // minimum RNR NACK timer
    bool tx_flush_done;         // tx recv flush err done
    bool rx_flush_done;         // rx buf ctx all report
    umq_queue_mode_t mode;      // mode of queue, QUEUE_MODE_POLLING for default
    umq_state_t state;
    rx_buf_ctx_list_t rx_buf_ctx_list;
    umq_buf_t *notify_buf;      // qbuf for manage message exchange, such as mem import/initial flow control window
    uint64_t umqh;
} ub_queue_t;

typedef struct ub_queue_ctx_list {
    urpc_list_t queue_list;
    pthread_rwlock_t lock;
} ub_queue_ctx_list_t;

static ub_queue_ctx_list_t g_umq_ub_queue_ctx_list;

static inline uint64_t umq_ub_notify_buf_addr_get(ub_queue_t *queue, umq_ub_rw_segment_offset_t offset)
{
    return (uint64_t)((uintptr_t)queue->notify_buf->buf_data + offset * UMQ_UB_RW_SEGMENT_LEN);
}

static int rx_buf_ctx_list_init(ub_queue_t *queue)
{
    rx_buf_ctx_list_t *rx_buf_ctx_list = &queue->rx_buf_ctx_list;
    uint32_t num = queue->rx_depth;

    rx_buf_ctx_list->addr = calloc(num, sizeof(rx_buf_ctx_t));
    urpc_list_init(&rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_init(&rx_buf_ctx_list->used_rx_buf_ctx_list);

    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)rx_buf_ctx_list->addr;
    if (rx_buf_ctx == NULL) {
        UMQ_VLOG_ERR("rx buf ctx list calloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    for (uint32_t i = 0; i < num; i++) {
        urpc_list_push_back(&rx_buf_ctx_list->idle_rx_buf_ctx_list, &rx_buf_ctx->node);
        rx_buf_ctx = rx_buf_ctx + 1;
    }
    return UMQ_SUCCESS;
}

static inline void rx_buf_ctx_list_uninit(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    // empty the idle/used rx buf ctx list
    urpc_list_init(&rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_init(&rx_buf_ctx_list->used_rx_buf_ctx_list);
    // release the memory of rx buf ctx list
    free(rx_buf_ctx_list->addr);
    rx_buf_ctx_list->addr = NULL;
}

static inline rx_buf_ctx_t *queue_rx_buf_ctx_get(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    if (urpc_list_is_empty(&rx_buf_ctx_list->idle_rx_buf_ctx_list)) {
        UMQ_LIMIT_VLOG_ERR("rx buf ctx is used up\n");
        return NULL;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    URPC_LIST_FIRST_NODE(rx_buf_ctx, node, &rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_remove(&rx_buf_ctx->node);
    urpc_list_push_back(&rx_buf_ctx_list->used_rx_buf_ctx_list, &rx_buf_ctx->node);
    return rx_buf_ctx;
}

static inline void queue_rx_buf_ctx_put(rx_buf_ctx_list_t *rx_buf_ctx_list, rx_buf_ctx_t *rx_buf_ctx)
{
    if (rx_buf_ctx == NULL) {
        return;
    }
    urpc_list_remove(&rx_buf_ctx->node);
    urpc_list_push_back(&rx_buf_ctx_list->idle_rx_buf_ctx_list, &rx_buf_ctx->node);
}

static inline rx_buf_ctx_t *queue_rx_buf_ctx_flush(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    if (rx_buf_ctx_list == NULL) {
        return NULL;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    URPC_LIST_FIRST_NODE(rx_buf_ctx, node, &rx_buf_ctx_list->used_rx_buf_ctx_list);
    queue_rx_buf_ctx_put(rx_buf_ctx_list, rx_buf_ctx);
    return rx_buf_ctx;
}

typedef struct umq_ub_bind_info {
    bool is_binded;
    umq_trans_mode_t umq_trans_mode;
    urma_transport_mode_t trans_mode;
    urma_jetty_grp_policy_t policy;
    urma_jetty_id_t jetty_id;
    urma_target_type_t type;
    urma_order_type_t order_type;
    urma_token_t token;
    urma_target_seg_t tseg;
    umq_buf_mode_t buf_pool_mode;
    uint64_t notify_buf;
    uint64_t win_buf_addr;
    uint32_t win_buf_len;
    uint32_t rx_depth;
    uint32_t tx_depth;
    uint32_t rx_buf_size;
    uint32_t feature;
    umq_state_t state;
} umq_ub_bind_info_t;

typedef struct ub_bind_ctx {
    umq_ub_bind_info_t bind_info;
    urma_target_jetty_t *tjetty;
    uint32_t remote_eid_id;
    uint64_t remote_notify_addr;
} ub_bind_ctx_t;

static umq_ub_ctx_t *g_ub_ctx = NULL;
static uint32_t g_ub_ctx_count = 0;

static ALWAYS_INLINE uint16_t remote_rx_window_inc_non_atomic(struct ub_flow_control *fc, uint16_t new_win)
{
    uint32_t win_sum = fc->remote_rx_window + new_win;
    if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN("receive remote win exceed UINT16_MAX, current win %d, new win %d, remote rx depth %d\n",
                            fc->remote_rx_window, new_win, fc->remote_rx_depth);
        fc->total_remote_rx_received_error += new_win;
        return fc->remote_rx_window;
    }

    if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
        UMQ_LIMIT_VLOG_WARN("receive remote win exceed rx depth, current win %d, new win %d, remote rx depth %d\n",
                            fc->remote_rx_window, new_win, fc->remote_rx_depth);
    }

    fc->total_remote_rx_received += new_win;
    fc->remote_rx_window = (uint16_t)win_sum;
    return fc->remote_rx_window;
}

static ALWAYS_INLINE uint16_t remote_rx_window_exchange_non_atomic(struct ub_flow_control *fc)
{
    uint16_t win = fc->remote_rx_window;
    fc->total_remote_rx_consumed += win;
    fc->remote_rx_window = 0;
    return win;
}

static ALWAYS_INLINE uint16_t remote_rx_window_dec_non_atomic(struct ub_flow_control *fc, uint16_t required_win)
{
    if (URPC_LIKELY(fc->remote_rx_window >= required_win)) {
        fc->remote_rx_window -= required_win;
        fc->total_remote_rx_consumed += required_win;
        return required_win;
    } else {
        fc->total_flow_controlled_wr += (required_win - fc->remote_rx_window);
    }

    return remote_rx_window_exchange_non_atomic(fc);
}

static ALWAYS_INLINE uint16_t remote_rx_window_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->remote_rx_window;
}

static ALWAYS_INLINE uint16_t local_rx_posted_inc_non_atomic(struct ub_flow_control *fc, uint16_t rx_posted)
{
    uint32_t rx_sum = fc->local_rx_posted + rx_posted;
    if (URPC_UNLIKELY(rx_sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN("rx posted exceed UINT16_MAX, current rx %d, new post %d, local rx depth %d\n",
                            fc->local_rx_posted, rx_posted, fc->local_rx_depth);
        fc->total_local_rx_posted_error += rx_posted;
        return fc->local_rx_posted;
    }

    if (URPC_UNLIKELY(rx_sum > fc->local_rx_depth)) {
        UMQ_LIMIT_VLOG_WARN("rx posted exceed rx depth, current win %d, new win %d, local rx depth %d\n",
                            fc->local_rx_posted, rx_posted, fc->local_rx_depth);
    }

    fc->total_local_rx_posted += rx_posted;
    fc->local_rx_posted = (uint16_t)rx_sum;
    return fc->local_rx_posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_exchange_non_atomic(struct ub_flow_control *fc)
{
    uint16_t posted = fc->local_rx_posted;
    fc->total_local_rx_notified += posted;
    fc->local_rx_posted = 0;
    return posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->local_rx_posted;
}

static ALWAYS_INLINE void flow_control_stats_query_non_atomic(struct ub_flow_control *fc, umq_flowcontrol_stats_t *out)
{
    out->local_rx_posted = fc->local_rx_posted;
    out->remote_rx_window = fc->remote_rx_window;
    out->total_local_rx_posted = fc->total_local_rx_posted;
    out->total_local_rx_notified = fc->total_local_rx_notified;
    out->total_local_rx_posted_error = fc->total_local_rx_posted_error;
    out->total_remote_rx_received = fc->total_remote_rx_received;
    out->total_remote_rx_consumed = fc->total_remote_rx_consumed;
    out->total_remote_rx_received_error = fc->total_remote_rx_received_error;
    out->total_flow_controlled_wr = fc->total_flow_controlled_wr;
}

static ALWAYS_INLINE uint16_t remote_rx_window_inc_atomic(struct ub_flow_control *fc, uint16_t new_win)
{
    uint16_t after, before = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t win_sum;
    do {
        win_sum = before + new_win;
        if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN(
                "receive remote win exceed UINT16_MAX, current win %d, new win %d, remote rx depth %d\n",
                fc->remote_rx_window, new_win, fc->remote_rx_depth);
            ret = before;
            break;
        }

        if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
            UMQ_LIMIT_VLOG_WARN(
                "receive remote win exceed rx depth, current win %d, new win %d, remote rx depth %d\n",
                fc->remote_rx_window, new_win, fc->remote_rx_depth);
        }

        after = (uint16_t)win_sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&fc->remote_rx_window, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received_error, new_win, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received, new_win, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t remote_rx_window_exchange_atomic(struct ub_flow_control *fc)
{
    return __atomic_exchange_n(&fc->remote_rx_window, 0, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t remote_rx_window_dec_atomic(struct ub_flow_control *fc, uint16_t required_win)
{
    uint16_t after, before = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    uint16_t ret = before;
    do {
        if (URPC_UNLIKELY(before == 0)) {
            ret = 0;
            break;
        }

        after = before > required_win ? before - required_win : 0;
        ret = before - after;
    } while (
        !__atomic_compare_exchange_n(&fc->remote_rx_window, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret < required_win)) {
        (void)__atomic_add_fetch(&fc->total_flow_controlled_wr, (required_win - ret), __ATOMIC_RELAXED);
    }

    if (URPC_LIKELY(ret > 0)) {
        (void)__atomic_add_fetch(&fc->total_remote_rx_consumed, ret, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t remote_rx_window_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t local_rx_posted_inc_atomic(struct ub_flow_control *fc, uint16_t rx_posted)
{
    uint16_t after, before = __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t rx_sum;
    do {
        rx_sum = before + rx_posted;
        if (URPC_UNLIKELY(rx_sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN("rx posted exceed UINT16_MAX, current rx %d, new post %d, local rx depth %d\n",
                                before, rx_posted, fc->local_rx_depth);
            ret = before;
            break;
        }

        if (URPC_UNLIKELY(rx_sum > fc->local_rx_depth)) {
            UMQ_LIMIT_VLOG_WARN("rx posted exceed rx depth, current win %d, new win %d, local rx depth %d\n",
                                before, rx_posted, fc->local_rx_depth);
        }
        after = (uint16_t)rx_sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&fc->local_rx_posted, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&fc->total_local_rx_posted_error, rx_posted, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&fc->total_local_rx_posted, rx_posted, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t local_rx_posted_exchange_atomic(struct ub_flow_control *fc)
{
    uint16_t posted = __atomic_exchange_n(&fc->local_rx_posted, 0, __ATOMIC_RELAXED);
    if (URPC_LIKELY(posted > 0)) {
        (void)__atomic_add_fetch(&fc->total_local_rx_notified, posted, __ATOMIC_RELAXED);
    }
    return posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE void flow_control_stats_query_atomic(struct ub_flow_control *fc, umq_flowcontrol_stats_t *out)
{
    out->local_rx_posted = __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
    out->remote_rx_window = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    out->total_local_rx_posted = __atomic_load_n(&fc->total_local_rx_posted, __ATOMIC_RELAXED);
    out->total_local_rx_notified = __atomic_load_n(&fc->total_local_rx_notified, __ATOMIC_RELAXED);
    out->total_local_rx_posted_error = __atomic_load_n(&fc->total_local_rx_posted_error, __ATOMIC_RELAXED);
    out->total_remote_rx_received = __atomic_load_n(&fc->total_remote_rx_received, __ATOMIC_RELAXED);
    out->total_remote_rx_consumed = __atomic_load_n(&fc->total_remote_rx_consumed, __ATOMIC_RELAXED);
    out->total_remote_rx_received_error = __atomic_load_n(&fc->total_remote_rx_received_error, __ATOMIC_RELAXED);
    out->total_flow_controlled_wr = __atomic_load_n(&fc->total_flow_controlled_wr, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint64_t umq_ub_user_imm_bit_fields(ub_flow_control_t *fc)
{
    return fc->enabled ? UMQ_UB_IMM_WITHOUT_PRIVATE_BITS : UMQ_UB_IMM_BITS;
}

static int umq_ub_flow_control_init(
    ub_flow_control_t *fc, ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg)
{
    memset(fc, 0, sizeof(ub_flow_control_t));
    fc->enabled = (feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0;
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }

    fc->local_rx_depth = queue->rx_depth;
    fc->local_tx_depth = queue->tx_depth;
    fc->initial_window = cfg->initial_window;
    fc->notify_interval = cfg->notify_interval;
    if (cfg->initial_window == 0 || cfg->initial_window > queue->rx_depth) {
        fc->initial_window = fc->local_rx_depth >> 1;
    }
    if (fc->initial_window == 0) {
        fc->initial_window = 1;
    }
    if (cfg->notify_interval == 0 || cfg->notify_interval > queue->rx_depth) {
        fc->notify_interval = fc->local_rx_depth >> UMQ_UB_FLOW_CONTROL_NOTIFY_THR;
    }
    if (fc->notify_interval == 0) {
        fc->notify_interval = 1;
    }

    if (cfg->use_atomic_window) {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_atomic;
        fc->ops.remote_rx_window_exchange = remote_rx_window_exchange_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_atomic;

        fc->ops.local_rx_posted_inc = local_rx_posted_inc_atomic;
        fc->ops.local_rx_posted_load = local_rx_posted_load_atomic;
        fc->ops.local_rx_posted_exchange = local_rx_posted_exchange_atomic;

        fc->ops.stats_query = flow_control_stats_query_atomic;
    } else {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_non_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_non_atomic;
        fc->ops.remote_rx_window_exchange = remote_rx_window_exchange_non_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_non_atomic;

        fc->ops.local_rx_posted_inc = local_rx_posted_inc_non_atomic;
        fc->ops.local_rx_posted_load = local_rx_posted_load_non_atomic;
        fc->ops.local_rx_posted_exchange = local_rx_posted_exchange_non_atomic;

        fc->ops.stats_query = flow_control_stats_query_non_atomic;
    }

    UMQ_VLOG_INFO("umq flow control init success, use %s window\n", cfg->use_atomic_window ? "atomic" : "non-atomic");

    return UMQ_SUCCESS;
}

static void umq_ub_flow_control_uninit(ub_flow_control_t *fc)
{
    if (!fc->enabled) {
        return;
    }

    UMQ_VLOG_INFO("umq flow control uninit success\n");
}

static int umq_ub_window_init(ub_flow_control_t *fc, umq_ub_bind_info_t *info)
{
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }

    if (info->win_buf_addr == 0 || info->win_buf_len < sizeof(uint16_t)) {
        UMQ_VLOG_ERR("umq window init failed, remote flow control qbuf is empty\n");
        return UMQ_FAIL;
    }

    fc->remote_win_buf_addr = info->win_buf_addr;
    fc->remote_win_buf_len = info->win_buf_len;
    fc->remote_rx_depth = info->rx_depth;
    fc->remote_tx_depth = info->tx_depth;
    fc->remote_rx_window = 0; // remote window need to be updated after remote rx_posted

    return UMQ_SUCCESS;
}

static inline void umq_ub_window_inc(ub_flow_control_t *fc, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.remote_rx_window_inc(fc, win);
}

static void umq_ub_window_read(ub_flow_control_t *fc, ub_queue_t *queue)
{
    if (!fc->enabled || queue->bind_ctx == NULL) {
        return;
    }
    // post read remote window
    urma_jfs_wr_t *bad_wr = NULL;
    urma_sge_t src_sge = {
        .addr = fc->remote_win_buf_addr, .len = sizeof(uint16_t), .tseg = queue->imported_tseg_list[0]};
    urma_sge_t dst_sge = {.addr = umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL) + sizeof(uint16_t),
                          .len = sizeof(uint16_t),
                          .tseg = queue->dev_ctx->tseg_list[0]};
    urma_jfs_wr_t urma_wr = {.rw = {.src = {.sge = &src_sge, .num_sge = 1}, .dst = {.sge = &dst_sge, .num_sge = 1}},
        .user_ctx = 0,
        .opcode = URMA_OPC_READ,
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 0}},
        .tjetty = queue->bind_ctx->tjetty};
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        fc->remote_get = true;
        return;
    }

    UMQ_LIMIT_VLOG_ERR("umq ub flow control get remote window failed, error %d\n", (int)status);
}

static inline uint16_t umq_ub_window_dec(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return win;
    }

    if (!fc->remote_get) {
        umq_ub_window_read(fc, queue);
        return 0;
    }

    return fc->ops.remote_rx_window_dec(fc, win);
}

static inline void umq_ub_rq_posted_notifier_inc(ub_flow_control_t *fc, uint16_t rx_posted)
{
    if (rx_posted == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.local_rx_posted_inc(fc, rx_posted);
}

static void umq_ub_rq_posted_notifier_update(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t rx_posted)
{
    fc->need_notify = false;
    if (rx_posted == 0 || !fc->enabled) {
        return;
    }

    uint16_t notify = fc->ops.local_rx_posted_inc(fc, rx_posted);
    if (notify < fc->notify_interval || queue->bind_ctx == NULL) {
        return;
    }

    if (!fc->local_set && notify >= fc->initial_window) {
        notify = fc->ops.local_rx_posted_exchange(fc);
        if (notify == 0) {
            return;
        }

        uint16_t *remote_data = (uint16_t *)(uintptr_t)umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL);
        *remote_data = notify;
        fc->local_set = true;

        if (!fc->remote_get) {
            umq_ub_window_read(fc, queue);
        }

        return;
    }

    if (umq_ub_window_dec(fc, queue, 1) != 1) {
        fc->need_notify = true;
        return;
    }

    notify = fc->ops.local_rx_posted_exchange(fc);
    if (notify == 0) {
        umq_ub_window_inc(fc, 1);
        return;
    }

    umq_ub_imm_t imm = {
        .flow_control = {
            .umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_FLOW_CONTROL, .in_user_buf = 0, .window = notify}};
    // user_ctx used as notify for recovery on tx error
    urma_jfs_wr_t urma_wr = {.user_ctx = notify,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = queue->bind_ctx->tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        return;
    }

    UMQ_LIMIT_VLOG_ERR("flow control window send failed, errno %d\n", (int)status);
    fc->need_notify = true;
    umq_ub_window_inc(fc, 1);
    umq_ub_rq_posted_notifier_inc(fc, notify);
}

static inline uint32_t token_policy_get(bool enable)
{
    return enable ? URMA_TOKEN_PLAIN_TEXT : URMA_TOKEN_NONE;
}

static inline int umq_ub_token_generate(bool enable_token, uint32_t *token)
{
    if (!enable_token) {
        *token = get_timestamp();
        return 0;
    }

    return urpc_rand_generate((uint8_t *)token, sizeof(uint32_t));
}

static int umq_ub_register_seg(umq_ub_ctx_t *ctx, uint8_t mempool_id, void *addr, uint64_t size)
{
    bool enable_token = (ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t mem_token;
    int ret = umq_ub_token_generate(enable_token, &mem_token);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("generate memory token failed\n");
        return ret;
    }

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = token_policy_get(enable_token),
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };
    urma_token_t token = { .token = mem_token };
    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)(uintptr_t)addr,
        .len = size,
        .token_id = NULL,
        .token_value = token,
        .flag = flag,
        .user_ctx = token.token,
        .iova = 0
    };

    ctx->tseg_list[mempool_id] = urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (ctx->tseg_list[mempool_id] == NULL) {
        UMQ_VLOG_ERR("fail to register segment\n");
        return -UMQ_ERR_ENODEV;
    }

    return UMQ_SUCCESS;
}

static inline void umq_ub_unregister_seg(umq_ub_ctx_t *ctx_list, uint32_t ctx_cnt, uint8_t mempool_id)
{
    for (uint32_t i = 0; i < ctx_cnt; i++) {
        if (ctx_list[i].tseg_list[mempool_id] != NULL &&
            urma_unregister_seg(ctx_list[i].tseg_list[mempool_id]) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("ub ctx[%u] unregister segment failed\n", i);
        }
        ctx_list[i].tseg_list[mempool_id] = NULL;
    }
}

static int huge_qbuf_pool_memory_init(uint8_t mempool_id, enum HUGE_QBUF_POOL_SIZE_TYPE type, void **buffer_addr)
{
    uint32_t align_size = umq_huge_qbuf_get_size_for_type(type);
    uint32_t total_len = align_size * HUGE_QBUF_BUFFER_INC_BATCH;
    void *addr = (void *)memalign(align_size, total_len);
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
    huge_qbuf_pool_cfg_t small_cfg = {
        .total_size = umq_buf_size_middle() * HUGE_QBUF_BUFFER_INC_BATCH,
        .data_size = umq_buf_size_middle(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
        .type = HUGE_QBUF_POOL_SIZE_TYPE_MID,
        .memory_init_callback = huge_qbuf_pool_memory_init,
        .memory_uninit_callback = huge_qbuf_pool_memory_uninit,
    };
    int ret = umq_huge_qbuf_config_init(&small_cfg);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("initialize configuration for huge qbuf pool(small) failed\n");
        return ret;
    }

    huge_qbuf_pool_cfg_t big_cfg = {
        .total_size = umq_buf_size_big() * HUGE_QBUF_BUFFER_INC_BATCH,
        .data_size = umq_buf_size_big(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
        .type = HUGE_QBUF_POOL_SIZE_TYPE_BIG,
        .memory_init_callback = huge_qbuf_pool_memory_init,
        .memory_uninit_callback = huge_qbuf_pool_memory_uninit,
    };
    ret = umq_huge_qbuf_config_init(&big_cfg);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("initialize configuration for huge qbuf pool(big) failed\n");
        return ret;
    }

    huge_qbuf_pool_cfg_t huge_cfg = {
        .total_size = umq_buf_size_huge() * HUGE_QBUF_BUFFER_INC_BATCH,
        .data_size = umq_buf_size_huge(),
        .headroom_size = cfg->headroom_size,
        .mode = cfg->buf_mode,
        .type = HUGE_QBUF_POOL_SIZE_TYPE_HUGE,
        .memory_init_callback = huge_qbuf_pool_memory_init,
        .memory_uninit_callback = huge_qbuf_pool_memory_uninit,
    };
    ret = umq_huge_qbuf_config_init(&huge_cfg);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("initialize configuration for huge qbuf pool(big) failed\n");
        return ret;
    }
    return UMQ_SUCCESS;
}

void umq_ub_huge_qbuf_pool_uninit(void)
{
    umq_huge_qbuf_pool_uninit();
}

static ALWAYS_INLINE urma_opcode_t transform_op_code(umq_opcode_t opcode)
{
    static const urma_opcode_t opcode_map[UMQ_OPC_LAST] = {
        [UMQ_OPC_WRITE]     = URMA_OPC_WRITE,
        [UMQ_OPC_WRITE_IMM] = URMA_OPC_WRITE_IMM,
        [UMQ_OPC_READ]      = URMA_OPC_READ,
        [UMQ_OPC_SEND]      = URMA_OPC_SEND,
        [UMQ_OPC_SEND_IMM]  = URMA_OPC_SEND_IMM,
    };

    uint32_t opcode_index = (uint32_t)opcode;
    if (opcode_index < UMQ_OPC_LAST) {
        urma_opcode_t code = opcode_map[opcode_index];
        if (code == 0 && (opcode_index != UMQ_OPC_WRITE)) {
            return URMA_OPC_SEND;
        }
        return code;
    }
    return URMA_OPC_SEND;
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
    (void)memcpy(&info->tseg, queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID], sizeof(urma_target_seg_t));
    info->buf_pool_mode = umq_qbuf_mode_get();
    return sizeof(umq_ub_bind_info_t);
}

static ALWAYS_INLINE void process_bad_wr(ub_queue_t *queue, urma_jfr_wr_t *bad_wr, umq_buf_t *end_buf)
{
    umq_buf_t *last_fail_end = NULL;
    urma_jfr_wr_t *wr = bad_wr;
    while (wr) { // tranverse bad wr, add qbuf chain back
        rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)wr->user_ctx;
        umq_buf_t *fail = rx_buf_ctx->buffer;

        // if last fail end is not null, set its qbuf next to current qbuf
        if (last_fail_end != NULL) {
            last_fail_end->qbuf_next = fail;
        }

        // find last qbuf of current wr, and record it in last_fail_end
        while (fail->qbuf_next) {
            fail = fail->qbuf_next;
        }

        queue_rx_buf_ctx_put(&queue->rx_buf_ctx_list, rx_buf_ctx);
        last_fail_end = fail;
        wr = wr->next;
    }

    if (last_fail_end != NULL) {
        last_fail_end->qbuf_next = end_buf;
    }
}

static uint16_t umq_ub_post_rx_failed_num(urma_jfr_wr_t *recv_wr, uint16_t num, umq_buf_t *bad)
{
    for (uint16_t i = 0; i < num; i++) {
        if (recv_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            return num - i;
        }
    }

    return 0;
}

static int umq_ub_post_rx_inner_impl(ub_queue_t *queue, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    uint32_t max_sge_num = queue->max_rx_sge;
    urma_jfr_wr_t recv_wr[UMQ_POST_POLL_BATCH] = {0};
    urma_jfr_wr_t *recv_wr_ptr = recv_wr;

    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_sge_t *sges_ptr;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    urma_jfr_wr_t *bad_wr = NULL;
    umq_buf_t *buffer = qbuf;
    uint16_t wr_index = 0;
    *bad_qbuf = NULL;
    rx_buf_ctx_t *rx_buf_ctx = NULL;
    umq_buf_t *wr_last_buf = NULL;  // record last qbuf of current wr
    while (buffer) {
        uint32_t rest_size = buffer->total_data_size;
        uint32_t sge_num = 0;

        rx_buf_ctx = queue_rx_buf_ctx_get(&queue->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            goto PUT_ALL_RX_CTX;
        }
        rx_buf_ctx->buffer = buffer;
        uint64_t user_ctx = (uint64_t)(uintptr_t)rx_buf_ctx;
        sges_ptr = sges[wr_index];
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                goto PUT_CUR_RX_CTX;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together rx buffer, rest size is negative\n");
                goto PUT_CUR_RX_CTX;
            } else if (rest_size == buffer->data_size) {
                wr_last_buf = buffer;
            }
            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough rx buffer\n");
            goto PUT_CUR_RX_CTX;
        }

        wr_last_buf->qbuf_next = NULL;  // last buffer of current wr
        recv_wr_ptr->src.sge = sges[wr_index];
        recv_wr_ptr->src.num_sge = sge_num;
        recv_wr_ptr->user_ctx = user_ctx;
        recv_wr_ptr++;
        (recv_wr_ptr - 1)->next = recv_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR("wr count exceeds %d, not supported\n", UMQ_BATCH_SIZE);
            goto PUT_ALL_RX_CTX;
        }
    }
    (recv_wr_ptr - 1)->next = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    if (urma_post_jetty_recv_wr(queue->jetty, recv_wr, &bad_wr) < 0) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_recv_wr failed\n");
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        umq_ub_rq_posted_notifier_update(&queue->flow_control, queue,
                                         umq_ub_post_rx_failed_num(recv_wr, wr_index, *bad_qbuf));
        // if fails, add chain of qbuf back for rx
        process_bad_wr(queue, bad_wr, NULL);
        return -UMQ_ERR_EAGAIN;
    }
    umq_ub_rq_posted_notifier_update(&queue->flow_control, queue, wr_index);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp, queue->dev_ctx->feature);
    return UMQ_SUCCESS;

PUT_CUR_RX_CTX:
    buffer = rx_buf_ctx->buffer;
    // put rx buf ctx that was not added to recv wr
    queue_rx_buf_ctx_put(&queue->rx_buf_ctx_list, rx_buf_ctx);

PUT_ALL_RX_CTX:
    // put rx buf in recv wr
    if (wr_index > 0) {
        (recv_wr_ptr - 1)->next = NULL;
        *bad_qbuf = ((rx_buf_ctx_t *)(uintptr_t)recv_wr->user_ctx)->buffer;
        process_bad_wr(queue, recv_wr, buffer);
    } else {
        *bad_qbuf = qbuf;
    }
    return UMQ_FAIL;
}

static int umq_ub_post_rx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    int ret = umq_ub_post_rx_inner_impl(queue, qbuf, bad_qbuf);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

typedef struct xchg_mem_info {
    uint64_t seg_len;
    uint32_t seg_token_id;
    urma_import_seg_flag_t seg_flag;
    urma_token_t token;
    urma_ubva_t ubva;
} __attribute__((packed)) xchg_mem_info_t;

static urma_target_seg_t *import_mem(urma_context_t *urma_ctx, xchg_mem_info_t *xchg_mem)
{
    if (xchg_mem == NULL) {
        UMQ_VLOG_ERR("xchg_mem invalid\n");
        return NULL;
    }

    urma_seg_t remote_seg = {
        .attr.value = xchg_mem->seg_flag.value,
        .len = xchg_mem->seg_len,
        .token_id = xchg_mem->seg_token_id
    };
    urma_token_t token = xchg_mem->token;
    (void)memcpy(&remote_seg.ubva, &xchg_mem->ubva, sizeof(urma_ubva_t));
    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };

    urma_target_seg_t *import_tseg = urma_import_seg(urma_ctx, &remote_seg, &token, 0, flag);
    if (import_tseg == NULL) {
        UMQ_VLOG_ERR("urma import segment failed\n");
        return NULL;
    }
    return import_tseg;
}

static inline uint32_t umq_ub_bind_fature_allowlist_get(void)
{
    return UMQ_FEATURE_ENABLE_STATS | UMQ_FEATURE_ENABLE_PERF;
}

static inline bool umq_ub_bind_feature_check(uint32_t local_feature, uint32_t remote_feature)
{
    return ((local_feature ^ remote_feature) & (~umq_ub_bind_fature_allowlist_get())) == 0;
}

static int umq_ub_bind_info_check(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    if (info->umq_trans_mode != UMQ_TRANS_MODE_UB && info->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        info->umq_trans_mode != UMQ_TRANS_MODE_UBMM && info->umq_trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_ERR("trans mode %d is not UB\n", info->umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->state > QUEUE_STATE_READY || info->state > QUEUE_STATE_READY) {
        UMQ_VLOG_ERR("queue state is not ready, local is %u, remote is %u\n", queue->state, info->state);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->dev_ctx->trans_info.trans_mode != info->umq_trans_mode) {
        UMQ_VLOG_ERR("trans mode misatch, local is %u but remote %u\n",
            queue->dev_ctx->trans_info.trans_mode, info->umq_trans_mode)
        return -UMQ_ERR_EINVAL;
    }

    if (!umq_ub_bind_feature_check(queue->dev_ctx->feature, info->feature)) {
        UMQ_VLOG_ERR("feature misatch, local is %u but remote %u\n", queue->dev_ctx->feature, info->feature);
        return -UMQ_ERR_EINVAL;
    }

    if (info->buf_pool_mode != umq_qbuf_mode_get()) {
        UMQ_VLOG_ERR("buf pool mode negotiation inconsistency, recv mode: %d\n", info->buf_pool_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->bind_ctx != NULL || info->is_binded) {
        UMQ_VLOG_ERR("umq has already been binded\n");
        return -UMQ_ERR_EEXIST;
    }

    if (memcmp(&queue->jetty->jetty_id.eid, &info->jetty_id.eid, sizeof(urma_eid_t)) == 0 &&
        queue->jetty->jetty_id.id == info->jetty_id.id) {
        UMQ_VLOG_ERR("the queue cannot bind itself\n");
        return -UMQ_ERR_EINVAL;
    }
    return UMQ_SUCCESS;
}

static int umq_ub_prefill_rx_buf(ub_queue_t *queue)
{
    uint32_t require_rx_count = queue->rx_depth;
    uint32_t cur_batch_count = 0;
    int ret = UMQ_SUCCESS;

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    do {
        cur_batch_count = require_rx_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : require_rx_count;
        umq_buf_t *qbuf = umq_buf_alloc(queue->rx_buf_size, cur_batch_count, 0, NULL);
        if (qbuf == NULL) {
            UMQ_VLOG_ERR("alloc rx failed\n");
            ret = UMQ_ERR_ENOMEM;
            goto DEC_REF;
        }

        umq_buf_t *bad_buf = NULL;
        if (umq_ub_post_rx_inner_impl(queue, qbuf, &bad_buf) != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("post rx failed\n");
            umq_buf_free(bad_buf);
            ret = UMQ_FAIL;
            goto DEC_REF;
        }
        require_rx_count -= cur_batch_count;
    } while (require_rx_count > 0);

DEC_REF:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

static int umq_ub_eid_id_get(
    remote_imported_tseg_info_t *remote_imported_info, umq_ub_bind_info_t *info, uint32_t *remote_eid_id)
{
    urma_eid_t *remote_eid = &info->jetty_id.eid;
    uint32_t hash = urpc_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    pthread_mutex_lock(&remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if (memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0) {
            find = true;
            break;
        }
    }

    if (find) {
        *remote_eid_id = eid_node->remote_eid_id;
        eid_node->ref_cnt++;
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        return UMQ_SUCCESS;
    }

    eid_node = (remote_eid_hmap_node_t *)malloc(sizeof(remote_eid_hmap_node_t));
    if (eid_node == NULL) {
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("malloc eid node failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    uint32_t eid_id = util_id_allocator_get(&remote_imported_info->eid_id_allocator);
    if (eid_id >= UMQ_UB_MAX_REMOTE_EID_NUM) {
        free(eid_node);
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("remote eid cnt exceed maxinum limit\n");
        return -UMQ_ERR_ENODEV;
    }

    eid_node->remote_eid_id = eid_id;
    eid_node->ref_cnt = 1;
    *remote_eid_id = eid_id;
    (void)memset(remote_imported_info->tesg_imported[eid_id], 0, sizeof(bool) * UMQ_MAX_TSEG_NUM);
    remote_imported_info->tesg_imported[eid_id][UMQ_QBUF_DEFAULT_MEMPOOL_ID] = true;
    (void)memcpy(&eid_node->eid, remote_eid, sizeof(urma_eid_t));
    urpc_hmap_insert(&remote_imported_info->remote_eid_id_table, &eid_node->node, hash);
    pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;
}

static int umq_ub_eid_id_release(remote_imported_tseg_info_t *remote_imported_info, ub_bind_ctx_t *ctx)
{
    if (remote_imported_info == NULL || ctx == NULL || ctx->tjetty == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_eid_t *remote_eid = &ctx->tjetty->id.eid;
    uint32_t hash = urpc_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    pthread_mutex_lock(&remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if (memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0 &&
            eid_node->remote_eid_id == ctx->remote_eid_id) {
            find = true;
            break;
        }
    }

    if (!find) {
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("not find eid node %u\n", ctx->remote_eid_id);
        return -UMQ_ERR_ENODEV;
    }

    eid_node->ref_cnt--;
    if (eid_node->ref_cnt == 0) {
        util_id_allocator_release(&remote_imported_info->eid_id_allocator, eid_node->remote_eid_id);
        urpc_hmap_remove(&remote_imported_info->remote_eid_id_table, &eid_node->node);
        free(eid_node);
    }
    pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;
}

static int umq_ub_bind_inner_impl(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    urma_target_seg_t *tseg = &info->tseg;
    urma_seg_t *seg = &tseg->seg;
    xchg_mem_info_t mem_info = {
        .seg_len = seg->len,
        .seg_token_id = seg->token_id,
        .seg_flag = (urma_import_seg_flag_t)seg->attr.value,
        .token.token = (uint32_t)tseg->user_ctx
    };

    (void)memcpy(&mem_info.ubva, &seg->ubva, sizeof(urma_ubva_t));
    queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID] = import_mem(queue->dev_ctx->urma_ctx, &mem_info);
    if (queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID] == NULL) {
        return -UMQ_ERR_ENODEV;
    }

    ub_bind_ctx_t *ctx = (ub_bind_ctx_t *)calloc(1, sizeof(ub_bind_ctx_t));
    if (ctx == NULL) {
        UMQ_VLOG_ERR("bind ctx calloc failed\n");
        goto UNIMPORT_SEG;
    }

    ctx->remote_notify_addr = info->notify_buf;

    urma_rjetty_t rjetty = {
        .jetty_id = info->jetty_id,
        .trans_mode = info->trans_mode,
        .type = info->type,
        .flag.bs.token_policy = token_policy_get((queue->dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0),
        .flag.bs.order_type = info->order_type,
        .flag.bs.share_tp = 1
    };
    urma_target_jetty_t *tjetty = urma_import_jetty(queue->dev_ctx->urma_ctx, &rjetty, &info->token);
    if (tjetty == NULL) {
        UMQ_VLOG_ERR("import jetty failed\n");
        goto FREE_CTX;
    }

    urma_status_t status = urma_bind_jetty(queue->jetty, tjetty);
    if (status != URMA_SUCCESS && status != URMA_EEXIST) {
        UMQ_VLOG_ERR("bind jetty failed, status:%d\n", (int)status);
        goto UNIMPORT_JETTY;
    }
    // if mode is UB, post rx here. if mode is UB PRO, no need to post rx
    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        int ret = umq_ub_prefill_rx_buf(queue);
        if (ret != UMQ_SUCCESS) {
            goto UNIMPORT_JETTY;
        }
    }

    ctx->tjetty = tjetty;
    queue->bind_ctx = ctx;

    if (umq_ub_eid_id_get(queue->dev_ctx->remote_imported_info, info, &ctx->remote_eid_id) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("get eid id failed\n");
        goto UNBIND_JETTY;
    }

    uint32_t max_msg_size = queue->dev_ctx->dev_attr.dev_cap.max_msg_size;
    queue->remote_rx_buf_size = (max_msg_size > info->rx_buf_size) ? info->rx_buf_size : max_msg_size;
    return UMQ_SUCCESS;

UNBIND_JETTY:
    queue->bind_ctx = NULL;
    urma_unbind_jetty(queue->jetty);

UNIMPORT_JETTY:
    urma_unimport_jetty(tjetty);

FREE_CTX:
    free(ctx);

UNIMPORT_SEG:
    (void)urma_unimport_seg(queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID]);
    queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID] = NULL;
    return UMQ_FAIL;
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

int umq_modify_ubq_to_err(ub_queue_t *queue)
{
    urma_jetty_attr_t jetty_attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_ERROR,
    };
    urma_status_t urma_status = urma_modify_jetty(queue->jetty, &jetty_attr);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR("modify jetty to URMA_JETTY_STATE_ERROR fail, status %u\n", urma_status);
    }

    urma_jfr_attr_t jfr_attr = {
        .mask = JETTY_STATE,
        .state = URMA_JFR_STATE_ERROR,
    };
    urma_status = urma_modify_jfr(queue->jfr, &jfr_attr);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR("modify jfr to URMA_JFR_STATE_ERROR fail, status %u\n", urma_status);
    }

    queue->state = QUEUE_STATE_ERR;
    return urma_status;
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
        enum HUGE_QBUF_POOL_SIZE_TYPE type = umq_huge_qbuf_get_type_for_size(buf_size);
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

static uint32_t get_dev_by_eid_str(urma_transport_type_t type, urma_eid_t *eid, urma_device_t **urma_dev,
                                   uint32_t *eid_index)
{
    if (eid == NULL) {
        UMQ_VLOG_ERR("eid is null\n");
        return 0;
    }

    int device_num = 0;
    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        UMQ_VLOG_ERR("urma get device list failed\n");
        return 0;
    }

    uint32_t j, cnt = 0;
    int i;
    for (i = 0; i < device_num; i++) {
        if (device_list[i]->type != type) {
            continue;
        }
        urma_eid_info_t *eid_list = urma_get_eid_list(device_list[i], &cnt);
        if (eid_list == NULL || cnt == 0) {
            continue;
        }
        for (j = 0; j < cnt; j++) {
            if ((memcmp(eid, &eid_list[j].eid, sizeof(urma_eid_t)) == 0)) {
                *urma_dev = device_list[i];
                *eid_index = eid_list[j].eid_index;
                break;
            }
        }
        urma_free_eid_list(eid_list);
        if (j != cnt) {
            break;
        }
    }

    urma_free_device_list(device_list);

    if (i == device_num) {
        UMQ_VLOG_ERR("get device failed, EID " EID_FMT "\n", EID_ARGS(*eid));
        return 0;
    }
    UMQ_VLOG_INFO("success to find ub device by eid: " EID_FMT "\n",  EID_ARGS(*eid));
    return 1;
}

static uint32_t umq_find_ub_dev_by_eid(urma_transport_type_t type, umq_dev_assign_t *dev_info, urma_device_t **urma_dev,
                                       uint32_t *eid_index)
{
    urma_eid_t *eid = (urma_eid_t *)&dev_info->eid.eid;
    return get_dev_by_eid_str(type, eid, urma_dev, eid_index);
}

static uint32_t umq_find_ub_dev_by_ip_addr(urma_transport_type_t type, umq_dev_assign_t *dev_info,
                                           urma_device_t **urma_dev, uint32_t *eid_index)
{
    const char *ip_addr = dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ? dev_info->ipv4.ip_addr
                                                                                 : dev_info->ipv6.ip_addr;
    urma_eid_t eid;
    int ret = urma_str_to_eid(ip_addr, &eid);
    if (ret != 0) {
        UMQ_VLOG_ERR("format ip addr to eid failed\n");
        return 0;
    }
    return get_dev_by_eid_str(type, &eid, urma_dev, eid_index);
}

static uint32_t umq_find_ub_dev_by_name(char *dev_name, urma_device_t **urma_dev)
{
    *urma_dev = urma_get_device_by_name(dev_name);
    if (*urma_dev == NULL) {
        UMQ_VLOG_ERR("urma get device by name failed\n");
        return 0;
    }

    return 1;
}

static uint32_t umq_ub_get_urma_dev(umq_dev_assign_t *dev_info, urma_device_t **urma_dev, uint32_t *eid_index)
{
    uint32_t eid_cnt = 0;
    if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_DEV) {
        eid_cnt = umq_find_ub_dev_by_name(dev_info->dev.dev_name, urma_dev);
        *eid_index = dev_info->dev.eid_idx;
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_EID) {
        eid_cnt = umq_find_ub_dev_by_eid(URMA_TRANSPORT_UB, dev_info, urma_dev, eid_index);
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ||
               dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV6) {
        eid_cnt = umq_find_ub_dev_by_ip_addr(URMA_TRANSPORT_UB, dev_info, urma_dev, eid_index);
    } else {
        UMQ_VLOG_ERR("assign mode: %d not supported\n", dev_info->assign_mode);
    }
    return eid_cnt;
}

static int umq_ub_create_urma_ctx(urma_device_t *urma_dev, uint32_t eid_index, umq_ub_ctx_t *ub_ctx)
{
    urma_device_attr_t dev_attr;
    if (urma_query_device(urma_dev, &dev_attr) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("query device failed, device name: %s\n", *urma_dev->name);
        return -UMQ_ERR_ENODEV;
    }
    ub_ctx->dev_attr = dev_attr;

    ub_ctx->urma_ctx = urma_create_context(urma_dev, eid_index);
    if (ub_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR("failed to create urma context\n");
        return -UMQ_ERR_ENODEV;
    }
    return UMQ_SUCCESS;
}

static int umq_ub_delete_urma_ctx(umq_ub_ctx_t *ub_ctx)
{
    if (ub_ctx == NULL || ub_ctx->urma_ctx) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    urma_status_t urma_status = urma_delete_context(ub_ctx->urma_ctx);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete context failed\n");
        return -UMQ_ERR_ENODEV;
    }

    ub_ctx->urma_ctx = NULL;
    return UMQ_SUCCESS;
}

static int umq_ub_get_eid_dev_info(urma_device_t *urma_dev, uint32_t eid_idx, umq_dev_assign_t *out_info)
{
    uint32_t eid_cnt = 0;
    urma_eid_info_t *eid_info_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_info_list == NULL || eid_cnt == 0) {
        UMQ_VLOG_ERR("get eid list fialed\n");
        return -UMQ_ERR_ENODEV;
    }

    for (uint32_t i = 0; i < eid_cnt; i++) {
        if (eid_info_list[i].eid_index != eid_idx) {
            continue;
        }

        out_info->assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
        (void)memcpy(&out_info->eid.eid, &eid_info_list[i].eid, sizeof(urma_eid_t));
        break;
    }
    return UMQ_SUCCESS;
}

static umq_ub_ctx_t *umq_ub_get_ub_ctx_by_dev_info(
    umq_ub_ctx_t *ub_ctx_list, uint32_t ub_ctx_cnt, umq_dev_assign_t *dev_info)
{
    urma_device_t *urma_dev;
    uint32_t eid_index = 0;
    uint32_t eid_cnt = umq_ub_get_urma_dev(dev_info, &urma_dev, &eid_index);
    if (eid_cnt == 0) {
        UMQ_VLOG_ERR("failed to get urma dev\n");
        return NULL;
    }

    umq_dev_assign_t eid_dev_info;
    int ret = umq_ub_get_eid_dev_info(urma_dev, eid_index, &eid_dev_info);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get eid trans info\n");
        return NULL;
    }

    umq_ub_ctx_t *ub_ctx = NULL;
    for (uint32_t i = 0; i < ub_ctx_cnt; i++) {
        if (ub_ctx_list[i].trans_info.dev_info.assign_mode == eid_dev_info.assign_mode &&
            memcmp(&ub_ctx_list[i].trans_info.dev_info.eid.eid, &eid_dev_info.eid.eid, sizeof(umq_eid_t)) == 0) {
            ub_ctx = &ub_ctx_list[i];
            break;
        }
    }
    return ub_ctx;
}

static int umq_find_ub_device(umq_trans_info_t *info, umq_ub_ctx_t *ub_ctx)
{
    if (g_ub_ctx_count >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR("ub ctx cnt exceeded the maximum limit %u\n", MAX_UMQ_TRANS_INFO_NUM);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_ub_get_ub_ctx_by_dev_info(g_ub_ctx, g_ub_ctx_count, &info->dev_info) != NULL) {
        UMQ_VLOG_ERR("ub ctx already exists\n");
        return -UMQ_ERR_EEXIST;
    }

    urma_device_t *urma_dev;
    uint32_t eid_index = 0;
    uint32_t eid_cnt = umq_ub_get_urma_dev(&info->dev_info, &urma_dev, &eid_index);
    if (eid_cnt == 0) {
        UMQ_VLOG_ERR("failed to get urma dev\n");
        return -UMQ_ERR_ENODEV;
    }

    ub_ctx->trans_info.trans_mode = info->trans_mode;
    int ret = umq_ub_get_eid_dev_info(urma_dev, eid_index, &ub_ctx->trans_info.dev_info);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get eid trans info\n");
        return ret;
    }

    ret = umq_ub_create_urma_ctx(urma_dev, eid_index, ub_ctx);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get urma ctx failed\n");
        return ret;
    }

    return UMQ_SUCCESS;
}

static remote_imported_tseg_info_t *umq_ub_ctx_imported_info_create(void)
{
    remote_imported_tseg_info_t *remote_imported_tseg_info =
        (remote_imported_tseg_info_t *)calloc(1, sizeof(remote_imported_tseg_info_t));
    if (remote_imported_tseg_info == NULL) {
        UMQ_VLOG_ERR("calloc imported info failed\n");
        return NULL;
    }

    int ret = urpc_hmap_init(&remote_imported_tseg_info->remote_eid_id_table, UMQ_UB_MAX_REMOTE_EID_NUM);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("remote eid map init failed\n");
        goto FREE_INFO;
    }

    ret = util_id_allocator_init(&remote_imported_tseg_info->eid_id_allocator,
        UMQ_UB_MAX_REMOTE_EID_NUM, UMQ_UB_MIN_EID_ID);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("bind id allocator init failed\n");
        goto REMOTE_EID_MAP_UNINIT;
    }

    (void)pthread_mutex_init(&remote_imported_tseg_info->remote_eid_id_table_lock, NULL);
    return remote_imported_tseg_info;

REMOTE_EID_MAP_UNINIT:
    urpc_hmap_uninit(&remote_imported_tseg_info->remote_eid_id_table);

FREE_INFO:
    free(remote_imported_tseg_info);
    return NULL;
}

static void umq_ub_ctx_imported_info_destroy(umq_ub_ctx_t *ub_ctx)
{
    if (ub_ctx == NULL || ub_ctx->remote_imported_info == NULL) {
        return;
    }

    remote_imported_tseg_info_t *remote_imported_tseg_info = ub_ctx->remote_imported_info;
    remote_eid_hmap_node_t *cur = NULL;
    remote_eid_hmap_node_t *next = NULL;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, node, &remote_imported_tseg_info->remote_eid_id_table) {
        urpc_hmap_remove(&remote_imported_tseg_info->remote_eid_id_table, &cur->node);
        free(cur);
    }
    (void)pthread_mutex_destroy(&remote_imported_tseg_info->remote_eid_id_table_lock);
    urpc_hmap_uninit(&remote_imported_tseg_info->remote_eid_id_table);
    util_id_allocator_uninit(&ub_ctx->remote_imported_info->eid_id_allocator);
    free(ub_ctx->remote_imported_info);
    ub_ctx->remote_imported_info = NULL;
}

uint8_t *umq_ub_ctx_init_impl(umq_init_cfg_t *cfg)
{
    if (g_ub_ctx_count > 0) {
        UMQ_VLOG_WARN("umq ub ctx already inited\n");
        return (uint8_t *)g_ub_ctx;
    }

    if (util_id_allocator_init(&g_umq_ub_id_allocator, UMQ_MAX_ID_NUM, 1) != 0) {
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

    urpc_list_init(&g_umq_ub_queue_ctx_list.queue_list);
    (void)pthread_rwlock_init(&g_umq_ub_queue_ctx_list.lock, NULL);

    return (uint8_t *)(uintptr_t)g_ub_ctx;

IO_BUF_FREE:
    umq_io_buf_free();

ROLLBACL_UB_CTX:
    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        umq_ub_ctx_imported_info_destroy(&g_ub_ctx[g_ub_ctx_count]);
        umq_ub_delete_urma_ctx(&g_ub_ctx[g_ub_ctx_count]);
    }
    g_ub_ctx_count = 0;
    (void)urma_uninit();

FREE_CTX:
    free(g_ub_ctx);
    g_ub_ctx = NULL;

UNINIT_ALLOCATOR:
    util_id_allocator_uninit(&g_umq_ub_id_allocator);
    return NULL;
}

void umq_ub_ctx_uninit_impl(uint8_t *ctx)
{
    ub_queue_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        urpc_list_remove(&cur_node->qctx_node);
    }
    (void)pthread_rwlock_destroy(&g_umq_ub_queue_ctx_list.lock);

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
    util_id_allocator_uninit(&g_umq_ub_id_allocator);
    free(context);
    g_ub_ctx_count = 0;
    urma_uninit();
}

static urma_jetty_t *umq_create_jetty(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx)
{
    urma_jetty_cfg_t jetty_cfg = {
        .jfs_cfg = {
            .flag.bs.order_type = dev_ctx->order_type,
            .trans_mode = URMA_TM_RC,
            .depth = queue->tx_depth,
            .priority = queue->priority,
            .max_sge = queue->max_tx_sge,
            .max_inline_data = dev_ctx->dev_attr.dev_cap.max_jfs_inline_len,
            .jfc = queue->jfs_jfc,
            .rnr_retry = queue->rnr_retry,
            .err_timeout = queue->err_timeout,
        },
        .id = 0,
    };
    jetty_cfg.flag.bs.share_jfr = true;
    jetty_cfg.shared.jfr = queue->jfr;

    urma_jetty_t *jetty = urma_create_jetty(dev_ctx->urma_ctx, &jetty_cfg);
    if (jetty == NULL) {
        UMQ_VLOG_ERR("urma create jetty failed\n");
        return NULL;
    }
    return jetty;
}

static int check_and_set_param(umq_ub_ctx_t *dev_ctx, umq_create_option_t *option, ub_queue_t *queue)
{
    if (option->create_flag & UMQ_CREATE_FLAG_RX_BUF_SIZE) {
        if (option->rx_buf_size > dev_ctx->dev_attr.dev_cap.max_msg_size) {
            UMQ_VLOG_ERR("rx buf size [%u] exceed max buf size [%d]\n", option->rx_buf_size,
                         dev_ctx->dev_attr.dev_cap.max_msg_size);
            return -UMQ_ERR_EINVAL;
        }
        queue->rx_buf_size = option->rx_buf_size;
    } else {
        queue->rx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size < UMQ_DEFAULT_BUF_SIZE ?
                             dev_ctx->dev_attr.dev_cap.max_msg_size : UMQ_DEFAULT_BUF_SIZE;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_TX_BUF_SIZE) {
        if (option->tx_buf_size > dev_ctx->dev_attr.dev_cap.max_msg_size) {
            UMQ_VLOG_ERR("tx buf size [%u] exceed max buf size [%d]\n", option->tx_buf_size,
                         dev_ctx->dev_attr.dev_cap.max_msg_size);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_buf_size = option->tx_buf_size;
    } else {
        queue->tx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size < UMQ_DEFAULT_BUF_SIZE ?
                             dev_ctx->dev_attr.dev_cap.max_msg_size : UMQ_DEFAULT_BUF_SIZE;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_RX_DEPTH) {
        if (option->rx_depth > dev_ctx->dev_attr.dev_cap.max_jfc_depth) {
            UMQ_VLOG_ERR("rx depth [%u] exceed max depth [%d]\n", option->rx_depth,
                         dev_ctx->dev_attr.dev_cap.max_jfc_depth);
            return -UMQ_ERR_EINVAL;
        }
        queue->rx_depth = option->rx_depth;
    } else {
        queue->rx_depth = dev_ctx->dev_attr.dev_cap.max_jfc_depth < UMQ_DEFAULT_DEPTH ?
                          dev_ctx->dev_attr.dev_cap.max_jfc_depth : UMQ_DEFAULT_DEPTH;
    }

    if ((dev_ctx->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0 &&
        (queue->tx_depth > UINT16_MAX || (queue->rx_depth > UINT16_MAX))) {
        UMQ_VLOG_ERR("queue tx depth %u, rx depth %u exceed %u\n", queue->tx_depth, queue->rx_depth, UINT16_MAX);
        return -UMQ_ERR_EINVAL;
    }

    if (option->create_flag & UMQ_CREATE_FLAG_TX_DEPTH) {
        if (option->tx_depth > dev_ctx->dev_attr.dev_cap.max_jfc_depth) {
            UMQ_VLOG_ERR("rx depth [%u] exceed max depth [%d]\n", option->tx_depth,
                         dev_ctx->dev_attr.dev_cap.max_jfc_depth);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_depth = option->tx_depth;
    } else {
        queue->tx_depth = dev_ctx->dev_attr.dev_cap.max_jfc_depth < UMQ_DEFAULT_DEPTH ?
                          dev_ctx->dev_attr.dev_cap.max_jfc_depth : UMQ_DEFAULT_DEPTH;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) {
        if (option->mode < 0 || option->mode >= UMQ_MODE_MAX) {
            UMQ_VLOG_ERR("queue mode[%d] is invalid\n", option->mode);
            return -UMQ_ERR_EINVAL;
        }
        queue->mode = option->mode;
    }
    queue->max_rx_sge = dev_ctx->dev_attr.dev_cap.max_jfr_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfr_sge : UMQ_MAX_SGE_NUM;
    queue->max_tx_sge = dev_ctx->dev_attr.dev_cap.max_jfs_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfs_sge : UMQ_MAX_SGE_NUM;
    queue->priority = DEFAULT_PRIORITY;
    queue->err_timeout = DEFAULT_ERR_TIMEOUT;
    queue->rnr_retry = DEFAULT_RNR_RETRY;
    queue->min_rnr_timer = DEFAULT_MIN_RNR_TIMER;
    (void)memcpy(queue->name, option->name, UMQ_NAME_MAX_LEN);
    queue->dev_ctx = dev_ctx;
    queue->umq_trans_mode = option->trans_mode;
    queue->remote_rx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size;
    return UMQ_SUCCESS;
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
    (void)pthread_mutex_init(&queue->imported_tseg_list_mutex, NULL);
    queue->ref_cnt = 1;
    queue->tx_outstanding = 0;
    queue->state = queue->flow_control.enabled ? QUEUE_STATE_IDLE : QUEUE_STATE_READY;
    queue->umqh = umqh;
    (void)pthread_rwlock_wrlock(&g_umq_ub_queue_ctx_list.lock);
    urpc_list_push_back(&g_umq_ub_queue_ctx_list.queue_list, &queue->qctx_node);
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
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
    pthread_mutex_destroy(&queue->imported_tseg_list_mutex);
    umq_buf_free(queue->notify_buf);

    umq_ub_flow_control_uninit(&queue->flow_control);
    rx_buf_ctx_list_uninit(&queue->rx_buf_ctx_list);

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
    (void)pthread_rwlock_wrlock(&g_umq_ub_queue_ctx_list.lock);
    urpc_list_remove(&queue->qctx_node);
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->dev_ctx->ref_cnt, 1);
    free(queue);
    return UMQ_SUCCESS;
}

static int umq_ub_send_imm(ub_queue_t *queue, uint64_t imm_value, urma_sge_t *sge, uint64_t user_ctx)
{
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    urma_jfs_wr_t urma_wr = {
        .send = {.src = {.sge = sge, .num_sge = 1}, .imm_data = imm_value },
        .user_ctx = user_ctx,
        .flag = { .bs = { .complete_enable = 1, .inline_flag = 0, } },
        .tjetty = queue->bind_ctx->tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_SEND_IMM, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
        return -status;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE void fill_big_data_ref_sge(ub_queue_t *queue, ub_ref_sge_t *ref_sge,
    umq_buf_t *buffer, ub_import_mempool_info_t *import_mempool_info, umq_imm_head_t *umq_imm_head)
{
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[buffer->mempool_id];
    urma_seg_t *seg = &tseg->seg;
    if (!queue->dev_ctx->remote_imported_info->tesg_imported[queue->bind_ctx->remote_eid_id][buffer->mempool_id]) {
        umq_imm_head->type = IMM_PROTOCAL_TYPE_IMPORT_MEM;
        umq_imm_head->mempool_num++;
        import_mempool_info->mempool_seg_flag = seg->attr.value;
        import_mempool_info->mempool_length = seg->len;
        import_mempool_info->mempool_token_id = seg->token_id;
        import_mempool_info->mempool_id = buffer->mempool_id;
        import_mempool_info->mempool_token_value = tseg->user_ctx;
        (void)memcpy(import_mempool_info->mempool_ubva, &seg->ubva, sizeof(urma_ubva_t));
    }

    ref_sge->addr = (uint64_t)(uintptr_t)buffer->buf_data;
    ref_sge->length = buffer->data_size;
    ref_sge->token_id = seg->token_id;
    ref_sge->mempool_id = buffer->mempool_id;
    ref_sge->token_value = tseg->user_ctx;
}

void ubmm_fill_big_data_ref_sge(uint64_t umqh_tp, ub_ref_sge_t *ref_sge,
    umq_buf_t *buffer, ub_import_mempool_info_t *import_mempool_info, umq_imm_head_t *umq_imm_head)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    fill_big_data_ref_sge(queue, ref_sge, buffer, import_mempool_info, umq_imm_head);
}

static int umq_ub_send_big_data(ub_queue_t *queue, umq_buf_t **buffer)
{
    // apply for one to avoid memory leak
    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), UMQ_MAX_QBUF_NUM, UMQ_INVALID_HANDLE, NULL);
    if (send_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq malloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    // In the tx direction, user_ctx needs to initialize imm data ub_plus type
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)send_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {
        .ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_UB_PLUS, .sub_type = IMM_TYPE_UB_PLUS_DEFAULT}};
    buf_pro->imm_data = imm_temp.value;
    uint16_t msg_id = util_id_allocator_get(&g_umq_ub_id_allocator);
    queue->addr_list[msg_id] = (uint64_t)(uintptr_t)(*buffer);

    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)send_buf->buf_data;
    ub_fill_umq_imm_head(umq_imm_head, *buffer);
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);

    ub_import_mempool_info_t import_mempool_info[UMQ_MAX_TSEG_NUM];
    uint32_t rest_size = (*buffer)->total_data_size;
    int32_t buf_index = 0;
    uint16_t ref_sge_num = (umq_buf_size_small() - sizeof(umq_imm_head_t)) / sizeof(ub_ref_sge_t);
    urma_sge_t sge;
    uint32_t max_data_size = 0;
    while ((*buffer) && rest_size != 0) {
        if (rest_size < (*buffer)->data_size) {
            UMQ_LIMIT_VLOG_ERR("remaining size[%u] is smaller than data_size[%u]\n", rest_size, (*buffer)->data_size);
            goto FREE_BUF;
        }

        if (buf_index == ref_sge_num) {
            UMQ_LIMIT_VLOG_ERR("the buf num [%d] exceeds the maximum limit [%u]\n", buf_index, (uint32_t)ref_sge_num);
            goto FREE_BUF;
        }

        fill_big_data_ref_sge(
            queue, &ref_sge[buf_index], *buffer, &import_mempool_info[umq_imm_head->mempool_num], umq_imm_head);

        max_data_size =  (*buffer)->data_size > max_data_size ? (*buffer)->data_size : max_data_size;
        rest_size -= (*buffer)->data_size;
        (*buffer) = QBUF_LIST_NEXT((*buffer));
        ++buf_index;
    }

    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_IMPORT_MEM) {
        if ((sizeof(umq_imm_head_t) + sizeof(ub_ref_sge_t) * buf_index +
                sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num) >
            (umq_buf_size_small() * UMQ_MAX_QBUF_NUM)) {
            UMQ_LIMIT_VLOG_ERR("import mempool info is not enough\n");
            goto FREE_BUF;
        }
        (void)memcpy(ref_sge + buf_index,
            import_mempool_info, sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num);
    }
    umq_imm_head->mem_interval = get_mem_interval(max_data_size);

    uint64_t user_ctx = (uint64_t)(uintptr_t)send_buf;
    sge.addr = (uint64_t)(uintptr_t)send_buf->buf_data;
    sge.len = sizeof(umq_imm_head_t) +
        buf_index * sizeof(ub_ref_sge_t) + umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t);
    sge.tseg = queue->dev_ctx->tseg_list[send_buf->mempool_id];
    umq_ub_imm_t imm = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                    .type = IMM_TYPE_UB_PLUS,
                                    .sub_type = IMM_TYPE_REVERSE_PULL_MEM,
                                    .msg_id = msg_id,
                                    .msg_num = (uint16_t)buf_index}};
    int ret = umq_ub_send_imm(queue, imm.value, &sge, user_ctx);
    if (ret != UMQ_SUCCESS) {
        umq_buf_free(send_buf);
        UMQ_LIMIT_VLOG_ERR("umq_ub_send_imm failed\n");
        return ret;
    }
    return UMQ_SUCCESS;

FREE_BUF:
    umq_buf_free(send_buf);
    return UMQ_FAIL;
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

static void umq_ub_fill_tx_imm(ub_flow_control_t *fc, urma_jfs_wr_t *urma_wr, umq_buf_pro_t *buf_pro)
{
    // user send wr can carry flow control
    if (!fc->enabled || urma_wr->opcode != URMA_OPC_SEND) {
        return;
    }

    uint16_t notify = fc->ops.local_rx_posted_load(fc);
    if (notify < fc->notify_interval) {
        return;
    }

    notify = fc->ops.local_rx_posted_exchange(fc);
    if (notify == 0) {
        return;
    }

    umq_ub_imm_t imm = {.flow_control = {
                            .umq_private = UMQ_UB_IMM_PRIVATE,
                            .type = IMM_TYPE_FLOW_CONTROL,
                            .in_user_buf = UMQ_UB_IMM_IN_USER_BUF,
                            .window = notify,
                        }};
    urma_wr->opcode = URMA_OPC_SEND_IMM;
    urma_wr->send.imm_data = imm.value;
    buf_pro->opcode = UMQ_OPC_SEND_IMM;
    buf_pro->imm_data = imm.value;
}

static void umq_ub_recover_tx_imm(ub_queue_t *queue, urma_jfs_wr_t *urma_wr, uint16_t wr_index, umq_buf_t *bad)
{
    if (!queue->flow_control.enabled) {
        return;
    }

    bool find = false;
    umq_buf_pro_t *buf_pro = NULL;
    umq_ub_imm_t imm;
    for (uint16_t i = 0; i < wr_index; i++) {
        if (urma_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            find = true;
        }

        if (find && urma_wr[i].opcode == URMA_OPC_SEND_IMM) {
            imm.value = urma_wr[i].send.imm_data;
            if (imm.bs.umq_private == 0 || imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
                continue;
            }

            umq_ub_rq_posted_notifier_update(&queue->flow_control, queue, imm.flow_control.window);
            buf_pro = (umq_buf_pro_t *)(((umq_buf_t *)(uintptr_t)urma_wr[i].user_ctx)->qbuf_ext);
            buf_pro->opcode = UMQ_OPC_SEND;
            buf_pro->imm_data = 0;
        }
    }
}

static uint16_t umq_ub_tx_failed_num(urma_jfs_wr_t *urma_wr, uint16_t wr_index, umq_buf_t *bad)
{
    for (uint16_t i = 0; i < wr_index; i++) {
        if (urma_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            return wr_index - i;
        }
    }
    return 0;
}

static int umq_ub_fill_wr(ub_queue_t *queue, umq_buf_t *buffer, urma_jfs_wr_t *urma_wr_ptr, urma_sge_t *sges_ptr,
                          uint32_t sge_num, urma_sge_t *src_sge, urma_sge_t *dst_sge)
{
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
    switch (buf_pro->opcode) {
        case UMQ_OPC_READ:
            if (buf_pro->remote_sge.length > buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR("local buffer size[%u] is smaller than remote buffer size[%u]\n",
                                   buffer->total_data_size, buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            src_sge->addr = buf_pro->remote_sge.addr;
            src_sge->len = buf_pro->remote_sge.length;
            src_sge->tseg = queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID];
            urma_wr_ptr->rw.src.sge = src_sge;
            urma_wr_ptr->rw.src.num_sge = 1;
            urma_wr_ptr->rw.dst.sge = sges_ptr;
            urma_wr_ptr->rw.dst.num_sge = sge_num;
            break;
        case UMQ_OPC_WRITE:
            if (buf_pro->remote_sge.length < buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR("local buffer size[%u] is larger than remote buffer size[%u]\n",
                                   buffer->total_data_size, buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            dst_sge->addr = buf_pro->remote_sge.addr;
            dst_sge->len = buf_pro->remote_sge.length;
            dst_sge->tseg = queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID];
            urma_wr_ptr->rw.dst.sge = dst_sge;
            urma_wr_ptr->rw.dst.num_sge = 1;
            urma_wr_ptr->rw.src.sge = sges_ptr;
            urma_wr_ptr->rw.src.num_sge = sge_num;
            break;
        case UMQ_OPC_SEND:
        case UMQ_OPC_SEND_IMM:
            urma_wr_ptr->send.src.sge = sges_ptr;
            urma_wr_ptr->send.src.num_sge = sge_num;
            break;
        default:
            break;
    }
    return UMQ_SUCCESS;
}

static int umq_ub_post_tx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    int ret = UMQ_SUCCESS;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        *bad_qbuf = qbuf;
        return -UMQ_ERR_ENODEV;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    uint32_t max_sge_num = queue->max_tx_sge;
    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    urma_jfs_wr_t *urma_wr_ptr = urma_wr;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_sge_t src_sge, dst_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint16_t wr_index = 0;
    uint16_t max_tx = 0;
    bool opcode_consume_rqe = false;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;

    *bad_qbuf = NULL;
    while (buffer) {
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > max_send_size) {
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max send size[%u]\n", rest_size, max_send_size);
            ret = -UMQ_ERR_EINVAL;
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        sges_ptr = sges[wr_index];
        uint32_t sge_num = 0;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        umq_opcode_t opcode = buf_pro->opcode;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        umq_buf_t *tmp_buf = buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_ENOMEM;
            goto ERROR;
        }
        ret = umq_ub_fill_wr(queue, tmp_buf, urma_wr_ptr, sges[wr_index], sge_num, &src_sge, &dst_sge);
        if (ret != UMQ_SUCCESS) {
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->opcode = transform_op_code(opcode);
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        if (urma_wr_ptr->opcode == URMA_OPC_SEND_IMM) {
            urma_wr_ptr->send.imm_data = buf_pro->imm_data & umq_ub_user_imm_bit_fields(&queue->flow_control);
        }
        opcode_consume_rqe = (opcode == UMQ_OPC_SEND || opcode == UMQ_OPC_SEND_IMM ||
                              opcode == UMQ_OPC_WRITE_IMM);
        umq_ub_fill_tx_imm(&queue->flow_control, urma_wr_ptr, buf_pro);
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR("wr count exceeds %d, not supported\n", UMQ_BATCH_SIZE);
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_EINVAL;
            goto ERROR;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    max_tx = opcode_consume_rqe ? umq_ub_window_dec(&queue->flow_control, queue, wr_index) : wr_index;
    if (max_tx == 0) {
        *bad_qbuf = qbuf;
        ret = -UMQ_ERR_EAGAIN;
        goto ERROR;
    } else if (max_tx < wr_index) {
        urma_wr[max_tx - 1].next = NULL;
    }

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        ret = -(int)status;
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
        goto RECOVER_WINDOW;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    if (max_tx < wr_index) {
        *bad_qbuf = (umq_buf_t *)(uintptr_t)urma_wr[max_tx].user_ctx;
        return -UMQ_ERR_EAGAIN;
    }

    return UMQ_SUCCESS;

RECOVER_WINDOW:
    if (opcode_consume_rqe) {
        umq_ub_window_inc(&queue->flow_control, umq_ub_tx_failed_num(urma_wr, max_tx, *bad_qbuf));
    }

ERROR:
    umq_ub_recover_tx_imm(queue, urma_wr, wr_index, *bad_qbuf);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
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

typedef struct user_ctx {
    umq_buf_t *dst_buf;
    uint32_t wr_cnt;
    uint32_t wr_total;
    uint32_t msg_id;
} user_ctx_t;


static inline uint32_t umq_read_alloc_mem_size(umq_size_interval_t size_interval)
{
    if (size_interval == UMQ_SIZE_0K_SMALL_INTERVAL) {
        return umq_buf_size_small();
    } else if (size_interval == UMQ_SIZE_SMALL_MID_INTERVAL) {
        return umq_buf_size_middle();
    } else if (size_interval == UMQ_SIZE_MID_BIG_INTERVAL) {
        return umq_buf_size_big();
    } else if (size_interval == UMQ_SIZE_BIG_HUGE_INTERVAL) {
        return umq_buf_size_huge();
    }

    UMQ_LIMIT_VLOG_ERR("size_interval: %d is invalid\n", size_interval);
    return UINT32_MAX;
};

static ALWAYS_INLINE uint32_t umq_ub_get_read_pre_allocate_max_total_size(
    umq_size_interval_t size_interval, uint16_t buf_num)
{
    uint32_t read_alloc_mem_size = umq_read_alloc_mem_size(size_interval);
    if (read_alloc_mem_size == UINT32_MAX) {
        return UINT32_MAX;
    }

    umq_buf_mode_t buf_mode = umq_qbuf_mode_get();
    if (buf_mode == UMQ_BUF_SPLIT) {
        return read_alloc_mem_size * buf_num - umq_qbuf_headroom_get();
    } else if (buf_mode == UMQ_BUF_COMBINE) {
        return read_alloc_mem_size * buf_num - sizeof(umq_buf_t) * buf_num - umq_qbuf_headroom_get();
    }

    UMQ_LIMIT_VLOG_ERR("buf mode: %d is invalid\n", buf_mode);
    return UINT32_MAX;
}

static umq_buf_t *umq_ub_read_ctx_create(
    ub_queue_t *queue, umq_imm_head_t *umq_imm_head, uint16_t buf_num, uint16_t msg_id)
{
    umq_buf_t *ctx_buf = umq_buf_alloc(sizeof(user_ctx_t), 1, UMQ_INVALID_HANDLE, NULL);
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("ctx_buf malloc failed\n");
        return NULL;
    }
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)ctx_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                         .type = IMM_TYPE_UB_PLUS,
                                         .sub_type = IMM_TYPE_REVERSE_PULL_MEM_DONE}};
    buf_pro->imm_data = imm_temp.value;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;

    uint32_t total_size = umq_ub_get_read_pre_allocate_max_total_size(umq_imm_head->mem_interval, buf_num);
    if (total_size == UINT32_MAX) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR("get total data size failed\n");
        return NULL;
    }

    user_ctx->dst_buf = umq_buf_alloc(total_size, 1, UMQ_INVALID_HANDLE, NULL);
    if (user_ctx->dst_buf == NULL) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR("dst_buf malloc failed\n");
        return NULL;
    }

    user_ctx->wr_total = buf_num;
    user_ctx->msg_id = msg_id;
    user_ctx->wr_cnt = 0;
    return ctx_buf;
}

static inline void umq_ub_read_ctx_destory(umq_buf_t *ctx_buf)
{
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;
    if (user_ctx->dst_buf != NULL) {
        umq_buf_free(user_ctx->dst_buf);
    }
    umq_buf_free(ctx_buf);
}

static ALWAYS_INLINE urma_status_t umq_ub_read_post_send(
    ub_queue_t *queue, urma_sge_t *src_sge, urma_sge_t *dst_sge, umq_buf_t *ctx_buf)
{
    urma_jfs_wr_t urma_wr = {.rw = {.src = {.sge = src_sge, .num_sge = 1},
        .dst = {.sge = dst_sge, .num_sge = 1}},
        .user_ctx = (uint64_t)(uintptr_t)ctx_buf,
        .opcode = URMA_OPC_READ,
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 0}},
        .tjetty = queue->bind_ctx->tjetty};

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_READ, start_timestamp, queue->dev_ctx->feature);
    return status;
}

int umq_ub_read(uint64_t umqh_tp, umq_buf_t *rx_buf, umq_ub_imm_t imm)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    uint16_t buf_num = imm.ub_plus.msg_num;
    uint16_t msg_id = imm.ub_plus.msg_id;
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)rx_buf->buf_data;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);
    umq_buf_t *ctx_buf = umq_ub_read_ctx_create(queue, umq_imm_head, buf_num, msg_id);
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("create ctx buf failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;
    umq_buf_t *dst_buf = user_ctx->dst_buf;
    umq_buf_t *tmp_buf = dst_buf;
    urma_sge_t src_sge[buf_num];
    urma_sge_t dst_sge[buf_num];
    uint32_t total_data_size = 0;
    uint32_t src_buf_length = 0;
    for (uint32_t i = 0; i < buf_num; i++) {
        src_buf_length = ref_sge[i].length;

        dst_sge[i].addr = (uint64_t)(uintptr_t)tmp_buf->buf_data;
        dst_sge[i].len = src_buf_length;
        dst_sge[i].user_tseg = NULL;
        dst_sge[i].tseg = tseg_list[tmp_buf->mempool_id];

        src_sge[i].addr = ref_sge[i].addr;
        src_sge[i].len = src_buf_length;
        src_sge[i].tseg = queue->imported_tseg_list[ref_sge[i].mempool_id];
        if (src_sge[i].tseg == NULL) {
            UMQ_LIMIT_VLOG_ERR("imported memory handle not exist\n");
            goto FREE_CTX_BUF;
        }

        tmp_buf->data_size = src_buf_length;
        tmp_buf = QBUF_LIST_NEXT(tmp_buf);
        total_data_size += src_buf_length;

        urma_status_t status = umq_ub_read_post_send(queue, src_sge + i, dst_sge + i, ctx_buf);
        if (status != URMA_SUCCESS) {
            umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
            UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
            if (i == 0) {
                goto FREE_CTX_BUF;
            } else {
                return -status;
            }
        }
    }
    dst_buf->total_data_size = total_data_size;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, buf_num);
    return UMQ_SUCCESS;

FREE_CTX_BUF:
    umq_ub_read_ctx_destory(ctx_buf);
    return UMQ_FAIL;
}

static int umq_ub_read_done(ub_queue_t *queue, uint16_t msg_id)
{
    umq_ub_imm_t imm = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                    .type = IMM_TYPE_UB_PLUS,
                                    .sub_type = IMM_TYPE_REVERSE_PULL_MEM_FREE,
                                    .msg_id = msg_id}};

    urma_sge_t sge = {
        .tseg = queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };
    return umq_ub_send_imm(queue, imm.value, &sge, 0);
}

static inline umq_buf_t *umq_get_buf_by_user_ctx(ub_queue_t *queue, uint64_t user_ctx)
{
    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)user_ctx;
    umq_buf_t *buf = rx_buf_ctx->buffer;
    queue_rx_buf_ctx_put(&queue->rx_buf_ctx_list, rx_buf_ctx);
    return buf;
}

static int umq_report_incomplete_rx(ub_queue_t *queue, uint32_t max_rx_ctx, umq_buf_t **buf)
{
    int buf_cnt = 0;
    if (!queue->tx_flush_done || queue->rx_flush_done ||
        queue->state != QUEUE_STATE_ERR || queue->jfr->jfr_cfg.trans_mode != URMA_TM_RC) {
        return buf_cnt;
    }

    rx_buf_ctx_t *rx_buf_ctx;
    for (buf_cnt = 0; buf_cnt < (int)max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            break;
        }
        buf[buf_cnt] = rx_buf_ctx->buffer;
        buf[buf_cnt]->io_direction = UMQ_IO_RX;
        buf[buf_cnt]->status = UMQ_BUF_WR_FLUSH_ERR;
    }

    if (buf_cnt == 0) {
        queue->rx_flush_done = true;
    }
    return buf_cnt;
}

static inline int umq_ub_import_mem_done(ub_queue_t *queue, uint16_t mempool_id)
{
    umq_ub_imm_t imm = { .mem_import_done =
        { .umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_MEM_IMPORT_DONE, .mempool_id = mempool_id} };
    return umq_ub_write_imm((uint64_t)(uintptr_t)queue, queue->bind_ctx->remote_notify_addr, 1, imm.value);
}

static int umq_ub_data_plan_import_mem(uint64_t umqh_tp, umq_buf_t *rx_buf, uint32_t msg_num)
{
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)rx_buf->buf_data;
    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_NONE) {
        return UMQ_SUCCESS;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    pthread_mutex_lock(&queue->imported_tseg_list_mutex);
    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)
            (rx_buf->buf_data + sizeof(umq_imm_head_t) + msg_num * sizeof(ub_ref_sge_t));
    for (uint32_t i = 0; i < umq_imm_head->mempool_num; i++) {
        if (queue->imported_tseg_list[import_mempool_info[i].mempool_id] != NULL) {
            UMQ_LIMIT_VLOG_INFO("mempool %u has been imported\n", import_mempool_info[i].mempool_id);
            (void)umq_ub_import_mem_done(queue, import_mempool_info[i].mempool_id);
            continue;
        }

        xchg_mem_info_t mem_info = {
            .seg_len = import_mempool_info[i].mempool_length,
            .seg_token_id = import_mempool_info[i].mempool_token_id,
            .seg_flag = (urma_import_seg_flag_t)import_mempool_info[i].mempool_seg_flag,
            .token.token = import_mempool_info[i].mempool_token_value
        };

        (void)memcpy(&mem_info.ubva, &import_mempool_info[i].mempool_ubva, sizeof(urma_ubva_t));
        urma_target_seg_t *imported_tseg = import_mem(queue->dev_ctx->urma_ctx, &mem_info);
        if (imported_tseg == NULL) {
            pthread_mutex_unlock(&queue->imported_tseg_list_mutex);
            UMQ_LIMIT_VLOG_ERR("import memory failed\n");
            return UMQ_FAIL;
        }

        if (umq_ub_import_mem_done(queue, import_mempool_info[i].mempool_id) != UMQ_SUCCESS) {
            // send import mem done failed not cause the data plane to be unavailable
            UMQ_LIMIT_VLOG_WARN("send import mem done imm failed\n");
        }
        queue->imported_tseg_list[import_mempool_info[i].mempool_id] = imported_tseg;
    }
    pthread_mutex_unlock(&queue->imported_tseg_list_mutex);
    return UMQ_SUCCESS;
}

static int process_send_imm(umq_buf_t *rx_buf, umq_ub_imm_t imm, uint64_t umqh)
{
    int ret = 0;
    if (imm.bs.umq_private == 0) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
        return UMQ_SUCCESS;
    }
    if (imm.bs.type != IMM_TYPE_UB_PLUS) {
        return ret;
    }
    if (imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM) {
        if (umq_ub_data_plan_import_mem(umqh, rx_buf, imm.ub_plus.msg_num) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("import mem failed\n");
            umq_buf_free(rx_buf); // release rx
            return UMQ_CONTINUE_FLAG;
        }

        if (umq_ub_read(umqh, rx_buf, imm) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("umq ub send read failed\n");
        }
        umq_buf_free(rx_buf); // release rx
        ret = UMQ_CONTINUE_FLAG;
    } else if (imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_FREE) {
        uint16_t msg_id = (uint16_t)(imm.ub_plus.msg_id);
        if (msg_id != 0) {
            ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
            umq_buf_t *buffer = (umq_buf_t *)queue->addr_list[msg_id];
            /*
             * break qbuf list for many batches connected, only release the first batch,
             * can't break qbuf list when send, because all qbufs of 128 wr are connected,
             * and the address of the first qbuf is placed in the user_ctx of the 128th wr, then released
             */
            (void)umq_buf_break_and_free(buffer);
            util_id_allocator_release(&g_umq_ub_id_allocator, msg_id);
        }
        umq_buf_free(rx_buf); // release rx
        ret = UMQ_CONTINUE_FLAG;
    }
    return ret;
}

static int umq_ub_on_rx_done(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t *rx_buf, umq_buf_status_t *qbuf_status)
{
    if (cr->opcode != URMA_CR_OPC_SEND_WITH_IMM) {
        return UMQ_SUCCESS;
    }

    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (imm.bs.umq_private == 0) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
        return UMQ_SUCCESS;
    }

    if (imm.bs.type == IMM_TYPE_FLOW_CONTROL) {
        umq_ub_window_inc(&queue->flow_control, imm.flow_control.window);
        *qbuf_status = UMQ_BUF_FLOW_CONTROL_UPDATE;
        if (imm.flow_control.in_user_buf == UMQ_UB_IMM_IN_USER_BUF) {
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
            buf_pro->opcode = UMQ_OPC_SEND;
            buf_pro->imm_data = 0;
            return UMQ_SUCCESS;
        }
    }

    return UMQ_SUCCESS;
}

static int process_rx_msg(urma_cr_t *cr, umq_buf_t *buf, ub_queue_t *queue, umq_buf_status_t *qbuf_status)
{
    int ret = 0;
    *qbuf_status = (umq_buf_status_t)cr->status;
    switch (cr->opcode) {
        case URMA_CR_OPC_WRITE_WITH_IMM: {
            if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
                /* on condition of base feature, write imm is used for ubmm event notify,
                 * and it counsumes one rqe, so fill rx buffer here.
                 * on condition of pro feature, report it to user.
                */
                umq_buf_t *write_qbuf = umq_get_buf_by_user_ctx(queue, cr->user_ctx);
                umq_buf_t *bad_qbuf = NULL;
                if (umq_ub_post_rx_inner_impl(queue, write_qbuf, &bad_qbuf) != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR("ub post rx failed\n");
                    umq_buf_free(write_qbuf);
                }
                ret = UMQ_CONTINUE_FLAG;
            } else {
                ret = UMQ_SUCCESS;
            }
            break;
        }
        case URMA_CR_OPC_SEND_WITH_IMM: {
            ret = umq_ub_on_rx_done(queue, cr, buf, qbuf_status);
            break;
        }
        default:
            break;
    }
    return ret;
}

static inline void umq_perf_record_write_poll(umq_perf_record_type_t type, uint64_t start, uint32_t feature, int cr_cnt)
{
    if ((feature & UMQ_FEATURE_ENABLE_PERF) == 0) {
        return;
    }
    if (cr_cnt > 0) {
        umq_perf_record_write(type, start);
    } else {
        umq_perf_record_write(type + UMQ_PERF_RECORD_TRANSPORT_POLL_EMPTY_OFFSET, start);
    }
}

static int umq_ub_poll_rx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    urma_cr_t cr[max_batch];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, queue->dev_ctx->feature, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }
    int32_t qbuf_cnt = 0;
    int ret = 0;
    umq_buf_status_t qbuf_status;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        ret = process_rx_msg(&cr[i], buf[qbuf_cnt], queue, &qbuf_status);
        if (ret == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = qbuf_status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d]\n", i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[qbuf_cnt];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        ++qbuf_cnt;
    }
    qbuf_cnt += umq_report_incomplete_rx(queue, max_batch - rx_cr_cnt, buf + qbuf_cnt);

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return qbuf_cnt;
}

static void umq_ub_on_tx_done(ub_flow_control_t *fc, umq_buf_t *buf, bool failed)
{
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
    bool opcode_consume_rqe =
        buf_pro->opcode == UMQ_OPC_SEND || buf_pro->opcode == UMQ_OPC_SEND_IMM || buf_pro->opcode == UMQ_OPC_WRITE_IMM;
    if (failed && opcode_consume_rqe) {
        umq_ub_window_inc(fc, 1);
    }

    if (buf_pro->opcode != UMQ_OPC_SEND_IMM) {
        return;
    }

    umq_ub_imm_t imm = {.value = buf_pro->imm_data};
    if (imm.bs.umq_private == 0 || imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
        return;
    }

    if (failed) {
        umq_ub_rq_posted_notifier_inc(fc, imm.flow_control.window);
    }
    buf_pro->opcode = UMQ_OPC_SEND;
    buf_pro->imm_data = 0;
}

static int umq_ub_poll_tx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    urma_cr_t cr[max_batch];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, queue->dev_ctx->feature, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return tx_cr_cnt;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }

            // recover flow control window and rx_posted
            if (cr[i].user_ctx == 0) {
                queue->flow_control.remote_get = false;
                UMQ_LIMIT_VLOG_ERR("get remote window post read failed\n");
                continue;
            } else if (cr[i].user_ctx <= UINT16_MAX) {
                umq_ub_window_inc(&queue->flow_control, 1);
                umq_ub_rq_posted_notifier_inc(&queue->flow_control, (uint16_t)cr[i].user_ctx);
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            // window read ok
            uint16_t *remote_win =
                (uint16_t *)(uintptr_t)(umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL) + sizeof(uint16_t));
            if (*remote_win == 0) {
                queue->flow_control.remote_get = false;
                umq_ub_window_read(&queue->flow_control, queue);
            } else {
                UMQ_VLOG_DEBUG("umq ub flow control update initial window %d\n", *remote_win);
                umq_ub_window_inc(&queue->flow_control, *remote_win);
                queue->state = QUEUE_STATE_READY;
            }
            continue;
        } else if (cr[i].user_ctx <= UINT16_MAX) {
            continue;
        }
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[qbuf_cnt]->io_direction = UMQ_IO_TX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        umq_ub_on_tx_done(&queue->flow_control, buf[qbuf_cnt], (cr[i].status != URMA_CR_SUCCESS));
        ++qbuf_cnt;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return qbuf_cnt;
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

static void umq_flush_rx(ub_queue_t *queue, uint32_t max_retry_times)
{
    int rx_cnt = 0;
    uint32_t retry_times = 0;
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    uint32_t remain = queue->rx_depth - atomic_load_explicit(&queue->require_rx_count, memory_order_acquire);
    while (remain > 0 && retry_times < max_retry_times) {
        rx_cnt = umq_ub_poll_rx((uint64_t)(uintptr_t)queue, buf, UMQ_POST_POLL_BATCH);
        if (rx_cnt < 0) {
            return;
        }
        umq_buf_list_t head;
        for (int i = 0; i < rx_cnt; i++) {
            head.first = buf[i];
            umq_qbuf_free(&head);
        }
        remain -= (uint32_t)rx_cnt;
        retry_times++;
    }
}

static void umq_flush_tx(ub_queue_t *queue, uint32_t max_retry_times)
{
    int tx_cnt = 0;
    uint32_t retry_times = 0;
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    while (!queue->tx_flush_done && retry_times < max_retry_times) {
        tx_cnt = umq_ub_poll_tx((uint64_t)(uintptr_t)queue, buf, UMQ_POST_POLL_BATCH);
        if (tx_cnt < 0) {
            return;
        }
        for (int i = 0; i < tx_cnt; i++) {
            (void)umq_buf_break_and_free(buf[i]);
        }
        retry_times++;
    }
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
    (void)urma_unbind_jetty(queue->jetty);
    (void)urma_unimport_jetty(tjetty);
    (void)urma_unimport_seg(queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID]);
    queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID] = NULL;
    umq_modify_ubq_to_err(queue);

    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        umq_flush_tx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
        umq_flush_rx(queue, UMQ_FLUSH_MAX_RETRY_TIMES);
    }

    free(queue->bind_ctx);
    queue->bind_ctx = NULL;
    return UMQ_SUCCESS;
}

static void umq_ub_enqueue_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            continue;
        }
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        (void)umq_buf_break_and_free(buf[qbuf_cnt]);
        ++qbuf_cnt;
    }
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, qbuf_cnt);
}

static void umq_ub_enqueue_plus_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            if (cr[i].opcode == URMA_CR_OPC_SEND_WITH_IMM) {
                umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            }
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[qbuf_cnt]->io_direction = UMQ_IO_TX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf[qbuf_cnt]->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_UB_PLUS && imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            user_ctx_t *user_ctx = (user_ctx_t *)buf[qbuf_cnt]->buf_data;
            user_ctx->wr_cnt++;
            if (user_ctx->wr_cnt == user_ctx->wr_total) {
                if (umq_ub_read_done(queue, user_ctx->msg_id) != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR("umq ub send imm failed\n");
                }
                umq_buf_t *tmp = buf[qbuf_cnt];
                if (user_ctx->dst_buf) {
                    buf[qbuf_cnt] = user_ctx->dst_buf;
                    buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
                    ++qbuf_cnt;
                }
                umq_buf_free(tmp);
            }
            continue;
        }
        (void)umq_buf_break_and_free(buf[qbuf_cnt]);
        ++qbuf_cnt;
    }
}

static void process_bad_qbuf(urma_jfs_wr_t *bad_wr, umq_buf_t **bad_qbuf, umq_buf_t *qbuf, ub_queue_t *queue)
{
    *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
    umq_buf_t *tmp_qbuf = qbuf;
    uint32_t count = 0;
    umq_buf_t *previous = NULL;
    while (tmp_qbuf != NULL && tmp_qbuf != *bad_qbuf) {
        count++;
        previous = tmp_qbuf;
        tmp_qbuf = tmp_qbuf->qbuf_next;
    }
    if (previous) {
        // break chain of succeed qbuf and failed qbuf on tx
        previous->qbuf_next = NULL;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, count);
}

static int umq_ub_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;
    uint32_t sge_num = 0;

    while (buffer != NULL) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        buf_pro->flag.value = 0;
        buf_pro->flag.bs.complete_enable = 1;
        buf_pro->flag.bs.solicited_enable = 1;
        if (buffer->data_size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            buf_pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        buf_pro->opcode = UMQ_OPC_SEND;

        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > max_send_size) {
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max_send_size[%u]\n", rest_size, max_send_size);
            return -UMQ_ERR_EINVAL;
        }
        sges_ptr = sges[wr_index];
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        sge_num = 0;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = sges[wr_index];
        urma_wr_ptr->send.src.num_sge = sge_num;
        urma_wr_ptr->opcode = URMA_OPC_SEND;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;
        wr_index++;
        if ((wr_index == remain_tx || wr_index == UMQ_POST_POLL_BATCH) && buffer != NULL) {
            // wr count exceed remain_tx or UMQ_POST_POLL_BATCH
            UMQ_LIMIT_VLOG_ERR("wr count %u exceeds remain_tx %u or max_post_size %d, not supported\n", wr_index,
                               remain_tx, UMQ_POST_POLL_BATCH);
            return -UMQ_ERR_EINVAL;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    return wr_index;
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

static int umq_ub_plus_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t remote_rx_buf_size = queue->remote_rx_buf_size;
    uint32_t sge_num = 0;

    while (buffer != NULL) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        buf_pro->flag.value = 0;
        buf_pro->flag.bs.complete_enable = 1;
        buf_pro->flag.bs.solicited_enable = 1;
        if (buffer->data_size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            buf_pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        buf_pro->opcode = UMQ_OPC_SEND_IMM;
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > remote_rx_buf_size) {
            int ret = umq_ub_send_big_data(queue, &buffer);
            if (ret != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR("send big data failed\n");
                return ret;
            }
            if (buffer) {
                continue;
            } else if (buffer == NULL && wr_index != 0) {
                break;
            }
            return 0;
        }
        if (rest_size > queue->tx_buf_size) {
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max tx size[%u]\n", rest_size, queue->tx_buf_size);
            return -UMQ_ERR_EINVAL;
        }
        sges_ptr = sges[wr_index];
        sge_num = 0;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = sges[wr_index];
        urma_wr_ptr->send.src.num_sge = sge_num;
        urma_wr_ptr->send.imm_data = buf_pro->imm_data;
        urma_wr_ptr->opcode = URMA_OPC_SEND_IMM;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;
        wr_index++;
        if ((wr_index == remain_tx || wr_index == UMQ_POST_POLL_BATCH) && buffer != NULL) {
            // wr count exceed remain_tx or UMQ_POST_POLL_BATCH
            UMQ_LIMIT_VLOG_ERR("wr count %u exceeds remain_tx %u or max_post_size %d, not supported\n", wr_index,
                               remain_tx, UMQ_POST_POLL_BATCH);
            return -UMQ_ERR_EINVAL;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    return wr_index;
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

static void umq_ub_fill_rx_buffer(ub_queue_t *queue, int rx_cnt)
{
    atomic_fetch_add_explicit(&queue->require_rx_count, rx_cnt, memory_order_relaxed);
    uint32_t require_rx_count = umq_get_post_rx_num(queue->rx_depth, &queue->require_rx_count);
    if (require_rx_count > 0) {
        umq_buf_list_t head;
        uint32_t cur_batch_count = 0;
        do {
            cur_batch_count = require_rx_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : require_rx_count;
            QBUF_LIST_INIT(&head);
            if (umq_qbuf_alloc(queue->rx_buf_size, cur_batch_count, NULL, &head) != UMQ_SUCCESS) {
                atomic_fetch_add_explicit(&queue->require_rx_count, cur_batch_count, memory_order_relaxed);
                UMQ_LIMIT_VLOG_ERR("alloc rx failed\n");
                break;
            }
            umq_buf_t *bad_buf = NULL;
            if (umq_ub_post_rx_inner_impl(queue, QBUF_LIST_FIRST(&head), &bad_buf) != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR("post rx failed\n");
                QBUF_LIST_FIRST(&head) = bad_buf;
                uint32_t fail_count = 0;
                while (bad_buf) {
                    fail_count++;
                    bad_buf = bad_buf->qbuf_next;
                }
                umq_qbuf_free(&head);
                atomic_fetch_add_explicit(&queue->require_rx_count, fail_count, memory_order_relaxed);
                break;
            }
            require_rx_count -= cur_batch_count;
        } while (require_rx_count > 0);
    }
}

static void umq_ub_merge_rx_buffer(umq_buf_t *cur_buf, umq_buf_t **previous_last)
{
    umq_buf_t *tmp_buf = cur_buf;
    if (*previous_last != NULL) {
        (*previous_last)->qbuf_next = tmp_buf;
    }
    uint32_t rest_data_size = tmp_buf->total_data_size;
    while (tmp_buf && rest_data_size > 0) {
        if (rest_data_size <= tmp_buf->data_size) {
            tmp_buf->qbuf_next = NULL;
            *previous_last = tmp_buf;
            break;
        }
        rest_data_size -= tmp_buf->data_size;
        tmp_buf = tmp_buf->qbuf_next;
    }
}

static int umq_report_incomplete_and_merge_rx(
    ub_queue_t *queue, int max_rx_ctx, umq_buf_t **buf, umq_buf_t **previous_last)
{
    int buf_cnt = 0;
    if (!queue->tx_flush_done || queue->rx_flush_done ||
        queue->state != QUEUE_STATE_ERR || queue->jfr->jfr_cfg.trans_mode != URMA_TM_RC) {
        return buf_cnt;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    for (; buf_cnt < max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            break;
        }
        buf[buf_cnt] = rx_buf_ctx->buffer;
        buf[buf_cnt]->buf_data = 0;
        buf[buf_cnt]->io_direction = UMQ_IO_RX;
        buf[buf_cnt]->status = UMQ_BUF_WR_FLUSH_ERR;
        umq_ub_merge_rx_buffer(buf[buf_cnt], previous_last);
    }

    if (buf_cnt == 0) {
        queue->rx_flush_done = true;
    }
    return buf_cnt;
}

static int umq_ub_dequeue_with_poll_rx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf)
{
    int qbuf_cnt = 0;
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }
    // merge rx buffer
    umq_buf_t *previous_last = NULL;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[i] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        buf[i]->io_direction = UMQ_IO_RX;
        buf[i]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d]\n", i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[i];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        umq_ub_merge_rx_buffer(buf[i], &previous_last);
    }
    qbuf_cnt = rx_cr_cnt;
    qbuf_cnt +=
        umq_report_incomplete_and_merge_rx(queue, UMQ_POST_POLL_BATCH - rx_cr_cnt, buf + qbuf_cnt, &previous_last);
    return qbuf_cnt;
}

static int process_write_imm(umq_buf_t *rx_buf, umq_ub_imm_t imm, uint64_t umqh)
{
    int ret = 0;
    if (imm.bs.umq_private == 0) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(uintptr_t)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
    } else if (imm.bs.type == IMM_TYPE_MEM_IMPORT_DONE) {
        ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
        queue->dev_ctx->remote_imported_info->
            tesg_imported[queue->bind_ctx->remote_eid_id][imm.mem_import_done.mempool_id] = true;
        ret = UMQ_CONTINUE_FLAG;
        umq_buf_free(rx_buf);
    } else if (imm.bs.type == IMM_TYPE_NOTIFY) {
        ret = UMQ_CONTINUE_FLAG;
        umq_buf_free(rx_buf);
    }
    return ret;
}

static inline int process_imm_msg(uint64_t umqh_tp, umq_buf_t *buf, urma_cr_t *cr)
{
    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (cr->opcode == URMA_CR_OPC_SEND_WITH_IMM) {
        return process_send_imm(buf, imm, umqh_tp);
    } else if (cr->opcode == URMA_CR_OPC_WRITE_WITH_IMM) {
        return process_write_imm(buf, imm, umqh_tp);
    }
    return UMQ_SUCCESS;
}

static int umq_ub_dequeue_plus_with_poll_rx(uint64_t umqh_tp, urma_cr_t *cr, umq_buf_t **buf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    int qbuf_cnt = 0;
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }
    // merge rx buffer
    umq_buf_t *previous_last = NULL;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        if (process_imm_msg(umqh_tp, buf[qbuf_cnt], cr + i) == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d]\n", i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[qbuf_cnt];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        umq_ub_merge_rx_buffer(buf[qbuf_cnt], &previous_last);
        ++qbuf_cnt;
    }
    if (rx_cr_cnt != 0) {
        umq_ub_fill_rx_buffer(queue, rx_cr_cnt);
    }
    qbuf_cnt +=
        umq_report_incomplete_and_merge_rx(queue, UMQ_POST_POLL_BATCH - rx_cr_cnt, buf + qbuf_cnt, &previous_last);
    return qbuf_cnt;
}

static void umq_ub_rev_pull_tx_cqe(
    ub_queue_t *queue, umq_buf_t *cur_tx_buf, umq_buf_t **buf, int *qbuf_cnt, int *return_rx_cnt)
{
    user_ctx_t *user_ctx = (user_ctx_t *)cur_tx_buf->buf_data;
    user_ctx->wr_cnt++;
    if (user_ctx->wr_cnt == user_ctx->wr_total) {
        if (umq_ub_read_done(queue, user_ctx->msg_id) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("umq ub send imm failed\n");
        }
        umq_buf_t *tmp = cur_tx_buf;
        if (user_ctx->dst_buf) {
            cur_tx_buf = user_ctx->dst_buf;
            cur_tx_buf->io_direction = UMQ_IO_RX;
            if (*return_rx_cnt == 0) {
                buf[*return_rx_cnt] = cur_tx_buf;
            } else {
                buf[*return_rx_cnt] = cur_tx_buf;
                buf[*return_rx_cnt - 1]->qbuf_next = cur_tx_buf;
            }
            (*return_rx_cnt)++;
            ++(*qbuf_cnt);
        }
        umq_buf_free(tmp);
    }
}

static void umq_ub_non_rev_pull_tx_cqe(ub_queue_t *queue, umq_buf_t *cur_tx_buf, int *qbuf_cnt)
{
    (void)umq_buf_break_and_free(cur_tx_buf);
    ++(*qbuf_cnt);
}

static int umq_ub_dequeue_plus_with_poll_tx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf, int return_rx_cnt)
{
    umq_buf_t *tx_buf[UMQ_POST_POLL_BATCH];
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return return_rx_cnt;
    }
    int qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }
        if (cr[i].user_ctx == 0) {
            if (cr[i].opcode == URMA_CR_OPC_SEND_WITH_IMM) {
                umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            }
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        tx_buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(tx_buf[qbuf_cnt])->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_UB_PLUS && imm.bs.umq_private == UMQ_UB_IMM_PRIVATE &&
            imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            umq_ub_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], buf, &qbuf_cnt, &return_rx_cnt);
            continue;
        }
        umq_ub_non_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], &qbuf_cnt);
    }
    return return_rx_cnt;
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

int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len, uint64_t imm_value)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    /* Prepare src_sge. */
    uint8_t src = 1;
    urma_sge_t src_sge = {
        .addr = (uint64_t)(uintptr_t)&src,
        .len = 1,
        .tseg = queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };

    /* Prepare dst_sge. */
    urma_sge_t dst_sge = {
        .addr = target_addr,
        .len = len,
        .tseg = queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };

    /* WRITE to dst_sge. */
    urma_jfs_wr_t urma_wr = {
        .opcode = URMA_OPC_WRITE_IMM,
        .flag.bs.solicited_enable = URMA_SOLICITED_ENABLE,
        .flag.bs.inline_flag = URMA_INLINE_ENABLE,
        .tjetty = queue->bind_ctx->tjetty,
        .user_ctx = 0,
        .rw = { .src = {.sge = &src_sge, .num_sge = 1},
                .dst = {.sge = &dst_sge, .num_sge = 1},
                .notify_data = imm_value, },
        .next = NULL
    };

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_WRITE_IMM, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d\n", status);
        return -status;
    }
    return UMQ_SUCCESS;
}

void umq_ub_get_token(uint64_t umqh_tp, uint8_t mempool_id, uint32_t *token_id, uint32_t *token_value)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];

    *token_id = tseg->seg.token_id;
    *token_value = tseg->user_ctx;
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
    return &g_umq_ub_id_allocator;
}

umq_state_t umq_ub_state_get_impl(uint64_t umqh_tp)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    return queue->state;
}

int umq_ub_async_event_fd_get(umq_trans_info_t *trans_info)
{
    umq_ub_ctx_t *dev_ctx = NULL;

    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        if (memcmp(&g_ub_ctx[i].trans_info.dev_info, &trans_info->dev_info, sizeof(umq_dev_assign_t)) == 0) {
            dev_ctx = &g_ub_ctx[i];
            break;
        }
    }
    if (dev_ctx == NULL || dev_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR("dev_ctx invalid\n");
        return UMQ_INVALID_FD;
    }
    return dev_ctx->urma_ctx->async_fd;
}

static void handle_async_event_jfc_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfs_jfc == urma_event->element.jfc || local->jfr_jfc == urma_event->element.jfc) {
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

static void handle_async_event_jfr_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr == urma_event->element.jfr) {
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

static void handle_async_event_jfr_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr == urma_event->element.jfr) {
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

static void handle_async_event_jetty_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty == urma_event->element.jetty) {
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

static void handle_async_event_jetty_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty == urma_event->element.jetty) {
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

int umq_ub_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
    umq_ub_ctx_t *dev_ctx = NULL;

    for (uint32_t i = 0; i < g_ub_ctx_count; i++) {
        if (memcmp(&g_ub_ctx[i].trans_info.dev_info, &trans_info->dev_info, sizeof(umq_dev_assign_t)) == 0) {
            dev_ctx = &g_ub_ctx[i];
            break;
        }
    }
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
        UMQ_VLOG_ERR("get roite list failed\n");
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
    if (in->opcode != UMQ_OPCODE_FLOW_CONTROL_STATS_QUERY  || out->addr == 0 ||
        out->len != sizeof(umq_flowcontrol_stats_t)) {
        UMQ_VLOG_ERR("umq ub user ctl parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_flowcontrol_stats_t *stats = (umq_flowcontrol_stats_t *)(uintptr_t)out->addr;
    queue->flow_control.ops.stats_query(&queue->flow_control, stats);
    return UMQ_SUCCESS;
}
