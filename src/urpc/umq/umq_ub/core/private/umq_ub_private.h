/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: pervate header file for UMQ
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#ifndef UMQ_UB_PRIVATE_H
#define UMQ_UB_PRIVATE_H

#include <pthread.h>
#include <sys/queue.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>

#include "urma_api.h"
#include "umq_inner.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "umq_dfx_types.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "util_id_generator.h"
#include "umq_inner.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_ub_imm_data.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_MAX_ID_NUM (1 << 16)
#define UMQ_CONTINUE_FLAG 1
#define UMQ_MAX_TSEG_NUM (1 + (64 * HUGE_QBUF_POOL_SIZE_TYPE_MAX))
#define UMQ_UB_RW_SEGMENT_LEN 64 // ub_queue read/write buf splited 64B for each module, such as mem import/flow control
#define HUGE_QBUF_BUFFER_INC_BATCH 64
#define UMQ_QBUF_ALIGN_SIZE 4096

#define UMQ_UB_MAX_REMOTE_EID_NUM 1024
#define UMQ_UB_MIN_EID_ID 0

#define MEMPOOL_UBVA_SIZE 28
#define UMQ_IMM_VERSION 0
#define UMQ_UB_FLOW_CONTORL_JETTY_DEPTH 2
#define UMQ_UB_FLOW_CONTORL_BIT_SHIFIT 16 // use (ack | notify) as flow control tx ctx

#define UMQ_UB_DEV_STR_LENGTH 64
#define UMQ_UB_NAMESPACE_SIZE 256
#define UMQ_UB_NAMESPACE_PATH "/proc/self/ns/net"

typedef enum umq_size_interval {
    UMQ_SIZE_0K_SMALL_INTERVAL,     // (0K, umq_buf_size_small()] size
    UMQ_SIZE_SMALL_MID_INTERVAL,    // (umq_buf_size_small(), umq_buf_size_middle()] size
    UMQ_SIZE_MID_BIG_INTERVAL,      // (umq_buf_size_middle(), umq_buf_size_big()] size
    UMQ_SIZE_BIG_HUGE_INTERVAL,     // (umq_buf_size_big(), umq_buf_size_huge()] size
    UMQ_SIZE_HUGE_GIGANTIC_INTERVAL, // (umq_buf_size_huge(), umq_buf_size_gigantic()] size
    UMQ_SIZE_INTERVAL_MAX,
} umq_size_interval_t;

typedef enum umq_imm_protocol_type {
    IMM_PROTOCAL_TYPE_NONE = 0,
    IMM_PROTOCAL_TYPE_IMPORT_MEM = 1,
} umq_imm_protocol_type_t;

typedef enum ub_queue_jetty_index {
    UB_QUEUE_JETTY_IO,
    UB_QUEUE_JETTY_FLOW_CONTROL, // flow control jetty only send imm without data

    UB_QUEUE_JETTY_NUM,
} ub_queue_jetty_index_t;

typedef struct umq_imm_head {
    uint32_t version : 8;
    uint32_t type : 8;
    uint32_t mem_interval : 4;
    uint32_t mempool_num : 12;
} umq_imm_head_t;

typedef struct ub_ref_sge {
    uint64_t addr;
    uint32_t length;
    uint32_t token_id : 20;
    uint32_t mempool_id : 12;
    uint32_t token_value;
} ub_ref_sge_t;

typedef struct ub_import_mempool_info {
    char mempool_ubva[MEMPOOL_UBVA_SIZE];
    uint32_t mempool_seg_flag;
    uint32_t mempool_length;
    uint32_t mempool_token_id : 20;
    uint32_t mempool_id : 12;
    uint32_t mempool_token_value;
} ub_import_mempool_info_t;

typedef enum ub_packet_stats_type {
    UB_PACKET_STATS_TYPE_SEND,
    UB_PACKET_STATS_TYPE_SEND_SUCCESS,
    UB_PACKET_STATS_TYPE_RECV,
    UB_PACKET_STATS_TYPE_SEND_ERROR,
    UB_PACKET_STATS_TYPE_RECV_ERROR,
    UB_PACKET_STATS_TYPE_MAX,
} ub_packet_stats_type_t;

struct ub_flow_control;
struct ub_queue;
typedef struct ub_flow_control_window_ops {
    // update tx window after receive IMM_TYPE_FLOW_CONTROL
    uint16_t (*remote_rx_window_inc)(struct ub_flow_control *fc, uint16_t new_win, bool is_return_rollback);
    // alloc tx window, may return [0, required_win]
    uint16_t (*remote_rx_window_dec)(struct ub_flow_control *fc, uint16_t required_win, bool is_return);
    // load current tx window
    uint16_t (*remote_rx_window_load)(struct ub_flow_control *fc);
    uint64_t (*local_rx_allocated_inc)(struct ub_flow_control *fc, uint16_t new_win);
    uint16_t (*local_rx_allocated_dec)(struct ub_flow_control *fc, uint16_t required_win);
    uint64_t (*local_rx_allocated_load)(struct ub_flow_control *fc);
    void (*stats_query)(struct ub_flow_control *fc, struct ub_queue *queue, umq_flow_control_stats_t *out);
    void (*packet_stats)(struct ub_flow_control *fc, uint32_t cnt, ub_packet_stats_type_t type);
} ub_flow_control_window_ops_t;

typedef enum ub_queue_fc_stat_u16 {
    FC_COUNTER_MAX_U16
} ub_queue_fc_stat_u16_t;

typedef enum ub_queue_fc_stat_u64 {
    ALLOCATED_SUCCESS, // credits successfully allocated to the peer
    ALLOCATED_TOTAL, // the total num  of credits allocated to the peer
    FC_COUNTER_MAX_U64
} ub_queue_fc_stat_u64_t;

typedef struct ub_flow_control {
    ub_flow_control_window_ops_t ops;
    volatile uint64_t total_local_rx_posted;
    volatile uint64_t total_local_rx_notified;
    volatile uint64_t total_local_rx_posted_error;
    volatile uint64_t total_remote_rx_received;
    volatile uint64_t total_remote_rx_consumed;
    volatile uint64_t total_remote_rx_received_error;
    volatile uint64_t total_flow_controlled_wr;
    volatile uint64_t packet_stats[UB_PACKET_STATS_TYPE_MAX];
    volatile uint64_t stats_u64[FC_COUNTER_MAX_U64];
    uint64_t remote_win_buf_addr;
    uint32_t remote_win_buf_len;
    volatile uint16_t local_rx_posted;
    volatile uint16_t remote_rx_window;
    volatile uint16_t stats_u16[FC_COUNTER_MAX_U16];
    uint16_t credits_per_request;
    uint16_t max_credits_request;
    uint16_t initial_credit;
    uint16_t credit_request_threshold;
    uint16_t return_ratio;
    uint16_t min_reserved_credit;
    float credit_multiple;
    uint16_t local_tx_depth;
    uint16_t local_rx_depth;
    uint16_t remote_tx_depth;
    uint16_t remote_rx_depth;
    uint32_t timeout_us;
    bool local_set;
    bool remote_get;
    bool enabled;
    volatile bool is_credit_applying;
} ub_flow_control_t;

typedef struct remote_eid_hmap_node {
    struct urpc_hmap_node node;
    urma_eid_t eid;
    uint32_t pid;
    char remote_namespace[UMQ_UB_NAMESPACE_SIZE];
    uint32_t remote_eid_id;
    uint32_t ref_cnt;
} remote_eid_hmap_node_t;

typedef struct remote_imported_tseg_info {
    bool tesg_imported[UMQ_UB_MAX_REMOTE_EID_NUM][UMQ_MAX_TSEG_NUM];
    urma_target_seg_t *imported_tseg_list[UMQ_UB_MAX_REMOTE_EID_NUM][UMQ_MAX_TSEG_NUM];
    pthread_mutex_t imported_tseg_list_mutex[UMQ_UB_MAX_REMOTE_EID_NUM];
    struct urpc_hmap remote_eid_id_table;
    pthread_mutex_t remote_eid_id_table_lock;
    util_id_allocator_t eid_id_allocator;
} remote_imported_tseg_info_t;

typedef struct umq_ub_ctx {
    bool io_lock_free;
    volatile uint32_t ref_cnt;
    uint32_t feature;
    umq_flow_control_cfg_t flow_control;
    urma_context_t *urma_ctx;
    urma_device_attr_t dev_attr;
    umq_dev_assign_t dev_info;
    urma_target_seg_t *tseg_list[UMQ_MAX_TSEG_NUM];
    remote_imported_tseg_info_t *remote_imported_info;
    urma_target_jetty_t *tjetty;
    umq_trans_info_t trans_info;
    uint64_t remote_notify_addr;
    uint64_t *umq_ctx_jetty_table;
    volatile uint64_t *rx_consumed_jetty_table;
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

typedef enum umq_ub_bind_version {
    UMQ_UB_BIND_VERSION_0 = 0,
    UMQ_UB_BIND_VERSION_MAX,
} umq_ub_bind_version_t;

#define UMQ_UB_BIND_VERSION (0)

typedef enum umq_ub_bind_info_type {
    UMQ_UB_BIND_INFO_TYPE_VERSION = 0x10000,
    UMQ_UB_BIND_INFO_TYPE_DEV,
    UMQ_UB_BIND_INFO_TYPE_QUEUE,
    UMQ_UB_BIND_INFO_TYPE_FC,
    UMQ_UB_BIND_INFO_TYPE_MAX,
} umq_ub_bind_info_type_t;

typedef struct umq_ub_bind_version_info {
    uint32_t version;
} umq_ub_bind_version_info_t;

typedef struct umq_ub_bind_dev_info {
    umq_trans_mode_t umq_trans_mode;
    urma_target_seg_t tseg;
    umq_buf_mode_t buf_pool_mode;
    uint32_t feature;
    uint32_t pid;
    uint32_t namespace_len;
    char bind_namespace[0];
} umq_ub_bind_dev_info_t;

typedef struct umq_ub_bind_queue_info {
    uint8_t is_binded;
    urma_jetty_grp_policy_t policy;
    urma_jetty_id_t jetty_id;
    urma_order_type_t order_type;
    urma_target_type_t type;
    urma_transport_mode_t tp_mode;
    urma_tp_type_t tp_type;
    urma_token_t token;
    uint64_t notify_buf;
    uint32_t rx_depth;
    uint32_t tx_depth;
    uint32_t rx_buf_size;
    umq_state_t state;
} umq_ub_bind_queue_info_t;

typedef struct umq_ub_bind_fc_info {
    urma_jetty_id_t jetty_id;
    urma_token_t token;
    uint64_t win_buf_addr;
    uint32_t win_buf_len;
} umq_ub_bind_fc_info_t;

typedef struct umq_ub_bind_info {
    umq_ub_bind_version_info_t *version_info;
    umq_ub_bind_dev_info_t *dev_info;
    umq_ub_bind_queue_info_t *queue_info;
    umq_ub_bind_fc_info_t *fc_info;
} umq_ub_bind_info_t;

typedef struct ub_bind_ctx {
    urma_target_jetty_t *tjetty[UB_QUEUE_JETTY_NUM];
    uint32_t remote_pid;
    char remote_namespace[UMQ_UB_NAMESPACE_SIZE];
    uint32_t remote_eid_id;
    uint64_t remote_notify_addr;
} ub_bind_ctx_t;

struct ub_credit_pool;
typedef struct ub_credit_pool_ops {
    // update shared jfr rx_posted after post rx buffer
    uint16_t (*available_credit_inc)(struct ub_credit_pool *shared_credit, uint16_t count);
    // distribute x in batch
    uint16_t (*available_credit_dec)(struct ub_credit_pool *shared_credit, uint16_t count);
    // return unused credit
    uint16_t (*available_credit_return)(struct ub_credit_pool *shared_credit, uint16_t count);
    uint16_t (*allocated_credit_dec)(struct ub_credit_pool *shared_credit, uint16_t count);
    void (*stats_query)(struct ub_credit_pool *fc, umq_credit_pool_stats_t *out);
} ub_credit_pool_ops_t;

typedef enum ub_credit_stat_u64 {
    CREDIT_POOL_IDLE_TOTAL = 0,     // the total number of idle credit in the statistics pool
    CREDIT_POOL_ALLOCATED_TOTAL,    // the total number of credit allocated from the credit pool
    CREDIT_POOL_ERR_TOTAL,          // invalid total credit count (which will cause pool_idle statistics failure)
    CREDIT_COUNTER_MAX_U64
} ub_credit_stat_u64_t;

typedef enum ub_credit_stat_u16 {
    CREDIT_POOL_IDLE = 0,           // the number of credits available in the current credit pool
    CREDIT_POOL_ALLOCATED,          // the number of credit currently be allocated form the credit pool
    CREDIT_COUNTER_MAX_U16
} ub_credit_stat_u16_t;

typedef struct ub_credit_pool {
    ub_credit_pool_ops_t ops;
    volatile uint64_t stats_u64[CREDIT_COUNTER_MAX_U64];
    volatile uint16_t stats_u16[CREDIT_COUNTER_MAX_U16];
    uint16_t capacity;
} ub_credit_pool_t;

typedef struct jfr_ctx {
    urma_jfr_t *jfr;
    urma_jfc_t *jfr_jfc;
    urma_jfce_t *jfr_jfce; // io and flow control jetty share same jfce
    volatile uint32_t ref_cnt;
    rx_buf_ctx_list_t rx_buf_ctx_list;
    ub_credit_pool_t credit;
} jfr_ctx_t;

typedef struct ub_queue_interrupt_ctx {
    bool tx_io_interrupt;
    bool rx_io_interrupt;
    bool tx_fc_interrupt;
    bool rx_fc_interrupt;
} ub_queue_interrupt_ctx_t;

typedef struct wait_ack_import {
    uint16_t *wait_ack_pool_id;
    uint16_t wait_ack_idx;
    pthread_rwlock_t lock;
} wait_ack_import_t;

typedef struct ub_queue_idle_check {
    urpc_list_t node;
    struct ub_queue *umq;
    volatile uint64_t last_send;
    volatile uint64_t target_slot_id;
    volatile bool need_return_credit;
    int event_fd;
    pthread_mutex_t lock;
} ub_queue_idle_check_t;

typedef struct ub_queue {
    urpc_list_t qctx_node;
    // queue param
    urma_jetty_t *jetty[UB_QUEUE_JETTY_NUM];
    jfr_ctx_t *jfr_ctx[UB_QUEUE_JETTY_NUM];
    urma_jfc_t *jfs_jfc[UB_QUEUE_JETTY_NUM];
    urma_jfce_t *jfs_jfce; // io and flow control jetty share same jfce
    ub_queue_interrupt_ctx_t interrupt_ctx;
    umq_ub_ctx_t *dev_ctx;
    struct ub_bind_ctx *bind_ctx;
    volatile uint32_t ref_cnt;
    volatile uint32_t require_rx_count;
    volatile uint32_t tx_outstanding;
    volatile uint64_t packet_stats[UB_PACKET_STATS_TYPE_MAX];
    uint32_t create_flag;
    uint64_t umq_ctx;
    urma_target_seg_t **imported_tseg_list;   // read-only
    umq_buf_t *addr_list;
    wait_ack_import_t wait_ack_import;

    // config param
    umq_trans_mode_t umq_trans_mode;
    urma_order_type_t order_type;
    urma_transport_mode_t tp_mode;
    urma_tp_type_t tp_type;
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
    umq_buf_t *notify_buf;      // qbuf for manage message exchange, such as mem import/initial flow control window
    uint64_t umqh;
    uint64_t share_rq_umqh;
    ub_queue_idle_check_t *checker;
} ub_queue_t;

typedef struct user_ctx {
    umq_buf_t *dst_buf;
    uint32_t wr_cnt;
    uint32_t wr_total;
    uint32_t msg_id;
} user_ctx_t;

typedef struct ub_queue_ctx_list {
    urpc_list_t queue_list;
    pthread_rwlock_t lock;
} ub_queue_ctx_list_t;

typedef struct xchg_mem_info {
    uint64_t seg_len;
    uint32_t seg_token_id;
    urma_import_seg_flag_t seg_flag;
    urma_token_t token;
    urma_ubva_t ubva;
} __attribute__((packed)) xchg_mem_info_t;

typedef enum umq_ub_rw_segment_offset {
    OFFSET_MEM_IMPORT = 0,
    OFFSET_FLOW_CONTROL, // 16bit local window, 16bit remote window
} umq_ub_rw_segment_offset_t;

typedef struct umq_ub_raw_dev {
    urma_device_t *urma_dev;
    umq_eid_t eid;
    uint32_t eid_index;
} umq_ub_raw_dev_t;

static inline uint64_t umq_ub_notify_buf_addr_get(ub_queue_t *queue, umq_ub_rw_segment_offset_t offset)
{
    return (uint64_t)((uintptr_t)queue->notify_buf->buf_data + offset * UMQ_UB_RW_SEGMENT_LEN);
}

int rx_buf_ctx_list_init(rx_buf_ctx_list_t *rx_buf_ctx_list, uint32_t ctx_num);
void rx_buf_ctx_list_uninit(rx_buf_ctx_list_t *rx_buf_ctx_list);
umq_buf_t *umq_get_buf_by_user_ctx(ub_queue_t *queue, uint64_t user_ctx, ub_queue_jetty_index_t jetty_index);

// for control plane on umq ub api
int umq_ub_post_rx_inner_impl(ub_queue_t *queue, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
int umq_ub_data_plan_import_mem(uint64_t umqh_tp, umq_buf_t *rx_buf, uint32_t ref_seg_num, bool send_ack);
rx_buf_ctx_t *queue_rx_buf_ctx_flush(rx_buf_ctx_list_t *rx_buf_ctx_list);

int umq_ub_post_rx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
int umq_ub_post_tx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
int umq_ub_poll_rx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count);
int umq_ub_poll_tx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count);

// token
uint32_t token_policy_get(bool enable);
int umq_ub_token_generate(bool enable_token, uint32_t *token);
int umq_ub_bind_info_check(ub_queue_t *queue, umq_ub_bind_info_t *info);
int umq_ub_eid_id_release(remote_imported_tseg_info_t *remote_imported_info, ub_bind_ctx_t *ctx);
int umq_ub_bind_inner_impl(ub_queue_t *queue, umq_ub_bind_info_t *info);
uint32_t umq_ub_bind_info_serialize(ub_queue_t *queue, uint8_t *bind_info, uint32_t bind_info_size);
int umq_ub_bind_info_deserialize(uint8_t *bind_info_buf, uint32_t bind_info_size, umq_ub_bind_info_t *bind_info);
int umq_modify_ubq_to_err(ub_queue_t *queue, umq_io_direction_t direction, ub_queue_jetty_index_t jetty_idx);
remote_imported_tseg_info_t *umq_ub_ctx_imported_info_create(void);
void umq_ub_ctx_imported_info_destroy(umq_ub_ctx_t *ub_ctx);
urma_jetty_t *umq_create_jetty(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, ub_queue_jetty_index_t jetty_idx);
int check_and_set_param(umq_ub_ctx_t *dev_ctx, umq_create_option_t *option, ub_queue_t *queue);
int umq_ub_register_seg(umq_ub_ctx_t *ctx, uint16_t mempool_id, void *addr, uint64_t size);
void umq_ub_unregister_seg(umq_ub_ctx_t *ctx_list, uint32_t ctx_cnt, uint16_t mempool_id);
int share_rq_param_check(ub_queue_t *queue, ub_queue_t *share_rq);
void umq_ub_jfr_ctx_put(ub_queue_t *queue);
int umq_ub_jfr_ctx_get(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, umq_create_option_t *option,
                       ub_queue_t *share_queue);
jfr_ctx_t *umq_ub_jfr_ctx_create(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, ub_queue_jetty_index_t jetty_idx);
void umq_ub_jfr_ctx_destroy(ub_queue_t *queue, ub_queue_jetty_index_t jetty_idx);
int umq_status_convert(urma_status_t urma_status);
umq_tp_mode_t umq_tp_mode_convert(urma_transport_mode_t tp_mode);
umq_tp_type_t umq_tp_type_convert(urma_tp_type_t tp_type);

// hanele async event
void handle_async_event_jfc_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event);
void handle_async_event_jfr_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event);
void handle_async_event_jfr_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event);
void handle_async_event_jetty_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event);
void handle_async_event_jetty_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event);

// queue ctx list
void umq_ub_queue_ctx_list_init(void);
void umq_ub_queue_ctx_list_uninit(void);
void umq_ub_queue_ctx_list_push(urpc_list_t *qctx_node);
void umq_ub_queue_ctx_list_remove(urpc_list_t *qctx_node);

// msg id
int umq_ub_id_allocator_init(void);
void umq_ub_id_allocator_uninit(void);
util_id_allocator_t *umq_ub_id_allocator_get(void);

umq_buf_t *umq_ub_read_ctx_create(ub_queue_t *queue, umq_imm_head_t *umq_imm_head, uint16_t buf_num, uint16_t msg_id);

int umq_ub_plus_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr,
                             urma_sge_t *sges, uint32_t remain_tx);
int umq_ub_dequeue_plus_with_poll_tx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf, int return_rx_cnt);
uint32_t umq_ub_ref_sge_cnt(umq_buf_t *buffer);

typedef struct mempool_info_ctx {
    ub_import_mempool_info_t *import_mempool_info;
    umq_imm_head_t *umq_imm_head;
    bool mempool_info_record[UMQ_MAX_TSEG_NUM];
} mempool_info_ctx_t;

int fill_big_data_ref_sge(ub_queue_t *queue, ub_ref_sge_t *ref_sge, umq_buf_t *buffer, mempool_info_ctx_t *ctx);
void umq_ub_fill_rx_buffer(ub_queue_t *queue, int rx_cnt);
int umq_ub_dequeue_with_poll_rx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf);
int umq_ub_dequeue_plus_with_poll_rx(uint64_t umqh_tp, urma_cr_t *cr, umq_buf_t **buf);
void process_bad_qbuf(umq_buf_t *bad_qbuf, umq_buf_t *qbuf, ub_queue_t *queue);
void umq_ub_enqueue_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf);
void umq_ub_enqueue_plus_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf);
void umq_flush_rx(ub_queue_t *queue, uint32_t max_retry_times);
void umq_flush_tx(ub_queue_t *queue, uint32_t max_retry_times);
void ub_fill_umq_imm_head(umq_imm_head_t *umq_imm_head, umq_buf_t *buffer);
int umq_ub_send_imm(ub_queue_t *queue, uint64_t imm_value, urma_sge_t *sge, uint64_t user_ctx);
int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len, uint64_t imm_value);
int umq_ub_read(uint64_t umqh_tp, umq_buf_t *rx_buf, umq_ub_imm_t imm);
int umq_ub_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr,
                        urma_sge_t *sges, uint32_t remain_tx);

int umq_ub_fill_fc_rx_buf(ub_queue_t *queue);
uint32_t umq_ub_poll_fc_rx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count);
int umq_ub_poll_fc_tx(ub_queue_t *queue);

int umq_ub_wait_rx_interrupt(ub_queue_t *queue, int time_out, urma_jfc_t *jfc[]);
int umq_ub_wait_tx_interrupt(ub_queue_t *queue, int time_out, urma_jfc_t *jfc[]);
int umq_flow_control_stats_get(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats);
uint32_t umq_ub_timer_timeout_get(void);
int umq_ub_queue_addr_list_alloc(ub_queue_t *queue);
void umq_ub_queue_addr_list_record(umq_buf_t *addr_list, uint16_t msg_id, umq_buf_t *buf);
umq_buf_t *umq_ub_queue_addr_list_remove(umq_buf_t *addr_list, uint16_t msg_id);
void umq_ub_ack_import_tseg(ub_queue_t *queue);

// dev info
int umq_ub_dev_str_get(umq_dev_assign_t *dev_info, char *dev_str, int dev_str_len);
int umq_ub_dev_info_init(void);
void umq_ub_dev_info_uninit(void);
int umq_ub_dev_num_get(void);
void umq_ub_dev_info_dump(umq_trans_mode_t umq_trans_mode, int num, umq_dev_info_t *out);
int umq_ub_dev_info_dump_by_name(char *dev_name, umq_trans_mode_t umq_trans_mode, umq_dev_info_t *out);
int umq_ub_dev_lookup_by_name(char *dev_name, uint32_t eid_index, umq_ub_raw_dev_t *out);
int umq_ub_dev_lookup_by_eid(umq_eid_t *eid, umq_ub_raw_dev_t *out);
int umq_ub_get_urma_dev(umq_dev_assign_t *dev_info, urma_device_t **urma_dev, umq_eid_t *eid, uint32_t *eid_index);
umq_ub_ctx_t *umq_ub_get_ub_ctx_by_dev_info(umq_ub_ctx_t *ub_ctx_list, uint32_t ub_ctx_cnt, umq_dev_assign_t *dev_info);
int umq_ub_create_urma_ctx(urma_device_t *urma_dev, uint32_t eid_index, umq_ub_ctx_t *ub_ctx);
int umq_ub_delete_urma_ctx(umq_ub_ctx_t *ub_ctx);

static ALWAYS_INLINE void umq_ub_io_packet_stats(
    ub_queue_t *queue, ub_packet_stats_type_t type, uint32_t cnt, bool lock_free)
{
    if ((queue->dev_ctx->feature & UMQ_FEATURE_ENABLE_STATS) == 0) {
        return;
    }

    if (lock_free) {
        queue->packet_stats[type] += cnt;
    } else {
        (void)__atomic_add_fetch(&queue->packet_stats[type], cnt, __ATOMIC_RELAXED);
    }
}

#ifdef __cplusplus
}
#endif

#endif