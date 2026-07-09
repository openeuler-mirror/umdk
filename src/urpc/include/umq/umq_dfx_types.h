/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Public header file of UMQ dfx types
 * Create: 2026-2-4
 * Note:
 * History: 2026-2-4
 */

#ifndef UMQ_DFX_TYPES_H
#define UMQ_DFX_TYPES_H

#include <stdlib.h>
#include <stdint.h>
#include "umq_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_STATS_QBUF_POOL_TYPE_MAX (16u)
#define UMQ_PERF_QUANTILE_CNT (4u)
#define UMQ_PERF_QUANTILE_P50   (0u)
#define UMQ_PERF_QUANTILE_P90   (1u)
#define UMQ_PERF_QUANTILE_P99   (2u)
#define UMQ_PERF_QUANTILE_P9999 (3u)
#define UMQ_PERF_REC_MAX_NUM (64u)
#define UMQ_DFX_TO_STRING_DEFAULT_LEN (20480)
#define UMQ_LOCAL_QBUF_POOL_MAX_NUM (64)

typedef struct umq_packet_stats {
    uint64_t send_cnt;              // number of packets sent
    uint64_t send_success;          // number of packets successfully sent
    uint64_t recv_cnt;              // number of packets received
    uint64_t send_eagain_cnt;       // number of packets failed to send due to flowcontrol eagain
    uint64_t send_error_cnt;        // number of packets failed to send
    uint64_t recv_error_cnt;        // number of packets failed to receive
    uint64_t recv_duplicate_req_cnt;      // number of duplicate flow control request packets received
    uint64_t recv_duplicate_rsp_cnt;      // number of duplicate flow control response packets received
} umq_packet_stats_t;

typedef struct umq_credit_pool_stats {
    /* current actual statistics of the system */
    uint64_t pool_idle; // the number of credits currently available in the credit pool
    uint64_t pool_be_allocated; // the number of credits currently allocated and taken from the credit pool
    uint64_t rsvd0[2];

    /* cumulative statistics */
    uint64_t total_pool_idle; // the total number of available credits in the current credit pool.
    uint64_t total_pool_be_allocated; // the total number of credits currently allocated and taken from the credit pool
    uint64_t rsvd1[2];

    /* error in statistics */
    uint64_t total_pool_post_rx_err; // the total number of invalid credits (which will cause `pool_idle` to overflow)
    uint64_t rsvd2[2];
} umq_credit_pool_stats_t;

typedef struct umq_credit_private_stats {
    /* current actual statistics at the queue level */
    uint64_t queue_idle; // credits to be allocated to the peer (no practical use, always 0, reserved field)
    uint64_t queue_be_allocated; // credits already be allocated to the peer, used for rx direction receive io
    uint64_t queue_acquired; // credits acquired from the peer, used for tx direction send io
    uint64_t rsvd0[2];

    /* cumulative statistics at the queue level */
    uint64_t total_queue_idle; // the total number of credits to be allocated to the peer
    uint64_t total_queue_acquired; // the total number of credits obtained from the peer
    uint64_t total_queue_be_allocated; // the total number of credits already be allocated to the peer
    uint64_t total_queue_post_tx_success; // the total number of already consumed credits in the tx direction
    uint64_t rsvd1[2];

    /* error in statistics */
    uint64_t total_queue_post_tx_err; // the total number of transmitted io that failed in the tx direction
    uint64_t total_queue_acquired_err; // the total number of credits obtained from the peer that were invalid
    uint64_t rsvd[4];
} umq_credit_private_stats_t;

typedef struct umq_flow_control_stats {
    umq_credit_pool_stats_t pool_credit; // credit-related statistics of a main queue
    umq_credit_private_stats_t queue_credit; // credit-related statistics of a specific queue
    umq_packet_stats_t packet_stats; // flow control packet statistics
} umq_flow_control_stats_t;

typedef struct umq_expansion_pool_stats {
    uint32_t expansion_count;               // number of expansions performed
    uint64_t exp_total_block_num;           // total number of blocks in the expansion pool
    uint64_t exp_total_free_block_num;      // number of free blocks in the expansion pool
    uint64_t exp_total_mem_size;            // total memory of the expansion pool
    uint64_t exp_used_mem_size;             // used memory of the expansion pool
    uint64_t total_expansion_count;         // cumulative number of expansions
    uint64_t total_shrink_count;            // cumulative number of contractions
} umq_expansion_pool_stats_t;

typedef enum umq_qbuf_pool_type {
    UMQ_QBUF_POOL_TYPE_SMALL,
    UMQ_QBUF_POOL_TYPE_MEDIUM,
    UMQ_QBUF_POOL_TYPE_BIG,
    UMQ_QBUF_POOL_TYPE_HUGE,
    UMQ_QBUF_POOL_TYPE_GIGANTIC,
    UMQ_QBUF_POOL_TYPE_TINY,
    UMQ_QBUF_POOL_TYPE_MAX,
} umq_qbuf_pool_type_t;

typedef struct umq_local_qbuf_pool_stats {
    umq_qbuf_pool_type_t type;                 // qbuf pool type
    uint64_t tid;                              // thread ID
    uint64_t capacity_with_data;               // capacity of with-data buffer in the local memory pool
    uint64_t buf_cnt_with_data;                // number of with-data buffer in the local memory pool
    uint64_t capacity_without_data;            // capacity of without-data buffer in the local memory pool
    uint64_t buf_cnt_without_data;             // number of without-data buffer in the local memory pool
    uint64_t tls_fetch_cnt_with_data;          // total number of times buffer(withdata) acquired from the global pool
    uint64_t tls_fetch_buf_cnt_with_data;      // total number of buffer(withdata) acquired from the global pool
    uint64_t tls_fetch_cnt_without_data;       // total number of times buffer(nodata) acquired from the global pool
    uint64_t tls_fetch_buf_cnt_without_data;   // total number of buffer(withdata) acquired from the global pool
    uint64_t tls_return_cnt_with_data;         // total number of times buffer(withdata) returned to the global pool
    uint64_t tls_return_buf_cnt_with_data;     // total number of buffer(withdata) returned to the global pool
    uint64_t tls_return_cnt_without_data;      // total number of times buffer(nodata) returned to the global pool
    uint64_t tls_return_buf_cnt_without_data;  // total number of buffer(nodata) returned to the global pool
    uint64_t alloc_cnt_with_data;              // total number of buffer(withdata) allocation requests
    uint64_t alloc_cnt_without_data;           // total number of buffer(nodata) allocation requests
    uint64_t free_cnt_with_data;               // total number of buffer(withdata) free requests
    uint64_t free_cnt_without_data;            // total number of buffer(nodata) free requests
} umq_local_qbuf_pool_stats_t;

typedef struct umq_qbuf_pool_info {
    umq_qbuf_pool_type_t type;                 // qbuf pool type
    umq_buf_mode_t mode;                      // split or combine
    uint64_t total_size;                      // qbuf pool total size
    uint64_t total_block_num;                 // total number of blocks
    uint32_t block_size;                      // the size of each block in the memory pool
    uint32_t headroom_size;                   // header size of umq buffer
    uint32_t data_size;                       // combine: block_size - umq_buf_t_size, split: block_size
    uint32_t buf_size;                        // combine: block_size, split: block_size + umq_buf_t_size
    uint32_t umq_buf_t_size;                  // size of umq_buf_t
    union {
        struct {
            uint64_t block_num_with_data;     // number of available buf in data area
            uint64_t size_with_data;          // available buf size in data area
            uint64_t block_num_without_data;  // number of available buf in non-data area
            uint64_t size_without_data;       // available buf size in non-data area
        } split;
        struct {
            uint64_t block_num_with_data;
            uint64_t size_with_data;
        } combine;
    } available_mem;
} umq_qbuf_pool_info_t;

typedef struct umq_qbuf_pool_stats {
    umq_qbuf_pool_info_t qbuf_pool_info[UMQ_STATS_QBUF_POOL_TYPE_MAX]; // statistical information list for qbuf pool
    uint32_t num; // number of valid qbuf pool info structures

    umq_expansion_pool_stats_t exp_pool_with_data;  // with_data expansion pool statistics
    umq_expansion_pool_stats_t exp_pool_without_data; // without_data expansion pool statistics

    umq_local_qbuf_pool_stats_t local_qbuf_pool_stats[UMQ_LOCAL_QBUF_POOL_MAX_NUM]; // local buf pool statistics
    uint32_t local_qbuf_pool_num; // local buf pool statistics count

    // escape
    uint64_t escape_buf_cnt;
} umq_qbuf_pool_stats_t;

typedef struct umq_info {
    umq_trans_mode_t trans_mode; // transmission mode of the queue
    union {
        struct {
            uint32_t umq_id; // the ID of the UMQ
            umq_eid_t eid; // the EID used by the UMQ
            char dev_name[UMQ_DEV_NAME_SIZE]; // the UDMA device name corresponding to the EID
            uint32_t local_io_jetty_id; // the I/O jetty ID within the UMQ
            uint32_t local_fc_jetty_id; // the flow control jetty ID within the UMQ
            uint32_t remote_io_jetty_id; // the I/O jetty ID of the peer UMQ that is bound to the local UMQ
            uint32_t remote_fc_jetty_id; // the flow control jetty ID of the peer UMQ that is bound to the local UMQ
        } ub;
    };
} umq_info_t;

typedef enum umq_perf_record_type {
    /* record point for umq_enqueue */
    UMQ_PERF_RECORD_ENQUEUE,
    /* record point for umq_dequeue */
    UMQ_PERF_RECORD_DEQUEUE,
    /* record point for umq_dequeue empty */
    UMQ_PERF_RECORD_DEQUEUE_EMPTY,
    /* record point for umq_post_all */
    UMQ_PERF_RECORD_POST_ALL,
    /* record point for umq_post_tx */
    UMQ_PERF_RECORD_POST_TX,
    /* record point for umq_post_rx */
    UMQ_PERF_RECORD_POST_RX,
    /* record point for umq_poll_all */
    UMQ_PERF_RECORD_POLL_ALL,
    /* record point for umq_poll_tx */
    UMQ_PERF_RECORD_POLL_TX,
    /* record point for umq_poll_rx */
    UMQ_PERF_RECORD_POLL_RX,
    /* record point for umq_poll_all when poll is empty */
    UMQ_PERF_RECORD_POLL_ALL_EMPTY,
    /* record point for umq_poll_tx when tx is empty */
    UMQ_PERF_RECORD_POLL_TX_EMPTY,
    /* record point for umq_poll_rx when rx is empty */
    UMQ_PERF_RECORD_POLL_RX_EMPTY,
    /* record point for umq_rearm_interrupt tx */
    UMQ_PERF_RECORD_REARM_TX,
    /* record point for umq_rearm_interrupt rx */
    UMQ_PERF_RECORD_REARM_RX,
    /* record point for umq_wait_interrupt rx */
    UMQ_PERF_RECORD_WAIT_TX,
    /* record point for umq_wait_interrupt tx */
    UMQ_PERF_RECORD_WAIT_RX,
    /* record point for umq_ack_interrupt tx */
    UMQ_PERF_RECORD_ACK_TX,
    /* record point for umq_ack_interrupt rx */
    UMQ_PERF_RECORD_ACK_RX,
    /* record point for umq_notify */
    UMQ_PERF_RECORD_NOTIFY,
    /* record point for umq_buf_alloc */
    UMQ_PERF_RECORD_BUF_ALLOC,
    /* record point for umq_buf_free */
    UMQ_PERF_RECORD_BUF_FREE,
    /* record point for umq_data_to_head */
    UMQ_PERF_RECORD_BUF_DATA_TO_HEAD,

    /* record point for umq_create */
    UMQ_PERF_RECORD_CREATE,
    /* record point for umq_destroy */
    UMQ_PERF_RECORD_DESTROY,
    /* record point for umq_get_route_list */
    UMQ_PERF_RECORD_ROUTE_LIST_GET,
    /* record point for umq_bind_info_get */
    UMQ_PERF_RECORD_BIND_INFO_GET,
    /* record point for umq_bind */
    UMQ_PERF_RECORD_BIND,
    /* record point for umq_unbind */
    UMQ_PERF_RECORD_UNBIND,

    /* record point for transport post send in umq_enqueue and umq_post */
    UMQ_PERF_RECORD_TRANSPORT_POST_SEND,
    /* record point for transport post recv in umq_enqueue and umq_post */
    UMQ_PERF_RECORD_TRANSPORT_POST_RECV,
    /* record point for transport post send get eagain in umq_enqueue and umq_post */
    UMQ_PERF_RECORD_TRANSPORT_POST_SEND_EAGAIN,
    /* record point for transport poll tx in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_POLL_TX,
    /* record point for transport poll rx in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_POLL_RX,
    /* record point for transport poll tx in umq_dequeue and umq_poll when tx is empty */
    UMQ_PERF_RECORD_TRANSPORT_POLL_TX_EMPTY,
    /* record point for transport poll rx in umq_dequeue and umq_poll when rx is empty */
    UMQ_PERF_RECORD_TRANSPORT_POLL_RX_EMPTY,
    /* record point for transport rearm interrupt tx */
    UMQ_PERF_RECORD_TRANSPORT_REARM_TX,
    /* record point for transport rearm interrupt rx */
    UMQ_PERF_RECORD_TRANSPORT_REARM_RX,
    /* record point for transport wait interrupt rx */
    UMQ_PERF_RECORD_TRANSPORT_WAIT_TX,
    /* record point for transport wait interrupt tx */
    UMQ_PERF_RECORD_TRANSPORT_WAIT_RX,
    /* record point for transport ack interrupt tx */
    UMQ_PERF_RECORD_TRANSPORT_ACK_TX,
    /* record point for transport ack interrupt rx */
    UMQ_PERF_RECORD_TRANSPORT_ACK_RX,

    /* record point for transport JFCE create */
    UMQ_PERF_RECORD_TRANSPORT_CREATE_JFCE,
    /* record point for transport JFC create */
    UMQ_PERF_RECORD_TRANSPORT_CREATE_JFC,
    /* record point for transport JFR create */
    UMQ_PERF_RECORD_TRANSPORT_CREATE_JFR,
    /* record point for transport JETTY create */
    UMQ_PERF_RECORD_TRANSPORT_CREATE_JETTY,
    /* record point for transport JFCE destroy */
    UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFCE,
    /* record point for transport JFC destroy */
    UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFC,
    /* record point for transport JFR destroy */
    UMQ_PERF_RECORD_TRANSPORT_DESTROY_JFR,
    /* record point for transport JETTY destroy */
    UMQ_PERF_RECORD_TRANSPORT_DESTROY_JETTY,
    /* record point for transport rjetty get */
    UMQ_PERF_RECORD_TRANSPORT_RJETTY_GET,
    /* record point for transport rjetty put */
    UMQ_PERF_RECORD_TRANSPORT_RJETTY_PUT,
    /* record point for transport route path get */
    UMQ_PERF_RECORD_TRANSPORT_PATH_GET,
    /* record point for transport import */
    UMQ_PERF_RECORD_TRANSPORT_IMPORT_JETTY,
    /* record point for transport bind */
    UMQ_PERF_RECORD_TRANSPORT_BIND_JETTY,
    /* record point for transport import */
    UMQ_PERF_RECORD_TRANSPORT_UNIMPORT_JETTY,
    /* record point for transport bind */
    UMQ_PERF_RECORD_TRANSPORT_UNBIND_JETTY,
    UMQ_PERF_RECORD_TYPE_MAX,
} umq_perf_record_type_t;

/* trace type — UMQ top-level operation categories */
typedef enum umq_trace_type {
    UMQ_TRACE_TYPE_POST,                /* umq_post */
    UMQ_TRACE_TYPE_POLL,                /* umq_poll */
    UMQ_TRACE_TYPE_WAIT,                /* umq_wait_interrupt */
    UMQ_TRACE_TYPE_REARM,               /* umq_rearm_interrupt */
    UMQ_TRACE_TYPE_MAX,
} umq_trace_type_t;

/* urma function type — identifies which URMA API is being timed */
typedef enum umq_urma_func_type {
    UMQ_URMA_FUNC_POST_TX,                  /* urma_post_jetty_send_wr */
    UMQ_URMA_FUNC_POST_RX,                  /* urma_post_jetty_recv_wr/urma_post_jfr_wr */
    UMQ_URMA_FUNC_POLL_TX,                  /* urma_poll_jfc (tx) */
    UMQ_URMA_FUNC_POLL_RX,                  /* urma_poll_jfc (rx) */
    UMQ_URMA_FUNC_WAIT_TX_JFC,              /* urma_wait_jfc (tx) */
    UMQ_URMA_FUNC_WAIT_RX_JFC,              /* urma_wait_jfc (rx) */
    UMQ_URMA_FUNC_ACK_TX_JFC,               /* urma_ack_jfc (tx) */
    UMQ_URMA_FUNC_ACK_RX_JFC,               /* urma_ack_jfc (rx) */
    UMQ_URMA_FUNC_REARM_JFC,                /* urma_rearm_jfc */
    UMQ_URMA_FUNC_FC_REARM_JFC,             /* urma_rearm_jfc (fc) */
    UMQ_URMA_FUNC_FC_POST_TX,               /* urma_post_jetty_send_wr (fc) */
    UMQ_URMA_FUNC_FC_POLL_TX,               /* urma_poll_jfc (fc tx) */
    UMQ_URMA_FUNC_FC_POST_RX,               /* urma_post_jetty_recv_wr/urma_post_jfr_wr (fc) */
    UMQ_URMA_FUNC_FC_POLL_RX,               /* urma_poll_jfc (fc rx) */
    UMQ_URMA_FUNC_MAX,
} umq_urma_func_type_t;

#define UMQ_PERF_MAX_SUB_TIME_NUM  (8u)

/* sub-branch timing — one entry per URMA call within a UMQ operation */
typedef struct umq_sub_time {
    uint64_t start_time;                    /* URMA call start timestamp (ns) */
    uint64_t exec_time;                     /* URMA call execution time (delta, ns) */
    umq_urma_func_type_t func_type;         /* which URMA API */
} umq_sub_time_t;

/* one data item — a single buffer (POST) or completion (POLL) */
typedef struct umq_trace_item {
    uint32_t sub_umq_id;                    /* sub umq id for poll_rx */
    uint32_t msn;                           /* imm msn for traceability */
    uint32_t size;                          /* data size of this item */
} umq_trace_item_t;

/* core data record — abstracted from post/poll/interrupt specifics */
typedef struct umq_data_record {
    /* meta — traceability fields */
    umq_trace_item_t items[UMQ_BATCH_SIZE]; /* per-buffer/per-completion data */
    uint32_t item_cnt;                      /* number of valid items[] entries */
    uint64_t timestamp;                     /* record creation timestamp (ns) */
    uint64_t tag_timestamp;                 /* tag timestamp (ns) */
    uint32_t umq_id;                        /* umq id */

    /* timing */
    uint64_t start_time;                    /* UMQ operation start (ns) */
    uint64_t end_time;                      /* UMQ operation end (ns) */

    /* sub-branch — URMA call timing */
    uint32_t sub_time_cnt;
    umq_sub_time_t sub_time[UMQ_PERF_MAX_SUB_TIME_NUM];

    /* type */
    umq_trace_type_t type;                  /* POST / POLL / WAIT / REARM */
} umq_data_record_t;

typedef struct umq_perf_stats {
    struct {
        umq_perf_record_type_t type; // types of probe points supported by perf probe
        uint64_t sample_num; // statistical count
        uint64_t average; // average latency
        uint64_t mininum; // min latency
        uint64_t maxinum; // max latency
        uint64_t quantile[UMQ_PERF_QUANTILE_CNT]; // quantile values in ns (p50/p90/p99/p9999)
    } type_record[UMQ_PERF_RECORD_TYPE_MAX]; // statistical results list for each type of probe point
} umq_perf_stats_t;

typedef struct umq_perf_stats_cfg {
} umq_perf_stats_cfg_t;

#define UMQ_TRACE_FLAG_RECORD_NUM              (1U)
#define UMQ_TRACE_FLAG_OUTPUT_LIMIT            (1U << 1)

typedef struct umq_trace_cfg {
    uint32_t flag;
    uint32_t record_num; // total number of record array
    uint32_t output_limit; // log limit of data record
} umq_trace_cfg_t;

typedef void (*umq_io_perf_callback_t)(umq_perf_record_type_t record_type, umq_buf_t *qbuf);

typedef struct umq_transport_pool_stats {
    uint64_t total_num;
    uint64_t global_num;
    uint64_t cache_num;
    uint64_t in_use_num;
    uint64_t error_num;
    uint64_t acc_alloc_num;
    uint64_t acc_free_num;
    uint64_t acc_miss_num;
} umq_transport_pool_stats_t;

#ifdef __cplusplus
}
#endif

#endif
