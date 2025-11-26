/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ function types
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_TYPES_H
#define UMQ_TYPES_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_LOG_FLAG_FUNC              (1U)
#define UMQ_LOG_FLAG_LEVEL             (1U << 1)
#define UMQ_LOG_FLAG_RATE_LIMITED      (1U << 2)

typedef enum umq_log_level {
    UMQ_LOG_LEVEL_EMERG = 0,
    UMQ_LOG_LEVEL_ALERT,
    UMQ_LOG_LEVEL_CRIT,
    UMQ_LOG_LEVEL_ERR,
    UMQ_LOG_LEVEL_WARN,
    UMQ_LOG_LEVEL_NOTICE,
    UMQ_LOG_LEVEL_INFO,
    UMQ_LOG_LEVEL_DEBUG,
    UMQ_LOG_LEVEL_MAX,
} umq_log_level_t;

typedef void (*umq_log_func_t)(int level, char *log_msg);

typedef struct umq_log_config {
    uint32_t log_flag;
    umq_log_func_t func;
    umq_log_level_t level;
    struct {
        uint32_t interval_ms;    // rate-limited log output interval. If the value is 0, rate is not limited.
        uint32_t num;            // maximum number of rate-limited logs that can be output in a specified interval.
    } rate_limited;
} umq_log_config_t;

typedef enum umq_buf_mode {
    UMQ_BUF_SPLIT,                  // umq_buf_t and buf is split
    UMQ_BUF_COMBINE,                // umq_buf_t and buf is combine
} umq_buf_mode_t;

typedef enum umq_io_direction {
    UMQ_IO_ALL = 0,
    UMQ_IO_TX,
    UMQ_IO_RX,
    UMQ_IO_MAX,
} umq_io_direction_t;

typedef enum umq_queue_mode {
    UMQ_MODE_POLLING,             // polling mode
    UMQ_MODE_INTERRUPT,           // interrupt mode
    UMQ_MODE_MAX
} umq_queue_mode_t;

typedef enum umq_trans_mode {
    UMQ_TRANS_MODE_UB = 0,              // ub, max io size 64K
    UMQ_TRANS_MODE_IB,                  // ib, max io size 64K
    UMQ_TRANS_MODE_UCP,                 // ub offload, max io size 64K
    UMQ_TRANS_MODE_IPC,                 // local ipc, max io size 10M
    UMQ_TRANS_MODE_UBMM,                // ub share memory, max io size 8K
    UMQ_TRANS_MODE_UB_PLUS,             // ub, max io size 10M
    UMQ_TRANS_MODE_IB_PLUS,             // ib, max io size 10M
    UMQ_TRANS_MODE_UBMM_PLUS,           // ub share memory, max io size 10M
    UMQ_TRANS_MODE_MAX,
} umq_trans_mode_t;

typedef enum umq_dev_assign_mode {
    UMQ_DEV_ASSIGN_MODE_IPV4,
    UMQ_DEV_ASSIGN_MODE_IPV6,
    UMQ_DEV_ASSIGN_MODE_EID,
    UMQ_DEV_ASSIGN_MODE_DEV,
    UMQ_DEV_ASSIGN_MODE_MAX
} umq_dev_assign_mode_t;

#define UMQ_EID_SIZE                 (16)
#define UMQ_IPV4_SIZE                (16)
#define UMQ_IPV6_SIZE                (46)
#define UMQ_DEV_NAME_SIZE            (64)
#define UMQ_BATCH_SIZE               (64)

#define UMQ_INTERRUPT_FLAG_IO_DIRECTION         (1)         // enable arg direction

typedef struct umq_interrupt_option {
    uint32_t flag;                      // indicates which below property takes effect
    umq_io_direction_t direction;
} umq_interrupt_option_t;

typedef union umq_eid {
    uint8_t raw[UMQ_EID_SIZE];      // Network Order
    struct {
        uint64_t reserved;          // If IPv4 mapped to IPv6, == 0
        uint32_t prefix;            // If IPv4 mapped to IPv6, == 0x0000ffff
        uint32_t addr;              // If IPv4 mapped to IPv6, == IPv4 addr
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} umq_eid_t;

typedef struct umq_dev_assign {
    umq_dev_assign_mode_t assign_mode;  // Decide how to choose a device
    union {
        struct {
            char ip_addr[UMQ_IPV4_SIZE];
        } ipv4;
        struct {
            char ip_addr[UMQ_IPV6_SIZE];
        } ipv6;
        struct {
            umq_eid_t eid;
        } eid;
        struct {
            char dev_name[UMQ_DEV_NAME_SIZE];
        } dev;
    };
} umq_dev_assign_t;

typedef struct umq_trans_info {
    umq_trans_mode_t trans_mode;
    umq_dev_assign_t dev_info;
} umq_trans_info_t;

#define MAX_UMQ_TRANS_INFO_NUM (128)

/* umq feature */
#define UMQ_FEATURE_API_BASE                (0)         // enable base feature. set when use umq_enqueue/umq_dequeue
#define UMQ_FEATURE_API_PRO                 (1)         // enable pro feature. set when use umq_post/umq_poll
#define UMQ_FEATURE_ENABLE_TOKEN_POLICY     (1 << 1)    // enable token policy.
#define UMQ_FEATURE_ENABLE_STATS            (1 << 2)    // enable stats collection
#define UMQ_FEATURE_ENABLE_PERF             (1 << 3)    // enable performance collection
#define UMQ_FEATURE_ENABLE_FLOW_CONTROL     (1 << 4)    // enable flow control

typedef struct umq_flow_control_cfg {
    // set when rx >= initial_window at first, [1, rx_depth], otherwise use rx_depth / 2 by default
    uint16_t initial_window;
    // notify when rx >= notify_interval, [1, rx_depth], otherwise use rx_depth / 16 by default
    uint16_t notify_interval;
    // use atomic variables as flow control window
    bool use_atomic_window;
} umq_flow_control_cfg_t;

typedef struct umq_init_cfg {
    umq_buf_mode_t buf_mode;
    uint32_t feature;               // feature flags
    uint16_t headroom_size;         // header size of umq buffer, [0, UMQ_HEADROOM_SIZE_LIMIT]
    bool io_lock_free;              // true: user should ensure thread safety when call io function
    uint8_t trans_info_num;
    umq_flow_control_cfg_t flow_control; // used when UMQ_FEATURE_ENABLE_FLOW_CONTROL is set
    uint16_t eid_idx;
    uint16_t cna;
    uint32_t ubmm_eid;
    umq_trans_info_t trans_info[MAX_UMQ_TRANS_INFO_NUM];
} umq_init_cfg_t;

#define UMQ_NAME_MAX_LEN (32)

#define UMQ_CREATE_FLAG_RX_BUF_SIZE         (1)             // enable arg rx_buf_size when create umq
#define UMQ_CREATE_FLAG_TX_BUF_SIZE         (1 << 1)        // enable arg tx_buf_size when create umq
#define UMQ_CREATE_FLAG_RX_DEPTH            (1 << 2)        // enable arg rx_depth when create umq
#define UMQ_CREATE_FLAG_TX_DEPTH            (1 << 3)        // enable arg tx_depth when create umq
#define UMQ_CREATE_FLAG_QUEUE_MODE          (1 << 4)        // enable arg mode when create umq

typedef struct umq_create_option {
    /*************Required paramenters start*****************/
    umq_trans_mode_t trans_mode;
    umq_dev_assign_t dev_info;
    char name[UMQ_NAME_MAX_LEN];     // include '\0', size of valid name is UMQ_NAME_MAX_LEN - 1

    uint32_t create_flag;            // indicates which below creation property takes effect
    /*************Required paramenters end*******************/
    /*************Optional paramenters start*****************/
    uint32_t rx_buf_size;
    uint32_t tx_buf_size;
    uint32_t rx_depth;
    uint32_t tx_depth;

    umq_queue_mode_t mode;      // mode of queue, QUEUE_MODE_POLLING for default
    /*************Optional paramenters end*******************/
} umq_create_option_t;

typedef enum umq_state {
    QUEUE_STATE_IDLE,
    // if flow control is enabled, QUEUE_STATE_READY means initial_window is updated
    QUEUE_STATE_READY,
    QUEUE_STATE_ERR,
    QUEUE_STATE_MAX
} umq_state_t;

/**
 * layout: | umq_buf_t | headroom | data |  unuse |
 * buf_size = sizeof(umq_buf_t) + headroom_size + data_size +  sizeof(unuse)
 * total_data_size of one qbuf = data_size + data_size of qbuf_next  + data_size of qbuf_next + ...
 * we can also list multi-qbufs with qbuf_next
 */
typedef struct umq_buf umq_buf_t;
struct umq_buf {
    // cache line 0 : 64B
    umq_buf_t *qbuf_next;

    uint64_t umqh;                        // umqh which buf alloc from

    uint32_t total_data_size;             // size of a batch of umq buf data, only valid in first qbuf of this batch
    uint32_t buf_size;                    // size of current umq buf

    uint32_t data_size;                   // size of umq buf data
    uint16_t headroom_size;               // size of umq buf headroom
    uint16_t first_fragment : 1;          // first piece of each batch buf
    uint16_t rsvd1 : 15;

    uint32_t token_id : 20;               // token_id for reference operation
    uint32_t rsvd2 : 4;
    uint32_t mempool_id : 8;              // indicate which memory pool it is allocated from
    uint32_t token_value;                 // token_value for reference operation

    uint64_t status : 32;                 // umq_buf_status_t
    uint64_t io_direction : 2;            // 0: no direction; 1: tx qbuf; 2: rx qbuf
    uint64_t need_import : 1;
    uint64_t rsvd3 : 29;

    uint64_t rsvd4;

    char *buf_data;                       // point to data[0]

    // cache line 1 : 64B
    uint64_t qbuf_ext[8];                 // extern data, etc: umq_buf_pro_t

    char data[0];                         // size of data should be data_size
};

#define UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE         (1)             // enable arg headroom_size

typedef struct umq_alloc_option {
    uint32_t flag;                          // indicates which below property takes effect
    uint16_t headroom_size;
} umq_alloc_option_t;

typedef enum umq_dfx_module_id {
    UMQ_DFX_MODULE_PERF,
    UMQ_DFX_MODULE_STATS,
    UMQ_DFX_MODULE_MAX
} umq_dfx_module_id_t;

typedef enum umq_perf_cmd_id {
    UMQ_PERF_CMD_START,
    UMQ_PERF_CMD_STOP,
    UMQ_PERF_CMD_CLEAR,
    UMQ_PERF_CMD_GET_RESULT,
    UMQ_PERF_CMD_MAX
} umq_perf_cmd_id_t;

typedef enum umq_stats_cmd_id {
    UMQ_STATS_CMD_START,
    UMQ_STATS_CMD_STOP,
    UMQ_STATS_CMD_CLEAR,
    UMQ_STATS_CMD_GET_RESULT,
    UMQ_STATS_CMD_MAX
} umq_stats_cmd_id_t;

typedef enum umq_stats_type {
    UMQ_STATS_TYPE_SEND,                   // send cnt
    UMQ_STATS_TYPE_RECEIVE,                // recv cnt
    UMQ_STATS_TYPE_READ,                   // read cnt
    UMQ_STATS_TYPE_MAX,
} umq_stats_type_t;

typedef enum umq_err_stats_type {
    UMQ_ERR_STATS_TYPE_POST_PARM_INVALID,                   // post parameter invalid cnt
    UMQ_ERR_STATS_TYPE_POST_SEND,                           // post send cnt
    UMQ_ERR_STATS_TYPE_POST_RECV,                           // post recv cnt
    UMQ_ERR_STATS_TYPE_POST_IO_DIRECTION_INVALID,           // post io direction invalid cnt
    UMQ_ERR_STATS_TYPE_POST_DATA_SIZE_INVALID,              // post qbuf data size invalid cnt
    UMQ_ERR_STATS_TYPE_POST_SGE_NUM_INVALID,                // post sge num invalid cnt
    UMQ_ERR_STATS_TYPE_POST_WR_COUNT_INVALID,               // post wr count invalid cnt

    UMQ_ERR_STATS_TYPE_POST_BIG_DATA,                       // post send big data cnt

    UMQ_ERR_STATS_TYPE_POLL_PARM_INVALID,                   // poll cnt
    UMQ_ERR_STATS_TYPE_POLL_TX,                             // poll tx failed
    UMQ_ERR_STATS_TYPE_POLL_RX,                             // poll rx failed
    UMQ_ERR_STATS_TYPE_POLL_IO_DIRECTION_INVALID,           // poll io direction invalid cnt

    UMQ_ERR_STATS_TYPE_READ,                                // read failed
    UMQ_ERR_STATS_TYPE_READ_BIND_CTX_INVALID,               // read bind ctx invalid cnt
    UMQ_ERR_STATS_TYPE_READ_TSEG_INVALID,                   // read tseg invalid cnt

    UMQ_ERR_STATS_TYPE_ENQUEUE_PARM_INVALID,                // enqueue parameter invalid cnt
    UMQ_ERR_STATS_TYPE_ENQUEUE_DATA_NUM_INVALID,            // enqueue data num invalid cnt
    UMQ_ERR_STATS_TYPE_ENQUEUE_POST_TX_BATCH,               // enqueue post tx batch failed
    UMQ_ERR_STATS_TYPE_ENQUEUE_SGE_NUM_INVALID,             // enqueue sge num invalid cnt

    UMQ_ERR_STATS_TYPE_DEQUEUE_PARM_INVALID,                // dequeue parameter invalid cnt
    UMQ_ERR_STATS_TYPE_DEQUEUE_BIND_CTX_INVALID,            // dequeue bind ctx invalid cnt
    UMQ_ERR_STATS_TYPE_DEQUEUE_SHM_QBUF,                    // dequeue shm qbuf cnt

    UMQ_ERR_STATS_TYPE_QBUF_ALLOC,                          // qbuf alloc cnt
    UMQ_ERR_STATS_TYPE_RX_BUF_CTX_ALLOC,                    // rx buf ctx alloc cnt
    UMQ_ERR_STATS_TYPE_MAX,
} umq_err_stats_type_t;

typedef struct umq_stats_info_instance {
    uint64_t stats[UMQ_STATS_TYPE_MAX];
    uint64_t umqh;
} umq_stats_info_instance_t;

typedef struct umq_stats_infos {
    uint64_t err_stats[UMQ_ERR_STATS_TYPE_MAX];
    uint32_t stats_info_num;
    umq_stats_info_instance_t stats_info[0];
} umq_stats_infos_t;

#define UMQ_PERF_QUANTILE_MAX_NUM (8u)

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
    /* record point for umq_notify */
    UMQ_PERF_RECORD_NOTIFY,
    /* record point for transport post send in umq_enqueue and umq_post */
    UMQ_PERF_RECORD_TRANSPORT_POST_SEND,
    /* record point for transport post recv in umq_enqueue and umq_post */
    UMQ_PERF_RECORD_TRANSPORT_POST_RECV,
    /* record point for transport poll tx in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_POLL_TX,
    /* record point for transport poll rx in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_POLL_RX,
    /* record point for transport poll tx in umq_dequeue and umq_poll when tx is empty */
    UMQ_PERF_RECORD_TRANSPORT_POLL_TX_EMPTY,
    /* record point for transport poll rx in umq_dequeue and umq_poll when rx is empty */
    UMQ_PERF_RECORD_TRANSPORT_POLL_RX_EMPTY,
    /* record point for transport read in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_READ,
    /* record point for transport send imm in umq_dequeue and umq_poll */
    UMQ_PERF_RECORD_TRANSPORT_SEND_IMM,
    /* record point for transport write in umq_notify */
    UMQ_PERF_RECORD_TRANSPORT_WRITE_IMM,
    UMQ_PERF_RECORD_TYPE_MAX,
} umq_perf_record_type_t;

typedef struct umq_perf_record {
    struct {
        uint64_t accumulation;
        uint64_t min;
        uint64_t max;
        uint64_t cnt;
        uint64_t bucket[UMQ_PERF_QUANTILE_MAX_NUM + 1];
    } type_record[UMQ_PERF_RECORD_TYPE_MAX];
    bool is_used;
} umq_perf_record_t;

typedef struct perf_in_parm {
    // Record data within the specified interval
    uint64_t thresh_array[UMQ_PERF_QUANTILE_MAX_NUM];
    uint32_t thresh_num;
} perf_in_parm_t;

typedef struct umq_perf_infos {
    uint32_t perf_record_num;
    umq_perf_record_t *perf_record[0];
} umq_perf_infos_t;

typedef struct umq_dfx_cmd {
    umq_dfx_module_id_t module_id;
    union {
        umq_perf_cmd_id_t perf_cmd_id;
        umq_stats_cmd_id_t stats_cmd_id;
    };
    union {
        perf_in_parm_t perf_in_parm;
    };
} umq_dfx_cmd_t;

typedef struct umq_dfx_result {
    umq_dfx_module_id_t module_id;
    union {
        umq_perf_cmd_id_t perf_cmd_id;
        umq_stats_cmd_id_t stats_cmd_id;
    };
    int err_code;
    union {
        char *perf_char;
        umq_perf_infos_t *perf_out_parm;
        umq_stats_infos_t *stats_out_parm;
    };
} umq_dfx_result_t;

typedef enum umq_async_event_type {
    UMQ_EVENT_QH_ERR,
    UMQ_EVENT_QH_LIMIT,
    UMQ_EVENT_PORT_ACTIVE,
    UMQ_EVENT_PORT_DOWN,
    UMQ_EVENT_DEV_FATAL,
    UMQ_EVENT_EID_CHANGE,       // eid change, HNM and other management roles will be modified.
    UMQ_EVENT_ELR_ERR,          // Entity level error
    UMQ_EVENT_ELR_DONE,         // Entity flush done
    UMQ_EVENT_OTHER,
} umq_async_event_type_t;

typedef struct umq_async_event {
    umq_trans_info_t trans_info;
    union {
        uint64_t umqh;
        uint32_t port_id;
    } element;
    umq_async_event_type_t event_type;
    int original_code; // record original event
    void *priv;
} umq_async_event_t;

#ifdef __cplusplus
}
#endif

#endif
