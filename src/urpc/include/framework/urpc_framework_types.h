/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: Public header file of URPC function arguments
 * Create: 2024-1-1
 * Note:
 * History: 2024-1-1
 */

#ifndef URPC_TYPES_H
#define URPC_TYPES_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_QUEUE_SIZE (256)
#define MAX_MEM_H_SIZE (256)
#define MAX_SERVER_INFO_NUM (8)
#define MAX_TRANS_INFO_NUM (32)

#define URPC_SGE_NUM                        32

#define URPC_EID_SIZE                 (16)
#define URPC_IPV4_SIZE                (16)
#define URPC_IPV6_SIZE                (46)
#define URPC_DEV_NAME_SIZE            (64)

typedef enum urpc_hdr_type {
    URPC_REQ,
    URPC_ACK,
    URPC_RSP
} urpc_hdr_type_t;

// function define module
#define FUNC_DEF_NULL    (0)

typedef union urpc_eid {
    uint8_t raw[URPC_EID_SIZE];     // Network Order
    struct {
        uint64_t reserved;          // If IPv4 mapped to IPv6, == 0
        uint32_t prefix;            // If IPv4 mapped to IPv6, == 0x0000ffff
        uint32_t addr;              // If IPv4 mapped to IPv6, == IPv4 addr
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} urpc_eid_t;

typedef enum urpc_server_type {
    SERVER_TYPE_IPV4,
    SERVER_TYPE_IPV6,
    SERVER_TYPE_UB
} urpc_server_type_t;

typedef struct urpc_server_info {
    urpc_server_type_t server_type;    // use ip/port or eid to attach server.
    union {
        struct {
            char ip_addr[URPC_IPV4_SIZE];
            uint16_t port;
        } ipv4;
        struct {
            char ip_addr[URPC_IPV6_SIZE];
            uint16_t port;
        } ipv6;
        struct {
            urpc_eid_t eid;
        } ub;
    };
    struct {
        union {
            char ipv4_addr[URPC_IPV4_SIZE];
            char ipv6_addr[URPC_IPV6_SIZE];
        };
        uint16_t port;
        bool bind_local_addr_enabled;
    } assigned_addr;
    uint8_t version;
} urpc_server_info_t;

typedef enum urpc_host_type {
    HOST_TYPE_IPV4,
    HOST_TYPE_IPV6,
    HOST_TYPE_UB
} urpc_host_type_t;

typedef struct urpc_host_info {
    urpc_host_type_t host_type;  // use ip/port or eid as host cfg
    union {
        struct {
            char ip_addr[URPC_IPV4_SIZE];
            uint16_t port;
        } ipv4;
        struct {
            char ip_addr[URPC_IPV6_SIZE];
            uint16_t port;
        } ipv6;
        struct {
            urpc_eid_t eid;
        } ub;
    };
} urpc_host_info_t;

typedef struct urpc_control_plane_config {
    urpc_server_info_t server;
    void *user_ctx;                 // context for user set
} urpc_control_plane_config_t;

typedef enum urpc_role {
    URPC_ROLE_SERVER = 1,
    URPC_ROLE_CLIENT,
    URPC_ROLE_SERVER_CLIENT,
    URPC_ROLE_MAX
} urpc_role_t;

typedef enum urpc_trans_mode {
    URPC_TRANS_MODE_UB = 1,
    URPC_TRANS_MODE_MAX
} urpc_trans_mode_t;

typedef enum urpc_dev_assign_mode {
    DEV_ASSIGN_MODE_IPV4,
    DEV_ASSIGN_MODE_IPV6,
    DEV_ASSIGN_MODE_EID,
    DEV_ASSIGN_MODE_DEV,
    DEV_ASSIGN_MODE_MAX
} urpc_dev_assign_mode_t;

typedef struct urpc_trans_info {
    urpc_trans_mode_t trans_mode;
    urpc_dev_assign_mode_t assign_mode;
    union {
        struct {
            char ip_addr[URPC_IPV4_SIZE];
        } ipv4;
        struct {
            char ip_addr[URPC_IPV6_SIZE];
        } ipv6;
        struct {
            urpc_eid_t eid;
        } ub;
        struct {
            char dev_name[URPC_DEV_NAME_SIZE];
            uint8_t is_ipv6; // indicate using ipv4 or ipv6
        } dev;
    };
} urpc_trans_info_t;

/* uRPC feature */
#define URPC_FEATURE_FLOW_CONTROL           (1)      // (reserved) enable flow control
// (1 << 1) reserved
#define URPC_FEATURE_HWUB_OFFLOAD           (1 << 2) // enable hwoff
#define URPC_FEATURE_TIMEOUT                (1 << 3) // enable timeout
#define URPC_FEATURE_DISABLE_TOKEN_POLICY   (1 << 4) // disable token policy
#define URPC_FEATURE_DISABLE_STATS          (1 << 5) // disable urpc stats
#define URPC_FEATURE_KEEPALIVE              (1 << 6) // enable keep alive
/*
 * Currently, 'URPC_FEATURE_MULTI_EID' is used only for large-scale deployment verification tests.
 * Note:
 * 1. only 'DEV_ASSIGN_MODE_DEV' can be used to enable multi-eid.
 * 2. The EIDs bound to input devices all will be enabled.
 */
#define URPC_FEATURE_MULTI_EID              (1 << 7) // enable multi-eid for input device
#define URPC_FEATURE_GET_FUNC_INFO          (1 << 8) // enable get function info when attach server
#define URPC_FEATURE_MULTIPLEX              (1 << 9) // enable x client channels to one server channel

/* urpc channel aysnc support features */
#define URPC_CHANNEL_AYSNC_FLAG_CTX         (1)      // enable ctx
#define URPC_CHANNEL_AYSNC_FLAG_TIMEOUT     (1 << 1) // enable timeout

typedef struct mem_seg_token {
    uint32_t token_id;
    uint32_t token_value;
} mem_seg_token_t;

typedef struct urpc_sge {
    uint64_t addr;
    uint32_t length;
    uint32_t flag;
    uint64_t mem_h;
} urpc_sge_t;

typedef enum urpc_keepalive_event_type {
    URPC_KEEPALIVE_FAILED = 0,
    URPC_KEEPALIVE_MSG_RECEIVED,
    URPC_KEEPALIVE_RECOVER,

    URPC_KEEPALIVE_EVENT_MAX,
} urpc_keepalive_event_type_t;

typedef struct urpc_keepalive_event_info {
    uint64_t        user_ctx;
    uint32_t        inactivated_time;
    uint32_t        peer_pid;           // obtained by calling the function getpid() of unistd.h
    urpc_sge_t      user_msg;
} urpc_keepalive_event_info_t;

typedef void (*keepalive_callback_t)(urpc_keepalive_event_type_t type, urpc_keepalive_event_info_t info);

typedef struct urpc_keepalive_config {
    keepalive_callback_t keepalive_callback;   // keepalive failed callback
    uint64_t user_ctx;                         // user context which will report by callback
    uint32_t keepalive_cycle_time;             // keepalive send interval time(s), [1, 3600]
    uint32_t keepalive_check_time;             // keepalive check drop time interval (s), [keepalive_cycle_time, 3600]
    uint32_t delay_release_time;               // delay release time of input msg when detach (s), [1, 3600]
    uint32_t max_msg_size;                     // keepalive max message size (no use)
    uint32_t q_depth;                          // keepalive queue depth, use 128 by default if out of range [1, 128]
} urpc_keepalive_config_t;

typedef struct urpc_config {
    urpc_role_t role;
    uint32_t feature;
    uint16_t device_class;
    uint16_t sub_class;
    uint8_t trans_info_num;
    urpc_trans_info_t trans_info[MAX_TRANS_INFO_NUM];
    char *unix_domain_file_path;
    urpc_keepalive_config_t keepalive_cfg;
} urpc_config_t;

typedef struct urpc_ref_sge {
    uint64_t addr;
    uint32_t length;
    uint32_t token_id;
    uint32_t token_value;
} urpc_ref_sge_t;

typedef struct urpc_allocator_option {
    uint64_t qcustom_flag;      // user can get different layout of buf base on custom flag of queue
    uint8_t is_rx_buf;          // Add for DataNet to prevent false reporting of rx buffer memory leakage.
} urpc_allocator_option_t;

typedef struct urpc_allocator {
    /* get buf with sge layout which size equal total_size */
    int (*get)(urpc_sge_t **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option);
    /* put buffer & SGEs */
    int (*put)(urpc_sge_t *sge, uint32_t num, urpc_allocator_option_t *option);
    /* only get 'total_size' bytes buffer and fill sge info */
    int (*get_raw_buf)(urpc_sge_t *sge_one, uint64_t total_size, urpc_allocator_option_t *option);
    /* put buffer */
    int (*put_raw_buf)(urpc_sge_t *sge_one, urpc_allocator_option_t *option);
    /* only get SGEs */
    int (*get_sges)(urpc_sge_t **sge, uint32_t sge_num, urpc_allocator_option_t *option);
    /* put SGEs */
    int (*put_sges)(urpc_sge_t *sge, urpc_allocator_option_t *option);
} urpc_allocator_t;

typedef struct urpc_ccfg_get {
    uint32_t l_max_qnum;
    uint32_t r_max_qnum;
    uint32_t attr;
    uint32_t req_entry_size;
} urpc_ccfg_get_t;

#define CHANNEL_CFG_SET_FLAG_REQ_ENTRY_SIZE     (1)

typedef struct urpc_ccfg_set {
    uint32_t set_flag;              // indicates which property takes effect
    uint32_t req_entry_size;        // the size can only be a power of 2
} urpc_ccfg_set_t;

typedef enum urpc_queue_type {
    QUEUE_TYPE_NORMAL,
    QUEUE_TYPE_QGROUP,      // (reserved) queue group
    QUEUE_TYPE_MAX
} urpc_queue_type_t;

typedef enum urpc_queue_status {
    /** queue is idle */
    QUEUE_STATUS_IDLE,
    /** queue is importing */
    QUEUE_STATUS_RUNNING,
    /** queue is reset */
    QUEUE_STATUS_RESET,
    /** queue is ready */
    QUEUE_STATUS_READY,
    /** queue has seen a failure but expects to recover */
    QUEUE_STATUS_FAULT,
    /** queue has seen a failure that it cannot recover */
    QUEUE_STATUS_ERR,
    QUEUE_STATUS_MAX
} urpc_queue_status_t;

#define URPC_QFLUSH_FLAG_VTP            (1)     // enable arg vtp when flush queue

typedef struct urpc_channel_qinfo {
    uint64_t urpc_qh;               // queue unique identifier
    urpc_queue_type_t type;         // type of queue, normal or queue_group
    urpc_queue_status_t status;     // status of queue
    uint32_t ref_cnt;               // reference count for adding a queue to a channel
} urpc_channel_qinfo_t;

typedef struct urpc_channel_qinfos {
    uint16_t l_qnum;                               // number of local queues related to the channel
    urpc_channel_qinfo_t l_qinfo[MAX_QUEUE_SIZE];  // detailed information of local queues related to the channel
    uint16_t r_qnum;                               // number of remote queues related to the channel
    urpc_channel_qinfo_t r_qinfo[MAX_QUEUE_SIZE];  // detailed information of remote queues related to the channel
} urpc_channel_qinfos_t;

typedef enum urpc_queue_trans_mode {
    QUEUE_TRANS_MODE_JETTY,             // transfer base on jetty in order mode
    QUEUE_TRANS_MODE_MAX
} urpc_queue_trans_mode_t;

typedef enum urpc_queue_mode {
    QUEUE_MODE_POLLING,             // polling mode
    QUEUE_MODE_INTERRUPT,           // interrupt mode
    QUEUE_MODE_MAX
} urpc_queue_mode_t;

#define QCREATE_FLAG_QGRPH          (1)         // (reserved) enable arg urpc_qgrph when create queue
#define QCREATE_FLAG_QH_SHARE_RQ    (1 << 1)    // enable arg urpc_qh_share_rq when create queue
#define QCREATE_FLAG_CUSTOM_FLAG    (1 << 2)    // enable arg custom_flag when create queue
#define QCREATE_FLAG_RX_BUF_SIZE    (1 << 3)    // enable arg rx_buf_size when create queue
#define QCREATE_FLAG_RX_DEPTH       (1 << 4)    // enable arg rx_depth when create queue
#define QCREATE_FLAG_TX_DEPTH       (1 << 5)    // enable arg tx_depth when create queue
#define QCREATE_FLAG_PRIORITY       (1 << 6)    // enable arg priority when create queue
#define QCREATE_FLAG_MAX_RX_SGE     (1 << 7)    // enable arg max_rx_sge when create queue
#define QCREATE_FLAG_MAX_TX_SGE     (1 << 8)    // enable arg max_tx_sge when create queue
#define QCREATE_FLAG_LOCK_FREE      (1 << 9)    // enable arg lock_free when create queue
#define QCREATE_FLAG_MODE           (1 << 10)   // enable arg mode when create queue
#define QCREATE_FLAG_SKIP_POST_RX   (1 << 11)   // enable arg skip_post_rx when create queue
#define QCREATE_FLAG_ERR_TIMEOUT    (1 << 12)   // enable arg err_timeout when create queue
#define QCREATE_FLAG_RNR_RETRY      (1 << 13)   // enable arg rnr_retry when create queue
#define QCREATE_FLAG_MIN_RNR_TIMER  (1 << 14)   // enable arg min_rnr_timer when create queue
#define QCREATE_FLAG_QH_SHARE_TX_CQ (1 << 15)   // enable arg urpc_qh_share_tx_cq when create queue
#define QCREATE_FLAG_RX_CQ_DEPTH    (1 << 16)   // enable arg rx_cq_depth when create queue
#define QCREATE_FLAG_TX_CQ_DEPTH    (1 << 17)   // enable arg tx_cq_depth when create queue

typedef struct urpc_qcfg_create {
    uint32_t create_flag;       // indicates which creation property takes effect
    uint64_t urpc_qgrph;        // (reserved) create queue based on queue group
    uint64_t urpc_qh_share_rq;  // queue handle which will share receive queue with it
                                // If 'QCREATE_FLAG_QH_SHARE_RQ' is enable, both RQ & CQ are shared from it
    uint64_t urpc_qh_share_tx_cq;
    uint64_t custom_flag;       // user can define some flag for queue
    uint32_t rx_buf_size;       // size of the receive buffer
    uint32_t rx_depth;          // depth of the receive buffer ring
    uint32_t tx_depth;          // depth of the send buffer ring
    uint32_t rx_cq_depth;       // depth of receive completion queue
    uint32_t tx_cq_depth;       // depth of send completion queue
    uint8_t priority;           // priority of the queue
    uint8_t max_rx_sge;         // max sge number of receive array
    uint8_t max_tx_sge;         // max sge number of send array
    uint8_t lock_free;          // whether the queue is lock free, 0 means locked, otherwise means lock free
    urpc_queue_mode_t mode;     // mode of queue, QUEUE_MODE_POLLING for default
    uint8_t skip_post_rx;       // whether the queue is skip post rx buf, 0 means don't skip, otherwise means skip
    uint8_t err_timeout;        // jetty timeout before report error
    uint8_t rnr_retry;          // number of times that jfs will resend packets before report error, when remote (RNR)
    uint8_t min_rnr_timer;      // minimum RNR NACK timer
} urpc_qcfg_create_t;

typedef struct urpc_qcfg_get {
    uint64_t custom_flag;       // user can define some flag for queue
    uint32_t rx_buf_size;       // size of the receive buffer
    uint32_t rx_depth;          // depth of the receive buffer ring
    uint32_t tx_depth;          // depth of the send buffer ring
    uint32_t rx_cq_depth;       // depth of receive completion queue
    uint32_t tx_cq_depth;       // depth of send completion queue
    uint32_t qid;               // queue id
    urpc_server_info_t info;    // server information the queue belongs to
    urpc_queue_type_t type;     // type of queue
    urpc_queue_trans_mode_t trans_mode;  // transmission mode of the queue
    urpc_queue_mode_t mode;     // mode of queue, QUEUE_MODE_POLLING for default
    uint8_t trans_qnum;         // number of transmission channels corresponding to the queue
    uint8_t priority;           // priority of the queue
    uint8_t max_rx_sge;         // max sge number of receive array
    uint8_t max_tx_sge;         // max sge number of send array
    uint8_t lock_free;          // whether the queue is lock free, 0 means locked, otherwise means lock free
    uint8_t skip_post_rx;       // whether the queue is skip post rx buf, 0 means don't skip, otherwise means skip
    uint8_t err_timeout;        // jetty timeout before report error
    uint8_t rnr_retry;          // number of times that jfs will resend packets before report error, when remote (RNR)
    uint8_t min_rnr_timer;      // minimum RNR NACK timer
} urpc_qcfg_get_t;

#define QCFG_SET_FLAG_TRANS_NUM     (1)         // enable arg trans_qnum when set queue cfg
#define QCFG_SET_FLAG_PRIORITY      (1 << 1)    // enable arg priority when set queue cfg
#define QCFG_SET_FLAG_FE_IDX        (1 << 2)    // enable arg fe_idx when set queue cfg

typedef struct urpc_qcfg_set {
    uint32_t set_flag;  // indicates which setting property takes effect
    uint8_t trans_qnum; // number of transmission channels corresponding to the queue
    uint8_t priority;   // priority of the queue
    uint32_t fe_idx;    // fe_idx of the queue which create by vm, only use in DFV.
} urpc_qcfg_set_t;

typedef enum urpc_handler_type {
    URPC_HANDLER_SYNC,                  // See "urpc_sync_handler_t"
    URPC_HANDLER_ASYNC,                 // See "urpc_async_handler_t"
    URPC_HANDLER_MAX
} urpc_handler_type_t;

/**
 * URPC lib sync handler
 * @param[in] args: SGE array for function arguments
 * @param[in] args_sge_num: Number of SGEs for function arguments
 * @param[in] ctx: user ctx
 * @param[out] rsps: SGE array for function arguments
 * @param[out] rsps_sge_num: Number of SGEs for function arguments
 */
typedef void (*urpc_sync_handler_t)(urpc_sge_t *args, uint32_t args_sge_num, void *ctx, urpc_sge_t **rsps,
    uint32_t *rsps_sge_num);

/**
 * URPC lib async handler
 * @param[in] args: SGE array for function arguments
 * @param[in] args_sge_num: Number of SGEs for function arguments
 * @param[in] ctx: user ctx
 * @param[in] req_ctx: Context information of function request
 * @param[in] qh: queue unique identifier
 * @note use async handler when handle stream call
 */
typedef void (*urpc_async_handler_t)(urpc_sge_t *args, uint32_t args_sge_num, void *ctx, void *req_ctx, uint64_t qh);

#define FUNCTION_NAME_LEN 128

typedef struct urpc_handler_info {
    urpc_handler_type_t type;
    union {
        urpc_sync_handler_t sync_handler;
        urpc_async_handler_t async_handler;
    };
    void *ctx;           // context information carried by the function execution
    char name[FUNCTION_NAME_LEN];    // function name
} urpc_handler_info_t;

typedef void (*urpc_req_cb_t)(urpc_sge_t *rsps, uint32_t rsps_sge_num, int err, void *arg, void *ctx);

typedef struct urpc_call_wr {
    uint64_t func_id;      // function ID to be executed on the server side
    urpc_sge_t *args; // uRPC request parameter array
    uint32_t args_num;     // number of parameters
    urpc_req_cb_t cb;      // callback function for receiving completion
    void *cb_arg;          // information to be passed to the callback
} urpc_call_wr_t;

#define FUNC_CALL_FLAG_TIMEOUT          (1)         // enable arg timeout when func_call
#define FUNC_CALL_FLAG_L_QH             (1 << 1)    // enable arg l_qh when func_call
#define FUNC_CALL_FLAG_R_QH             (1 << 2)    // enable arg r_qh when func_call
#define FUNC_CALL_FLAG_USER_CTX         (1 << 3)    // enable arg user_ctx when func_call
#define FUNC_CALL_FLAG_CALL_MODE        (1 << 4)    // enable arg call_mode when func_call
#define FUNC_CALL_FLAG_FUNC_DEFINED     (1 << 5)    // enable arg func_defined when func_call

#define FUNC_CALL_MODE_EARLY_RSP    (1)         // call mode early_rsp, server will not send urpc rsp to client
#define FUNC_CALL_MODE_ACK          (1 << 1)    // call mode ack, server should send urpc ack to client
#define FUNC_CALL_MODE_WAIT_RSP     (1 << 2)    // call mode wait rsp, client will wait rsp by urpc_func_poll_wait()

typedef struct urpc_call_option {
    uint32_t option_flag;   // flag of the option, indicating which fields are valid
    uint32_t timeout;       // timeout
    uint64_t l_qh;          // local queue unique identifier
    uint64_t r_qh;          // remote queue unique identifier
    void *user_ctx;         // context for user set
    uint16_t call_mode;     // call mode, indicating early_rsp mode, ack mode, etc.
    uint8_t func_defined;   // function define module, eg. FUNC_DEF_NULL
} urpc_call_option_t;

typedef struct urpc_ref_wr {
    urpc_sge_t *l_sges;             // local sges which reference read/write from
    uint32_t l_sges_num;            // num of local sges which reference read/write from
    urpc_ref_sge_t *r_ref_sges;     // remote sges which reference read/write to
    uint32_t r_ref_sges_num;        // num of remote sges which reference read/write to
} urpc_ref_wr_t;

#define FUNC_REF_FLAG_TIMEOUT          (1U)         // enable arg timeout when func_ref
#define FUNC_REF_FLAG_USER_CTX         (1U << 1)    // enable arg user_ctx when func_ref

typedef struct urpc_ref_option {
    uint32_t option_flag;       // flag of the option, indicating which fields are valid
    uint32_t timeout;           // reference read/write timeout
    void *user_ctx;             // context for user set
} urpc_ref_option_t;

typedef enum urpc_poll_direction {
    POLL_DIRECTION_ALL = 0,
    POLL_DIRECTION_TX,
    POLL_DIRECTION_RX,
} urpc_poll_direction_t;

typedef struct urpc_poll_option {
    uint64_t urpc_qh; // designated queue identifier to be retrieved (0 means not specified)
    urpc_poll_direction_t poll_direction;
    uint32_t timeout_ms;
} urpc_poll_option_t;

#define EXT_POLL_INFO_SIZE  128

typedef enum urpc_poll_event {
    POLL_EVENT_REQ_ACKED,       // client event, poll the event when client only receive urpc ack
    POLL_EVENT_REQ_RSPED,       // client event, poll the event when client only receive urpc rsp
    POLL_EVENT_REQ_ACKED_RSPED, // client event, poll the event when client receive both urpc ack and urpc rsp
    POLL_EVENT_REQ_ERR,         // client event, poll the event when client handle urpc req error
    POLL_EVENT_REQ_RECVED,      // server event, poll the event when server receive urpc req
    POLL_EVENT_REQ_SENDED,      // client event, poll the event when client send urpc req successfully
    POLL_EVENT_RSP_SENDED,      // server event, poll the event when server send urpc rsp successfully
    POLL_EVENT_RSP_ERR,         // client event, poll the event when client handle urpc rsp error
    POLL_EVENT_READ_RET,        // server event, poll the event when server finish one read wr
    POLL_EVENT_EXT,             // client & server event, poll the ext event and user change it to ext struct
    POLL_EVENT_ERR,             // client & server event, poll the event when a error occurs
    POLL_EVENT_MAX
} urpc_poll_event_t;

typedef enum urpc_poll_err_event {
    POLL_ERR_EVENT_POLL_ERR = 0,    // client & server event, poll the event when a poll error occurs
    POLL_ERR_EVENT_QUEUE_ERR,       // client & server event, poll the event when a queue error occurs
    POLL_ERR_EVENT_CTX_ERR,         // client & server event, poll the event when a ctx error occurs
    POLL_ERR_EVENT_PROTOCOL_ERR,    // client & server event, poll the event when a protocol error occurs
    POLL_ERR_EVENT_MAX
} urpc_poll_err_event_t;

typedef struct urpc_poll_msg {
    urpc_poll_event_t event;
    uint32_t func_defined : 8;
    uint32_t reserved : 24;
    union {
        struct {
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            uint64_t req_h;
            void *user_ctx;                     // context for user set
            uint32_t urpc_chid;
        } req_acked;
        struct {
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            urpc_sge_t *rsps;                   // function response sge array
            uint32_t rsps_sge_num;              // number of function response sge
            uint32_t rsp_valid_total_size;      // total length of the valid data area in the function response
            uint64_t req_h;
            void *user_ctx;                     // context for user set
            uint32_t urpc_chid;
        } req_rsped;
        struct {
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            urpc_sge_t *rsps;                   // function response sge array
            uint32_t rsps_sge_num;              // number of function response sge
            uint32_t rsp_valid_total_size;      // total length of the valid data area in the function response
            uint64_t req_h;
            void *user_ctx;                     // context for user set
            uint32_t urpc_chid;
        } req_acked_rsped;
        struct {
            /* args will be NULL for server report, non-NULL for client report */
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            uint64_t req_h;
            void *user_ctx;                     // context for user set
            uint32_t urpc_chid;
            uint32_t err_code;
        } req_err;
        struct {
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            uint32_t arg_valid_total_size;      // total length of the valid data area of the function request
            uint64_t func_id;
            void *req_ctx;                      // context information of the function request
        } req_recved;
        struct {
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
        } req_sended;
        struct {
            urpc_sge_t *rsps;                   // function response sge array
            uint32_t rsps_sge_num;              // number of function response sge
        } rsp_sended;
        struct {
            urpc_sge_t *rsps;                   // function response sge array
            uint32_t rsps_sge_num;              // number of function response sge
            void *user_ctx;                     // context for user set
            uint32_t err_code;
        } rsp_err;
        struct {
            urpc_poll_err_event_t err_event;
            urpc_sge_t *args;                   // function request parameter sge array
            uint32_t args_sge_num;              // number of function request parameter sge
            int32_t err_code;
            uint64_t urpc_qh;
            uint32_t urpc_chid;
        } event_err;
        struct {
            urpc_sge_t *l_sges;                 // local sges which reference read from
            uint32_t l_sges_num;                // num of local sges which reference read from
            void *req_ctx;                      // context information of the function request
            void *user_ctx;                     // context for user set
            uint32_t ret_code;                  // read result, 0 on success, error code on failure
        } ref_read_result;
        struct {
            char ext_info[EXT_POLL_INFO_SIZE];  // reserved for ext info, user change it to urpc_ext_poll_msg_t
        } ext_event;
    };
} urpc_poll_msg_t;

typedef struct urpc_return_wr {
    urpc_sge_t *rsps;       // function response sge array
    uint32_t rsps_sge_num;  // number of function response sge
    uint8_t status;         // function status
} urpc_return_wr_t;

#define FUNC_RETURN_FLAG_FUNC_DEFINED (1)    // enable arg func_defined when func_return

typedef struct urpc_return_option {
    uint32_t option_flag;           // flag of the option, indicating which fields are valid
    uint8_t func_defined;           // function define module, eg. FUNC_DEF_NULL
} urpc_return_option_t;

#define URPC_LOG_FLAG_FUNC              (1U)
#define URPC_LOG_FLAG_LEVEL             (1U << 1)
#define URPC_LOG_FLAG_RATE_LIMITED      (1U << 2)

typedef enum urpc_log_level {
    URPC_LOG_LEVEL_EMERG = 0,
    URPC_LOG_LEVEL_ALERT,
    URPC_LOG_LEVEL_CRIT,
    URPC_LOG_LEVEL_ERR,
    URPC_LOG_LEVEL_WARN,
    URPC_LOG_LEVEL_NOTICE,
    URPC_LOG_LEVEL_INFO,
    URPC_LOG_LEVEL_DEBUG,
    URPC_LOG_LEVEL_MAX,
} urpc_log_level_t;

typedef void (*urpc_log_func_t)(int level, char *log_msg);

typedef struct urpc_log_config {
    uint32_t log_flag;
    urpc_log_func_t func;
    urpc_log_level_t level;
    struct {
        uint32_t interval_ms;    // rate-limited log output interval. If the value is 0, rate is not limited.
        uint32_t num;            // maximum number of rate-limited logs that can be output in a specified interval.
    } rate_limited;
} urpc_log_config_t;

/* The following sge flags are mutually exclusive */
#define SGE_FLAG_RSVD                     (1 << 0)  // This flag means sge is reserved
#define SGE_FLAG_DATA_ZONE                (1 << 1)
#define SGE_FLAG_NO_MEM                   (1 << 2)  // This flag means sge not alloc mem
#define SGE_FLAG_WITH_SGL                 (1 << 3)  // This flag means sge carried read or write sgl
#define SGE_FLAG_WITH_DMA                 (1 << 4)  // This flag means sge carried read or write dma

typedef enum urpc_stats_type {
    STATS_TYPE_REQUEST_SEND,                   // request send cnt
    STATS_TYPE_REQUEST_SGES_SEND,              // request sges send cnt, not include dma sges
    STATS_TYPE_REQUEST_BYTES_SEND,             // request sge bytes send cnt, not include dma sge bytes
    STATS_TYPE_REQUEST_DMA_SGES,               // request dma sges cnt
    STATS_TYPE_REQUEST_DMA_BYTES,              // request dma sge bytes cnt
    STATS_TYPE_ACK_SEND,                       // ack send cnt
    STATS_TYPE_ACK_SGES_SEND,                  // ack sges send cnt
    STATS_TYPE_ACK_BYTES_SEND,                 // ack sge bytes send cnt
    STATS_TYPE_RESPONSE_SEND,                  // response send cnt
    STATS_TYPE_RESPONSE_SGES_SEND,             // response sges send cnt
    STATS_TYPE_RESPONSE_BYTES_SEND,            // response sge bytes send cnt
    STATS_TYPE_ACK_RESPONSE_SEND,              // ack and response send cnt
    STATS_TYPE_ACK_RESPONSE_SGES_SEND,         // ack and response sges send cnt
    STATS_TYPE_ACK_RESPONSE_BYTES_SEND,        // ack and response sge bytes send cnt
    STATS_TYPE_READ,                           // read cnt
    STATS_TYPE_READ_SGES,                      // read sges cnt
    STATS_TYPE_READ_BYTES,                     // read sge bytes cnt

    STATS_TYPE_REQUEST_SEND_CONFIRMED,         // request send confirmed cnt
    STATS_TYPE_REQUEST_SGES_SEND_CONFIRMED,    // request sges send confirmed cnt, not include dma sges
    STATS_TYPE_REQUEST_BYTES_SEND_CONFIRMED,   // request sge bytes send confirmed cnt, not include dma sge bytes
    STATS_TYPE_ACK_SEND_CONFIRMED,             // ack send confirmed cnt
    STATS_TYPE_ACK_SGES_SEND_CONFIRMED,        // ack sges send confirmed cnt
    STATS_TYPE_ACK_BYTES_SEND_CONFIRMED,       // ack sge bytes send confirmed cnt
    STATS_TYPE_RESPONSE_SEND_CONFIRMED,        // response send confirmed cnt
    STATS_TYPE_RESPONSE_SGES_SEND_CONFIRMED,   // response sges send confirmed cnt
    STATS_TYPE_RESPONSE_BYTES_SEND_CONFIRMED,  // response sge bytes send confirmed cnt
    STATS_TYPE_ACK_RESPONSE_SEND_CONFIRMED,        // ack and response send cnt
    STATS_TYPE_ACK_RESPONSE_SGES_SEND_CONFIRMED,   // ack and response sges send cnt
    STATS_TYPE_ACK_RESPONSE_BYTES_SEND_CONFIRMED,  // ack and response sge bytes send cnt
    STATS_TYPE_READ_CONFIRMED,                     // read confirmed cnt
    STATS_TYPE_READ_SGES_CONFIRMED,                // read sges confirmed cnt
    STATS_TYPE_READ_BYTES_CONFIRMED,               // read sge bytes confirmed cnt

    STATS_TYPE_REQUEST_RECEIVE,                // request recv cnt
    STATS_TYPE_REQUEST_SGES_RECEIVE,           // request sges recv cnt
    STATS_TYPE_REQUEST_BYTES_RECEIVE,          // request sge bytes recv cnt
    STATS_TYPE_ACK_RECEIVE,                    // ack recv cnt
    STATS_TYPE_ACK_SGES_RECEIVE,               // ack sges recv cnt
    STATS_TYPE_ACK_BYTES_RECEIVE,              // ack sge bytes recv cnt
    STATS_TYPE_RESPONSE_RECEIVE,               // response recv cnt
    STATS_TYPE_RESPONSE_SGES_RECEIVE,          // response sges recv cnt
    STATS_TYPE_RESPONSE_BYTES_RECEIVE,         // response sge bytes recv cnt
    STATS_TYPE_ACK_RESPONSE_RECEIVE,           // ack and response recv cnt
    STATS_TYPE_ACK_RESPONSE_SGES_RECEIVE,      // ack and response sges recv cnt
    STATS_TYPE_ACK_RESPONSE_BYTES_RECEIVE,     // ack and response sge bytes recv cnt

    STATS_TYPE_RECV_PLOG_REQ,                  // server recv plog req cnt
    STATS_TYPE_RECV_PLOG_REQ_SGES,             // server recv plog req sges
    STATS_TYPE_RECV_PLOG_REQ_SGES_BYTES,       // server recv plog req bytes

    STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ_SENDED,    // early rsp without ack, req sended cnt
    STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ_RSPED,     // early rsp without ack, req rsped cnt
    STATS_TYPE_EARLY_RSP_WITH_ACK_REQ_SENDED,       // early rsp with ack,  req sended cnt
    STATS_TYPE_EARLY_RSP_WITH_ACK_REQ_ACKED_RSPED,  // early rsp with ack,  req acked cnt

    STATS_TYPE_NORMAL_WITH_ACK_REQ_SENDED,          // normal with ack, req sended cnt
    STATS_TYPE_NORMAL_WITH_ACK_REQ_ACKED_RSPED,     // normal with ack, req acked and rsped cnt
    STATS_TYPE_NORMAL_WITH_ACK_REQ_ACKED,           // normal with ack, req acked cnt
    STATS_TYPE_NORMAL_WITHOUT_ACK_REQ_SENDED,       // normal without ack, req sended cnt
    STATS_TYPE_NORMAL_WITHOUT_ACK_REQ_RSPED,        // normal without ack, req rsped cnt
    STATS_TYPE_MAX,
} urpc_stats_type_t;

typedef enum urpc_error_stats_type {
    ERR_STATS_TYPE_INVALID_PARAM,              // invalid parameter
    ERR_STATS_TYPE_INVALID_MEM_HANDLE,         // invalid memory handle in read sge
    ERR_STATS_TYPE_INVALID_HEADER_VERSION,     // invalid header version
    ERR_STATS_TYPE_INVALID_HEADER_LENGTH,      // invalid header length
    ERR_STATS_TYPE_INVALID_HEADER_RSN,         // invalid header rsn
    ERR_STATS_TYPE_INVALID_HEADER_FUNC_DEFINED,  // invalid header function defined
    ERR_STATS_TYPE_NO_CHANNEL,                 // get channel failed
    ERR_STATS_TYPE_NO_LOCAL_QUEUE,             // get local queue failed
    ERR_STATS_TYPE_NO_REMOTE_QUEUE,            // get remote queue failed
    ERR_STATS_TYPE_NO_MEM,                     // get queue ctx memory failed
    ERR_STATS_TYPE_SEND,                       // queue post send failed
    ERR_STATS_TYPE_READ,                       // queue post read failed
    ERR_STATS_TYPE_READ_EAGAIN,                // queue post read need retry
    ERR_STATS_TYPE_POLL,                       // queue poll failed
    ERR_STATS_TYPE_POST,                       // queue post recv buffer failed

    ERR_STATS_TYPE_ACK_NO_BUFFER_FAILED,       // send ack no allocator buffer
    ERR_STATS_TYPE_ACK_BUF_LEN_INVALID,        // send ack allocator buffer length invalid
    ERR_STATS_TYPE_ACK_GET_TX_CTX_FAILED,      // send ack get tx ctx failed
    ERR_STATS_TYPE_ACK_SEND_FAILED,            // send ack failed

    ERR_STATS_TYPE_ACK_RSP_NO_BUF,             // send ack rsp no allocator buffer
    ERR_STATS_TYPE_ACK_RSP_BUF_LEN_INVALID,    // send ack rsp allocator buffer length invalid
    ERR_STATS_TYPE_ACK_RSP_GET_TX_CTX_FAILED,  // send ack rsp get tx ctx failed
    ERR_STATS_TYPE_ACK_RSP_SEND_FAILED,        // send ack rsp failed

    ERR_STATS_TYPE_REQ_INVALID_HEADER_LENGTH,  // recv req invalid header length
    ERR_STATS_TYPE_REQ_INVALID_HEADER_VERSION, // recv req invalid header version
    ERR_STATS_TYPE_REQ_NO_REMOTE_QUEUE,        // recv req no remote queue
    ERR_STATS_TYPE_REQ_GET_REQ_CTX_NO_MEM,     // recv req get req ctx memory failed
    ERR_STATS_TYPE_REQ_INVALID_DMA_CNT,        // recv read req invalid dma cnt
    ERR_STATS_TYPE_REQ_INVALID_DMA_POS,        // recv read req get dma pos failed
    ERR_STATS_TYPE_REQ_INVALID_DMA_INFO_LEN,   // recv read req invalid dma len
    ERR_STATS_TYPE_REQ_READ_NO_TX_CTX,         // recv read req get read tx ctx failed
    ERR_STATS_TYPE_READ_PARM_INVALID,          // recv read req parm invalid
    ERR_STATS_TYPE_READ_PROVIDER_INVALID,      // recv read req provider invalid
    ERR_STATS_TYPE_REQ_POST_INVALID_DATA_INFO, // recv read data post invalid dma info
    ERR_STATS_TYPE_REQ_READ_ERR_CQE,           // recv read req err cqe
    ERR_STATS_TYPE_REQ_READ_ERR_DATA_TRANS_MODE,  // recv read req err data trans mode

    ERR_STATS_TYPE_CALL_PARM_INVALID,          // urpc func call param invalid
    ERR_STATS_TYPE_CALL_NO_CHANNEL,            // urpc func call no channel
    ERR_STATS_TYPE_CALL_NO_L_QUEUE,            // urpc func call no local queue
    ERR_STATS_TYPE_CALL_NO_R_QUEUE,            // urpc func call no remote queue
    ERR_STATS_TYPE_CALL_GET_TX_CTX_FAILED,     // urpc func call get tx ctx failed
    ERR_STATS_TYPE_CALL_NO_RSN,                // urpc func call no rsn
    ERR_STATS_TYPE_CALL_QUEUE_PROTOCOL,        // urpc func call queue protocol mismatch
    ERR_STATS_TYPE_CALL_SEND_FAILED,           // urpc func call send failed

    ERR_STATS_TYPE_EXT_CALL_PARM_INVALID,      // urpc ext func call param invalid
    ERR_STATS_TYPE_EXT_CALL_PARM_VALID_FAILED, // urpc ext func call param valid failed
    ERR_STATS_TYPE_EXT_CALL_FILL_HDR_FAILED,   // urpc ext func call fill ext hdr failed
    ERR_STATS_TYPE_EXT_CALL_CALL_MODE_INVALID, // urpc ext func call mode invalid

    ERR_STATS_TYPE_FILL_DMA_INFO_NO_CHANNEL,   // urpc ext func call fill dma info no channel
    ERR_STATS_TYPE_FILL_DMA_INFO_NO_PROVIDER,  // urpc ext func call fill dma info no provider
    ERR_STATS_TYPE_FILL_DMA_INFO_SGE_NUM_LESS, // urpc ext func call fill dma info sge num invalid
    ERR_STATS_TYPE_FILL_DMA_INFO_NO_MEM_SGE,   // urpc ext func call fill dma info not have no mem sge
    ERR_STATS_TYPE_FILL_DMA_INFO_DMA_CNT_ZERO, // urpc ext func call fill dma info dma cnt zero
    ERR_STATS_TYPE_FILL_DMA_INFO_SGE_FLAG_ERR, // urpc ext func call fill dma info data sge flag invalid
    ERR_STATS_TYPE_FILL_DMA_INFO_NO_BUF,       // urpc ext func call fill dma info get raw buf failed
    ERR_STATS_TYPE_FILL_DMA_INFO_MEMH_INVALID, // urpc ext func call fill dma info memh invalid

    ERR_STATS_TYPE_SELECT_QUEUE_NO_CHANNEL,    // urpc call select queue no channel
    ERR_STATS_TYPE_SELECT_QUEUE_NO_L_QUEUE,    // urpc call select queue no local queue

    ERR_STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ,  // in early rsp without ack mode, req error cnt
    ERR_STATS_TYPE_EARLY_RSP_WITH_ACK_REQ,     // in early rsp with ack mode, req error cnt
    ERR_STATS_TYPE_NORMAL_WITH_ACK_REQ,        // in normal with ack mode, req error cnt
    ERR_STATS_TYPE_NORMAL_WITHOUT_ACK_REQ,     // in normal without ack mode, req error cnt
    ERR_STATS_TYPE_RSP,                        // rsp error
    ERR_STATS_TYPE_MAX,
} urpc_error_stats_type_t;

/**
 * URPC_SSL_FLAG_ENABLE: enable security capabilities for control plane and data plane
 * URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE: data plane option, disable the encryption of urpc payload
 * which is enabled by default.
 * Note that, urpc header encryption is still enabled.
 * URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE: data plane option, disable the encryption of urpc header
 * which is enabled by default.
 *
 * URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE and URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE only take effect when URPC_SSL_FLAG_ENABLE
 * is set. Only support to set URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE alone or (URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE |
 * URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE) together.
 */
#define URPC_SSL_FLAG_ENABLE                    (1U)
#define URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE       (1U << 1)
#define URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE      (1U << 2)

typedef enum urpc_ssl_mode {
    SSL_MODE_PSK = 0,

    SSL_MODE_MAX,
} urpc_ssl_mode_t;

typedef unsigned int (*urpc_ssl_psk_client_cb_func)(void *ssl, const char *hint, char *identity,
    unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
typedef unsigned int (*urpc_ssl_psk_server_cb_func)(
    void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);

typedef enum urpc_tls_version {
    URPC_TLS_VERSION_1_2 = 0,
    URPC_TLS_VERSION_1_3,

    URPC_TLS_VERSION_MAX,
} urpc_tls_version_t;

typedef struct urpc_ssl_config {
    uint32_t ssl_flag;                                    // Indicates whether SSL is enabled.
    urpc_ssl_mode_t ssl_mode;
    urpc_tls_version_t min_tls_version;
    urpc_tls_version_t max_tls_version;
    union {
        struct {
            char *cipher_list;                           // Select the cipher used which takes effect in TLS1.2. The
                                                         // maximum length cannot exceed 4096 (include '\0').
            char *cipher_suites;                         // Select the cipher used which takes effect in TLS1.3. The
                                                         // maximum length cannot exceed 4096 (include '\0').
            urpc_ssl_psk_client_cb_func client_cb_func;  // client_cb_func should not be NULL for client/server_client.
            urpc_ssl_psk_server_cb_func server_cb_func;  // server_cb_func should not be NULL for server/server_client.
        } psk;
    };
} urpc_ssl_config_t;

typedef struct urpc_ctrl_msg_id {
    urpc_eid_t eid;
    uint32_t uasid;
    uint32_t id;
} urpc_ctrl_msg_id_t;

typedef struct urpc_ctrl_msg {
    void *user_ctx;                         // context for user set
    char *msg;          // msg transferred in control path, including client send to server, and server reply to client
    uint32_t msg_size;  // size of msg transferred in control path
    uint32_t msg_max_size;                  // max size of msg buffer in control path
    urpc_ctrl_msg_id_t id[MAX_QUEUE_SIZE];  // remote queue id transferred in control path
    uint32_t id_num;                        // valid num of remote queue id transferred in control path
    uint32_t is_server : 1;                  // whether the callback comes from the client or the server
    uint32_t rsvd : 31;
} urpc_ctrl_msg_t;

typedef enum urpc_ctrl_msg_type {
    URPC_CTRL_MSG_ATTACH = 0,
    URPC_CTRL_MSG_REFRESH,
    URPC_CTRL_MSG_DETACH,

    URPC_CTRL_MSG_MAX,
} urpc_ctrl_msg_type_t;

typedef enum urpc_async_event_type {
    URPC_ASYNC_EVENT_CHANNEL_ATTACH,
    URPC_ASYNC_EVENT_CHANNEL_REFRESH,
    URPC_ASYNC_EVENT_CHANNEL_DETACH,
    URPC_ASYNC_EVENT_CHANNEL_QUEUE_ADD,
    URPC_ASYNC_EVENT_CHANNEL_QUEUE_RM,
    URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR,
    URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR,
    URPC_ASYNC_EVENT_TYPE_MAX,
} urpc_async_event_type_t;

typedef struct urpc_async_event {
    urpc_async_event_type_t event_type;
    int err_code;
    void *ctx;
    uint64_t l_qh;
    uint64_t r_qh;
    uint32_t channel_id;
} urpc_async_event_t;

/* urpc channel connect options */
#define URPC_CHANNEL_CONN_FLAG_FEATURE     (1)      // enable feature
#define URPC_CHANNEL_CONN_FLAG_CTX         (1 << 1) // enable ctx
#define URPC_CHANNEL_CONN_FLAG_CTRL_MSG    (1 << 2) // enable ctrl_msg
#define URPC_CHANNEL_CONN_FLAG_BIND_LOCAL  (1 << 3) // enable bind local info
#define URPC_CHANNEL_CONN_FLAG_TIMEOUT     (1 << 4) // enable timeout

#define URPC_CHANNEL_CONN_FEATURE_NONBLOCK (1)

typedef struct urpc_channel_connect_option {
    uint32_t flag;              // flag of the option, indicating which fields are valid
    uint32_t feature;           // connect feature
    void *ctx;                  // connect ctx in non-block async_event
    urpc_ctrl_msg_t *ctrl_msg;  // msg transferred in control path
    urpc_host_info_t local;     // bind local
    int timeout;                // timeout duration (in milliseconds, -1 indicates infinite waiting, 0 is invalid)
} urpc_channel_connect_option_t;

typedef enum urpc_channel_queue_type {
    CHANNEL_QUEUE_TYPE_LOCAL,
    CHANNEL_QUEUE_TYPE_REMOTE,
} urpc_channel_queue_type_t;

typedef struct urpc_channel_queue_attr {
    urpc_channel_queue_type_t type;
} urpc_channel_queue_attr_t;

typedef int (*urpc_ctrl_cb_t)(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg);

typedef enum urpc_perf_record_point {
    /* record point for urpc_func_call */
    PERF_RECORD_POINT_FUNC_CALL,
    /* record point for urpc_func_poll */
    PERF_RECORD_POINT_FUNC_POLL,
    /* record point for urpc_func_return */
    PERF_RECORD_POINT_FUNC_RETURN,
    /* record point for urpc_ref_read */
    PERF_RECORD_POINT_REF_READ,
    /* record point for urpc_queue_rx_post */
    PERF_RECORD_POINT_QUEUE_RX_POST,
    /* record point for urpc_ext_func_call */
    PERF_RECORD_POINT_EXT_FUNC_CALL,
    /* record point for urpc_ext_func_return */
    PERF_RECORD_POINT_EXT_FUNC_RETURN,
    /* record point for transport send in urpc_func_call and urpc_func_return */
    PERF_RECORD_POINT_TRANSPORT_SEND,
    /* record point for transport poll in urpc_func_poll */
    PERF_RECORD_POINT_TRANSPORT_POLL,
    /* record point for transport read in urpc_ref_read */
    PERF_RECORD_POINT_TRANSPORT_READ,
    /* record point for transport post in urpc_queue_rx_post */
    PERF_RECORD_POINT_TRANSPORT_POST,
    PERF_RECORD_POINT_MAX,
} urpc_perf_record_point_t;

typedef enum urpc_perf_record_type {
    PERF_RECORD_TYPE_BEGIN,
    PERF_RECORD_TYPE_END,
} urpc_perf_record_type_t;

typedef void (*urpc_perf_recorder_t)(urpc_perf_record_type_t type, urpc_perf_record_point_t point);

#ifdef __cplusplus
}
#endif

#endif
