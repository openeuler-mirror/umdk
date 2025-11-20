/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_types.h
 * Description   : dlock type definitions
 * History       : create file & add functions
 * 1.Date        : 2022-03-21
 * Author        : geyi
 * Modification  : Created file
 */

#ifndef _DLOCK_TYPES_H__
#define _DLOCK_TYPES_H__

#include <cstdint>

namespace dlock {
extern "C" {

typedef enum debug_stats_code {
    DEBUG_STATS_EAGAIN = 0,   // Resource temporarily unavailable
    DEBUG_STATS_NO_URMA_BUF, // No registered buf for URMA
    DEBUG_STATS_ENOMEM,   // Failed to allocate memory
    DEBUG_STATS_ETIMEOUT, // Operation time out
    DEBUG_STATS_EINVAL_LOCK_OP,
    DEBUG_STATS_EINVAL_LOCK_TYPE,
    DEBUG_STATS_EINVAL_LOCK_OFFSET,
    DEBUG_STATS_EINVAL_LOCK_RET,
    DEBUG_STATS_ETICKET,
    DEBUG_STATS_EASYNC,
    DEBUG_STATS_CLIENT_NOT_INIT, // always == 0
    DEBUG_STATS_LOCK_NOT_GET,
    DEBUG_STATS_ALREADY_LOCKED,
    DEBUG_STATS_ALREADY_UNLOCKED,
    DEBUG_STATS_ATOMIC_TRYLOCK_FAIL,
    DEBUG_STATS_ATOMIC_UNLOCK_FAIL,
    DEBUG_STATS_ATOMIC_EXTEND_FAIL,
    DEBUG_STATS_RW_TRYLOCK_EX_FAIL,
    DEBUG_STATS_RW_UNLOCK_EX_FAIL,
    DEBUG_STATS_RW_TRYLOCK_SH_FAIL,
    DEBUG_STATS_RW_UNLOCK_SH_FAIL,
    DEBUG_STATS_FAIR_QUEUE_LIMIT,
    DEBUG_STATS_FAIR_UNLOCK_EX_FAIL,
    DEBUG_STATS_FAIR_UNLOCK_SH_FAIL,
    DEBUG_STATS_FAIR_EX_TICKET_PASSED,
    DEBUG_STATS_FAIR_SH_TICKET_PASSED,
    DEBUG_STATS_INVALID_LOCK_STATE, // Try to acquire an excusive lock in shared mode, or do an opposite way
    DEBUG_STATS_TICKET_TO_UNLOCK, // Indicate ticket got by client, unlock should be called before release called
    DEBUG_STATS_NETWORK_FAIL, // post_send or post_recv failed
    DEBUG_STATS_SEND_FAIL, // server post_send failed
    DEBUG_STATS_BAD_RESPONSE,
    DEBUG_STATS_CLIENT_DISCONNECT, // connection closed by client exceptionally
    DEBUG_STATS_FAIL,
    DEBUG_STATS_CLIENTMGR_NOT_INIT, // always == 0
    DEBUG_STATS_NOT_READY,
    DEBUG_STATS_NO_ASYNC,
    DEBUG_STATS_ASYNC_AGAIN,
    DEBUG_STATS_REPLICA_INIT_FAIL,
    DEBUG_STATS_SERVER_NOT_INIT,
    DEBUG_STATS_ENCRYPT_FAIL,
    DEBUG_STATS_DECRYPT_FAIL,
    DEBUG_STATS_CLIENT_ID_VERIFY_FAIL,
    DEBUG_STATS_BAD_REQUEST,
    DEBUG_STATS_OBJECT_NOT_GET,
    DEBUG_STATS_OBJECT_CAS_FAILED,
    DEBUG_STATS_MAX
} debug_stats_code_t;

struct debug_stats {
    uint64_t stats[DEBUG_STATS_MAX];
};

enum lock_ops {
    LOCK_EXCLUSIVE = 0,
    LOCK_SHARED,
    UNLOCK,
    EXTEND_LOCK_EXCLUSIVE,
    EXTEND_LOCK_SHARED,
    LOCK_OPS_MAX
};

enum dlock_type { DLOCK_ATOMIC = 0, DLOCK_RW, DLOCK_FAIR, DLOCK_MAX };

struct err_event {
    uint8_t err_type;
};

constexpr unsigned int MAX_LOCK_DESC_LEN = 512;
constexpr unsigned int MAX_UMO_ATOMIC64_DESC_LEN = MAX_LOCK_DESC_LEN;
constexpr unsigned int MAX_LOCK_BATCH_SIZE = 31;
constexpr int SLEEP_INTERVAL = 100000;
#ifdef URMA_EID_SIZE
#define DLOCK_EID_SIZE URMA_EID_SIZE
#else
#define DLOCK_EID_SIZE (16)
#endif

struct lock_desc {
    char *p_desc;
    unsigned int len;
    unsigned int lock_type;
    unsigned int lease_time;
};

struct lock_request {
    int lock_id;
    int lock_op;
    unsigned int expire_time;
};

typedef int (*callback_func_t)(const struct err_event *);
typedef struct {
    int client_id;
    uint32_t time_out;
} atomic_state;

typedef struct {
    uint32_t time_out;
    int32_t client_id;
    uint32_t rcount;
    uint32_t rsvd;
} rw_state;

typedef struct {
    uint16_t n_exclusive;
    uint16_t n_shared;
    uint16_t m_exclusive;
    uint16_t m_shared;
    uint32_t time_out;
    union {
        uint32_t t_value;
        struct {
            uint16_t rms;
            uint16_t rflag : 1;
            uint16_t rsvd : 9;
            uint16_t rcnt : 6;
        } bs;
    };
} fairlock_state;

typedef union {
    atomic_state atomic;
    rw_state rw;
    fairlock_state fl;
    uint64_t base;
} lock_state;

struct lock_op_res {
    union {
        atomic_state atomic;
        rw_state rw;
        fairlock_state fl;
    };
    int op_ret;
};

struct lock_context {
    unsigned int lock_type;
    int32_t lock_id;
    uint32_t lease_time;
    unsigned int ref_count;
    lock_state ls;
};

enum server_type {
    SERVER_PRIMARY,
    SERVER_REPLICA,
    SERVER_MAX
};

enum thread_type {
    CTRL_THREAD,
    CMD_THREAD
};

/* TLS callback function type */
typedef int (*tls_cert_verify_callback_func_t)(void *ctx, const char *crl_path);
typedef void (*tls_prkey_pwd_callback_func_t)(char **prkey_pwd, int *prkey_pwd_len);
typedef void (*tls_erase_prkey_callback_func_t)(void *prkey_pwd, int prkey_pwd_len);

struct ssl_cfg {
    bool ssl_enable;
    char *ca_path;
    char *crl_path;
    char *cert_path;
    char *prkey_path;
    tls_cert_verify_callback_func_t cert_verify_cb;
    tls_prkey_pwd_callback_func_t prkey_pwd_cb;
    tls_erase_prkey_callback_func_t erase_prkey_cb;
};

typedef enum trans_mode {
    SEPERATE_CONN, // two-way tansports take seperate urma connections
    UNI_CONN // two-way tansports share the same urma connection
} trans_mode_t;

typedef enum new_jetty_type { // indicate different num_buf
    CLIENT,
    CLIENT_PRIMARY,
    REPLICA_PRIMARY
} new_jetty_t;

typedef union dlock_eid {
    uint8_t raw[DLOCK_EID_SIZE]; /* Network Order */
    struct {
        uint64_t reserved;      /* If IPv4 mapped to IPv6, == 0 */
        uint32_t prefix;        /* If IPv4 mapped to IPv6, == 0x0000ffff */
        uint32_t addr;          /* If IPv4 mapped to IPv6, == IPv4 addr */
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} dlock_eid_t;

struct client_cfg {
    char *dev_name;
    dlock_eid_t eid;
    int log_level;
    int primary_port;
    struct ssl_cfg ssl;
    trans_mode_t tp_mode;
    bool ub_token_disable;
};

struct primary_cfg {
    unsigned int num_of_replica;
    unsigned int recovery_client_num;
    char *ctrl_cpuset;
    char *cmd_cpuset;
    char *server_ip_str;
    int server_port;
    int replica_port;
    bool replica_enable;
};

struct replica_cfg {
    char *primary_ip_str;
    int primary_port;
};

struct server_cfg {
    enum server_type type;
    char *dev_name;
    dlock_eid_t eid;
    int log_level;
    bool sleep_mode_enable;
    union {
        struct primary_cfg primary;
        struct replica_cfg replica;
    };
    struct ssl_cfg ssl;
    trans_mode_t tp_mode;
    bool ub_token_disable;
};

struct umo_atomic64_desc {
    char *p_desc;
    uint32_t len;
    uint32_t lease_time;
};

typedef enum dlock_status {
    DLOCK_SUCCESS = 0,
    DLOCK_DONE,
    DLOCK_EAGAIN = 0x1000,   // Resource temporarily unavailable
    DLOCK_ENOMEM,   // Failed to allocate memory
    DLOCK_ETIMEOUT, // Operation time out
    DLOCK_EINVAL,   // Invalid argument
    DLOCK_ETICKET,
    DLOCK_EASYNC,
    DLOCK_CLIENT_NOT_INIT = 0x2000,
    DLOCK_LOCK_NOT_GET,
    DLOCK_ALREADY_LOCKED,
    DLOCK_ALREADY_UNLOCKED,
    DLOCK_TICKET_TO_UNLOCK, // Indicate ticket got by client, unlock should be called before release called
    DLOCK_BAD_RESPONSE,
    DLOCK_FAIL,
    DLOCK_CLIENTMGR_NOT_INIT,
    DLOCK_NOT_READY,
    DLOCK_NO_ASYNC,
    DLOCK_ASYNC_AGAIN,
    DLOCK_REPLICA_INIT_FAIL,
    DLOCK_SERVER_NOT_INIT,
    DLOCK_CLIENT_REMOVED_BY_SERVER,
    DLOCK_PROTO_VERSION_NEGOTIATION_FAIL,
    DLOCK_SERVER_NO_RESOURCE,
    DLOCK_OBJECT_ALREADY_EXISTED = 0x3000, // other clients has created the object
    DLOCK_OBJECT_ALREADY_CREATED,  // the same client has created the object before
    DLOCK_OBJECT_NOT_CREATE,
    DLOCK_OBJECT_INVALID_OWNER,
    DLOCK_OBJECT_NOT_GET,
    DLOCK_OBJECT_ALREADY_DESTROYED,
    DLOCK_OBJECT_TOO_MANY,
    DLOCK_OBJECT_CAS_FAILED,
} dlock_status_t;
}
};
#endif  // _DLOCK_TYPES_H__
