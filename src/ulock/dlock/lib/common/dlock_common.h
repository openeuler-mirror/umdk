/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_common.h
 * Description   : common definition of dlock
 * History       : create file & add functions
 * 1.Date        : 2021-06-15
 * Author        : zhangjun
 * Modification  : Created file
 */

#ifndef __DLOCK_COMMON_H__
#define __DLOCK_COMMON_H__

#include <shared_mutex>
#include <cstdint>
#include <ctime>
#include <string>

#include "urma_types.h"
#ifdef UB_AGG
#include "urma_ubagg.h"
#endif /* UB_AGG */
#include "dlock_types.h"

namespace dlock {
constexpr uint8_t DLOCK_PROTO_VERSION = 2;
constexpr uint8_t DLOCK_MIN_PROTO_VERSION = 2;    /* Minimum DLock protocol version supported for compatibility. */
constexpr uint32_t DLOCK_CP_MAGIC_NO = 0xedf7c94a;
constexpr uint32_t DLOCK_DP_MAGIC_NO = 0xedf7c94b;
constexpr long MAX_MSG_BODY_LEN = 1024;
constexpr unsigned int MAX_NUM_REPLICA = 8;
constexpr unsigned int CLIENT_PER_HOST = 32;
constexpr int MAX_NUM_CLIENT = 1000;
constexpr int MAX_NUM_SERVER = 32;
constexpr unsigned int CONTROL_PORT_REPLICA = 21615;
constexpr unsigned int CONTROL_PORT_CLIENT = 21616;
constexpr int LISTEN_QUEUE = 1024;
constexpr int EPOLL_TIMEOUT = 5000;    /* ms */
constexpr long LOCK_TIMEOUT = 5000000;
constexpr long PAGE_ALIGN = 4096;
constexpr unsigned int GID_SIZE = 16;
constexpr unsigned int URMA_MTU = 1024;
constexpr unsigned char QP_MIN_RNR_TIMER = 12;
constexpr unsigned char QP_TIMEOUT = 14;
constexpr unsigned char QP_RETRY_CNT = 7;
constexpr unsigned char QP_RNR_RETRY = 7;
constexpr unsigned int CMD_SQ_SIZE = 4;
constexpr unsigned int EXE_SQ_SIZE = 256;
constexpr unsigned int CMD_RQ_SIZE = 4;
constexpr unsigned int EXE_RQ_SIZE = 256;
constexpr unsigned int CQ_SIZE_PER_CLIENT = CMD_SQ_SIZE + CMD_RQ_SIZE;
constexpr int MIN_CQ_SIZE = 2;
constexpr int NUM_TO_SIGNAL = 20;
constexpr int MAX_SERVER_ID = 0xFFFFF;
constexpr unsigned int ONE_MILLION = 1000000;
constexpr unsigned int CONTROL_SOCKET_TIMEOUT = 10;    /* seconds */
constexpr unsigned int PRIMARY_SERVER_CONTROL_SOCKET_TIMEOUT = 2;    /* seconds */
constexpr unsigned int JETTY_MGR_NUM_PER_REPLICA = 2;
constexpr unsigned int SERVER_URMA_CTX_REG_BUF_NUM = MAX_NUM_CLIENT * (CMD_RQ_SIZE + CMD_SQ_SIZE) +
    MAX_NUM_REPLICA * JETTY_MGR_NUM_PER_REPLICA * (EXE_SQ_SIZE + EXE_RQ_SIZE);
constexpr uint32_t DLOCK_LOCK_CMD_MSG_CMP_SIZE = 10;
constexpr uint32_t OBJECT_MAX_NUMBER = 102400;
constexpr uint32_t OBJECT_MEMORY_SIZE = OBJECT_MAX_NUMBER * sizeof(uint64_t);
constexpr unsigned int DLOCK_UB_SEG_VA_ALIGN_SIZE = 4096;
constexpr uint32_t DLOCK_SEG_ACCESS_FLAGS = (URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC);

enum dlock_req_code {
    EXCLUSIVE_TRYLOCK = 0,
    EXCLUSIVE_UNLOCK,
    EXCLUSIVE_LOCK_EXTEND,
    EXCLUSIVE_TICKET_TRYLOCK,
    SHARED_TRYLOCK,
    SHARED_UNLOCK,
    SHARED_LOCK_EXTEND,
    SHARED_TICKET_TRYLOCK,
    OP_CODE_MAX,
    OP_CODE_NULL,
    OP_REPLICA_CATCH_UP,
    OP_REPLICA_SYNC,
    OP_LOCAL_RESET
};

enum dlock_state {
    LOCK_INITIALIZED = 0,
    EXCLUSIVE_LOCKED,
    SHARED_LOCKED,
    UNLOCKED,
    EXCLUSIVE_TICKETED,
    SHARED_TICKETED,
    LOCK_STATE_MAX
};

/* The enum type sequence cannot be changed. Otherwise, some codes are affected.
   If a new type is added, ensure that the value of REQUEST is an even number
   and the value of RESPONSE is an odd number. */
enum dlock_control_msg {
    REPLICA_INIT_REQUEST = 0,
    REPLICA_INIT_RESPONSE,
    REPLICA_CTRL_CATCHUP_REQUEST,
    REPLICA_CTRL_CATCHUP_RESPONSE,
    REPLICA_ADD_CLIENTS_REQUEST,
    REPLICA_ADD_CLIENTS_RESPONSE,
    REPLICA_ADD_LOCKS_REQUEST,
    REPLICA_ADD_LOCKS_RESPONSE,
    REPLICA_ADD_LOCK_CLIENT_RELS_REQUEST,
    REPLICA_ADD_LOCK_CLIENT_RELS_RESPONSE,
    REPLICA_DEINIT_REQUEST,
    REPLICA_DEINIT_RESPONSE,

    CLIENT_INIT_REQUEST,
    CLIENT_INIT_RESPONSE,
    CLIENT_DEINIT_REQUEST,
    CLIENT_DEINIT_RESPONSE,
    CLIENT_HEARTBEAT_REQUEST,
    CLIENT_HEARTBEAT_RESPONSE,
    GET_LOCK_REQUEST,
    GET_LOCK_RESPONSE,
    RELEASE_LOCK_REQUEST,
    RELEASE_LOCK_RESPONSE,
    BATCH_GET_LOCK_REQUEST,
    BATCH_GET_LOCK_RESPONSE,
    BATCH_RELEASE_LOCK_REQUEST,
    BATCH_RELEASE_LOCK_RESPONSE,

    OBJECT_CREATE_REQUEST,
    OBJECT_CREATE_RESPONSE,
    OBJECT_GET_REQUEST,
    OBJECT_GET_RESPONSE,
    OBJECT_RELEASE_REQUEST,
    OBJECT_RELEASE_RESPONSE,
    OBJECT_DESTROY_REQUEST,
    OBJECT_DESTROY_RESPONSE,

    CLIENT_REINIT_REQUEST,
    CLIENT_REINIT_RESPONSE,
    CLIENT_REINIT_DONE_REQUEST,
    CLIENT_REINIT_DONE_RESPONSE,
    BATCH_UPDATE_LOCKS_REQUEST,
    BATCH_UPDATE_LOCKS_RESPONSE,

    DLOCK_CONTROL_MAX
};

typedef enum dlock_response {
    DLOCK_RESP_OK = 0,
    DLOCK_RESP_INIT,
    DLOCK_RESP_CTRL_SYNC,
    DLOCK_RESP_DATA_SYNC,
} dlock_resp_t;

typedef enum dlock_server_state {
    SERVER_INIT = 0,
    SERVER_WAIT_REPLICA,
    SERVER_WAIT_CLIENT_REINIT,
    SERVER_READY,
    SERVER_REPLICA_INIT,
    SERVER_REPLICA_CTRL_SYNC,
    SERVER_REPLICA_DATA_SYNC,
    SERVER_REPLICA_READY,
    SERVER_REPLICA_FAILURE,
    /* replica threads or resources have been released partially, only used for repeat call of server_promote */
    SERVER_REPLICA_ONLY_PROMOTE,
} dlock_server_state_t;

struct dlock_control_hdr {
    uint32_t magic_no;
    uint8_t version;
    uint8_t hdr_len;
    uint8_t type;
    uint8_t rsvd;
    uint16_t total_len;
    uint16_t message_id;
    union {
        int32_t client_id; /* request */
        int32_t status; /* response */
        int32_t value;
    };
};

struct urma_init_body {
    trans_mode_t tp_mode;
    union {
        /* jfr for seperate transport mode */
        urma_jfr_id_t jfr_id;
        /* jetty for uni transport mode */
        urma_jetty_id_t jetty_id;
    };

    union {
        struct {
            uint32_t token_policy : 3;
            uint32_t reserved : 29;
        } bs;
        uint32_t value;
    } flag;

    uint32_t token; /* for jfr/jetty */

#ifdef UB_AGG
    bool is_bond;
    urma_bond_id_info_out_t bond_id_info;
#endif /* UB_AGG */
};

struct client_init_req_body {
    struct urma_init_body jetty_info;
    uint32_t min_version : 8;
    uint32_t rsvd : 24;
};

struct client_init_resp_body {
    struct urma_init_body jetty_info;
    int32_t client_id;
    uint32_t server_state : 8;
    uint32_t rsvd : 24;
    urma_seg_t obj_mem_seg;
    uint32_t obj_mem_seg_token;
};

struct get_lock_body {
    int32_t lock_id;
    uint32_t lock_type;
    uint32_t lease_time;
    uint32_t offset;
    uint32_t desc_len;
    unsigned char desc[0];
};

struct release_lock_body {
    int32_t lock_id;
};

struct batch_get_lock_body {
    uint32_t lock_num;
    struct get_lock_body get_lock_entry[0];
};

struct batch_release_lock_body {
    uint32_t lock_num;
    struct release_lock_body release_lock_entry[0];
};

struct lock_cmd_msg {
    uint32_t magic_no;
    uint32_t version : 8;
    uint32_t message_id : 16;
    uint32_t rsvd : 8;
    uint8_t  lock_type;
    uint8_t  op_code;
    uint16_t op_ret;
    uint32_t lock_offset;
    lock_state ls;
};

struct update_lock_body {
    int32_t lock_id;
    uint32_t lock_type;
    uint32_t lease_time;
    uint32_t offset;
    uint32_t desc_len;
    lock_state ls;
    unsigned char desc[0];
};

struct batch_update_lock_body {
    uint32_t lock_num;
    struct update_lock_body update_lock_entry[0];
};

struct object_create_body {
    int32_t obj_id;
    uint64_t offset;
    uint64_t init_value;
    uint32_t lease_time;
    uint32_t desc_len;
    unsigned char desc[0];

    static enum dlock_control_msg get_response_type()
    {
        return OBJECT_CREATE_RESPONSE;
    }
};

struct object_get_body {
    int32_t obj_id;
    uint64_t offset;
    uint32_t lease_time;
    uint32_t desc_len;
    unsigned char desc[0];

    static enum dlock_control_msg get_response_type()
    {
        return OBJECT_GET_RESPONSE;
    }
};

struct object_release_body {
    int32_t obj_id;

    static enum dlock_control_msg get_response_type()
    {
        return OBJECT_RELEASE_RESPONSE;
    }
};

struct object_destroy_body {
    int32_t obj_id;

    static enum dlock_control_msg get_response_type()
    {
        return OBJECT_DESTROY_RESPONSE;
    }
};

typedef struct {
    std::string ca_path;
    std::string crl_path;
    std::string cert_path;
    std::string prkey_path;
    tls_cert_verify_callback_func_t cert_verify_cb;
    tls_prkey_pwd_callback_func_t prkey_pwd_cb;
    tls_erase_prkey_callback_func_t erase_prkey_cb;
} ssl_init_attr_t;

using dlock_conn_peer_t = enum dlock_connection_peer_type {
    DLOCK_CONN_PEER_DEFAULT = 0,
    DLOCK_CONN_PEER_CLIENT,
    DLOCK_CONN_PEER_PRIMARY_SERVER,
    DLOCK_CONN_PEER_REPLICA_SERVER,
};

typedef struct {
    dlock_conn_peer_t peer_type;
    int peer_id; /* replica_id or client_id. If peer is primary server, peer_id is 0. */
} dlock_conn_peer_info_t;

constexpr uint8_t DLOCK_FIXED_CTRL_MSG_HDR_LEN = sizeof(struct dlock_control_hdr);
constexpr uint16_t DLOCK_CLIENT_INIT_REQ_BODY_LEN = sizeof(struct client_init_req_body);
constexpr uint16_t DLOCK_CLIENT_INIT_RESP_BODY_LEN = sizeof(struct client_init_resp_body);
constexpr uint16_t DLOCK_GET_LOCK_BODY_LEN = sizeof(struct get_lock_body);
constexpr uint16_t DLOCK_RELEASE_LOCK_BODY_LEN = sizeof(struct release_lock_body);
constexpr uint16_t DLOCK_UPDATE_LOCK_BODY_LEN = sizeof(struct update_lock_body);
constexpr uint16_t DLOCK_BATCH_GET_LOCK_BODY_LEN = sizeof(struct batch_get_lock_body);
constexpr uint16_t DLOCK_BATCH_RELEASE_LOCK_BODY_LEN = sizeof(struct batch_release_lock_body);
constexpr uint16_t DLOCK_BATCH_UPDATE_LOCK_BODY_LEN = sizeof(struct batch_update_lock_body);

constexpr uint16_t DLOCK_MAX_BATCH_UPDATE_LOCK_MSG_SIZE = DLOCK_FIXED_CTRL_MSG_HDR_LEN +
    DLOCK_BATCH_UPDATE_LOCK_BODY_LEN + ((DLOCK_UPDATE_LOCK_BODY_LEN + MAX_LOCK_DESC_LEN) * MAX_LOCK_BATCH_SIZE);
constexpr uint16_t DLOCK_MAX_CTRL_MSG_SIZE = DLOCK_MAX_BATCH_UPDATE_LOCK_MSG_SIZE;

constexpr uint16_t DLOCK_OBJECT_CREATE_BODY_LEN = sizeof(struct object_create_body);
constexpr uint16_t DLOCK_OBJECT_GET_BODY_LEN = sizeof(struct object_get_body);
constexpr uint16_t DLOCK_OBJECT_RELEASE_BODY_LEN = sizeof(struct object_release_body);
constexpr uint16_t DLOCK_OBJECT_DESTROY_BODY_LEN = sizeof(struct object_destroy_body);
};
#endif
