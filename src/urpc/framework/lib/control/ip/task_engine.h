/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define task engine function
 */
#ifndef URPC_TASK_ENGINE_H
#define URPC_TASK_ENGINE_H

#include <semaphore.h>

#ifdef __cplusplus
#include <atomic>
using namespace std;
#else
#include <stdatomic.h>
#endif
#include <unistd.h>

#include "cp_vers_compat.h"
#include "channel.h"
#include "protocol.h"
#include "urpc_hmap.h"
#include "urpc_list.h"
#include "urpc_socket.h"
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SERVER_TIMEOUT_MS                       300000 // 5min
#define URPC_CTL_VERSION_0                      0
#define URPC_CTL_VERSION_1                      1
#define URPC_CTL_VERSION_MAX                    URPC_CTL_VERSION_1
#define URPC_ERR_FORCE_EXIT                     INT_MAX
typedef struct ip_ctl_capability {
    uint16_t dp_encrypt : 1;
    uint16_t keepalive : 1;
    uint16_t primary_is_server : 1;
    uint16_t detach_manage : 1;
    uint16_t manage_channel_created : 1;
    uint16_t func_info_enabled : 1;
    uint16_t multiplex_enabled : 1;
    uint16_t rsvd : 9;
} ip_ctl_capability_t;

typedef enum task_workflow_action {
    ACTION_CONTINUE = 0,
    ACTION_STOP,
} task_workflow_action_t;

struct urpc_async_task_ctx;
typedef void (*async_callback_t)(void *ctx, int result);
typedef void (*prepare_input_callback_t)(void *buffer, struct urpc_async_task_ctx *task);
typedef struct handshaker_callback_ctx {
    union {
        sem_t sem;                  // use in the synchronous link establishment scenario
        urpc_async_event_t event;   // use in the asynchronous link establishment scenario
    };
    async_callback_t func;
    urpc_channel_connect_option_t conn_option;
    int result;
    uint8_t nonblock : 1;
    uint8_t rsvd : 7;
} handshaker_callback_ctx_t;

typedef struct task_instance_key {
    urpc_instance_key_t identity;
    int task_id; // task id assigned by the client
} task_instance_key_t;

typedef enum task_workflow_type {
    WORKFLOW_TYPE_CLIENT_ATTACH_SERVER = 0,
    WORKFLOW_TYPE_CLIENT_DETACH_SERVER,
    WORKFLOW_TYPE_CLIENT_REFRESH_SERVER,
    WORKFLOW_TYPE_SERVER_HANDSHAKE_CLIENT,
    WORKFLOW_TYPE_CHANNEL_ADD_QUEUE,
    WORKFLOW_TYPE_CHANNEL_RM_QUEUE,
    WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE,
    WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE,
    WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE,
    WORKFLOW_TYPE_CHANNEL_RM_REMOTE_QUEUE,
    WORKFLOW_TYPE_CHANNEL_PAIR_QUEUE,
    WORKFLOW_TYPE_CHANNEL_UNPAIR_QUEUE,
    WORKFLOW_TYPE_HANDLE_ATTACH_REQ,
    WORKFLOW_TYPE_HANDLE_DETACH_REQ,
    WORKFLOW_TYPE_HANDLE_ADVISE_REQ,
    WORKFLOW_TYPE_HANDLE_ADD_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_RM_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_ADD_LOCAL_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_ADD_REMOTE_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_RM_LOCAL_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_RM_REMOTE_QUEUE_REQ,
    WORKFLOW_TYPE_RELEASE_RESOURCE,
    WORKFLOW_TYPE_HANDLE_PAIR_QUEUE_REQ,
    WORKFLOW_TYPE_HANDLE_UNPAIR_QUEUE_REQ,
    WORKFLOW_TYPE_CONNECT_TIMER,
    WORKFLOW_TYPE_MAX,
} task_workflow_type_t;

typedef enum task_list_type {
    TASK_LIST_TYPE_UNKNOWN,
    TASK_LIST_TYPE_READY,
    TASK_LIST_TYPE_ACTIVE,
    TASK_LIST_TYPE_RUNNING,
    TASK_LIST_TYPE_MAX
} task_list_type_t;

typedef enum task_engine_task_state {
    TASK_PENDING_SEND,
    TASK_SENDING,
    TASK_PENDING_RECV,
    TASK_RECVING,
    TASK_IMPORTING,
    TASK_STEP_COMPLETED,
} task_engine_task_state_t;

typedef struct urpc_async_task_ctx {
    socket_addr_t tcp_addr;
    urpc_endpoints_t endpoints;
    task_instance_key_t key;
    urpc_list_t node;           // node of timeout check linked list
    urpc_list_t flow_node; // nodes on the task list on the same transmission channel
    struct urpc_hmap_node task_hash_node; // node of task hash table
    uint64_t timestamp; // timeout timestamp in milliseconds
    void *transport_handle;
    task_workflow_type_t workflow_type;
    task_list_type_t list_type;
    task_engine_task_state_t task_state;
    int ref_cnt;
    uint32_t ctl_opcode;
    uint32_t outer_step;
    uint32_t inner_step;
    uint32_t channel_id;
    int timeout; // timeout duration in milliseconds
    int result; // result of asynchronous connection establishment
    int err_code; // reserved error code for asynchronous connection establishment
    void *ctx; // inner callback ctx
    async_callback_t func; // register asynchronous connection inner callback function
    prepare_input_callback_t prepare_input; // prepare input data
    uint16_t is_server : 1;
    uint16_t use_delay_timeout : 1; // behavior after timeout is not triggered immediately.
    uint16_t is_recv_completed : 1; // receive complete message
    uint16_t is_initialized : 1; // used to mark whether the step function is initialized
    uint16_t is_send_cancel_msg : 1; // has cancellation message been sent already
    uint16_t is_notify : 1; // when a task fails, notify the other end to cancel the task
    uint16_t is_user_canceled : 1;
    uint16_t rsvd : 9;
} urpc_async_task_ctx_t;

typedef struct task_init_params {
    urpc_channel_info_t *channel;
    urpc_host_info_t *server;
    urpc_host_info_t *local;
    urpc_ctrl_msg_t *ctrl_msg;
    handshaker_callback_ctx_t *callback_ctx;
    task_workflow_type_t type;
    uint64_t urpc_qh;
    urpc_channel_queue_attr_t attr;
    socket_addr_t *tcp_addr;
    queue_t *local_q;
    queue_t *remote_q;
} task_init_params_t;

typedef struct queue_handshaker_client {
    urpc_channel_info_t *channel;
    uint32_t server_chid;
    queue_t *remote_queue;
} queue_handshaker_client_t;

typedef struct queue_handshaker_server {
    uint32_t chid;  // server chid
} queue_handshaker_server_t;

typedef struct queue_handshaker_ctx {
    urpc_async_task_ctx_t base_task;
    union {
        urpc_attach_msg_v1_t attach_msg_v1_send;
        urpc_attach_msg_v1_t attach_msg_v1_recv;
    };
    union {
        queue_handshaker_client_t client;
        queue_handshaker_server_t server;
    };
    queue_node_t *queue_node;
    uint64_t urpc_qh;
    urpc_channel_queue_type_t queue_type;
    batch_queue_import_ctx_t batch_import_ctx;
    uint8_t is_import_rollback : 1;
    uint8_t rsvd : 7;
} queue_handshaker_ctx_t;

typedef struct queue_handshaker_req_option {
    urpc_channel_queue_type_t queue_type;
    uint32_t server_chid;
    uint64_t qid;
} queue_handshaker_req_option_t;

typedef struct delayed_release_resources_ctx {
    urpc_async_task_ctx_t base_task;
    urpc_list_t server_channel_list;
    struct urpc_hmap_node node;
} delayed_release_resources_ctx_t;

typedef struct queue_bind_info {
    uint16_t l_qid;
    uint16_t r_qid;
    uint32_t mapped_server_chid;        // server search remote queues from this server channel
} queue_bind_info_t;
 
typedef struct queue_pair_ctx {
    urpc_async_task_ctx_t base_task;
    queue_t *l_q;
    queue_t *r_q;
    queue_bind_info_t l_bind_info;
    queue_bind_info_t *r_bind_info;
    uint32_t tp_created : 1;
    uint32_t rsvd : 31;
} queue_pair_ctx_t;

static inline void ip_ctl_fill_head(urpc_ctl_head_t *head, uint8_t version, uint32_t size, uint32_t chid,
    uint8_t opcode)
{
    head->version = version;
    head->opcode = URPC_CTL_HDR_OPCODE;
    head->error_code = 0;
    head->data_size = size;
    head->channel = chid;
    head->ctl_opcode = opcode;
}

static inline void ip_ctl_fill_head_flag(urpc_ctl_head_t *head, ip_ctl_capability_t *cap)
{
    head->dp_encrypt = cap->dp_encrypt;
    head->keepalive = cap->keepalive;
    head->primary_is_server = cap->primary_is_server;
    head->detach_manage = cap->detach_manage;
    head->manage_channel_created = cap->manage_channel_created;
    head->func_info_enabled = cap->func_info_enabled;
    head->multiplex_enabled = cap->multiplex_enabled;
    head->rsvd1 = 0;
}

static inline void task_engine_callback_event_set(
    uint32_t urpc_chid, urpc_async_event_type_t type, uint64_t l_qh, uint64_t r_qh, handshaker_callback_ctx_t *ctx)
{
    ctx->event.channel_id = urpc_chid;
    ctx->event.ctx = ctx->conn_option.ctx;
    ctx->event.event_type = type;
    ctx->event.err_code = URPC_SUCCESS;
    ctx->event.l_qh = l_qh;
    ctx->event.r_qh = r_qh;
}

uint8_t task_engine_handshaker_version_get(uint8_t recv_version);
void task_engine_task_process(bool need_input, urpc_ctl_head_t *head, void *buffer, urpc_async_task_ctx_t *task);
urpc_async_task_ctx_t *task_engine_server_task_create(urpc_ctl_head_t *head, void *buffer, void *user_ctx);
urpc_async_task_ctx_t *task_engine_client_handshaker_new(task_init_params_t *params);
urpc_async_task_ctx_t *task_engine_queue_handshaker_new(task_init_params_t *params);
urpc_async_task_ctx_t *task_engine_bind_new(task_init_params_t *params);
void task_engine_async_callback(void *ctx, int result);
void task_engine_sync_callback(void *ctx, int result);
handshaker_callback_ctx_t *task_engine_callback_construct(
    urpc_host_info_t *server, urpc_channel_connect_option_t *option);
void task_engine_callback_destruct(handshaker_callback_ctx_t *ctx);
bool task_can_stop_immediately(urpc_async_task_ctx_t *task);

#ifdef __cplusplus
}
#endif

#endif