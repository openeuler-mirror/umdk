/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize task engine function
 */

#include <string.h>

#include "async_event.h"
#include "client_manage_channel.h"
#include "cp.h"
#include "func.h"
#include "ip_handshaker.h"
#include "keepalive.h"
#include "server_manage_channel.h"
#include "task_manager.h"
#include "urpc_lib_log.h"

#include "task_engine.h"

static uint8_t g_urpc_ctl_version = URPC_CTL_VERSION_MAX;
typedef struct task_send_request_option {
    transport_handle_t *ctl_hdl;
    ip_ctl_capability_t cap;
    uint32_t ctl_opcode;
    uint32_t chid;
    int task_id;
    uint8_t is_start : 1;  // indicates the start of a new task.
    uint8_t cap_enable : 1; // initiate cap initialization
    uint8_t rsvd : 6;
    uint8_t version;
} task_send_request_option_t;

typedef enum task_engine_ctx_type {
    TASK_HANDSHAKER_CTX_TYPE = 0,
    QUEUE_HANDSHAKER_CTX_TYPE,
    RELEASE_RESOURCE_CTX_TYPE,
    BIND_CTX_TYPE,
    TASK_CTX_TYPE_MAX,
} task_engine_ctx_type_t;

typedef int (*task_workflow_handle_t)(urpc_async_task_ctx_t *task);
typedef void (*task_free_func_t)(void *task);
typedef void (*task_rollback_func_t)(void *task);
static task_workflow_handle_t *task_workflow_get(task_workflow_type_t type, uint32_t *total_steps);
static void task_handshaker_ctx_free(void *task);
static void task_engine_ctx_free(urpc_async_task_ctx_t *task);
static void queue_handshaker_ctx_free(void *task);
static void bind_ctx_free(void *task);
static void release_resource_ctx_free(void *task);
static int task_engine_send_check(urpc_async_task_ctx_t *task, transport_handle_t *ctl_hdl);
static void task_handshaker_rollback(void *task);
static void task_engine_task_rollback(urpc_async_task_ctx_t *task);
static void release_resource_rollback(void *task);
static void queue_handshaker_rollback(void *task);
static void queue_pair_rollback(void *task);
static task_engine_ctx_type_t task_engine_ctx_type_get(task_workflow_type_t type);
static int add_local_queue_init(urpc_async_task_ctx_t *task);
static transport_handle_t *transport_handle_get(urpc_async_task_ctx_t *task);
static int queue_info_recv(urpc_async_task_ctx_t *task);
static int queue_info_send(urpc_async_task_ctx_t *task);
static int task_engine_send_data(
    urpc_async_task_ctx_t *task, task_send_request_option_t *option, void *data, size_t size);
static bool channel_queue_info_validate(urpc_attach_msg_v1_t *attach_msg);
static int client_bind_init(urpc_async_task_ctx_t *task);
static void bind_info_recv_input_set(void *buffer, urpc_async_task_ctx_t *task);
static int server_queue_pair_handshaker_init(void *buffer, urpc_ctl_head_t *head, urpc_async_task_ctx_t *task);
static int server_queue_unpair_handshaker_init(void *buffer, urpc_ctl_head_t *head, urpc_async_task_ctx_t *task);
static int bind_info_send(urpc_async_task_ctx_t *task);
static int unbind_info_send(urpc_async_task_ctx_t *task);
static int client_recv_bind_info(urpc_async_task_ctx_t *task);
static int client_recv_unbind_info(urpc_async_task_ctx_t *task);
int client_queue_bind(urpc_async_task_ctx_t *task);
int server_queue_bind(urpc_async_task_ctx_t *task);
static int client_unbind(urpc_async_task_ctx_t *task);
static int server_pair_final(urpc_async_task_ctx_t *task);
static int server_queue_unbind(urpc_async_task_ctx_t *task);

static void queue_info_recv_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    urpc_attach_msg_v1_t *attach_msg = NULL;
    if (task->ctl_opcode == URPC_CTL_QUEUE_INFO_ADD || task->ctl_opcode == URPC_CTL_QUEUE_INFO_RM) {
        queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
        attach_msg = &ctx->attach_msg_v1_recv;
    } else {
        ip_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, ip_handshaker_ctx_t, base_task);
        attach_msg = &ctx->chnl_ctx.attach_msg_v1_recv;
    }
    attach_msg->data.buffer = buffer;
    task->is_recv_completed = URPC_TRUE;
}

uint8_t task_engine_handshaker_version_get(uint8_t recv_version)
{
    return (g_urpc_ctl_version > recv_version ? recv_version : g_urpc_ctl_version);
}

void task_engine_async_callback(void *ctx, int result)
{
    handshaker_callback_ctx_t *callback_ctx = (handshaker_callback_ctx_t *)ctx;
    URPC_LIB_LOG_DEBUG("handshake with server completed, to notify the user result:%d, type:%d\n",
        result, callback_ctx->event.event_type);
    callback_ctx->event.err_code = result;
    if (result != URPC_ERR_FORCE_EXIT) {
        async_event_notify(&callback_ctx->event);
    }
    task_engine_callback_destruct(callback_ctx);
}

void task_engine_sync_callback(void *ctx, int result)
{
    handshaker_callback_ctx_t *callback_ctx = (handshaker_callback_ctx_t *)ctx;
    callback_ctx->result = result;
    (void)sem_post(&callback_ctx->sem);
}

static void task_state_update_to_completed(urpc_async_task_ctx_t *task)
{
    if (task->task_state != TASK_IMPORTING) {
        task->task_state = TASK_STEP_COMPLETED;
    }
}

static void task_cancel_msg_send(urpc_async_task_ctx_t *task)
{
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return;
    }
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_TASK_CANCEL,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_FALSE,
        .version = URPC_INVALID_ID_U8,
    };
    if (task->is_send_cancel_msg == URPC_FALSE) {
        int ret = task_engine_send_data(task, &option, NULL, 0);
        if (ret == URPC_RUNNING) {
            URPC_LIB_LOG_DEBUG("%s sending a cancel message to the peer, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid),
                task->key.identity.pid, task->key.task_id);
            return;
        }
        if (ret == URPC_FAIL) {
            URPC_LIB_LOG_ERR(
                "%s send a cancel message to the peer failed, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid),
                task->key.identity.pid, task->key.task_id);
            return;
        }
        URPC_LIB_LOG_DEBUG("%s send a cancel message to the peer success, eid: " EID_FMT ", pid: %u, taskid: %d\n",
            task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid),
            task->key.identity.pid, task->key.task_id);
        task->is_send_cancel_msg = URPC_TRUE;
        return;
    }
    URPC_LIB_LOG_DEBUG(
        "%s already send a cancel message to the peer success, eid: " EID_FMT ", pid: %u, taskid: %d\n",
        task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid), task->key.identity.pid,
        task->key.task_id);
}

bool task_can_stop_immediately(urpc_async_task_ctx_t *task)
{
    return task->task_state != TASK_SENDING && task->task_state != TASK_RECVING && task->task_state != TASK_IMPORTING;
}

static void task_on_error(urpc_async_task_ctx_t *task, bool need_notify)
{
    URPC_LIB_LOG_DEBUG("%s task execute failed, eid: " EID_FMT ", pid: %u,taskid: %d, task_state: %d\n",
        task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid), task->key.identity.pid,
        task->key.task_id, task->task_state);
    if (need_notify) {
        task_cancel_msg_send(task);
    }
    if (task_can_stop_immediately(task)) {
        // process rollback
        task_engine_task_rollback(task);
        if (task->is_server == URPC_FALSE) {
            task_manager_client_task_clear(task);
        } else {
            if (task->workflow_type != WORKFLOW_TYPE_RELEASE_RESOURCE) {
                transport_server_task_unregister(task, (urpc_server_accept_entry_t *)task->transport_handle);
                task_manager_server_task_remove(task);
            } else {
                transport_server_releaser_remove(task);
            }
            task_manager_timeout_manager_remove(task);
        }
        task_engine_ctx_free(task);
        return;
    }
    URPC_LIB_LOG_INFO("%s task can not stop, eid: " EID_FMT ", pid: %u, taskid: %d\n",
        task->is_server ? "server" : "client", EID_ARGS(task->key.identity.eid),
        task->key.identity.pid, task->key.task_id)
    return;
}

static void task_on_success(urpc_async_task_ctx_t *task)
{
    if (task->is_server == URPC_FALSE) {
        task_manager_client_task_clear(task);
    } else {
        if (task->workflow_type != WORKFLOW_TYPE_RELEASE_RESOURCE) {
            transport_server_task_unregister(task, (urpc_server_accept_entry_t *)task->transport_handle);
            task_manager_server_task_remove(task);
        } else {
            transport_server_releaser_remove(task);
        }
        task_manager_timeout_manager_remove(task);
    }
    task_engine_ctx_free(task);
    return;
}

static int task_head_check(urpc_ctl_head_t *head, uint32_t ctl_opcode)
{
    if (head->opcode != URPC_CTL_HDR_OPCODE) {
        URPC_LIB_LOG_ERR("receive message opcode[%u] error, expect:%u\n", head->opcode, URPC_CTL_HDR_OPCODE);
        return URPC_FAIL;
    }

    if (head->error_code != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("received message header with error code (%d)\n", head->error_code);
        return URPC_FAIL;
    }

    if (head->ctl_opcode != URPC_CTL_TASK_CANCEL && head->ctl_opcode != ctl_opcode) {
        URPC_LIB_LOG_ERR("receive message control_opcode[%u] error, expect:%u\n", head->ctl_opcode, ctl_opcode);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int task_workflow_process(urpc_async_task_ctx_t *task)
{
    int ret = URPC_SUCCESS;
    task_workflow_action_t action = ACTION_CONTINUE;
    uint32_t total_steps = 0;
    task_workflow_handle_t *process = task_workflow_get(task->workflow_type, &total_steps);
    if (process == NULL) {
        task->result = URPC_FAIL;
        return URPC_FAIL;
    }
    URPC_LIB_LOG_DEBUG(
        "%s task continue process, eid: " EID_FMT ", pid: %u, taskid: %d, workflow type: %d, step: %u\n",
        task->is_server == URPC_TRUE ? "server" : "client", EID_ARGS(task->key.identity.eid),
        task->key.identity.pid, task->key.task_id, task->workflow_type, task->outer_step);
    do {
        if (task->outer_step >= total_steps) {
            URPC_LIB_LOG_DEBUG("task workflow finish, taskid: %d, ret: %d\n", task->key.task_id, ret);
            return ret;
        }
        task_workflow_handle_t fun = *(process + task->outer_step);
        ret = fun(task);
        switch (ret) {
            case URPC_RUNNING:
                action = ACTION_STOP;
                break;
            case URPC_FAIL:
                task->result = URPC_FAIL;
                action = ACTION_STOP;
                break;
            case URPC_SUCCESS:
                task->outer_step++;
                break;
            default:
                task->result = URPC_FAIL;
                action = ACTION_STOP;
                break;
        }
    } while (action == ACTION_CONTINUE);
    URPC_LIB_LOG_DEBUG("task jump out workflow, taskid: %d, step: %d, ret: %d\n",
        task->key.task_id, task->outer_step, ret);
    return ret;
}

void task_engine_task_process(bool need_input, urpc_ctl_head_t *head, void *buffer, urpc_async_task_ctx_t *task)
{
    bool is_server = task->is_server;
    if (!is_server) {
        task_manager_workflow_lock();
    }
    if (task->is_user_canceled == URPC_TRUE) {
        // process user cancel
        URPC_LIB_LOG_DEBUG("task was canceled by the user, taskid: %d\n", task->key.task_id);
        task->result = URPC_ERR_FORCE_EXIT;
        urpc_dbuf_free(buffer);
        goto WORKFLOW_ERROR;
    }

    // process recv peer cancel
    if (head != NULL && head->ctl_opcode == URPC_CTL_TASK_CANCEL) {
        // cancel_task
        task->result = URPC_FAIL;
        URPC_LIB_LOG_DEBUG("received task cancel msg from peer, taskid: %d\n", task->key.task_id);
        urpc_dbuf_free(buffer);
        task_on_error(task, false);
        goto WORKFLOW_UNLOCK;
    }

    // process workflow error
    if (task->result != URPC_SUCCESS) {
        urpc_dbuf_free(buffer);
        // import failed or transport error
        goto WORKFLOW_ERROR;
    }

    if (head != NULL) {
        // check head
        if (task_head_check(head, task->ctl_opcode) != URPC_SUCCESS) {
            task->result = URPC_FAIL;
            urpc_dbuf_free(buffer);
            goto WORKFLOW_ERROR;
        }
    }

    if (need_input && task->prepare_input != NULL) {
        // set input data
        task->prepare_input(buffer, task);
    } else {
        urpc_dbuf_free(buffer);
    }

    int ret = task_workflow_process(task);
    if (ret == URPC_RUNNING) {
        goto WORKFLOW_UNLOCK;
    }
    if (ret == URPC_FAIL) {
        goto WORKFLOW_ERROR;
    }
    task_on_success(task);
    goto WORKFLOW_UNLOCK;

WORKFLOW_ERROR:
    task_on_error(task, task->is_notify);

WORKFLOW_UNLOCK:
    // the task may have already been completed, cannot use task resource, so not use task->is_server
    if (!is_server) {
        task_manager_workflow_unlock();
    }
    return;
}

static urpc_async_task_ctx_t *server_handshaker_ctx_new(uint32_t ctl_opcode, void *user_ctx)
{
    if (ctl_opcode == URPC_CTL_QUEUE_INFO_ATTACH || ctl_opcode == URPC_CTL_QUEUE_INFO_DETACH) {
        ip_handshaker_ctx_t *ctx =
            (ip_handshaker_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(ip_handshaker_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ctx->cap.keepalive = is_feature_enable(URPC_FEATURE_KEEPALIVE) ? URPC_TRUE : URPC_FALSE;
        ctx->cap.dp_encrypt = crypto_is_dp_ssl_enabled() ? URPC_TRUE : URPC_FALSE;
        ctx->cap.func_info_enabled = is_feature_enable(URPC_FEATURE_GET_FUNC_INFO) ? URPC_TRUE : URPC_FALSE;
        ctx->cap.multiplex_enabled = is_feature_enable(URPC_FEATURE_MULTIPLEX) ? URPC_TRUE : URPC_FALSE;
        urpc_list_init(&ctx->batch_import_ctx.list);

        ctx->ctrl_msg = &ctx->dummy_ctrl_msg;
        ctx->ctrl_msg->user_ctx = user_ctx;
        ctx->ctrl_msg->msg_max_size = CTRL_MSG_MAX_SIZE;
        ctx->ctrl_msg->msg = urpc_dbuf_malloc(URPC_DBUF_TYPE_CP, CTRL_MSG_MAX_SIZE);
        if (ctx->ctrl_msg->msg == NULL) {
            urpc_dbuf_free(ctx);
            URPC_LIB_LOG_ERR("malloc ctrl msg buffer failed\n");
            return NULL;
        }

        ctx->server.chid = URPC_INVALID_ID_U32;
        ctx->server.manage_chid = URPC_INVALID_ID_U32;
        return (urpc_async_task_ctx_t *)(void *)ctx;
    }
    if (ctl_opcode == URPC_CTL_QUEUE_INFO_ADD || ctl_opcode == URPC_CTL_QUEUE_INFO_RM) {
        queue_handshaker_ctx_t *ctx =
            (queue_handshaker_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(queue_handshaker_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ctx->server.chid = URPC_INVALID_ID_U32;
        urpc_list_init(&ctx->batch_import_ctx.import_list);
        urpc_list_init(&ctx->batch_import_ctx.list);
        return (urpc_async_task_ctx_t *)(void *)ctx;
    }
    if (ctl_opcode == URPC_CTL_QUEUE_INFO_BIND || ctl_opcode == URPC_CTL_QUEUE_INFO_UNBIND) {
        queue_pair_ctx_t *ctx = (queue_pair_ctx_t *)urpc_dbuf_calloc(
            URPC_DBUF_TYPE_CP, 1, sizeof(queue_pair_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        return (urpc_async_task_ctx_t *)(void *)ctx;
    }
    return NULL;
}

static int server_queue_handshaker_init(void *buffer, urpc_ctl_head_t *head, urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = (queue_handshaker_ctx_t *)(uintptr_t)task;
    queue_handshaker_req_option_t *req = (queue_handshaker_req_option_t *)buffer;
    if (head->data_size != sizeof(queue_handshaker_req_option_t)) {
        URPC_LIB_LOG_ERR("server recv buffer size is invalid, taskid: %d, recv size: %u, expect size: %zu\n",
            head->task_id, head->data_size, sizeof(queue_handshaker_req_option_t));
        return URPC_FAIL;
    }
    ctx->urpc_qh = req->qid;
    ctx->server.chid = server_channel_id_map_lookup(req->server_chid);
    if (req->queue_type == CHANNEL_QUEUE_TYPE_LOCAL) {
        ctx->queue_type = CHANNEL_QUEUE_TYPE_LOCAL;
        if (head->ctl_opcode == URPC_CTL_QUEUE_INFO_ADD) {
            task->workflow_type = WORKFLOW_TYPE_HANDLE_ADD_LOCAL_QUEUE_REQ;
        } else {
            task->workflow_type = WORKFLOW_TYPE_HANDLE_RM_LOCAL_QUEUE_REQ;
        }
        return URPC_SUCCESS;
    } else if (req->queue_type == CHANNEL_QUEUE_TYPE_REMOTE) {
        ctx->queue_type = CHANNEL_QUEUE_TYPE_REMOTE;
        if (head->ctl_opcode == URPC_CTL_QUEUE_INFO_ADD) {
            task->workflow_type = WORKFLOW_TYPE_HANDLE_ADD_REMOTE_QUEUE_REQ;
        } else {
            task->workflow_type = WORKFLOW_TYPE_HANDLE_RM_REMOTE_QUEUE_REQ;
        }
        return URPC_SUCCESS;
    }
    return URPC_FAIL;
}

urpc_async_task_ctx_t *task_engine_server_task_create(urpc_ctl_head_t *head, void *buffer, void *user_ctx)
{
    urpc_async_task_ctx_t *task = server_handshaker_ctx_new(head->ctl_opcode, user_ctx);
    if (task == NULL) {
        return NULL;
    }
    task->ctl_opcode = head->ctl_opcode;
    task->is_server = URPC_TRUE;
    task->timeout = SERVER_TIMEOUT_MS;
    task->timestamp = get_timestamp_ms() + SERVER_TIMEOUT_MS;
    task->is_notify = URPC_TRUE;
    switch (head->ctl_opcode) {
        case URPC_CTL_QUEUE_INFO_ATTACH:
            task->workflow_type = WORKFLOW_TYPE_HANDLE_ATTACH_REQ;
            break;
        case URPC_CTL_QUEUE_INFO_DETACH:
            task->is_initialized = URPC_TRUE;
            task->is_recv_completed = URPC_FALSE;
            task->ctl_opcode = URPC_CTL_QUEUE_INFO_DETACH;
            task->prepare_input = queue_info_recv_input_set;
            task->workflow_type = WORKFLOW_TYPE_HANDLE_DETACH_REQ;
            break;
        case URPC_CTL_QUEUE_INFO_BIND:
            task->workflow_type = WORKFLOW_TYPE_HANDLE_ADVISE_REQ;
            task->prepare_input = bind_info_recv_input_set;
            if (server_queue_pair_handshaker_init(buffer, head, task) != URPC_SUCCESS) {
                URPC_LIB_LOG_ERR("server pair handshaker init failed, taskid: %d\n", head->task_id);
                urpc_dbuf_free(task);
                return NULL;
            }
            break;
        case URPC_CTL_QUEUE_INFO_UNBIND:
            task->workflow_type = WORKFLOW_TYPE_HANDLE_ADVISE_REQ;
            task->prepare_input = bind_info_recv_input_set;
            if (server_queue_unpair_handshaker_init(buffer, head, task) != URPC_SUCCESS) {
                URPC_LIB_LOG_ERR("server un pair handshaker init failed, taskid: %d\n", head->task_id);
                urpc_dbuf_free(task);
                return NULL;
            }
            break;
        case URPC_CTL_QUEUE_INFO_ADD:
        case URPC_CTL_QUEUE_INFO_RM:
            if (server_queue_handshaker_init(buffer, head, task) != URPC_SUCCESS) {
                URPC_LIB_LOG_ERR("server queue handshaker init failed, taskid: %d\n", head->task_id);
                urpc_dbuf_free(task);
                return NULL;
            }
            break;
        default:
            URPC_LIB_LOG_ERR("unknown opcode: %u\n", head->ctl_opcode);
            urpc_dbuf_free(task);
            return NULL;
    }
    return task;
}

static int task_engine_send_check(urpc_async_task_ctx_t *task, transport_handle_t *ctl_hdl)
{
    if (ctl_hdl->state == TCP_CONNECTING || ctl_hdl->state == TLS_CONNECTING) {
        task->task_state = TASK_PENDING_SEND;
        return URPC_RUNNING;
    }

    if (transport_should_stop(ctl_hdl->state)) {
        URPC_LIB_LOG_ERR("%s task send check failed, taskid: %d\n",
            task->is_server == URPC_TRUE ? "server" : "client", task->key.task_id);
        return URPC_FAIL;
    }

    if (ctl_hdl->is_write_buffer_full == URPC_FALSE) {
        task->task_state = TASK_SENDING;
        return URPC_SUCCESS;
    }
    task->task_state = TASK_PENDING_SEND;
    return URPC_RUNNING;
}

static int task_engine_recv_check(urpc_async_task_ctx_t *task, transport_handle_t *ctl_hdl)
{
    if (transport_should_stop(ctl_hdl->state)) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    if (!task->is_recv_completed) {
        URPC_LIB_LOG_DEBUG("%s task waiting recv data, taskid: %d\n",
            task->is_server == URPC_TRUE ? "server" : "client", task->key.task_id);
        task->task_state = TASK_PENDING_RECV;
        return URPC_RUNNING;
    }
    task_state_update_to_completed(task);
    return URPC_SUCCESS;
}

int task_engine_send_data(
    urpc_async_task_ctx_t *task, task_send_request_option_t *option, void *data, size_t size)
{
    if (size > URPC_CTL_BUF_MAX_LEN) {
        URPC_LIB_LOG_ERR("%s task id: %d send data failed, data packet is too large\n",
            task->is_server == URPC_TRUE ? "server" : "client", task->key.task_id);
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }

    transport_handle_t *ctl_hdl = option->ctl_hdl;
    int ret = task_engine_send_check(task, ctl_hdl);
    if (ret == URPC_FAIL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }

    urpc_ctl_head_t *head = &ctl_hdl->send_record.head;
    if (ctl_hdl->send_record.is_prepared_head == URPC_FALSE) {
        ip_ctl_fill_head(head, option->version, size, option->chid, option->ctl_opcode);
        if (option->cap_enable == URPC_TRUE) {
            ip_ctl_fill_head_flag(head, &option->cap);
        }
        head->is_start = option->is_start;
        head->task_id = task->key.task_id;
        ctl_hdl->send_record.is_prepared_head = URPC_TRUE;
    }

    task->task_state = TASK_SENDING;
    ret = transport_send_msg(ctl_hdl, data, size);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    task_state_update_to_completed(task);
    return ret;
}

int attach_server_init(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_channel_info_t *channel = ctx->client.channel;
    if (task->workflow_type == WORKFLOW_TYPE_CLIENT_REFRESH_SERVER) {
        // get server node
        server_node_t *target_node = channel_get_server_node(channel, NULL);
        if (target_node == NULL) {
            URPC_LIB_LOG_ERR("channel[%u] is not attached to any server\n", task->channel_id);
            return URPC_FAIL;
        }
        task->endpoints = target_node->endpoints;
        ctx->client.endpoints = target_node->endpoints;
    }
    ctx->client.client_inited = true;
    return URPC_SUCCESS;
}

static int client_send_neg_head(urpc_async_task_ctx_t *task)
{
    urpc_client_connect_entry_t *entry = NULL;
    if (task->is_initialized == URPC_FALSE) {
        task->is_initialized = URPC_TRUE;
        if (task->workflow_type == WORKFLOW_TYPE_CLIENT_ATTACH_SERVER) {
            entry = transport_connection_establish(task);
        } else {
            entry = transport_connection_get(&task->endpoints.server);
        }
        if (entry == NULL) {
            task_state_update_to_completed(task);
            return URPC_FAIL;
        }
        transport_client_task_register(task, entry);
    }

    entry = (urpc_client_connect_entry_t *)task->transport_handle;
    ip_handshaker_ctx_t *handshaker = (ip_handshaker_ctx_t *)(uintptr_t)task;
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = handshaker->cap,
        .chid = handshaker->client.channel->id,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_TRUE,
        .cap_enable = URPC_TRUE,
        .version = g_urpc_ctl_version,
    };

    int ret = task_engine_send_data(task, &option, NULL, 0);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    task->is_initialized = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send version info to server failed in channel[%u]\n", handshaker->client.channel->id);
    }
    if (ret == URPC_SUCCESS) {
        task->is_notify = URPC_TRUE;
    }
    return ret;
}

static void negotiate_msg_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *handshaker = (ip_handshaker_ctx_t *)(uintptr_t)task;
    handshaker->neg_ctx.neg_msg_v1.data.buffer = buffer;
    task->is_recv_completed = URPC_TRUE;
}

static int client_recv_neg_head_and_data(urpc_async_task_ctx_t *task)
{
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    ip_handshaker_ctx_t *handshaker = (ip_handshaker_ctx_t *)(uintptr_t)task;

    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH;
        // data can be empty
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = negotiate_msg_input_set;
        task->is_initialized = URPC_TRUE;
    }

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }

    // after recv complete, is_recv_completed reset
    task->is_recv_completed = URPC_FALSE;
    task->is_initialized = URPC_FALSE;

    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("task receive message error, taskid: %d, channel: %u\n",
            task->key.task_id, handshaker->client.channel->id);
        return URPC_FAIL;
    }

    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (!negotiate_msg_validate(handshaker, head)) {
        URPC_LIB_LOG_ERR("negotiate with server failed, taskid: %d, channel: %u\n",
            task->key.task_id, handshaker->client.channel->id);
        return URPC_FAIL;
    }

    urpc_neg_msg_v1_t *neg_msg = &handshaker->neg_ctx.neg_msg_v1;
    if (head->data_size != 0) {
        neg_msg->data.len = head->data_size;
        if (urpc_neg_msg_v1_deserialize(neg_msg) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("deserialize negotiate message failed, taskid: %d\n", task->key.task_id);
            return URPC_FAIL;
        }
    }

    // server version will be saved in server_node
    handshaker->client.endpoints.version = task_engine_handshaker_version_get(head->version);
    URPC_LIB_LOG_DEBUG("get control version success, taskid: %d, version: %hhu, channel: %u\n",
        task->key.task_id, handshaker->client.endpoints.version, handshaker->client.channel->id);

    return URPC_SUCCESS;
}

// get client channel queue info, user channel
static int client_queue_info_prepare(queue_handshaker_ctx_t *ctx)
{
    urpc_attach_msg_v1_t *client_attach_msg = &ctx->attach_msg_v1_send;
    urpc_attach_msg_input_t attach_msg_input = {
        .is_server = false,
        .attach_info = {
            .keepalive_attr = urpc_keepalive_attr_get(),
            .server_chid = channel_get_server_chid(ctx->client.channel, &ctx->base_task.endpoints.server),
        },
        .manage = {.client_channel = NULL, .q_num = 0, },
        .user = { .client_channel = ctx->client.channel, .q_num = 1 },
    };
    attach_msg_input.user.qh[0] = ctx->urpc_qh;
    if (urpc_attach_msg_v1_serialize(&attach_msg_input, client_attach_msg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("serialize client attach message failed\n");
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static int server_queue_info_prepare(queue_handshaker_ctx_t *ctx)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(ctx->server.chid, false);
    if (server_channel == NULL) {
        return URPC_FAIL;
    }
    urpc_attach_msg_input_t attach_msg_input = {
        .is_server = true,
        .attach_info = {
            .keepalive_attr = urpc_keepalive_attr_get(),
            .server_chid = server_channel->mapped_id,
        },
        .manage = { .server_channel_id = URPC_INVALID_ID_U32, },
        .user = { .server_channel_id = server_channel->mapped_id, }
    };
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    attach_msg_input.user.qh[0] = get_one_local_queue_by_qid(ctx->urpc_qh);
    if (attach_msg_input.user.qh[0] == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("server not find local queue, qid:%lu\n", ctx->urpc_qh);
        return URPC_FAIL;
    }
    attach_msg_input.user.q_num = 1;
    if (urpc_attach_msg_v1_serialize(&attach_msg_input, &ctx->attach_msg_v1_send) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("serialize client attach message failed\n");
        return URPC_FAIL;
    }
    ctx->base_task.is_initialized = URPC_TRUE;
    return URPC_SUCCESS;
}

static int attach_info_send(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }

    urpc_attach_msg_v1_t *attach_msg = &ctx->chnl_ctx.attach_msg_v1_send;
    // get attach info only once
    if (task->is_initialized == URPC_FALSE) {
        urpc_attach_msg_input_t attach_msg_input = {
            .is_server = (task->is_server == URPC_TRUE),
            .attach_info = {
                .keepalive_attr = urpc_keepalive_attr_get(),
                .server_chid = URPC_INVALID_ID_U32,
            },
            .user = {.client_channel = ctx->client.channel, .q_num = 0},
        };
        if (task->is_server == URPC_TRUE) {
            attach_msg_input.manage.server_channel_id = URPC_INVALID_ID_U32;
            attach_msg_input.user.server_channel_id = ctx->server.mapped_id;
        } else {
            attach_msg_input.attach_info.server_chid =
                channel_get_server_chid(ctx->client.channel, &ctx->base_task.endpoints.server);
        }

        if (urpc_attach_msg_v1_serialize(&attach_msg_input, attach_msg) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("serialize attach message failed\n");
            return URPC_FAIL;
        }

        task->is_initialized = URPC_TRUE;
    }

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = (task->is_server == URPC_TRUE) ? ctx->server.client_version : ctx->client.endpoints.version,
    };
    int ret = task_engine_send_data(task, &option, attach_msg->data.buffer, attach_msg->data.len);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // send return URPC_SUCCESS or URPC_FAIL, should reset is_initialized flag, continue next step
    task->is_initialized = URPC_FALSE;
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("send attach info to peer failed, taskid: %d\n", task->key.task_id);
    }
    return ret;
}

static int client_user_ctrl_info_send(urpc_async_task_ctx_t *task)
{
    // 3. send user ctrl input msg
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->client.endpoints.version
    };
    int ret = task_engine_send_data(task, &option, ctx->ctrl_msg->msg, ctx->ctrl_msg->msg_size);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send ctrl msg to server failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->client.channel->id);
    }
    return ret;
}

static void client_ctrl_msg_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *handshaker = (ip_handshaker_ctx_t *)(uintptr_t)task;
    handshaker->ctrl_msg_recv = buffer;
    task->is_recv_completed = URPC_TRUE;
}

static int client_process_ctrl_msg(urpc_ctrl_msg_type_t msg_type, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;

    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = ctrl_opcode_get(msg_type);
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = client_ctrl_msg_input_set;
        task->is_initialized = URPC_TRUE;
    }

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    // 4. recv ctrl msg
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_initialized = URPC_FALSE;
    task->is_recv_completed = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("recv server ctrl msg failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->client.channel->id);
        return URPC_FAIL;
    }

    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    ctx->ctrl_msg->is_server = URPC_FALSE;
    ctx->ctrl_msg->msg_size = head->data_size;
    // no input msg and no output msg
    if (ctx->ctrl_msg->msg_size == 0 || head->data_size == 0) {
        URPC_LIB_LOG_DEBUG("recv ctrl msg, taskid: %d, input msg size: %u, recv server msg size: %u\n",
            task->key.task_id, ctx->ctrl_msg->msg_size, ctx->head.data_size);
        ret = urpc_ctrl_msg_process(msg_type, ctx->ctrl_msg);
        if (ret != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("ctrl msg process failed, taskid: %d, channel: %u, ret: %d\n",
                task->key.task_id, ctx->client.channel->id, ret);
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    if (head->data_size > ctx->ctrl_msg->msg_max_size) {
        urpc_dbuf_free(ctx->ctrl_msg_recv);
        ctx->ctrl_msg_recv = NULL;
        URPC_LIB_LOG_ERR(
            "recv server ctrl msg exceed max size, taskid: %d, channel: %u, recv msg size: %u, max size: %u\n",
            task->key.task_id, ctx->client.channel->id, head->data_size, ctx->ctrl_msg->msg_max_size);
        return URPC_FAIL;
    }
    memcpy(ctx->ctrl_msg->msg, ctx->ctrl_msg_recv, head->data_size);
    urpc_dbuf_free(ctx->ctrl_msg_recv);
    ctx->ctrl_msg_recv = NULL;
    ctx->ctrl_msg->msg_size = head->data_size;

    if (ctx->chnl_ctx.attach_msg_v1_recv.data.buffer != NULL) {
        urpc_chmsg_v1_t *user_q_info = user_queue_info_xchg_get(ctx);
        urpc_chmsg_v1_t *manage_q_info = manage_queue_info_xchg_get(ctx);

        uint32_t q_count = user_q_info->qinfo_arr.arr_num;
        if (manage_q_info != NULL) {
            q_count += manage_q_info->qinfo_arr.arr_num;
        }

        ctx->ctrl_msg->id_num = q_count;
        for (uint16_t i = 0; i < q_count; i++) {
            queue_info_t *q_info;
            if (i < user_q_info->qinfo_arr.arr_num) {
                q_info = user_q_info->qinfo_arr.qinfos[i];
            } else {
                q_info = manage_q_info->qinfo_arr.qinfos[i - user_q_info->qinfo_arr.arr_num];
            }
            memcpy(&ctx->ctrl_msg->id[i].eid, &q_info->mode_jetty.jetty_id.eid, sizeof(urpc_eid_t));
            ctx->ctrl_msg->id[i].uasid = q_info->mode_jetty.jetty_id.uasid;
            ctx->ctrl_msg->id[i].id = q_info->mode_jetty.jetty_id.id;
        }
    } else {
        ctx->ctrl_msg->id_num = 0;
    }
    URPC_LIB_LOG_DEBUG("process ctrl msg, taskid: %d, msg size: %u, id num: %u\n",
        task->key.task_id, ctx->ctrl_msg->msg_size, ctx->ctrl_msg->id_num);
    ret = urpc_ctrl_msg_process(msg_type, ctx->ctrl_msg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("ctrl msg process failed, taskid: %d, ret: %d\n", task->key.task_id, ret);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int client_user_ctrl_info_recv(urpc_async_task_ctx_t *task)
{
    // 5. recv user ctrl msg from server, and process ctrl msg, to ensure import remote queue is available
    return client_process_ctrl_msg(URPC_CTRL_MSG_ATTACH, task);
}

static void client_func_recv_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    ctx->func_info.func = buffer;
    task->is_recv_completed = URPC_TRUE;
}

static int client_func_recv(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH;
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = client_func_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }
    if (ctx->cap.func_info_enabled == URPC_FALSE) {
        return URPC_SUCCESS;
    }

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_initialized = URPC_FALSE;
    task->is_recv_completed = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR(
            "client recv func msg failed, taskid: %d, channel: %u\n", task->key.task_id, ctx->client.channel->id);
        return URPC_FAIL;
    }
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    ret = urpc_func_info_set(&ctx->client.channel->func_tbl, (uint64_t)(uintptr_t)ctx->func_info.func, head->data_size);
    urpc_dbuf_free(ctx->func_info.func);
    ctx->func_info.func = NULL;
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR(
            "client parse func msg failed, taskid: %d, channel: %u\n", task->key.task_id, ctx->client.channel->id);
    } else {
        URPC_LIB_LOG_INFO(
            "create function table success, taskid: %d, channel: %u\n", task->key.task_id, ctx->client.channel->id);
    }
    return ret;
}

int urpc_mem_info_set(uint32_t chid, uint64_t addr, uint32_t len)
{
    urpc_tlv_arr_head_t *meminfo_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)addr;
    uint32_t mem_info_num = meminfo_arr_tlv_head->value.arr_num;
    xchg_mem_info_t *meminfo_arr[mem_info_num];
    int ret = meminfo_arr_deserialize(meminfo_arr_tlv_head, meminfo_arr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("deserialize meminfo arr failed\n")
        return ret;
    }

    ret = server_channel_put_mem_info(chid, meminfo_arr, mem_info_num);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("put mem info failed\n")
        return ret;
    }

    return URPC_SUCCESS;
}

static void server_mem_recv_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    ctx->mem_info.mem = buffer;
    task->is_recv_completed = URPC_TRUE;
}


static int server_mem_recv(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH;
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = server_mem_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_initialized = URPC_FALSE;
    task->is_recv_completed = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR(
            "client recv func msg failed, taskid: %d, channel: %u\n", task->key.task_id, ctx->client.channel->id);
        return URPC_FAIL;
    }
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;

    ret = urpc_mem_info_set(ctx->server.chid, (uint64_t)(uintptr_t)ctx->mem_info.mem, head->data_size);
    urpc_dbuf_free(ctx->mem_info.mem);
    ctx->mem_info.mem = NULL;
    return ret;
}

static int client_channel_info_get(ip_handshaker_ctx_t *ctx)
{
    // get manage channel info no need lock because only remote queue info will change during attach
    uint32_t user_q_num = ctx->client.channel->l_qnum;
    urpc_attach_msg_v1_t *client_attach_msg = &ctx->chnl_ctx.attach_msg_v1_send;
    urpc_attach_msg_input_t attach_msg_input = {
        .is_server = false,
        .attach_info = {
            .keepalive_attr = urpc_keepalive_attr_get(),
            .server_chid = channel_get_server_chid(ctx->client.channel, &ctx->client.endpoints.server),
        },
        .manage = { .client_channel = NULL, .q_num = 0, },
        .user = { .client_channel = ctx->client.channel, .q_num = user_q_num, },
    };
    if (channel_get_local_queues(ctx->client.channel, user_q_num, attach_msg_input.user.qh) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("get client channel queue info failed\n");
        return URPC_FAIL;
    }

    if (urpc_attach_msg_v1_serialize(&attach_msg_input, client_attach_msg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("serialize client attach message failed\n");
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static int detach_server_init(urpc_async_task_ctx_t *task)
{
    urpc_client_connect_entry_t *entry = NULL;
    // only once
    entry = transport_connection_get(&task->endpoints.server);
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    task->ctl_opcode = URPC_CTL_QUEUE_INFO_DETACH;
    transport_client_task_register(task, entry);
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    // 1. prepare detach msg
    server_node_t *server_node = channel_get_server_node(ctx->client.channel, &(task->endpoints.server));
    // no server_node, don't need detach
    if (server_node == NULL) {
        URPC_LIB_LOG_ERR("find server info failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    ctx->client.endpoints.version = server_node->endpoints.version;

    if (client_channel_info_get(ctx) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("prepare channel info failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int detach_server_msg_info_send(urpc_async_task_ctx_t *task)
{
    return queue_info_send(task);
}

static int detach_server_ctrl_msg_send(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_DETACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->client.endpoints.version,
    };
    int ret = task_engine_send_data(task, &option, (void *)ctx->ctrl_msg->msg, ctx->ctrl_msg->msg_size);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send ctrl msg to server failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->client.channel->id);
    }
    return ret;
}

static int detach_server_ctrl_msg_recv(urpc_async_task_ctx_t *task)
{
    // 3. recv and process ctrl msg
    return client_process_ctrl_msg(URPC_CTRL_MSG_DETACH, task);
}

static int detach_server_success_ack_recv(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }

    // after recv complete, is_recv_completed reset
    task->is_recv_completed = URPC_FALSE;
    task->is_initialized = URPC_FALSE;

    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (ret == URPC_FAIL || head->error_code != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("receive message head error, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->client.channel->id);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int server_recv_neg_head(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;

    task->is_notify = URPC_TRUE;
    uint8_t version = task_engine_handshaker_version_get(head->version);
    if (head->data_size != 0) {
        URPC_LIB_LOG_ERR("recv client negotiate msg failed, taskid: %d, data_size: %u, version: %d\n",
            task->key.task_id, head->data_size, head->version);
        return URPC_FAIL;
    }

    if (!negotiate_msg_validate(ctx, head)) {
        URPC_LIB_LOG_ERR("negotiate with client failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }

    URPC_LIB_LOG_DEBUG("server recv version success, taskid: %d, version: %d\n", task->key.task_id, version);
    ctx->server.client_version = version;
    return URPC_SUCCESS;
}

static int server_send_negotiated_data(urpc_async_task_ctx_t *task)
{
    // send negotiate head
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }

    if (task->is_initialized == URPC_FALSE) {
        task->is_initialized = URPC_TRUE;
        int send = create_negotiate_msg(ctx);
        if (send < 0) {
            return URPC_FAIL;
        }
    }

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };

    // send head and data
    int ret =
        task_engine_send_data(task, &option, ctx->neg_ctx.neg_msg_v1.data.buffer, ctx->neg_ctx.neg_msg_v1.data.len);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }

    // reset is_initialized
    task->is_initialized = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send negotiated data to client failed, taskid: %d\n", task->key.task_id);
    }
    return ret;
}

static int attach_info_recv(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }
    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH;
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = queue_info_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }

    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_recv_completed = URPC_FALSE;
    task->is_initialized = URPC_FALSE;
    if (ret == URPC_FAIL || head->data_size == 0) {
        // data size can not empty
        URPC_LIB_LOG_ERR("server recv queue info failed, task_id: %d, data_size: %u, ret: %d\n",
            task->key.task_id, head->data_size, ret);
        return URPC_FAIL;
    }

    urpc_attach_msg_v1_t *attach_msg = &ctx->chnl_ctx.attach_msg_v1_recv;
    attach_msg->data.len = head->data_size;

    if (urpc_attach_msg_v1_deserialize(attach_msg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("deserialize attach message failed, taskid: %d\n", task->key.task_id);
        urpc_attach_msg_v1_buffer_release(attach_msg);
        return URPC_FAIL;
    }

    if (!channel_queue_info_validate(attach_msg)) {
        URPC_LIB_LOG_ERR("recv channel queue info is invalid, taskid: %d\n", task->key.task_id);
        urpc_attach_msg_v1_buffer_release(attach_msg);
        return URPC_FAIL;
    }

    ctx->attach_info.server_chid = attach_msg->attach_info->server_chid;
    ctx->attach_info.channel_info.key = attach_msg->chmsg_arr.chmsgs[0].chinfo->key;
    ctx->attach_info.channel_info.cap = attach_msg->chmsg_arr.chmsgs[0].chinfo->cap;
    ctx->attach_info.channel_info.attr = attach_msg->chmsg_arr.chmsgs[0].chinfo->attr;
    ctx->attach_info.channel_info.chid = attach_msg->chmsg_arr.chmsgs[0].chinfo->chid;

    if (task->is_server != URPC_TRUE) {
        return URPC_SUCCESS;
    }

    ctx->server.client_chid = attach_msg->chmsg_arr.chmsgs[0].chinfo->chid;
    ctx->server.client_manage_chid = URPC_INVALID_ID_U32;
    ctx->server.client_keepalive_attr = attach_msg->attach_info->keepalive_attr;
    server_channel_connect_hmap_lock();
    // create server channel and server manager channel
    // the server channel and manager channel is write_locked. it's safe to use. unlock them before exit.
    if (server_attach_channel_process(ctx) != URPC_SUCCESS) {
        server_channel_connect_hmap_unlock();
        URPC_LIB_LOG_ERR("server attach channel failed, task_id: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    server_channel_connect_hmap_unlock();
    ctx->server.channel_attached = true;
    return URPC_SUCCESS;
}

static void server_ctl_msg_recv_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    task->is_recv_completed = URPC_TRUE;
    ctx->ctrl_msg_recv = buffer;
}

static int server_process_ctrl_msg(urpc_ctrl_msg_type_t msg_type, urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;

    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = ctrl_opcode_get(msg_type);
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = server_ctl_msg_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }

    transport_handle_t *ctl_hdl = &entry->conn_handle;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_recv_completed = URPC_FALSE;
    task->is_initialized = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("server recv ctrl msg failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }

    ctx->ctrl_msg->is_server = URPC_TRUE;
    ctx->ctrl_msg->msg_size = head->data_size;
    // no input msg, just return empty head
    if (head->data_size == 0) {
        URPC_LIB_LOG_INFO(
            "process ctrl msg, msg size: %u, id num: %u\n", ctx->ctrl_msg->msg_size, ctx->ctrl_msg->id_num);
        ret = urpc_ctrl_msg_process(msg_type, ctx->ctrl_msg);
        if (ret != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("server ctrl msg process failed, taskid: %d, ret: %d\n", task->key.task_id, ret);
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }

    if (head->data_size > ctx->ctrl_msg->msg_max_size) {
        URPC_LIB_LOG_ERR("recv ctrl msg size too large, taskid: %d, recv msg size: %u, max size: %u\n",
            task->key.task_id, head->data_size, ctx->ctrl_msg->msg_max_size);
        goto EXIT;
    }
    memcpy(ctx->ctrl_msg->msg, ctx->ctrl_msg_recv, head->data_size);
    ctx->ctrl_msg->msg_size = head->data_size;

    if (ctx->chnl_ctx.attach_msg_v1_recv.data.buffer != NULL) {
        urpc_chmsg_v1_t *user_q_info = user_queue_info_xchg_get(ctx);
        urpc_chmsg_v1_t *manage_q_info = manage_queue_info_xchg_get(ctx);

        uint32_t q_count = user_q_info->qinfo_arr.arr_num;
        if (manage_q_info != NULL) {
            q_count += manage_q_info->qinfo_arr.arr_num;
        }

        if (q_count > MAX_QUEUE_SIZE) {
            URPC_LIB_LOG_ERR("recv queue id num %u exceed max size %u in client channel\n", q_count, MAX_QUEUE_SIZE);
            goto EXIT;
        }

        ctx->ctrl_msg->id_num = q_count;
        for (uint32_t i = 0; i < q_count; i++) {
            queue_info_t *q_info;
            if (i < user_q_info->qinfo_arr.arr_num) {
                q_info = user_q_info->qinfo_arr.qinfos[i];
            } else {
                q_info = manage_q_info->qinfo_arr.qinfos[i - user_q_info->qinfo_arr.arr_num];
            }
            memcpy(&ctx->ctrl_msg->id[i].eid, &q_info->mode_jetty.jetty_id.eid, sizeof(urpc_eid_t));
            ctx->ctrl_msg->id[i].uasid = q_info->mode_jetty.jetty_id.uasid;
            ctx->ctrl_msg->id[i].id = q_info->mode_jetty.jetty_id.id;
        }
    } else {
        ctx->ctrl_msg->id_num = 0;
    }

    URPC_LIB_LOG_INFO("process ctrl msg, taskid: %d, msg size: %u, id num: %u\n",
        task->key.task_id, ctx->ctrl_msg->msg_size, ctx->ctrl_msg->id_num);
    ret = urpc_ctrl_msg_process(msg_type, ctx->ctrl_msg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("ctrl msg process failed, taskid: %d, ret: %d\n", task->key.task_id, ret);
        goto EXIT;
    }
    return URPC_SUCCESS;

EXIT:
    urpc_dbuf_free(ctx->ctrl_msg_recv);
    ctx->ctrl_msg_recv = NULL;

    return URPC_FAIL;
}

static int server_process_attach_user_ctrl_info_recv(urpc_async_task_ctx_t *task)
{
    // 3. recv user ctrl input msg from client, and process ctrl msg, to ensure import remote queue is available
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    int ret = server_process_ctrl_msg(URPC_CTRL_MSG_ATTACH, task);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("process user ctrl msg failed, taskid: %d, channel: %u, manage channel: %u\n",
            task->key.task_id, ctx->server.chid, ctx->server.manage_chid);
        return URPC_FAIL;
    }
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    return URPC_SUCCESS;
}

static int server_process_detach_ctrl_msg_recv(urpc_async_task_ctx_t *task)
{
    // 2. recv and process ctrl msg
    return server_process_ctrl_msg(URPC_CTRL_MSG_DETACH, task);
}

static int server_process_attach_user_ctrl_info_send(urpc_async_task_ctx_t *task)
{
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };
    int ret = task_engine_send_data(task, &option, ctx->ctrl_msg->msg, ctx->ctrl_msg->msg_size);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send ctrl msg to client failed, taskid: %d, channel: %u, manage channel: %u\n",
            task->key.task_id, ctx->server.chid, ctx->server.manage_chid);
    }

    return ret;
}

static int server_process_attach_final_step(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    if (ctx->cap.dp_encrypt != URPC_TRUE) {
        return URPC_SUCCESS;
    }
    urpc_server_channel_info_t *channel = server_channel_get_with_rw_lock(ctx->server.chid, true);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get server channel %u failed\n", ctx->server.chid);
        return URPC_FAIL;
    }
    int ret = server_channel_cipher_init(channel, ctx->neg_ctx.neg_msg_v1.crypto_key);
    (void)pthread_rwlock_unlock(&channel->rw_lock);
    return ret;
}

static int server_func_send(urpc_async_task_ctx_t *task)
{
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;

    if (ctx->cap.func_info_enabled == URPC_FALSE) {
        return URPC_SUCCESS;
    }
    if (task->is_initialized == URPC_FALSE &&
        urpc_func_info_get(&ctx->func_info.func, &ctx->func_info.len) != URPC_SUCCESS) {
        urpc_dbuf_free(ctx->func_info.func);
        ctx->func_info.func = NULL;
        URPC_LIB_LOG_ERR("server construct send func msg failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->server.chid);
        return URPC_FAIL;
    }
    task->is_initialized = URPC_TRUE;
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };
    int ret = task_engine_send_data(task, &option, ctx->func_info.func, ctx->func_info.len);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    urpc_dbuf_free(ctx->func_info.func);
    ctx->func_info.func = NULL;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("server send func msg to client failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->server.chid);
    } else {
        URPC_LIB_LOG_INFO("server send func info successfully, taskid: %d\n", task->key.task_id);
    }
    return ret;
}

int urpc_mem_info_get(uint32_t chid, mem_info_t *mem_info)
{
    urpc_channel_info_t *channel = channel_get(chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel failed\n");
        return -URPC_ERR_ENOMEM;
    }
    pthread_rwlock_rdlock(&channel->mem_info_lock);
    uint32_t mem_info_num = channel->mem_info_num;
    uint32_t mem_info_data_len =
        mem_info_num * ((uint32_t)sizeof(urpc_tlv_head_t) + (uint32_t)sizeof(xchg_mem_info_t)) +
        (uint32_t)sizeof(urpc_tlv_arr_head_t);
    urpc_tlv_arr_head_t *meminfo_arr_tlv_head =
        (urpc_tlv_arr_head_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, mem_info_data_len);
    if (meminfo_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("mem arr tlv head malloc failed\n");
        return -URPC_ERR_ENOMEM;
    }

    int ret = meminfo_arr_serialize(channel, meminfo_arr_tlv_head, mem_info_num);
    pthread_rwlock_unlock(&channel->mem_info_lock);
    if (ret != URPC_SUCCESS) {
        urpc_dbuf_free(meminfo_arr_tlv_head);
        URPC_LIB_LOG_ERR("serialize meminfo arr failed")
        return URPC_FAIL;
    }
    mem_info->mem = meminfo_arr_tlv_head;
    mem_info->len = mem_info_data_len;
    return URPC_SUCCESS;
}

int client_memh_send(urpc_async_task_ctx_t *task)
{
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;

    if (task->is_initialized == URPC_FALSE &&
        urpc_mem_info_get(task->channel_id, &ctx->mem_info) != URPC_SUCCESS) {
        ctx->mem_info.mem = NULL;
        URPC_LIB_LOG_ERR("server construct send func msg failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->server.chid);
        return URPC_FAIL;
    }
    task->is_initialized = URPC_TRUE;
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_ATTACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };

    int ret = task_engine_send_data(task, &option, ctx->mem_info.mem, ctx->mem_info.len);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }

    urpc_dbuf_free(ctx->mem_info.mem);
    ctx->mem_info.mem = NULL;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("server send func msg to client failed, taskid: %d, channel: %u\n",
            task->key.task_id, ctx->server.chid);
    } else {
        URPC_LIB_LOG_INFO("server send func info successfully, taskid: %d\n", task->key.task_id);
    }
    task->is_initialized = URPC_FALSE;
    return ret;
}

static int server_process_detach_msg_info_recv(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    int ret = queue_info_recv(task);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("recv client detach confirm msg failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    ctx->cap.detach_manage = ctx->head.detach_manage;
    ctx->server.client_version = ctx->head.version;
    return URPC_SUCCESS;
}

static int server_process_detach_ctr_msg_send(urpc_async_task_ctx_t *task)
{
    // 3. process and send ctrl msg
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_DETACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };

    int ret = task_engine_send_data(task, &option, (void *)ctx->ctrl_msg->msg, ctx->ctrl_msg->msg_size);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("server send detach ctrl msg to client failed, task_id: %d\n", task->key.task_id);
    }

    return ret;
}

static int server_process_detach_success_confirm_send(urpc_async_task_ctx_t *task)
{
    // 4. send server detach msg
    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    if (entry == NULL) {
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .cap = ctx->cap,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = URPC_CTL_QUEUE_INFO_DETACH,
        .ctl_hdl = &entry->conn_handle,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_TRUE,
        .version = ctx->server.client_version,
    };
    int ret = task_engine_send_data(task, &option, NULL, 0);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("server send detach confirm msg to client failed, task_id: %d\n", task->key.task_id);
    }
    return ret;
}

static int detach_server_resource_release(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    ctx->client.channel->manage_chid = URPC_INVALID_ID_U32;
    (void)channel_remove_server(ctx->client.channel, &(ctx->client.endpoints.server));
    URPC_LIB_LOG_INFO("client detach successful, client chid: %u\n", ctx->client.channel->id);
    return URPC_SUCCESS;
}

static int detach_server_release_func(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    if (urpc_hmap_count(&ctx->client.channel->func_tbl) != 0) {
        urpc_func_tbl_release(&ctx->client.channel->func_tbl);
        URPC_LIB_LOG_INFO("release function table success for channel[%u]\n", ctx->client.channel->id);
    }
    return URPC_SUCCESS;
}

static void server_channel_remote_q_remove(urpc_server_channel_info_t *server_channel, urpc_chmsg_v1_t *q_info)
{
    for (uint32_t i = 0; i < q_info->qinfo_arr.arr_num; i++) {
        queue_info_t *queue_info = q_info->qinfo_arr.qinfos[i];
        queue_node_t *cur_node = NULL;
        queue_node_t *next_node = NULL;
        URPC_SLIST_FOR_EACH_SAFE(cur_node, &server_channel->r_queue_nodes_head, node, next_node)
        {
            queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
            if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
                if (queue->ref_cnt > 0) {
                    queue->ref_cnt--;
                }
                if (queue->ref_cnt != 0) {
                    URPC_LIB_LOG_DEBUG("remove remote queue, ref_cnt[%u]\n", queue->ref_cnt);
                    continue;
                }
                server_channel_remove_remote_queue(server_channel, cur_node);
            }
        }
    }
}

static int server_process_detach_resource_release(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_attach_msg_v1_t *msg = &ctx->chnl_ctx.attach_msg_v1_recv;
    urpc_chmsg_v1_t *q_info = &msg->chmsg_arr.chmsgs[0];
    server_channel_connect_hmap_lock();
    // 5. release server channel resource
    uint32_t server_chid = server_channel_id_map_lookup(msg->attach_info->server_chid);
    urpc_server_channel_info_t *channel = server_channel_get_with_rw_lock(server_chid, true);
    if (channel == NULL || !urpc_instance_key_cmp(&q_info->chinfo->key, &channel->key)) {
        if (channel != NULL) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
        }
        URPC_LIB_LOG_INFO("recv unkown client detach msg, server channel[%u], " EID_FMT ", pid: %u\n",
            server_chid, EID_ARGS(q_info->chinfo->key.eid), q_info->chinfo->key.pid);
        server_channel_connect_hmap_unlock();
        return URPC_FAIL;
    }
    server_channel_remote_q_remove(channel, q_info);
    uint32_t client_chid = q_info->chinfo->chid;
    channel->manage_chid = URPC_INVALID_ID_U32;
    server_channel_rm_client_chid(channel, client_chid);
    if (channel->client_chid_num != 0) {
        pthread_rwlock_unlock(&channel->rw_lock);
        server_channel_connect_hmap_unlock();
        // delete server channel remote queue
        URPC_LIB_LOG_INFO(
            "server process detach successful, client chid[%u], server chid[%u]\n", client_chid, server_chid);
        return URPC_SUCCESS;
    }
    pthread_rwlock_unlock(&channel->rw_lock);
    (void)server_channel_free(server_chid, true);
    server_channel_connect_hmap_unlock();
    URPC_LIB_LOG_INFO("server process detach successful, client chid[%u], server chid[%u]\n", client_chid, server_chid);
    return URPC_SUCCESS;
}

static int attach_server_final_step(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_attach_msg_v1_t *attach_msg = &ctx->chnl_ctx.attach_msg_v1_recv;
    // create server node
    server_node_t *server_node = channel_get_server_node(ctx->client.channel, &task->endpoints.server);
    // 1. remote queue info is new, create new server node
    if (server_node == NULL) {
        server_node_t *node = (server_node_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(server_node_t));
        if (node == NULL) {
            URPC_LIB_LOG_ERR("malloc server node failed\n");
            return URPC_FAIL;
        }
        node->endpoints = task->endpoints;
        node->server_chid = attach_msg->chmsg_arr.chmsgs[0].chinfo->chid;
        node->cap = attach_msg->chmsg_arr.chmsgs[0].chinfo->cap;
        node->instance_key = attach_msg->chmsg_arr.chmsgs[0].chinfo->key;
        node->index = ctx->client.channel->server_node_index++;

        if (crypto_is_dp_ssl_enabled()) {
            node->cipher_opt = (urpc_cipher_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_ENCRYPT, 1, sizeof(urpc_cipher_t));
            if (node->cipher_opt == NULL) {
                URPC_LIB_LOG_ERR("malloc cipher_opt failed\n");
                urpc_dbuf_free(node);
                return URPC_FAIL;
            }
            node->cipher_opt->chid = URPC_INVALID_ID_U32;
        }
        urpc_list_push_back(&ctx->client.channel->server_nodes_list, &node->node);
    } else {
        uint32_t server_pid = attach_msg->chmsg_arr.chmsgs[0].chinfo->key.pid;
        if (server_node->instance_key.pid != server_pid) {
            channel_flush_server_node(server_node, (void *)&attach_msg->chmsg_arr.chmsgs[0], &task->endpoints);
        } else {
            channel_update_server_node(server_node, (void *)&attach_msg->chmsg_arr.chmsgs[0], &task->endpoints);
        }
    }
    if (ctx->cap.dp_encrypt == URPC_TRUE) {
        int ret = init_cipher_for_server_node(
            ctx->client.channel, &task->endpoints.server, ctx->neg_ctx.neg_msg_v1.crypto_key);
        if (ret != URPC_SUCCESS) {
            return URPC_FAIL;
        }
    }

    if (task->workflow_type == WORKFLOW_TYPE_CLIENT_ATTACH_SERVER) {
        urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
        entry->ref_cnt++;
        urpc_channel_info_t *channel = ctx->client.channel;
        if (!urpc_list_is_in_list(&channel->tcp_node)) {
            urpc_list_push_back(&entry->channel_list, &channel->tcp_node);
        }
    }
    return URPC_SUCCESS;
}

int detach_server_final_step(urpc_async_task_ctx_t *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)(uintptr_t)task;
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    // detach success, decrement the reference count by one
    entry->ref_cnt--;
    urpc_channel_info_t *channel = ctx->client.channel;
    if (urpc_list_is_in_list(&channel->tcp_node)) {
        urpc_list_remove(&channel->tcp_node);
    }
    return URPC_SUCCESS;
}

static task_workflow_handle_t g_urpc_attach_server_workflow[] = {
    attach_server_init,
    client_send_neg_head,
    client_recv_neg_head_and_data,
    attach_info_send,
    attach_info_recv,
    client_user_ctrl_info_send,
    client_user_ctrl_info_recv,
    client_memh_send,
    client_func_recv,
    attach_server_final_step
};

static task_workflow_handle_t g_urpc_handle_attach_req_workflow[] = {
    server_recv_neg_head,
    server_send_negotiated_data,
    attach_info_recv,
    attach_info_send,
    server_process_attach_user_ctrl_info_recv,
    server_process_attach_user_ctrl_info_send,
    server_mem_recv,
    server_func_send,
    server_process_attach_final_step
};

static task_workflow_handle_t g_urpc_detach_server_workflow[] = {
    detach_server_init,
    detach_server_msg_info_send,
    detach_server_ctrl_msg_send,
    detach_server_ctrl_msg_recv,
    detach_server_success_ack_recv,
    detach_server_resource_release,
    detach_server_release_func,
    detach_server_final_step
};

static task_workflow_handle_t g_urpc_handle_detach_req_workflow[] = {
    server_process_detach_msg_info_recv,
    server_process_detach_ctrl_msg_recv,
    server_process_detach_ctr_msg_send,
    server_process_detach_success_confirm_send,
    server_process_detach_resource_release
};

static int add_local_final_step(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_channel_info_t *channel = ctx->client.channel;
    URPC_SLIST_INSERT_HEAD(&channel->l_queue_nodes_head, ctx->queue_node, node);
    ctx->queue_node = NULL;
    channel->l_qnum++;
    queue_t *queue = (queue_t *)(uintptr_t)ctx->urpc_qh;
    (void)__sync_fetch_and_add(&queue->ref_cnt, 1);
    return URPC_SUCCESS;
}

static void client_channel_destroy_remote_queue(queue_handshaker_ctx_t *ctx)
{
    queue_t *queue = ctx->client.remote_queue;
    if (queue->ref_cnt != 0) {
        return;
    }
    urpc_channel_info_t *channel = ctx->client.channel;
    server_node_t *server_node = channel_get_server_node(channel, NULL);
    if (server_node == NULL) {
        URPC_LIB_LIMIT_LOG_DEBUG("server node is null\n");
        return;
    }
    uint64_t *urpc_qh_ptr = server_node->urpc_qh;
    uint32_t new_pos = 0;
    for (uint32_t i = 0; i < server_node->urpc_qh_count; i++) {
        if (urpc_qh_ptr[i] != (uint64_t)(uintptr_t)queue) {
            urpc_qh_ptr[new_pos++] = urpc_qh_ptr[i];
        } else {
            queue->ops->delete_remote_queue(queue);
        }
    }
    server_node->urpc_qh_count = new_pos;
    ctx->client.remote_queue = NULL;
}

static int rm_remote_final_step(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    // get remote handle;
    ctx->client.remote_queue = channel_get_remote_queue_by_qid(ctx->client.channel, (uint32_t)ctx->urpc_qh);
    if (ctx->client.remote_queue == NULL) {
        URPC_LIB_LOG_ERR("get remote queue failed, taskid: %d, qid: %u\n", task->key.task_id, (uint32_t)ctx->urpc_qh);
        return URPC_FAIL;
    }
    int ret = channel_remove_remote_queue_async(ctx->client.channel, ctx->client.remote_queue);
    client_channel_destroy_remote_queue(ctx);
    return ret;
}

static int client_handshaker_step_common_init(
    urpc_async_task_ctx_t *task, urpc_channel_info_t *channel, uint32_t *server_chid)
{
    // get server node
    server_node_t *target_node = channel_get_server_node(channel, NULL);
    if (target_node == NULL) {
        URPC_LIB_LOG_ERR("not attached to any server, taskid: %d, channel: %u\n", task->key.task_id, task->channel_id);
        return URPC_FAIL;
    }
    task->endpoints = target_node->endpoints;
    *server_chid = target_node->server_chid;
    urpc_client_connect_entry_t *entry = transport_connection_get(&task->endpoints.server);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("get connection failed, taskid: %d, channel: %u\n", task->key.task_id, task->channel_id);
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    transport_client_task_register(task, entry);
    return URPC_SUCCESS;
}

static int add_remote_queue_init(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_channel_info_t *channel = ctx->client.channel;

    int ret = client_handshaker_step_common_init(task, channel, &ctx->client.server_chid);
    if (ret != URPC_SUCCESS) {
        return ret;
    }
    if (channel->r_qnum >= MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("no more remote queues can be added to the current channel, channel[%u], r_qnum[%u]\n",
            channel->id, channel->r_qnum);
        return URPC_FAIL;
    }
    ctx->client.remote_queue = channel_get_remote_queue_by_qid(ctx->client.channel, (uint32_t)ctx->urpc_qh);
    if (ctx->client.remote_queue == NULL) {
        return URPC_SUCCESS;
    } else {
        if (ctx->client.remote_queue->ref_cnt != 0) {
            ctx->client.remote_queue->ref_cnt++;
            uint32_t total_steps = 0;
            (void)task_workflow_get(task->workflow_type, &total_steps);
            task->outer_step = total_steps - 1;
            return URPC_SUCCESS;
        }
    }

    return URPC_SUCCESS;
}

static int rm_local_queue_init(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    if (channel_remove_local_queue(ctx->client.channel, (queue_t *)(uintptr_t)ctx->urpc_qh) != URPC_SUCCESS) {
        return URPC_FAIL;
    }
    int ret = client_handshaker_step_common_init(task, ctx->client.channel, &ctx->client.server_chid);
    if (ret != URPC_SUCCESS) {
        return ret;
    }
    if (client_queue_info_prepare(ctx) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("prepare channel info failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int queue_cmd_send(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    if (task->transport_handle == NULL) {
        URPC_LIB_LOG_ERR("entry is invailed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    transport_handle_t *ctl_hdl = &entry->conn_handle;

    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = task->ctl_opcode,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_TRUE,
        .cap_enable = URPC_FALSE,
        .version = 0,
    };
    queue_handshaker_req_option_t cmd = {
        .queue_type = ctx->queue_type, .qid = ctx->urpc_qh, .server_chid = ctx->client.server_chid};
    int ret = task_engine_send_data(task, &option, &cmd, sizeof(queue_handshaker_req_option_t));
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    if (ret == URPC_SUCCESS) {
        task->is_notify = URPC_TRUE;
    }
    // send return URPC_SUCCESS or URPC_FAIL, should reset is_initialized flag, continue next step
    task->is_initialized = URPC_FALSE;
    return ret;
}

static int client_execute_import(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_attach_msg_v1_t *attach_msg = &ctx->attach_msg_v1_recv;
    if (attach_msg->chmsg_arr.chmsgs[0].qinfo_arr.arr_num == 0) {
        return URPC_FAIL;
    }

    int ret = client_channel_create_remote_queue(
        ctx->client.channel, &task->endpoints, &attach_msg->chmsg_arr.chmsgs[0], false);
    if (ret != URPC_SUCCESS) {
        return URPC_FAIL;
    }
    // get remote handle;
    ctx->client.remote_queue = channel_get_remote_queue_by_qid(ctx->client.channel, (uint32_t)ctx->urpc_qh);
    if (ctx->client.remote_queue == NULL) {
        URPC_LIB_LOG_ERR("get remote queue failed, taskid: %d, qid: %u\n", task->key.task_id, (uint32_t)ctx->urpc_qh);
        return URPC_FAIL;
    }

    ret = channel_add_remote_queue(
        ctx->client.channel, ctx->client.remote_queue, &ctx->batch_import_ctx, URPC_QUEUE_IMPORT_TIMEOUT);
    if (ret == URPC_FAIL) {
        // delete remote queue
        client_channel_destroy_remote_queue(ctx);
        URPC_LIB_LOG_ERR("import remote queue failed, taskid: %d\n", task->key.task_id);
        ctx->batch_import_ctx.result = URPC_FAIL;
        return URPC_FAIL;
    }
    if (ret == URPC_RUNNING) {
        task->task_state = TASK_IMPORTING;
        task->ref_cnt++;
    }
    // go into next step, wait get import result
    return URPC_SUCCESS;
}

static int server_execute_unimport(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_chmsg_v1_t *q_info = &ctx->attach_msg_v1_recv.chmsg_arr.chmsgs[0];
    ctx->batch_import_ctx.task = (void *)ctx;
    if (q_info->qinfo_arr.arr_num > 0) {
        server_channel_import_rollback(ctx->server.chid, q_info->qinfo_arr.qinfos[0]);
    }
    return URPC_SUCCESS;
}

static transport_handle_t *transport_handle_get(urpc_async_task_ctx_t *task)
{
    if (task->transport_handle == NULL) {
        task_state_update_to_completed(task);
        URPC_LIB_LOG_ERR("transport handle is invailed, taskid: %d\n", task->key.task_id);
        return NULL;
    }
    transport_handle_t *ctl_hdl = NULL;
    if (task->is_server == URPC_TRUE) {
        urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)task->transport_handle;
        ctl_hdl = &entry->conn_handle;
    } else {
        urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
        ctl_hdl = &entry->conn_handle;
    }
    return ctl_hdl;
}

static int queue_info_send(urpc_async_task_ctx_t *task)
{
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }
    urpc_attach_msg_v1_t *attach_msg = NULL;
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = task->ctl_opcode,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_FALSE,
        .version = 0,
    };

    if (task->ctl_opcode == URPC_CTL_QUEUE_INFO_ADD || task->ctl_opcode == URPC_CTL_QUEUE_INFO_RM) {
        queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
        attach_msg = &ctx->attach_msg_v1_send;
        option.is_start = URPC_FALSE;
        if (task->is_server == URPC_TRUE) {
            if (task->is_initialized == URPC_FALSE && server_queue_info_prepare(ctx) != URPC_SUCCESS) {
                return URPC_FAIL;
            }
        }
    } else {
        ip_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, ip_handshaker_ctx_t, base_task);
        attach_msg = &ctx->chnl_ctx.attach_msg_v1_send;
        option.is_start = URPC_TRUE;
    }

    int ret = task_engine_send_data(task, &option, attach_msg->data.buffer, attach_msg->data.len);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    if (ret == URPC_SUCCESS) {
        task->is_notify = URPC_TRUE;
    }
    // send return URPC_SUCCESS or URPC_FAIL, should reset is_initialized flag, continue next step
    task->is_initialized = URPC_FALSE;

    urpc_attach_msg_v1_buffer_release(attach_msg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("send queue info to server failed, taskid: %d\n", task->key.task_id);
    }
    return ret;
}

static int server_execute_import(urpc_async_task_ctx_t *task)
{
    int ret = URPC_SUCCESS;
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_chmsg_v1_t *q_info = &ctx->attach_msg_v1_recv.chmsg_arr.chmsgs[0];
    ctx->batch_import_ctx.task = (void *)ctx;
    ret = server_channel_put_remote_queue_async(ctx->server.chid, q_info, &ctx->batch_import_ctx);
    // cannot exit after failure, need to wait all import result
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR(
            "user channel put remote queue failed, taskid: %d, channel: %u\n", task->key.task_id, ctx->server.chid);
        ctx->batch_import_ctx.result = URPC_FAIL;
        if (ctx->batch_import_ctx.running_count == 0) {
            return URPC_FAIL;
        }
        // some queue import have been successfully executed, need wait get import result and ref_cnt + 1
        task->ref_cnt++;
        task->task_state = TASK_IMPORTING;
        // go into next step, wait get import result
        return URPC_SUCCESS;
    }

    if (ret == URPC_RUNNING) {
        task->task_state = TASK_IMPORTING;
        task->ref_cnt++;
    }
    // go into next step, wait get import result
    return URPC_SUCCESS;
}

static bool channel_queue_info_validate(urpc_attach_msg_v1_t *attach_msg)
{
    if (attach_msg->chmsg_arr.arr_num != 1) {
        URPC_LIB_LOG_ERR("recv invalid channel queue info, channel num: %u\n", attach_msg->chmsg_arr.arr_num);
        return false;
    }

    urpc_qinfo_arr_v1_t *qinfo_arr = &attach_msg->chmsg_arr.chmsgs[0].qinfo_arr;
    if (qinfo_arr->arr_num > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR(
            "recv invalid channel queue info, msg size: %ld, channel num: %u, queue num: %u\n",
            attach_msg->data.len, attach_msg->chmsg_arr.arr_num, qinfo_arr->arr_num);
        return false;
    }
    return true;
}

static int queue_info_recv(urpc_async_task_ctx_t *task)
{
    urpc_attach_msg_v1_t *attach_msg = NULL;
    if (task->ctl_opcode == URPC_CTL_QUEUE_INFO_ADD || task->ctl_opcode == URPC_CTL_QUEUE_INFO_RM) {
        queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
        attach_msg = &ctx->attach_msg_v1_recv;
    } else {
        ip_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, ip_handshaker_ctx_t, base_task);
        attach_msg = &ctx->chnl_ctx.attach_msg_v1_recv;
    }

    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }
    if (task->is_initialized == URPC_FALSE) {
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = queue_info_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }
    // 4. recv remote q info, including remote manage queue and remote user queue
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_recv_completed = URPC_FALSE;
    task->is_initialized = URPC_FALSE;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (ret == URPC_FAIL || head->data_size == 0) {
        // can not empty
        URPC_LIB_LOG_ERR("recv channel queue info failed, taskid: %d, ret: %d, data_size: %u\n",
            task->key.task_id, ret, head->data_size);
        return URPC_FAIL;
    }

    attach_msg->data.len = head->data_size;

    if (urpc_attach_msg_v1_deserialize(attach_msg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("serialize attach message failed, taskid: %d\n", task->key.task_id);
        urpc_attach_msg_v1_buffer_release(attach_msg);
        return URPC_FAIL;
    }

    if (!channel_queue_info_validate(attach_msg)) {
        URPC_LIB_LOG_ERR("recv channel queue info is invalid, taskid: %d\n", task->key.task_id);
        urpc_attach_msg_v1_buffer_release(attach_msg);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static void queue_handshaker_ack_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    task->is_recv_completed = URPC_TRUE;
    urpc_dbuf_free(buffer);
}

static int queue_handshaker_ack_recv(urpc_async_task_ctx_t *task)
{
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }
    if (task->is_initialized == URPC_FALSE) {
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = queue_handshaker_ack_input_set;
        task->is_initialized = URPC_TRUE;
    }

    // 4. recv ctrl msg
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_initialized = URPC_FALSE;
    task->is_recv_completed = URPC_FALSE;
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR(
            "recv import confirm msg failed, taskid: %d, is_server: %d\n", task->key.task_id, task->is_server);
        return URPC_FAIL;
    }

    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (head->error_code != URPC_SUCCESS || head->data_size != 0) {
        URPC_LIB_LOG_ERR("recv confirm msg failed, taskid: %d, error code: %d, data size: %u, is_server: %d\n",
            task->key.task_id, head->error_code, head->data_size, task->is_server);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static void channel_put_remote_queue_rollback(batch_queue_import_ctx_t *ctx, bool is_delete)
{
    queue_import_async_info_t *import_cur = NULL;
    queue_import_async_info_t *import_next = NULL;
    URPC_LIST_FOR_EACH_SAFE(import_cur, import_next, node, &ctx->import_list)
    {
        queue_t *queue = (queue_t *)(uintptr_t)import_cur->queue_handle;
        if (import_cur->status == QUEUE_IMPORT_SUCCESS) {
            queue->ops->unimport_remote_queue_async(queue);
        }
        if (is_delete) {
            queue->ops->delete_remote_queue(queue);
        }
        urpc_list_remove(&import_cur->node);
        urpc_dbuf_free(import_cur);
    }
}

static bool server_channel_r_queue_is_exited(uint32_t server_chid, queue_info_t *queue_info)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, false);
    if (server_channel == NULL) {
        return false;
    }
    bool is_exited = false;
    queue_node_t *cur_node;
    // The r_queue_nodes_head has corresponding identical local queue information.
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node)
    {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
            queue->ref_cnt++;
            // remote queues created by different providers have the same local queue information, so not return
            is_exited = true;
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    return is_exited;
}

static int server_after_import(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_chmsg_v1_t *chmsg = &ctx->attach_msg_v1_recv.chmsg_arr.chmsgs[0];
    queue_info_t *queue_info_entry = chmsg->qinfo_arr.qinfos[0];
    if (chmsg->qinfo_arr.arr_num == 0) {
        return URPC_FAIL;
    }

    if (ctx->batch_import_ctx.running_count != 0) {
        return URPC_RUNNING;
    }
    task->task_state = TASK_STEP_COMPLETED;
    if (ctx->batch_import_ctx.result != URPC_SUCCESS) {
        channel_put_remote_queue_rollback(&ctx->batch_import_ctx, true);
        return URPC_FAIL;
    }
    // Different channels add the same local queue, which results in the creation of multiple remote queues.
    // Therefore, additional remote queues are needed for removal.
    if (!urpc_list_is_empty(&ctx->batch_import_ctx.import_list) &&
        server_channel_r_queue_is_exited(ctx->server.chid, queue_info_entry)) {
        channel_put_remote_queue_rollback(&ctx->batch_import_ctx, true);
        return URPC_SUCCESS;
    }
    ctx->is_import_rollback = URPC_TRUE;
    int ret = server_channel_post_put_remote_queue(ctx->server.chid, &ctx->batch_import_ctx);
    if (ret != URPC_SUCCESS || ctx->batch_import_ctx.result != URPC_SUCCESS) {
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int client_after_import(urpc_async_task_ctx_t *task)
{
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    if (ctx->batch_import_ctx.running_count != 0) {
        return URPC_RUNNING;
    }
    task->task_state = TASK_STEP_COMPLETED;
    // list contains only one element.
    queue_import_async_info_t *cur = NULL;
    if (urpc_list_is_empty(&ctx->batch_import_ctx.import_list)) {
        return URPC_SUCCESS;
    }
    // import_list has only one queue;
    urpc_list_t *node_ptr = urpc_list_pop_front(&ctx->batch_import_ctx.import_list);
    ASSIGN_CONTAINER_PTR(cur, node_ptr, node);
    int ret = URPC_FAIL;
    if (cur->status == QUEUE_IMPORT_SUCCESS) {
        ret = channel_post_add_remote_queue(ctx->client.channel, ctx->client.remote_queue, NULL);
    }
    if (ret != URPC_SUCCESS) {
        client_channel_destroy_remote_queue(ctx);
    }
    urpc_dbuf_free(cur);
    return ret;
}

static int queue_handshaker_confirm_send(urpc_async_task_ctx_t *task)
{
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        return URPC_FAIL;
    }
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = task->ctl_opcode,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_FALSE,
        .cap_enable = URPC_FALSE,
    };
    int ret = task_engine_send_data(task, &option, NULL, 0);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send import confirm msg to peer failed, taskid: %d\n", task->key.task_id);
    }
    return ret;
}

static int server_release_resource(urpc_async_task_ctx_t *task)
{
    transport_server_release_resource(task);
    return URPC_SUCCESS;
}

static task_workflow_handle_t g_urpc_client_add_local_queue_workflow[] = {
    add_local_queue_init, queue_cmd_send, queue_info_send, queue_handshaker_ack_recv, add_local_final_step};

static task_workflow_handle_t g_urpc_handle_add_local_queue_req_workflow[] = {
    queue_info_recv,
    server_execute_import,
    server_after_import,
    queue_handshaker_confirm_send
};

static task_workflow_handle_t g_urpc_client_add_remote_queue_workflow[] = {
    add_remote_queue_init,
    queue_cmd_send,
    queue_info_recv,
    client_execute_import,
    client_after_import};

static task_workflow_handle_t g_urpc_handle_add_remote_queue_req_workflow[] = {
    queue_info_send};

static task_workflow_handle_t g_urpc_client_rm_local_queue_workflow[] = {
    rm_local_queue_init, queue_cmd_send, queue_info_send, queue_handshaker_ack_recv};

static task_workflow_handle_t g_urpc_handle_rm_local_queue_req_workflow[] = {
    queue_info_recv, server_execute_unimport, queue_handshaker_confirm_send};

static task_workflow_handle_t g_urpc_client_rm_remote_queue_workflow[] = {
    rm_remote_final_step
};

static task_workflow_handle_t g_urpc_client_pair_queue_workflow[] = {
    client_bind_init,
    bind_info_send,
    client_recv_bind_info,
    client_queue_bind
};
 
static task_workflow_handle_t g_urpc_handle_pair_queue_req_workflow[] = {
    server_queue_bind,
    bind_info_send,
    server_pair_final
};
 
static task_workflow_handle_t g_urpc_client_unpair_queue_workflow[] = {
    client_bind_init,
    unbind_info_send,
    client_recv_unbind_info,
    client_unbind
};
 
static task_workflow_handle_t g_urpc_handle_unpair_queue_req_workflow[] = {
    server_queue_unbind,
    unbind_info_send,
    server_pair_final
};

static task_workflow_handle_t g_urpc_handle_release_resource_req_workflow[] = {server_release_resource};

static task_workflow_handle_t *task_workflow_get(task_workflow_type_t type, uint32_t *total_steps)
{
    task_workflow_handle_t *process = NULL;
    switch (type) {
        case WORKFLOW_TYPE_CLIENT_ATTACH_SERVER:
        case WORKFLOW_TYPE_CLIENT_REFRESH_SERVER:
            process = g_urpc_attach_server_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_attach_server_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CLIENT_DETACH_SERVER:
            process = g_urpc_detach_server_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_detach_server_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_PAIR_QUEUE:
            process = g_urpc_client_pair_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_pair_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_UNPAIR_QUEUE:
            process = g_urpc_client_unpair_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_unpair_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE:
            process = g_urpc_client_add_local_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_add_local_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE:
            process = g_urpc_client_add_remote_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_add_remote_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE:
            process = g_urpc_client_rm_local_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_rm_local_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_CHANNEL_RM_REMOTE_QUEUE:
            process = g_urpc_client_rm_remote_queue_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_client_rm_remote_queue_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_ATTACH_REQ:
            process = g_urpc_handle_attach_req_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_handle_attach_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_DETACH_REQ:
            process = g_urpc_handle_detach_req_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_handle_detach_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_ADD_LOCAL_QUEUE_REQ:
            process = g_urpc_handle_add_local_queue_req_workflow;
            *total_steps =
                (uint32_t)(sizeof(g_urpc_handle_add_local_queue_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_ADD_REMOTE_QUEUE_REQ:
            process = g_urpc_handle_add_remote_queue_req_workflow;
            *total_steps =
                (uint32_t)(sizeof(g_urpc_handle_add_remote_queue_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_RM_LOCAL_QUEUE_REQ:
            process = g_urpc_handle_rm_local_queue_req_workflow;
            *total_steps =
                (uint32_t)(sizeof(g_urpc_handle_rm_local_queue_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_PAIR_QUEUE_REQ:
            process = g_urpc_handle_pair_queue_req_workflow;
            *total_steps =
                (uint32_t)(sizeof(g_urpc_handle_pair_queue_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_HANDLE_UNPAIR_QUEUE_REQ:
            process = g_urpc_handle_unpair_queue_req_workflow;
            *total_steps = (uint32_t)(sizeof(g_urpc_handle_unpair_queue_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        case WORKFLOW_TYPE_RELEASE_RESOURCE:
            process = g_urpc_handle_release_resource_req_workflow;
            *total_steps =
                (uint32_t)(sizeof(g_urpc_handle_release_resource_req_workflow) / sizeof(task_workflow_handle_t));
            break;
        default:
            URPC_LIB_LOG_ERR("get workflow failed, type: %d\n", type);
            break;
    }
    return process;
}

static int add_local_queue_init(urpc_async_task_ctx_t *task)
{
    queue_node_t *cur_node = NULL;
    queue_handshaker_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_handshaker_ctx_t, base_task);
    urpc_channel_info_t *channel = ctx->client.channel;

    int ret = client_handshaker_step_common_init(task, channel, &ctx->client.server_chid);
    if (ret != URPC_SUCCESS) {
        return URPC_FAIL;
    }
   
    queue_t *queue = (queue_t *)(uintptr_t)ctx->urpc_qh;
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node)
    {
        if ((uintptr_t)queue == cur_node->urpc_qh) {
            cur_node->ref_cnt++;
            task->outer_step =
                (uint32_t)(sizeof(g_urpc_client_add_local_queue_workflow) / sizeof(task_workflow_handle_t)) - 1;
            return URPC_SUCCESS;
        }
    }
    if (channel->l_qnum >= MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("no more local queue can be added to the current channel, channel[%u]\n", channel->id);
        return URPC_FAIL;
    }
    
    if (client_queue_info_prepare(ctx) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("prepare channel info failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
    ctx->queue_node = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    if (ctx->queue_node == NULL) {
        URPC_LIB_LOG_ERR("malloc queue node failed, taskid: %d\n", task->key.task_id);
        return URPC_FAIL;
    }

    ctx->queue_node->node.next = NULL;
    ctx->queue_node->urpc_qh = (uint64_t)(uintptr_t)queue;
    ctx->queue_node->ref_cnt = 1;
    return URPC_SUCCESS;
}

static void client_base_handshaker_init(task_init_params_t *params, urpc_async_task_ctx_t *task)
{
    handshaker_callback_ctx_t *callback_ctx = params->callback_ctx;
    urpc_channel_info_t *channel = params->channel;

    task->workflow_type = params->type;
    channel->provider->ops->get_eid(channel->provider, &task->key.identity.eid);
    task->key.identity.pid = (uint32_t)getpid();
    task->func = callback_ctx->func;
    task->ctx = (void *)callback_ctx;
    task->channel_id = channel->id;

    urpc_channel_connect_option_t *option = &callback_ctx->conn_option;
    task->timestamp = option->timeout >= 0 ? get_timestamp_ms() + (uint64_t)option->timeout : UINT64_MAX;
    task->timeout = option->timeout;
    switch (task->workflow_type) {
        case WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE:
        case WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE:
            task->ctl_opcode = URPC_CTL_QUEUE_INFO_ADD;
            break;
        case WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE:
        case WORKFLOW_TYPE_CHANNEL_RM_REMOTE_QUEUE:
            task->ctl_opcode = URPC_CTL_QUEUE_INFO_RM;
            break;
        default:
            break;
    }
}

urpc_async_task_ctx_t *task_engine_client_handshaker_new(task_init_params_t *params)
{
    ip_handshaker_ctx_t *ctx =
        (ip_handshaker_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(ip_handshaker_ctx_t));
    if (ctx == NULL) {
        URPC_LIB_LOG_ERR("alloc ctx failed\n");
        return NULL;
    }
    client_base_handshaker_init(params, &ctx->base_task);

    if (client_ctx_init(ctx, params->ctrl_msg, params->channel, params->server, params->local) != URPC_SUCCESS) {
        urpc_dbuf_free(ctx);
        return NULL;
    }
    return (urpc_async_task_ctx_t *)(uintptr_t)ctx;
}

urpc_async_task_ctx_t *task_engine_queue_handshaker_new(task_init_params_t *params)
{
    queue_handshaker_ctx_t *ctx =
        (queue_handshaker_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(queue_handshaker_ctx_t));
    if (ctx == NULL) {
        URPC_LIB_LOG_ERR("alloc ctx failed\n");
        return NULL;
    }

    client_base_handshaker_init(params, &ctx->base_task);
    urpc_list_init(&ctx->batch_import_ctx.import_list);
    ctx->batch_import_ctx.task = (void *)ctx;
    ctx->urpc_qh = params->urpc_qh;
    ctx->queue_type = params->attr.type;
    ctx->client.channel = params->channel;
    return (urpc_async_task_ctx_t *)(uintptr_t)ctx;
}

static task_free_func_t g_urpc_task_free_manager[TASK_CTX_TYPE_MAX] = {
    task_handshaker_ctx_free,
    queue_handshaker_ctx_free,
    release_resource_ctx_free,
    bind_ctx_free,
};

static void task_handshaker_ctx_free(void *task)
{
    ip_handshaker_ctx_t *ctx = (ip_handshaker_ctx_t *)task;

    urpc_dbuf_free(ctx->dummy_ctrl_msg.msg);
    ctx->dummy_ctrl_msg.msg = NULL;

    urpc_neg_msg_v1_buffer_release(&ctx->neg_ctx.neg_msg_v1);
    urpc_attach_msg_v1_buffer_release(&ctx->chnl_ctx.attach_msg_v1_send);
    urpc_attach_msg_v1_buffer_release(&ctx->chnl_ctx.attach_msg_v1_recv);
    urpc_detach_msg_v1_buffer_release(&ctx->detach_msg_v1);

    urpc_dbuf_free(ctx->ctrl_msg_recv);
    ctx->ctrl_msg_recv = NULL;

    urpc_dbuf_free(ctx->func_info.func);
    ctx->func_info.func = NULL;

    batch_import_ctx_free(&ctx->batch_import_ctx);
    urpc_dbuf_free(ctx);
}

static void queue_handshaker_ctx_free(void *task)
{
    queue_handshaker_ctx_t *ctx = (queue_handshaker_ctx_t *)task;
    if (ctx->base_task.workflow_type == WORKFLOW_TYPE_HANDLE_ADD_LOCAL_QUEUE_REQ ||
        ctx->base_task.workflow_type == WORKFLOW_TYPE_HANDLE_RM_LOCAL_QUEUE_REQ ||
        ctx->base_task.workflow_type == WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE) {
        urpc_attach_msg_v1_buffer_release(&ctx->attach_msg_v1_recv);
    }

    if (ctx->base_task.workflow_type == WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE ||
        ctx->base_task.workflow_type == WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE ||
        ctx->base_task.workflow_type == WORKFLOW_TYPE_HANDLE_ADD_REMOTE_QUEUE_REQ) {
        urpc_attach_msg_v1_buffer_release(&ctx->attach_msg_v1_send);
    }

    urpc_dbuf_free(ctx->queue_node);
    urpc_dbuf_free(ctx);
}

static void release_resource_ctx_free(void *task)
{
    delayed_release_resources_ctx_t *ctx = (delayed_release_resources_ctx_t *)task;
    urpc_server_channel_info_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &ctx->server_channel_list) {
        urpc_list_remove(&cur->node);
    }
    urpc_dbuf_free(ctx);
}

static void task_engine_ctx_free(urpc_async_task_ctx_t *task)
{
    if (task->ref_cnt != 0) {
        URPC_LIB_LOG_ERR("task can not free, ref_cnt: %d\n", task->ref_cnt);
        return;
    }

    URPC_LIB_LOG_DEBUG("task free, taskid: %d\n", task->key.task_id);
    task_free_func_t free_func = g_urpc_task_free_manager[task_engine_ctx_type_get(task->workflow_type)];
    free_func((void *)task);
}

handshaker_callback_ctx_t *task_engine_callback_construct(
    urpc_host_info_t *server, urpc_channel_connect_option_t *option)
{
    handshaker_callback_ctx_t *ctx =
        (handshaker_callback_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(handshaker_callback_ctx_t));
    if (ctx == NULL) {
        errno = URPC_ERR_ENOMEM;
        URPC_LIB_LOG_ERR("malloc connect callback ctx failed\n");
        return NULL;
    }
 
    if (!urpc_channel_connect_option_set(server, option, &ctx->conn_option)) {
        errno = URPC_ERR_EINVAL;
        urpc_dbuf_free(ctx);
        return NULL;
    }
 
    if ((ctx->conn_option.flag & URPC_CHANNEL_CONN_FLAG_FEATURE) != 0 &&
        (ctx->conn_option.feature & URPC_CHANNEL_CONN_FEATURE_NONBLOCK) != 0) {
        ctx->nonblock = URPC_TRUE;
        ctx->func = task_engine_async_callback;
    } else {
        sem_init(&ctx->sem, 0, 0);
        ctx->func = task_engine_sync_callback;
    }
    return ctx;
}

void task_engine_callback_destruct(handshaker_callback_ctx_t *ctx)
{
    if (ctx->nonblock == URPC_FALSE) {
        sem_destroy(&ctx->sem);
    }
 
    urpc_dbuf_free(ctx);
}

static task_engine_ctx_type_t task_engine_ctx_type_get(task_workflow_type_t type)
{
    task_engine_ctx_type_t ctx_type = QUEUE_HANDSHAKER_CTX_TYPE;
    switch (type) {
        case WORKFLOW_TYPE_CLIENT_ATTACH_SERVER:
        case WORKFLOW_TYPE_CLIENT_REFRESH_SERVER:
        case WORKFLOW_TYPE_CLIENT_DETACH_SERVER:
        case WORKFLOW_TYPE_HANDLE_ATTACH_REQ:
        case WORKFLOW_TYPE_HANDLE_DETACH_REQ:
            ctx_type = TASK_HANDSHAKER_CTX_TYPE;
            break;
        case WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE:
        case WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE:
        case WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE:
        case WORKFLOW_TYPE_CHANNEL_RM_REMOTE_QUEUE:
        case WORKFLOW_TYPE_HANDLE_ADD_LOCAL_QUEUE_REQ:
        case WORKFLOW_TYPE_HANDLE_ADD_REMOTE_QUEUE_REQ:
        case WORKFLOW_TYPE_HANDLE_RM_LOCAL_QUEUE_REQ:
        case WORKFLOW_TYPE_HANDLE_RM_REMOTE_QUEUE_REQ:
            ctx_type = QUEUE_HANDSHAKER_CTX_TYPE;
            break;
        case WORKFLOW_TYPE_RELEASE_RESOURCE:
            ctx_type = RELEASE_RESOURCE_CTX_TYPE;
            break;
        case WORKFLOW_TYPE_CHANNEL_PAIR_QUEUE:
        case WORKFLOW_TYPE_HANDLE_PAIR_QUEUE_REQ:
        case WORKFLOW_TYPE_CHANNEL_UNPAIR_QUEUE:
        case WORKFLOW_TYPE_HANDLE_UNPAIR_QUEUE_REQ:
            ctx_type = BIND_CTX_TYPE;
            break;
        default:
            URPC_LIB_LOG_ERR("get workflow failed, type: %d\n", type);
            break;
    }
    return ctx_type;
}

static task_rollback_func_t g_urpc_task_rollback_manager[TASK_CTX_TYPE_MAX] = {
    task_handshaker_rollback, queue_handshaker_rollback, release_resource_rollback, queue_pair_rollback};

static void task_handshaker_rollback(void *task)
{
    ip_handshaker_ctx_t *handshaker = (ip_handshaker_ctx_t *)task;
    urpc_async_task_ctx_t *base_task = &handshaker->base_task;
    if (base_task->result != URPC_SUCCESS && base_task->is_server == URPC_FALSE) {
        return;
    }
    if (base_task->result != URPC_SUCCESS && base_task->is_server == URPC_TRUE) {
        if (handshaker->server.channel_attached) {
            ip_handshaker_ctx_server_uninit(handshaker);
        }
    }
}

static void queue_handshaker_rollback(void *task)
{
    queue_handshaker_ctx_t *ctx = (queue_handshaker_ctx_t *)task;
    // During the task importing process, the task times out or the user cancels the task.
    if (ctx->base_task.is_server == URPC_FALSE) {
        channel_put_remote_queue_rollback(&ctx->batch_import_ctx, false);
        if (ctx->client.remote_queue != NULL) {
            client_channel_destroy_remote_queue(ctx);
        }
    } else {
        channel_put_remote_queue_rollback(&ctx->batch_import_ctx, true);
    }
    if (ctx->base_task.is_server == URPC_TRUE && ctx->is_import_rollback == URPC_TRUE) {
        urpc_chmsg_v1_t *q_info = &ctx->attach_msg_v1_recv.chmsg_arr.chmsgs[0];
        if (q_info->qinfo_arr.arr_num > 0) {
            server_channel_import_rollback(ctx->server.chid, q_info->qinfo_arr.qinfos[0]);
        }
    }
}

static void release_resource_rollback(void *task)
{
    return;
}

static void task_engine_task_rollback(urpc_async_task_ctx_t *task)
{
    task_rollback_func_t rollback = g_urpc_task_rollback_manager[task_engine_ctx_type_get(task->workflow_type)];
    rollback((void *)task);
}

static void queue_pair_rollback(void *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)ctx->l_q;
    if (local_q != NULL && local_q->is_binded == URPC_TRUE) {
        (void)local_q->queue.ops->unbind_queue(&local_q->queue);
    }
}

static void bind_info_recv_input_set(void *buffer, urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    ctx->r_bind_info = buffer;
    task->is_recv_completed = URPC_TRUE;
}

urpc_async_task_ctx_t *task_engine_bind_new(task_init_params_t *params)
{
    queue_pair_ctx_t *ctx =
        (queue_pair_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(queue_pair_ctx_t));
    if (ctx == NULL) {
        URPC_LIB_LOG_ERR("alloc ctx failed\n");
        return NULL;
    }
    client_base_handshaker_init(params, &ctx->base_task);
    ctx->l_q = params->local_q;
    ctx->r_q = params->remote_q;
    return (urpc_async_task_ctx_t *)(uintptr_t)ctx;
}

static int pair_info_send(urpc_async_task_ctx_t *task, enum urpc_ctl_opcode opcode)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    transport_handle_t *ctl_hdl = transport_handle_get(task);
    if (ctl_hdl == NULL) {
        URPC_LIB_LOG_ERR("entry is null, task id: %d\n", task->key.task_id);
        return URPC_FAIL;
    }
 
    task_send_request_option_t option = {
        .task_id = task->key.task_id,
        .chid = URPC_INVALID_ID_U32,
        .ctl_opcode = opcode,
        .ctl_hdl = ctl_hdl,
        .is_start = URPC_TRUE,
        .cap_enable = URPC_FALSE,
        .version = URPC_INVALID_ID_U8,
    };
    int ret = task_engine_send_data(task, &option, &ctx->l_bind_info, sizeof(queue_bind_info_t));
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    if (ret == URPC_SUCCESS) {
        task->is_notify = URPC_TRUE;
    }
    // send return URPC_SUCCESS or URPC_FAIL, should reset is_initialized flag, continue next step
    task->is_initialized = URPC_FALSE;
    return ret;
}

static int bind_info_send(urpc_async_task_ctx_t *task)
{
    return pair_info_send(task, URPC_CTL_QUEUE_INFO_BIND);
}

static int unbind_info_send(urpc_async_task_ctx_t *task)
{
    return pair_info_send(task, URPC_CTL_QUEUE_INFO_UNBIND);
}

static int client_bind_init(urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    urpc_channel_info_t *channel = channel_get(task->channel_id);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel failed, channel id: %u, task id: %d\n", task->channel_id, task->key.task_id);
        return URPC_FAIL;
    }

    server_node_t *target_node = channel_get_server_node(channel, NULL);
    if (target_node == NULL) {
        URPC_LIB_LOG_ERR("not attached to any server, taskid: %d, channel: %u\n", task->key.task_id, task->channel_id);
        return URPC_FAIL;
    }
    task->endpoints = target_node->endpoints;
    urpc_client_connect_entry_t *entry = transport_connection_get(&task->endpoints.server);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("get connection failed, taskid: %d, channel: %u\n", task->key.task_id, task->channel_id);
        task_state_update_to_completed(task);
        return URPC_FAIL;
    }
    transport_client_task_register(task, entry);

    if (!check_queue_in_channel(channel, (uint64_t)(uintptr_t)ctx->l_q) ||
        !check_queue_in_channel(channel, (uint64_t)(uintptr_t)ctx->r_q)) {
        return URPC_FAIL;
    }
    server_node_t *server_node = channel_get_server_node(channel, NULL);
    if (server_node == NULL) {
        URPC_LIB_LOG_ERR("get server_node failed, channel id: %u, task id: %d\n", task->channel_id, task->key.task_id);
        return URPC_FAIL;
    }
    task->endpoints = server_node->endpoints;
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)ctx->l_q;
    queue_remote_t *remote_q = (queue_remote_t *)(uintptr_t)ctx->r_q;
    queue_bind_info_t *l_bind_info = &ctx->l_bind_info;
    l_bind_info->l_qid = local_q->qid;
    l_bind_info->r_qid = remote_q->qid;
    l_bind_info->mapped_server_chid = remote_q->cfg.server_node->server_chid;

    return URPC_SUCCESS;
}

static inline bool queue_bind_info_validate(queue_bind_info_t *l_info, queue_bind_info_t *r_info)
{
    return (l_info->l_qid == r_info->r_qid) && (l_info->r_qid == r_info->l_qid);
}

static int client_recv_pair_info(urpc_async_task_ctx_t *task, enum urpc_ctl_opcode opcode)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    urpc_client_connect_entry_t *entry = (urpc_client_connect_entry_t *)task->transport_handle;
    if (task->is_initialized == URPC_FALSE) {
        task->ctl_opcode = opcode;
        task->is_recv_completed = URPC_FALSE;
        task->prepare_input = bind_info_recv_input_set;
        task->is_initialized = URPC_TRUE;
    }
 
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = task_engine_recv_check(task, ctl_hdl);
    if (ret == URPC_RUNNING) {
        return URPC_RUNNING;
    }
    // after recv complete, is_recv_completed reset
    task->is_initialized = URPC_FALSE;
    task->is_recv_completed = URPC_FALSE;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (ret == URPC_FAIL || head->data_size != sizeof(queue_bind_info_t) ||
        queue_bind_info_validate(&ctx->l_bind_info, ctx->r_bind_info) != URPC_TRUE) {
        URPC_LIB_LOG_ERR("client recv advise info failed, taskid: %d, ret: %d, recv size: %u, expect size: %zd,\n",
            task->key.task_id, ret, head->data_size, sizeof(queue_bind_info_t));
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int client_recv_bind_info(urpc_async_task_ctx_t *task)
{
    return client_recv_pair_info(task, URPC_CTL_QUEUE_INFO_BIND);
}

static int client_recv_unbind_info(urpc_async_task_ctx_t *task)
{
    return client_recv_pair_info(task, URPC_CTL_QUEUE_INFO_UNBIND);
}

int client_queue_bind(urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)ctx->l_q;
    queue_remote_t *remote_q = (queue_remote_t *)(uintptr_t)ctx->r_q;
    if (ctx->l_q->ops->bind_queue(ctx->l_q, ctx->r_q) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("bind queue establish connection failed, "
            "local id %u, remote id %u\n", local_q->qid, remote_q->qid);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int client_unbind(urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    urpc_channel_info_t *channel = channel_get(task->channel_id);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel failed, channel id: %u, task id: %d\n", task->channel_id, task->key.task_id);
        return URPC_FAIL;
    }
    if (!check_queue_in_channel(channel, (uint64_t)(uintptr_t)ctx->l_q) ||
        !check_queue_in_channel(channel, (uint64_t)(uintptr_t)ctx->r_q)) {
        return URPC_FAIL;
    }
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)ctx->l_q;
    if (local_q->queue.ops->unbind_queue(&local_q->queue) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("unbind queue failed, local id %u\n", local_q->qid);
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int server_queue_pair_handshaker_init(void *buffer, urpc_ctl_head_t *head, urpc_async_task_ctx_t *task)
{
    if (head->data_size != sizeof(queue_bind_info_t)) {
        URPC_LIB_LOG_ERR("server recv buffer size is invalid, taskid: %d, recv size: %u, expect size: %zu\n",
            head->task_id, head->data_size, sizeof(queue_bind_info_t));
        return URPC_FAIL;
    }
    task->workflow_type = WORKFLOW_TYPE_HANDLE_PAIR_QUEUE_REQ;
    return URPC_SUCCESS;
}

static int server_queue_unpair_handshaker_init(void *buffer, urpc_ctl_head_t *head, urpc_async_task_ctx_t *task)
{
    if (head->data_size != sizeof(queue_bind_info_t)) {
        URPC_LIB_LOG_ERR("server recv buffer size is invalid, taskid: %d, recv size: %u, expect size: %zu\n",
            head->task_id, head->data_size, sizeof(queue_bind_info_t));
        return URPC_FAIL;
    }
    task->workflow_type = WORKFLOW_TYPE_HANDLE_UNPAIR_QUEUE_REQ;
    return URPC_SUCCESS;
}

static queue_local_t *find_local_queue(queue_bind_info_t *r_bind_info)
{
    queue_local_t *temp_local_q;
    queue_transport_ctx_t *queue_ctx = get_queue_transport_ctx();
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(temp_local_q, node, &queue_ctx->queue_list) {
        if (temp_local_q->qid == r_bind_info->r_qid) {
            (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
            return temp_local_q;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
    return NULL;
}

int server_queue_bind(urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    queue_bind_info_t *r_bind_info = ctx->r_bind_info;
    
    queue_local_t *local_q = find_local_queue(r_bind_info);
    if (local_q == NULL) {
        URPC_LIB_LOG_ERR("process advise find local queue failed, qid %u\n", r_bind_info->r_qid);
        return URPC_FAIL;
    }

    queue_remote_t *remote_q = NULL;
    urpc_server_channel_info_t *server_channel =
        server_channel_get_with_rw_lock(server_channel_id_map_lookup(r_bind_info->mapped_server_chid), false);
    if (server_channel == NULL) {
        URPC_LIB_LOG_ERR(
            "process bind find server channel failed, server chid %u\n", r_bind_info->mapped_server_chid);
        return URPC_FAIL;
    }
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node) {
        queue_remote_t *tmp_queue = (queue_remote_t *)(uintptr_t)cur_node->urpc_qh;
        if (tmp_queue->qid == r_bind_info->l_qid) {
            remote_q = tmp_queue;
        }
    }
    if (remote_q == NULL) {
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);
        URPC_LIB_LOG_ERR("process bind find remote queue failed, qid %u\n", remote_q->qid);
        return URPC_FAIL;
    }

    if (local_q->queue.ops->bind_queue(&local_q->queue, &remote_q->queue) != URPC_SUCCESS) {
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);
        URPC_LIB_LOG_ERR("process bind establish connection failed, "
            "local id %u, remote id %u\n", local_q->qid, remote_q->qid);
        return URPC_FAIL;
    }

    // assignment must be done after successful bind, otherwise rollback will exception.
    ctx->l_q = &local_q->queue;
    ctx->r_q = &remote_q->queue;

    queue_bind_info_t *l_bind_info = &ctx->l_bind_info;
    l_bind_info->l_qid = local_q->qid;
    l_bind_info->r_qid = remote_q->qid;
    remote_q->bind_local_qid = local_q->qid;
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);

    return URPC_SUCCESS;
}

static int server_queue_unbind(urpc_async_task_ctx_t *task)
{
    queue_pair_ctx_t *ctx = CONTAINER_OF_FIELD(task, queue_pair_ctx_t, base_task);
    queue_bind_info_t *r_bind_info = ctx->r_bind_info;
    
    queue_local_t *local_q = find_local_queue(r_bind_info);
    if (local_q == NULL) {
        URPC_LIB_LOG_ERR("process advise find local queue failed, qid %u\n", r_bind_info->r_qid);
        return URPC_FAIL;
    }

    if (local_q->queue.ops->unbind_queue(&local_q->queue) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("process unbind failed, local id %u\n", local_q->qid);
        return URPC_FAIL;
    }
    queue_bind_info_t *l_bind_info = &ctx->l_bind_info;
    l_bind_info->l_qid = local_q->qid;
    l_bind_info->r_qid = r_bind_info->l_qid;

    return URPC_SUCCESS;
}

static void bind_ctx_free(void *task)
{
    queue_pair_ctx_t *ctx = (queue_pair_ctx_t *)task;
    urpc_dbuf_free(ctx->r_bind_info);
    ctx->r_bind_info = NULL;
    urpc_dbuf_free(ctx);
}

static int server_pair_final(urpc_async_task_ctx_t *task)
{
    return URPC_SUCCESS;
}
