/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize transport function
 */

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cp.h"
#include "channel.h"
#include "cp_vers_compat.h"
#include "urpc_hash.h"
#include "urpc_manage.h"
#include "urpc_lib_log.h"
#include "urpc_socket.h"
#include "task_manager.h"
#include "keepalive.h"

#include "transport.h"

#define TRANSPORT_MAX_CONNECTIONS 8192
#define TRANSPORT_RETRY_TIMES 1
#define TRANSPORT_EVENT_ERR_TIMES 3

static urpc_client_connect_table_t g_urpc_client_connect_hamp = {0};
static urpc_server_accept_manager_t g_urpc_server_accept_manager;

typedef struct server_channel_resource_table {
    struct urpc_hmap hmap;
} server_channel_resource_table_t;

static server_channel_resource_table_t g_urpc_server_resource_hamp;

static void client_on_ssl_handshake(uint32_t events, urpc_epoll_event_t *lev);
static void server_on_ssl_handshake(uint32_t events, urpc_epoll_event_t *lev);
static int server_do_ssl_handshake(urpc_server_accept_entry_t *handle);
static int client_do_ssl_handshake(urpc_client_connect_entry_t *handle);
static void server_on_io_event_process(uint32_t events, urpc_epoll_event_t *lev);
static void client_on_io_event_process(uint32_t events, urpc_epoll_event_t *lev);
static void heartbeat_loss(urpc_server_accept_entry_t *entry);
static int connection_create(urpc_host_type_t host_type, socket_addr_t *tcp_addr, urpc_host_info_t *local);
static void connect_msg_free(urpc_connect_msg_t *msg);
static urpc_connect_msg_t *connect_msg_create(urpc_connect_msg_input_t *input);

static void event_error_print(int fd, uint32_t events)
{
    int error = 0;
    socklen_t len = (socklen_t)sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &len) == 0) {
        URPC_LIB_LOG_ERR("event error, fd: %d, err: %s, events: %u\n", fd, strerror(error), events);
    } else {
        URPC_LIB_LOG_ERR("getsockopt failed, fd: %d, err: %s, events: %u\n", fd, strerror(error), events);
    }
}

static void server_reconnection_update(urpc_server_accept_entry_t *server)
{
    uint32_t hash = urpc_hash_bytes(&server->client_key, sizeof(urpc_instance_key_t), 0);
    delayed_release_resources_ctx_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash, &g_urpc_server_resource_hamp.hmap) {
        if (memcmp(&server->client_key, &entry->base_task.key.identity, sizeof(urpc_instance_key_t)) == 0) {
            // linked list node transfer
            urpc_server_channel_info_t *cur, *next;
            URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list) {
                urpc_list_remove(&cur->node);
                urpc_list_push_back(&server->server_channel_list, &cur->node);
            }
            entry->base_task.result = URPC_FAIL;
            task_engine_task_process(false, NULL, NULL, &entry->base_task);
            return;
        }
    }
}

static urpc_client_connect_entry_t *client_connect_entry_get(urpc_host_info_t *server)
{
    urpc_host_info_inner_t server_inner = {0};
    urpc_server_info_convert(server, &server_inner);
    uint32_t hash = urpc_hash_bytes(&server_inner, sizeof(urpc_host_info_inner_t), 0);

    urpc_client_connect_entry_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash, &g_urpc_client_connect_hamp.hmap) {
        if (memcmp(&server_inner, &entry->server_inner, sizeof(urpc_host_info_inner_t)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void client_connect_hmap_insert(struct urpc_hmap_node *node, uint32_t hash)
{
    urpc_hmap_insert(&g_urpc_client_connect_hamp.hmap, node, hash);
}

static void client_connect_hmap_remove(urpc_client_connect_entry_t *entry)
{
    urpc_hmap_remove(&g_urpc_client_connect_hamp.hmap, &entry->node);

    urpc_channel_info_t *cur = NULL;
    urpc_channel_info_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cur, next, tcp_node, &entry->channel_list) {
        urpc_list_remove(&cur->tcp_node);
    }
    connect_msg_free(entry->msg);
    entry->msg = NULL;
    urpc_dbuf_free(entry);
}

void server_accept_manager_insert(urpc_server_accept_entry_t *entry)
{
    urpc_list_push_back(&g_urpc_server_accept_manager.list, &entry->node);
}

void server_accept_manager_remove(urpc_server_accept_entry_t *entry)
{
    urpc_list_remove(&entry->node);
    urpc_dbuf_free(entry);
}

void transport_client_task_register(urpc_async_task_ctx_t *task, urpc_client_connect_entry_t *entry)
{
    task->transport_handle = (void *)entry;
    // there is no multithreaded operation on the task's reference count.
    urpc_list_push_back(&entry->list, &task->flow_node);
    task->ref_cnt++;
    task->list_type = TASK_LIST_TYPE_RUNNING;
    entry->ref_cnt++;
}

void transport_server_task_register(urpc_async_task_ctx_t *task, urpc_server_accept_entry_t *entry)
{
    // there is no multithreaded operation on the task's reference count.
    urpc_list_push_back(&entry->list, &task->flow_node);
    task->ref_cnt++;
    task->list_type = TASK_LIST_TYPE_RUNNING;
    entry->ref_cnt++;
}

void transport_client_task_unregister(urpc_async_task_ctx_t *task, urpc_client_connect_entry_t *entry)
{
    // there is no multithreaded operation on the task's reference count.
    if (task->list_type == TASK_LIST_TYPE_RUNNING && entry != NULL) {
        if (entry->ref_cnt > 0) {
            entry->ref_cnt--;
        }
    }
    if (urpc_list_is_in_list(&task->flow_node)) {
        urpc_list_remove(&task->flow_node);
        if (task->ref_cnt > 0) {
            task->ref_cnt--;
        }
        task->list_type = TASK_LIST_TYPE_UNKNOWN;
    }
    return;
}

void transport_server_task_unregister(urpc_async_task_ctx_t *task, urpc_server_accept_entry_t *entry)
{
    if (task->list_type == TASK_LIST_TYPE_RUNNING && entry != NULL) {
        if (entry->ref_cnt > 0) {
            entry->ref_cnt--;
        }
    }
    if (urpc_list_is_in_list(&task->flow_node)) {
        urpc_list_remove(&task->flow_node);
        if (task->ref_cnt > 0) {
            task->ref_cnt--;
        }
        task->list_type = TASK_LIST_TYPE_UNKNOWN;
    }
}

static int transport_event_add(transport_handle_t *handle, urpc_epoll_event_func_t func, uint32_t events, void *args)
{
    int epoll_fd = urpc_manage_get_epoll_fd(URPC_MANAGE_JOB_TYPE_LISTEN);
    if (epoll_fd < 0) {
        URPC_LIB_LOG_ERR("get epoll fd failed\n");
        handle->state = TCP_ERROR;
        return URPC_FAIL;
    }

    handle->event.fd = handle->fd;
    handle->event.args = args;
    handle->event.func = func;
    handle->event.events = events;
    handle->event.is_handshaker_ctx = false;
    if (handle->is_epoll_registered != URPC_TRUE) {
        handle->is_epoll_registered = URPC_TRUE;
        if (urpc_epoll_event_add(epoll_fd, &handle->event) != URPC_SUCCESS) {
            handle->event.fd = URPC_INVALID_FD;
            handle->event.func = NULL;
            handle->is_epoll_registered = URPC_FALSE;
            handle->state = TCP_ERROR;
            return URPC_FAIL;
        }
    } else {
        if (urpc_epoll_event_modify(epoll_fd, &handle->event) != URPC_SUCCESS) {
            handle->event.fd = URPC_INVALID_FD;
            handle->event.func = NULL;
            handle->state = TCP_ERROR;
            return URPC_FAIL;
        }
    }
    return URPC_SUCCESS;
}

static void transport_event_remove(transport_handle_t *handle)
{
    if (handle->is_epoll_registered) {
        urpc_epoll_event_delete(urpc_manage_get_epoll_fd(URPC_MANAGE_JOB_TYPE_LISTEN), &handle->event);
        handle->is_epoll_registered = false;
    }
}

static void connection_close(transport_handle_t *handle)
{
    transport_event_remove(handle);
    if (handle->ssl != NULL) {
        crypto_ssl_uninit(handle->ssl);
        handle->ssl = NULL;
    }
    if (handle->fd != URPC_INVALID_FD) {
        close(handle->fd);
        handle->state = TCP_ERROR;
        handle->fd = URPC_INVALID_FD;
    }
}

static void transport_client_task_clear(urpc_client_connect_entry_t *entry)
{
    urpc_async_task_ctx_t *cur = NULL;
    urpc_async_task_ctx_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cur, next, flow_node, &entry->list) {
        cur->result = URPC_FAIL;
        if (cur->task_state != TASK_IMPORTING) {
            cur->task_state = TASK_STEP_COMPLETED;
            task_engine_task_process(false, NULL, NULL, cur);
            // subsequent use of task is not allowed, maybe task_engine_task_process already free task
        } else {
            transport_client_task_unregister(cur, entry);
            cur->transport_handle = NULL;
        }
    }
}

static void transport_server_task_clear(urpc_server_accept_entry_t *entry)
{
    urpc_async_task_ctx_t *cur = NULL;
    urpc_async_task_ctx_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cur, next, flow_node, &entry->list) {
        cur->result = URPC_FAIL;
        if (cur->task_state != TASK_IMPORTING) {
            cur->task_state = TASK_STEP_COMPLETED;
            task_engine_task_process(false, NULL, NULL, cur);
            // subsequent use of task is not allowed, maybe task_engine_task_process already free task
        } else {
            transport_server_task_unregister(cur, entry);
            cur->transport_handle = NULL;
        }
    }
}

static void transport_shutdown_and_reconnect(urpc_client_connect_entry_t *entry)
{
    connection_close(&entry->conn_handle);
    transport_client_task_clear(entry);
    URPC_LIB_LOG_INFO("transport shutdown and reconnect\n");
    // prevent infinite loops by setting a retry limit.
    if (entry->retry_times >= TRANSPORT_RETRY_TIMES || entry->error_cnt >= TRANSPORT_EVENT_ERR_TIMES) {
        goto REMOVE_ENTRY;
    }
    entry->retry_times++;
    urpc_host_info_t *local = entry->is_bind_local ? &entry->local : NULL;
    int fd = connection_create(entry->server_inner.host_type, &entry->tcp_addr, local);
    if (fd == URPC_INVALID_FD) {
        goto REMOVE_ENTRY;
    }
    memset(&entry->conn_handle, 0, sizeof(transport_handle_t));
    entry->conn_handle.fd = fd;
    entry->conn_handle.state = TCP_CONNECTING;
    if (transport_event_add(&entry->conn_handle, client_on_ssl_handshake, EPOLLOUT, (void *)entry) !=
        URPC_SUCCESS) {
        close(fd);
        entry->conn_handle.fd = URPC_INVALID_FD;
        entry->conn_handle.state = TCP_ERROR;
        URPC_LIB_LOG_ERR("during the reconnection process, add event failed\n");
        goto REMOVE_ENTRY;
    }
    URPC_LIB_LOG_INFO("connection reconnecting, fd: %d\n", fd);
    return;

REMOVE_ENTRY:
    if (urpc_list_is_empty(&entry->channel_list)) {
        client_connect_hmap_remove(entry);
    }
}

static void transport_connection_shutdown(urpc_client_connect_entry_t *entry, bool normal)
{
    URPC_LIB_LOG_DEBUG("go to %s shutdown connection, fd: %d\n", normal ? "normal" : "forced", entry->conn_handle.fd);
    connection_close(&entry->conn_handle);
    if (normal) {
        // detaching the server, it should shut down normally
        if (entry->ref_cnt == 0 && urpc_list_is_empty(&entry->list)) {
            URPC_LIB_LOG_INFO("gracefully close a connection\n");
            client_connect_hmap_remove(entry);
        } else {
            URPC_LIB_LOG_ERR("cannot remove the connection, ref_cnt: %u\n", entry->ref_cnt);
        }
        return;
    }

    transport_client_task_clear(entry);
    URPC_LIB_LOG_INFO("connection force closed\n");
    client_connect_hmap_remove(entry);
    return;
}

static void transport_acception_shutdown(urpc_server_accept_entry_t *entry, bool normal, bool is_delay_release)
{
    URPC_LIB_LOG_DEBUG("go to %s shutdown acception:%d\n", normal ? "normal" : "forced", entry->conn_handle.fd);
    if (is_delay_release) {
        heartbeat_loss(entry);
    } else {
        urpc_server_channel_info_t *cur, *next;
        URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list) {
            (void)server_channel_free(cur->id, false);
        }
    }
    connection_close(&entry->conn_handle);
    if (normal) {
        // detaching the server, it should shut down normally
        if (entry->ref_cnt == 0 && urpc_list_is_empty(&entry->list)) {
            URPC_LIB_LOG_INFO("gracefully close a acception\n");
            server_accept_manager_remove(entry);
        } else {
            URPC_LIB_LOG_DEBUG("server cannot remove the acception, ref_cnt: %u\n", entry->ref_cnt);
        }
        return;
    }
    transport_server_task_clear(entry);
    URPC_LIB_LOG_INFO("acception force closed\n");
    server_accept_manager_remove(entry);
}

static int transport_recv_socket_async(transport_handle_t *ctl_hdl, void *data, size_t data_size)
{
    char *cur = data + ctl_hdl->recv_record.offset;
    ssize_t total = (ssize_t)data_size - (ssize_t)ctl_hdl->recv_record.offset;
    while (total > 0) {
        ssize_t done = urpc_socket_recv_async(ctl_hdl->fd, cur, total);
        if (done == 0) {
            ctl_hdl->state = TCP_CLOSED;
            URPC_LIB_LOG_DEBUG("the peer has closed the connection\n");
            return URPC_FAIL;
        }
        if (done < 0) {
            if (errno == EINTR) {
                // EINTR means retry read
                URPC_LIB_LOG_DEBUG("receiving data, try again read");
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket kernel buffer has no data
                ctl_hdl->recv_record.offset = data_size - (size_t)total;
                URPC_LIB_LOG_DEBUG("receiving data, total size: %zu, recved size: %zu, err: %s\n",
                    data_size, ctl_hdl->recv_record.offset, strerror(errno));
                return URPC_RUNNING;
            }
            ctl_hdl->state = TCP_ERROR;
            URPC_LIB_LOG_ERR("recv data failed, err: %s\n", strerror(errno));
            return URPC_FAIL;
        }
        URPC_LIB_LOG_DEBUG("recv data success, size: %zd\n", done);
        total -= done;
        cur += done;
    }

    ctl_hdl->recv_record.offset = data_size;
    return URPC_SUCCESS;
}

static int transport_recv_ssl_async(transport_handle_t *ctl_hdl, void *data, size_t data_size)
{
    char *cur = data + ctl_hdl->recv_record.offset;
    ssize_t total = (ssize_t)data_size - (ssize_t)ctl_hdl->recv_record.offset;

    while (total > 0) {
        ssize_t done = crypto_ssl_recv_async(ctl_hdl->ssl, cur, total);
        if (done > 0) {
            URPC_LIB_LOG_DEBUG("ssl read data success, size: %zd\n", done);
            total -= done;
            cur += done;
            continue;
        }

        if (done == 0) {
            ctl_hdl->state = TCP_CLOSED;
            URPC_LIB_LOG_DEBUG("the peer has closed the connection\n");
            return URPC_FAIL;
        }

        int err = SSL_get_error(ctl_hdl->ssl, done);
        if (err == SSL_ERROR_WANT_READ) {
            ctl_hdl->recv_record.offset = data_size - (size_t)total;
            URPC_LIB_LOG_DEBUG("ssl reading data, total size: %zu, readed size: %zu, err: %s\n",
                data_size, ctl_hdl->recv_record.offset, strerror(errno));
            return URPC_RUNNING;
        }
        ctl_hdl->state = TCP_ERROR;
        URPC_LIB_LOG_ERR("ssl read data failed, err: %s, errcode: %d\n", strerror(errno), err);
        return URPC_FAIL;
    }

    ctl_hdl->recv_record.offset = data_size;
    return URPC_SUCCESS;
}

static int transport_send_socket_async(
    transport_handle_t *ctl_hdl, urpc_epoll_event_func_t func, void *data, size_t data_size)
{
    char *cur = data + ctl_hdl->send_record.offset;
    ssize_t total = (ssize_t)data_size - (ssize_t)ctl_hdl->send_record.offset;

    while (total > 0) {
        ssize_t done = urpc_socket_send_async(ctl_hdl->fd, cur, total);
        if (done == 0) {
            ctl_hdl->state = TCP_ERROR;
            URPC_LIB_LOG_ERR("the peer has closed the connection\n");
            return URPC_FAIL;
        }
        if (done < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ctl_hdl->is_write_buffer_full = URPC_TRUE;
                ctl_hdl->send_record.offset = data_size - (size_t)total;
                URPC_LIB_LOG_DEBUG("sending data, total size: %zu, sended size: %zu, err: %s\n",
                    data_size, ctl_hdl->send_record.offset, strerror(errno));
                if (transport_event_add(ctl_hdl, func, EPOLLOUT | EPOLLIN, (void *)ctl_hdl->event.args) ==
                    URPC_SUCCESS) {
                    URPC_LIB_LOG_DEBUG("sending data, add event success\n");
                    return URPC_RUNNING;
                }
                URPC_LIB_LOG_DEBUG("sending data, add event failed\n");
                return URPC_FAIL;
            }
            ctl_hdl->state = TCP_ERROR;
            URPC_LIB_LOG_ERR("send data failed, err: %s\n", strerror(errno));
            return URPC_FAIL;
        }
        URPC_LIB_LOG_DEBUG("send data success, size: %zd\n", done);
        total -= done;
        cur += done;
    }

    ctl_hdl->send_record.offset = data_size;
    return URPC_SUCCESS;
}

static int transport_send_ssl_async(
    transport_handle_t *ctl_hdl, urpc_epoll_event_func_t func, void *data, size_t data_size)
{
    char *cur = data + ctl_hdl->send_record.offset;
    ssize_t total = (ssize_t)data_size - (ssize_t)ctl_hdl->send_record.offset;

    while (total > 0) {
        ssize_t done = crypto_ssl_send_async(ctl_hdl->ssl, cur, total);
        if (done > 0) {
            URPC_LIB_LOG_DEBUG("ssl write data success, size: %zd\n", done);
            total -= done;
            cur += done;
            continue;
        }
        int err = SSL_get_error(ctl_hdl->ssl, done);
        if (err == SSL_ERROR_WANT_WRITE) {
            ctl_hdl->is_write_buffer_full = URPC_TRUE;
            ctl_hdl->send_record.offset = data_size - (size_t)total;
            URPC_LIB_LOG_DEBUG("ssl writing data, total size: %zu, sended size: %zu, err: %s\n",
                data_size, ctl_hdl->send_record.offset, strerror(errno));
            if (transport_event_add(ctl_hdl, func, EPOLLOUT | EPOLLIN, (void *)ctl_hdl->event.args) == URPC_SUCCESS) {
                URPC_LIB_LOG_DEBUG("ssl writing data, add event success\n");
                return URPC_RUNNING;
            }
            return URPC_FAIL;
        }
        ctl_hdl->state = TCP_ERROR;
        URPC_LIB_LOG_ERR("ssl write data failed, err: %s, errcode: %d\n", strerror(errno), err);
        return URPC_FAIL;
    }

    ctl_hdl->send_record.offset = data_size;
    return URPC_SUCCESS;
}

static int server_handshake_completed(urpc_server_accept_entry_t *handle, bool support_ssl)
{
    if (support_ssl) {
        handle->conn_handle.send_async = transport_send_ssl_async;
        handle->conn_handle.recv_async = transport_recv_ssl_async;
    } else {
        handle->conn_handle.send_async = transport_send_socket_async;
        handle->conn_handle.recv_async = transport_recv_socket_async;
    }
   
    handle->conn_handle.state = TCP_CONNECTED;
    return transport_event_add(&handle->conn_handle, server_on_io_event_process, EPOLLIN, (void*)handle);
}

static urpc_connect_msg_t *connect_msg_create(urpc_connect_msg_input_t *input)
{
    size_t total_size =
        sizeof(urpc_connect_msg_t) + input->num * sizeof(urpc_chmsg_v1_t);
    return (urpc_connect_msg_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, total_size);
}

static void connect_msg_free(urpc_connect_msg_t *msg)
{
    urpc_connect_msg_buffer_release(msg);
    urpc_dbuf_free(msg);
}

static int connect_msg_prepare(urpc_client_connect_entry_t *entry)
{
    urpc_connect_msg_input_t input = {
        .chmsg_arr = NULL,
        .num = urpc_list_size(&entry->channel_list),
        .key = &entry->client_key,
    };

    if (!urpc_list_is_empty(&entry->channel_list)) {
        input.chmsg_arr =
            (urpc_chmsg_input_v2_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, input.num * sizeof(urpc_chmsg_input_v2_t));
        if (input.chmsg_arr == NULL) {
            URPC_LIB_LOG_ERR("create chmsg message failed\n");
            entry->conn_handle.state = TCP_ERROR;
            return URPC_FAIL;
        }
    }
    uint32_t i = 0;
    urpc_channel_info_t *cur = NULL;
    URPC_LIST_FOR_EACH(cur, tcp_node, &entry->channel_list) {
        // lock
        if (input.chmsg_arr == NULL || i >= input.num) {
            URPC_LIB_LOG_WARN(
                "the number of linked list nodes exceeds the array size , array size: %u, i: %u\n", input.num, i);
            break;
        }
        (void)pthread_rwlock_rdlock(&cur->rw_lock);
        // local queue num does not exceed MAX_QUEUE_SIZE
        input.chmsg_arr[i].q_num = cur->l_qnum;
        input.chmsg_arr[i].client_channel = cur;
        channel_get_local_queues(cur, cur->l_qnum, input.chmsg_arr[i].qh);
        i++;
        (void)pthread_rwlock_unlock(&cur->rw_lock);
    }
    // release the old connect message
    connect_msg_free(entry->msg);
    entry->msg = connect_msg_create(&input);
    if (entry->msg == NULL) {
        urpc_dbuf_free(input.chmsg_arr);
        URPC_LIB_LOG_ERR("create connect message failed\n");
        entry->conn_handle.state = TCP_ERROR;
        return URPC_FAIL;
    }
    // send eid and pid to server
    if (urpc_connect_msg_serialize(&input, entry->msg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("serialize connect message failed\n");
        entry->conn_handle.state = TCP_ERROR;
        urpc_dbuf_free(input.chmsg_arr);
        connect_msg_free(entry->msg);
        entry->msg = NULL;
        return URPC_FAIL;
    }
    urpc_dbuf_free(input.chmsg_arr);
    return URPC_SUCCESS;
}

static int client_handshake_completed(urpc_client_connect_entry_t *entry, bool support_ssl)
{
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    if (support_ssl) {
        ctl_hdl->send_async = transport_send_ssl_async;
        ctl_hdl->recv_async = transport_recv_ssl_async;
    } else {
        ctl_hdl->send_async = transport_send_socket_async;
        ctl_hdl->recv_async = transport_recv_socket_async;
    }

    if (connect_msg_prepare(entry) != URPC_SUCCESS) {
        return URPC_FAIL;
    }
    // prepare head
    ctl_hdl->send_record.offset = 0;
    ctl_hdl->send_record.head.data_size = entry->msg->data.len;
    ctl_hdl->send_record.head.task_id = URPC_INVALID_TASK_ID;
    ctl_hdl->send_record.head.is_start = URPC_TRUE;
    ctl_hdl->send_record.is_prepared_head = URPC_TRUE;
    ctl_hdl->event.func = client_on_io_event_process;
    // the first send, connect msg size is definitely smaller than the write buffer size, will not return running
    int ret = transport_send_msg(ctl_hdl, entry->msg->data.buffer, entry->msg->data.len);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("send connection info to server failed, ret: %d\n", ret);
        ctl_hdl->state = TCP_ERROR;
        connect_msg_free(entry->msg);
        entry->msg = NULL;
        return URPC_FAIL;
    }
    if (ret == URPC_RUNNING) {
        URPC_LIB_LOG_INFO("sending connection info to server, ret: %d\n", ret);
        return URPC_SUCCESS;
    }
    connect_msg_free(entry->msg);
    entry->msg = NULL;
    URPC_LIB_LOG_DEBUG("client send connection info to serve success, fd: %d\n", ctl_hdl->fd);
    entry->retry_times = 0;
    ctl_hdl->state = TCP_CONNECTED;
    return transport_event_add(ctl_hdl, client_on_io_event_process, EPOLLIN, (void*)entry);
}

static void client_do_send(urpc_client_connect_entry_t *entry)
{
    if (entry->msg != NULL) {
        // the reconnection information was not fully sent, continue send
        int ret = transport_send_msg(&entry->conn_handle, entry->msg->data.buffer, entry->msg->data.len);
        if (ret == URPC_FAIL) {
            URPC_LIB_LOG_ERR("send connection info to server failed, ret: %d\n", ret);
            entry->conn_handle.state = TCP_ERROR;
            connect_msg_free(entry->msg);
            entry->msg = NULL;
            return;
        }
        if (ret == URPC_RUNNING) {
            URPC_LIB_LOG_DEBUG("sending connection info to server, ret: %d\n", ret);
            return;
        }
        connect_msg_free(entry->msg);
        entry->msg = NULL;
        URPC_LIB_LOG_DEBUG("client send connection info to serve success, fd: %d\n", entry->conn_handle.fd);
        entry->conn_handle.state = TCP_CONNECTED;
        entry->retry_times = 0;
    }
    // continue process last send
    int task_id = entry->conn_handle.send_record.head.task_id;
    if (task_id != URPC_INVALID_TASK_ID) {
        // there is no last unsent message in the sending record
        urpc_async_task_ctx_t *task = task_manager_client_task_get(task_id);
        if (task == NULL) {
            URPC_LIB_LOG_ERR("can not find task\n");
            // System error，should be set transport error
            return;
        }
        if (task->task_state == TASK_SENDING) {
            (void)task_engine_task_process(false, NULL, NULL, task);
        }
    }
    // clear send record
    entry->conn_handle.send_record.task_id = URPC_INVALID_TASK_ID;
    entry->conn_handle.send_record.offset = 0;
    entry->conn_handle.send_record.phase = TRANSMISSION_HEAD;
    entry->conn_handle.send_record.data = NULL;

    urpc_async_task_ctx_t *cur = NULL;
    urpc_async_task_ctx_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cur, next, flow_node, &entry->list)
    {
        if (cur->task_state == TASK_PENDING_SEND) {
            (void)task_engine_task_process(false, NULL, NULL, cur);
        }
    }
    return;
}

static bool recv_one_message(transport_handle_t *ctl_hdl, bool *completed_msg)
{
    int ret;
    if (ctl_hdl->recv_record.phase == TRANSMISSION_HEAD) {
        ret = ctl_hdl->recv_async(ctl_hdl, &ctl_hdl->recv_record.head, sizeof(urpc_ctl_head_t));
        if (ret != URPC_SUCCESS) {
            return true;
        }
        if (ctl_hdl->recv_record.head.data_size == 0) {
            *completed_msg = true;
            ctl_hdl->recv_record.offset = 0;
            ctl_hdl->recv_record.data = NULL;
            return false;
        }
        ctl_hdl->recv_record.phase = TRANSMISSION_DATA;
        ctl_hdl->recv_record.offset = 0;
        if (ctl_hdl->recv_record.head.data_size > URPC_CTL_BUF_MAX_LEN) {
            ctl_hdl->state = TCP_ERROR;
            return true;
        }
        void *data = (void *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CP, ctl_hdl->recv_record.head.data_size);
        if (data == NULL) {
            URPC_LIB_LOG_ERR("malloc data memory failed\n");
            ctl_hdl->recv_record.data = NULL;
            // shoud discard this msg
            ctl_hdl->state = TCP_ERROR;
            return true;
        }
        ctl_hdl->recv_record.data = data;
    }
    ret = ctl_hdl->recv_async(ctl_hdl, ctl_hdl->recv_record.data, ctl_hdl->recv_record.head.data_size);
    if (ret != URPC_SUCCESS) {
        return true;
    }
    *completed_msg = true;
    ctl_hdl->recv_record.phase = TRANSMISSION_HEAD;
    ctl_hdl->recv_record.offset = 0;
    return false;
}

static void server_do_send(urpc_server_accept_entry_t *entry)
{
    // continue process last send
    task_instance_key_t key = {0};
    key.task_id = entry->conn_handle.send_record.head.task_id;
    key.identity = entry->client_key;
    urpc_async_task_ctx_t *task = task_manager_server_task_get(&key);
    if (task == NULL) {
        URPC_LIB_LOG_ERR("can not find task\n");
        // System error，should be set transport error
        return;
    }
    (void)task_engine_task_process(false, NULL, NULL, task);

    urpc_async_task_ctx_t *cur = NULL;
    urpc_async_task_ctx_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cur, next, flow_node, &entry->list)
    {
        if (cur->task_state == TASK_PENDING_SEND || cur->task_state == TASK_SENDING) {
            (void)task_engine_task_process(false, NULL, NULL, cur);
        }
    }

    return;
}

void server_channel_remote_queue_update(urpc_server_channel_info_t *server_channel, urpc_chmsg_v1_t *chinfo)
{
    // one channel to one server channel
    queue_node_t *cur_node;
    queue_node_t *next_node;
    // The r_queue_nodes_head has corresponding identical local queue information.
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &server_channel->r_queue_nodes_head, node, next_node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        bool is_find_queue = false;
        for (uint32_t j = 0; j < chinfo->qinfo_arr.arr_num; j++) {
            queue_info_t *queue_info = chinfo->qinfo_arr.qinfos[j];
            if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
                is_find_queue = true;
                break;
            }
        }
        if (!is_find_queue) {
            server_channel_remove_remote_queue(server_channel, cur_node);
        }
    }
}

static void one_by_one_server_resource_update(
    urpc_server_channel_info_t *server_channel, urpc_connect_msg_t *connection_msg)
{
    for (uint32_t i = 0; i < connection_msg->chmsg_arr.arr_num; i++) {
        if (server_channel->mapped_id == connection_msg->chmsg_arr.chmsgs[i].chinfo->server_chid) {
            urpc_chmsg_v1_t *chinfo = &connection_msg->chmsg_arr.chmsgs[i];
            server_channel_remote_queue_update(server_channel, chinfo);
            return;
        }
    }
    (void)server_channel_free(server_channel->id, true);
}

static void more_by_one_server_resource_update(
    urpc_server_channel_info_t *server_channel, urpc_connect_msg_t *connection_msg)
{
    queue_node_t *cur_node;
    queue_node_t *next_node;
    uint32_t ref = 0;
    bool is_find_channel = false;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &server_channel->r_queue_nodes_head, node, next_node) {
        ref = 0;
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        for (uint32_t i = 0; i < connection_msg->chmsg_arr.arr_num; i++) {
            urpc_chmsg_v1_t *chinfo = &connection_msg->chmsg_arr.chmsgs[i];
            for (uint32_t j = 0; j < chinfo->qinfo_arr.arr_num; j++) {
                queue_info_t *queue_info = chinfo->qinfo_arr.qinfos[j];
                if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
                    ref++;
                    break;
                }
            }
        }

        if (ref < queue->ref_cnt) {
            // when a network failure occurs, client remove the local queue or destroy channel, so ref < queue->ref_cnt
            queue->ref_cnt = ref;
        }
        if (queue->ref_cnt == 0) {
            server_channel_remove_remote_queue(server_channel, cur_node);
        }
        // ref > q->ref_cnt not exist, If it exists, do nothing
    }

    // update server channel client channel id
    for (uint32_t i = 0; i < server_channel->client_chid_num; i++) {
        is_find_channel = false;
        for (uint32_t j = 0; j < connection_msg->chmsg_arr.arr_num; j++) {
            if (server_channel->client_chid[i] == connection_msg->chmsg_arr.chmsgs[j].chinfo->chid) {
                is_find_channel = true;
                break;
            }
        }
        if (!is_find_channel) {
            server_channel_rm_client_chid(server_channel, server_channel->client_chid[i]);
        }
    }

    if (server_channel->client_chid_num == 0) {
        (void)server_channel_free(server_channel->id, true);
    }
}

static int server_process_connection_msg(urpc_ctl_head_t *head, void *buffer, urpc_server_accept_entry_t *entry)
{
    int channel_num = urpc_connect_msg_extract_channel_count(buffer, head->data_size);
    if (channel_num < 0) {
        urpc_dbuf_free(buffer);
        URPC_LIB_LOG_ERR("connection message get channel num failed\n");
        return URPC_FAIL;
    }
    size_t total_size = sizeof(urpc_connect_msg_t) + channel_num * sizeof(urpc_chmsg_v1_t);
    urpc_connect_msg_t *connection_msg = (urpc_connect_msg_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, total_size);
    if (connection_msg == NULL) {
        urpc_dbuf_free(buffer);
        URPC_LIB_LOG_ERR("create connection message failed\n");
        return URPC_FAIL;
    }
    connection_msg->data.buffer = buffer;
    connection_msg->data.len = head->data_size;
    if (urpc_connect_msg_deserialize(connection_msg) != URPC_SUCCESS) {
        connect_msg_free(connection_msg);
        URPC_LIB_LOG_ERR("deserialize connection message failed\n");
        return URPC_FAIL;
    }
    if (connection_msg->connect_info == NULL) {
        connect_msg_free(connection_msg);
        URPC_LIB_LOG_ERR("connect info is null\n");
        return URPC_FAIL;
    }
    entry->client_key = connection_msg->connect_info->key;
    server_reconnection_update(entry);
    urpc_server_channel_info_t *cur, *next;
    if (!is_feature_enable(URPC_FEATURE_MULTIPLEX)) {
        URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list) {
            one_by_one_server_resource_update(cur, connection_msg);
        }
    } else {
        URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list) {
            more_by_one_server_resource_update(cur, connection_msg);
        }
    }
    connect_msg_free(connection_msg);
    return URPC_SUCCESS;
}

static void server_process_msg(urpc_server_accept_entry_t *entry)
{
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    // the buffer release right is handed over to the task or connection msg.
    void *buffer = ctl_hdl->recv_record.data;
    ctl_hdl->recv_record.data = NULL;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    if (ctl_hdl->recv_record.head.task_id == URPC_INVALID_TASK_ID) {
        // this is connection msg
        if (server_process_connection_msg(head, buffer, entry) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("deserialize connection message failed\n");
            entry->conn_handle.state = TCP_ERROR;
            return;
        }
        return;
    }

    /* the key of the hash table needs to be reset to zero */
    task_instance_key_t key = {0};
    key.task_id = head->task_id;
    key.identity = entry->client_key;
    urpc_async_task_ctx_t *task = task_manager_server_task_get(&key);
    if (task == NULL && (head->ctl_opcode == URPC_CTL_TASK_CANCEL || head->is_start == URPC_FALSE)) {
        URPC_LIB_LOG_ERR("server task already finish, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                EID_ARGS(key.identity.eid), key.identity.pid, key.task_id);
        urpc_dbuf_free(buffer);
        return;
    }
    if (head->is_start == URPC_TRUE) {
        if (task != NULL) {
            // discard messages without processing
            URPC_LIB_LOG_ERR("server task already exists, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                EID_ARGS(key.identity.eid), key.identity.pid, key.task_id);
            urpc_dbuf_free(buffer);
            return;
        }
        task_manager_timeout_manager_lock();
        if (!task_manager_task_num_validate()) {
            task_manager_timeout_manager_unlock();
            URPC_LIB_LIMIT_LOG_ERR("the length exceeds the maximum value, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                EID_ARGS(key.identity.eid), key.identity.pid, key.task_id);
            urpc_dbuf_free(buffer);
            // the remote task ends upon timeout triggering.
            return;
        }
        task = task_engine_server_task_create(head, buffer, entry->user_ctx);
        if (task == NULL) {
            task_manager_timeout_manager_unlock();
            urpc_dbuf_free(buffer);
            URPC_LIB_LOG_ERR("server task create failed, eid: " EID_FMT ", pid: %u, taskid: %d\n",
                EID_ARGS(key.identity.eid), key.identity.pid, key.task_id);
            return;
        }
        task->transport_handle = (void *)entry;
        task->key = key;
        task_manager_timeout_manager_insert(task);
        task_manager_timeout_manager_unlock();
        task_manager_server_task_insert(task);
        transport_server_task_register(task, entry);
    }
    (void)task_engine_task_process(true, head, buffer, task);
}

static void client_process_msg(urpc_client_connect_entry_t *entry)
{
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    urpc_ctl_head_t *head = &ctl_hdl->recv_record.head;
    // the key of the hash table needs to be reset to zero

    void *buffer = ctl_hdl->recv_record.data;
    ctl_hdl->recv_record.data = NULL;

    urpc_async_task_ctx_t *task = task_manager_client_task_get(head->task_id);
    if (task == NULL) {
        URPC_LIB_LOG_ERR("client task not exists, taskid: %d\n", head->task_id);
        urpc_dbuf_free(buffer);
        return;
    }
    // the buffer of the data packet needs to be passed to the task.
    (void)task_engine_task_process(true, head, buffer, task);
}

static void server_on_new_messages(urpc_server_accept_entry_t *entry)
{
    bool read_eof = false;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    bool completed_msg = false;
    while (!read_eof) {
        read_eof = recv_one_message(ctl_hdl, &completed_msg);
        if (transport_should_stop(ctl_hdl->state)) {
            urpc_dbuf_free(ctl_hdl->recv_record.data);
            ctl_hdl->recv_record.data = NULL;
            return;
        }
        if (ctl_hdl->state == TCP_CONNECTED && completed_msg) {
            // The buffer of the data packet needs to be passed to the task.
            server_process_msg(entry);
            completed_msg = false;
        }
    }
}

static void client_on_new_messages(urpc_client_connect_entry_t *entry)
{
    bool read_eof = false;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    bool completed_msg = false;
    while (!read_eof) {
        read_eof = recv_one_message(ctl_hdl, &completed_msg);
        if (transport_should_stop(ctl_hdl->state)) {
            urpc_dbuf_free(ctl_hdl->recv_record.data);
            return;
        }
        if (ctl_hdl->state == TCP_CONNECTED && completed_msg) {
            // The buffer of the data packet needs to be passed to the task.
            client_process_msg(entry);
            completed_msg = false;
        }
    }
}

static int connection_create(urpc_host_type_t host_type, socket_addr_t *tcp_addr, urpc_host_info_t *local)
{
    int fd = socket(host_type == HOST_TYPE_IPV4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        URPC_LIB_LOG_ERR("create socket failed, err: %s\n", strerror(errno));
        return URPC_INVALID_FD;
    }

    // set non-blocking
    if (urpc_socket_set_non_block(fd) != 0) {
        URPC_LIB_LOG_ERR("set socket non block failed, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) != 0) {
        URPC_LIB_LOG_ERR("set socket no_delay failed, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(int)) != 0) {
        URPC_LIB_LOG_ERR("set socket reuse addr failed, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    if (urpc_socket_set_keepalive_timeout(fd, urpc_keepalive_check_time_get(), urpc_keepalive_cycle_time_get()) !=
        URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("set socket idle timeout failed, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    if ((local != NULL) && urpc_socket_bind_assigned_addr(local, fd) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("bind assigned local addr failed, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }
    int ret = connect(fd, (struct sockaddr *)(tcp_addr), sizeof(socket_addr_t));
    if (ret != 0 && errno != EINPROGRESS) {
        URPC_LIB_LOG_ERR("fail to connect to server, err: %s\n", strerror(errno));
        goto CLOSE_FD;
    }
    return fd;
CLOSE_FD:
    close(fd);
    return URPC_INVALID_FD;
}

urpc_client_connect_entry_t *transport_connection_establish(urpc_async_task_ctx_t *task)
{
    urpc_endpoints_t *endpoints = &task->endpoints;
    urpc_client_connect_entry_t *entry = client_connect_entry_get(&endpoints->server);
    if (entry != NULL) {
        if (transport_should_stop(entry->conn_handle.state)) {
            entry->retry_times = 0;
            entry->error_cnt = 0;
            transport_shutdown_and_reconnect(entry);
            // transport_shutdown_and_reconnect may be free entry
            entry = client_connect_entry_get(&endpoints->server);
        }
        return entry;
    }
    urpc_host_info_t *local = endpoints->bind_local ? &endpoints->local : NULL;
    int fd = connection_create(endpoints->server.host_type, &task->tcp_addr, local);
    if (fd == URPC_INVALID_FD) {
        URPC_LIB_LOG_ERR("fail to connect to server address, addr: %s\n",
            endpoints->server.host_type == HOST_TYPE_IPV4 ? endpoints->server.ipv4.ip_addr
                                                          : endpoints->server.ipv6.ip_addr);
        return NULL;
    }

    entry = (urpc_client_connect_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(urpc_client_connect_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("malloc urpc_client_connect_entry_t failed\n");
        goto CLOSE_FD;
    }
    entry->conn_handle.fd = fd;
    entry->conn_handle.state = TCP_CONNECTING;
    entry->client_key = task->key.identity;
    entry->is_bind_local = task->endpoints.bind_local;
    entry->local = task->endpoints.local;
    entry->tcp_addr = task->tcp_addr;
    urpc_list_init(&entry->channel_list);
    urpc_list_init(&entry->list);
    if (transport_event_add(&entry->conn_handle, client_on_ssl_handshake, EPOLLOUT, (void *)entry) != URPC_SUCCESS) {
        urpc_dbuf_free(entry);
        goto CLOSE_FD;
    }

    urpc_server_info_convert(&endpoints->server, &entry->server_inner);
    uint32_t hash = urpc_hash_bytes(&entry->server_inner, sizeof(urpc_host_info_inner_t), 0);
    client_connect_hmap_insert(&entry->node, hash);
    return entry;

CLOSE_FD:
    close(fd);
    return NULL;
}

urpc_server_accept_entry_t *transport_connection_accept(int listen_fd, void *user_ctx)
{
    socket_addr_t addr;
    socklen_t len = (socklen_t)sizeof(socket_addr_t);
    int fd = accept(listen_fd, (struct sockaddr *)(void *)&addr, &len);
    if (fd < 0) {
        URPC_LIB_LOG_ERR("server accept failed, err: %s\n", strerror(errno));
        return NULL;
    }
    // set the socket to non-blocking
    if (urpc_socket_set_non_block(fd) != 0) {
        URPC_LIB_LOG_ERR("set socket non block failed, err: %s\n", strerror(errno));
        goto EXIT;
    }

    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) != 0) {
        URPC_LIB_LOG_ERR("set socket no_delay failed, err: %s\n", strerror(errno));
        goto EXIT;
    }

    if (urpc_socket_set_keepalive_timeout(fd, urpc_keepalive_check_time_get(), urpc_keepalive_cycle_time_get()) !=
        URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("set socket idle timeout failed, err: %s\n", strerror(errno));
        goto EXIT;
    }

    urpc_server_accept_entry_t *entry = (urpc_server_accept_entry_t *)urpc_dbuf_calloc(
        URPC_DBUF_TYPE_CP, 1, sizeof(urpc_server_accept_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("create transport handle failed\n");
        goto EXIT;
    }
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    ctl_hdl->state = TLS_CONNECTING;
    ctl_hdl->fd = fd;
    entry->user_ctx = user_ctx;
    urpc_list_init(&entry->list);
    urpc_list_init(&entry->server_channel_list);
    if (server_do_ssl_handshake(entry) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("server do ssl handshake failed\n");
        goto TLS_UNINIT;
    }
    server_accept_manager_insert(entry);
    return entry;

TLS_UNINIT:
    if (ctl_hdl->ssl != NULL) {
        crypto_ssl_uninit(ctl_hdl->ssl);
    }
    urpc_dbuf_free(entry);
EXIT:
    (void)close(fd);
    return NULL;
}

static void client_on_ssl_handshake(uint32_t events, urpc_epoll_event_t *lev)
{
    urpc_client_connect_entry_t *entry = lev->args;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    int ret = URPC_SUCCESS;
    if (events & (EPOLLERR | EPOLLHUP)) {
        ctl_hdl->state = TCP_ERROR;
        event_error_print(ctl_hdl->fd, events);
        // indicates that the connect times out or the port is not listened on, the peer end returns rst.
        goto DISCONNECT;
    }

    if (events & lev->events) {
        transport_event_remove(ctl_hdl);
        if (ctl_hdl->state == TCP_CONNECTING) {
            if (!urpc_socket_check_connected(lev->fd)) {
                // connect failed
                goto DISCONNECT;
            }
            ctl_hdl->state = TLS_CONNECTING;
        }
        ret = client_do_ssl_handshake(entry);
        if (ret != URPC_SUCCESS) {
            goto DISCONNECT;
        }
        if (ctl_hdl->state == TCP_CONNECTED) {
            client_do_send(entry);
        }
        // check state
        if (transport_should_stop(ctl_hdl->state)) {
            goto DISCONNECT;
        }
        if (entry->ref_cnt == 0) {
            transport_connection_shutdown(entry, true);
        }
        return;
    }
    URPC_LIB_LOG_DEBUG("is not the desired event: %u, actual: %u\n", lev->events, events);
    return;

DISCONNECT:
    transport_shutdown_and_reconnect(entry);
    return;
}

static void server_on_ssl_handshake(uint32_t events, urpc_epoll_event_t *lev)
{
    urpc_server_accept_entry_t *entry = lev->args;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    if (events & (EPOLLERR | EPOLLHUP)) {
        ctl_hdl->state = TCP_ERROR;
        event_error_print(ctl_hdl->fd, events);
        goto DISCONNECT;
    }

    if (events & lev->events) {
        transport_event_remove(ctl_hdl);
        int ret = server_do_ssl_handshake(entry);
        if (ret != URPC_SUCCESS) {
            goto DISCONNECT;
        }
        return;
    }
    URPC_LIB_LOG_DEBUG("is not the desired event: %u, actual: %u\n", lev->events, events);
    return;

DISCONNECT:
    transport_acception_shutdown(entry, false, true);
    return;
}

static int client_do_ssl_handshake(urpc_client_connect_entry_t *handle)
{
    transport_handle_t *ctl_hdl = &handle->conn_handle;
    if (ctl_hdl->ssl == NULL) {
        if (!crypto_is_ssl_enabled()) {
            return client_handshake_completed(handle, false);
        }
        ctl_hdl->ssl = crypto_ssl_init(ctl_hdl->fd, false);
        if (ctl_hdl->ssl == NULL) {
            ctl_hdl->state = TCP_ERROR;
            return URPC_FAIL;
        }
    }
    int err = 0;
    int ret = crypto_ssl_connect(ctl_hdl->ssl, &err);
    if (ret == URPC_RUNNING) {
        uint32_t event = EPOLLOUT;
        if (err == SSL_ERROR_WANT_READ) {
            event = EPOLLIN;
        }
        if (transport_event_add(ctl_hdl, client_on_ssl_handshake, event, (void *)handle) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    if (ret == URPC_SUCCESS) {
        return client_handshake_completed(handle, true);
    }
    ctl_hdl->state = TCP_ERROR;
    return ret;
}

static int server_do_ssl_handshake(urpc_server_accept_entry_t *handle)
{
    transport_handle_t *ctl_hdl = &handle->conn_handle;
    if (ctl_hdl->ssl == NULL) {
        if (!crypto_is_ssl_enabled()) {
            return server_handshake_completed(handle, false);
        }
        ctl_hdl->ssl = crypto_ssl_init(ctl_hdl->fd, true);
        if (ctl_hdl->ssl == NULL) {
            ctl_hdl->state = TCP_ERROR;
            return URPC_FAIL;
        }
    }

    int err = 0;
    int ret = crypto_ssl_accept(ctl_hdl->ssl, &err);
    if (ret == URPC_RUNNING) {
        uint32_t event = EPOLLOUT;
        if (err == SSL_ERROR_WANT_READ) {
            event = EPOLLIN;
        }
        // TLS connection establishment is in progress
        if (transport_event_add(ctl_hdl, server_on_ssl_handshake, event, (void*)handle) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }

    if (ret == URPC_SUCCESS) {
        return server_handshake_completed(handle, true);
    }
    ctl_hdl->state = TCP_ERROR;
    return ret;
}

static void server_on_io_event_process(uint32_t events, urpc_epoll_event_t *lev)
{
    urpc_server_accept_entry_t *entry = lev->args;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    if (events & (EPOLLERR | EPOLLHUP)) {
        ctl_hdl->state = TCP_ERROR;
        event_error_print(ctl_hdl->fd, events);
        // indicates that the connect times out or the port is not listened on, the peer end returns rst.
        goto DISCONNECT;
    }

    // process epollout event
    if (ctl_hdl->is_write_buffer_full == URPC_TRUE && (events & (EPOLLOUT))) {
        // continue execute the task, send remaining data, until running is back
        ctl_hdl->is_write_buffer_full = URPC_FALSE;
        // remove epollout event
        transport_event_add(ctl_hdl, server_on_io_event_process, EPOLLIN, entry);
        server_do_send(entry);
        if (transport_should_stop(ctl_hdl->state)) {
            goto DISCONNECT;
        }
    }

    // process epollin event
    if (events & (EPOLLIN)) {
        server_on_new_messages(entry);
        if (transport_should_stop(ctl_hdl->state)) {
            goto DISCONNECT;
        }
        return;
    }
    return;

DISCONNECT:
    // close server transport resource
    transport_acception_shutdown(entry, false, true);
    return;
}

static void client_on_io_event_process(uint32_t events, urpc_epoll_event_t *lev)
{
    urpc_client_connect_entry_t *entry = lev->args;
    transport_handle_t *ctl_hdl = &entry->conn_handle;
    if (events & (EPOLLERR | EPOLLHUP)) {
        entry->error_cnt++;
        ctl_hdl->state = TCP_ERROR;
        event_error_print(ctl_hdl->fd, events);
         // indicates that the connect times out or the port is not listened on, the peer end returns rst.
         URPC_LIB_LOG_ERR("event error on fd: %d, " EID_FMT ", pid: %u\n",
            ctl_hdl->fd, EID_ARGS(entry->client_key.eid), entry->client_key.pid);
        goto DISCONNECT;
    }
    entry->error_cnt = 0;
    if (ctl_hdl->is_write_buffer_full == URPC_TRUE && (events & (EPOLLOUT))) {
        // 2.continue execute the task, send remaining data, until running is back
        // remove epollout event
        transport_event_add(ctl_hdl, client_on_io_event_process, EPOLLIN, entry);
        client_do_send(entry);
        if (transport_should_stop(ctl_hdl->state)) {
            goto DISCONNECT;
        }
    }
    if (entry->ref_cnt == 0) {
        transport_connection_shutdown(entry, false);
        return;
    }
    // process epollin event
    if (events & (EPOLLIN)) {
        client_on_new_messages(entry);
        if (transport_should_stop(ctl_hdl->state)) {
            goto DISCONNECT;
        }
        if (entry->ref_cnt == 0) {
            transport_connection_shutdown(entry, true);
        }
        return;
    }
    return;

DISCONNECT:
    transport_shutdown_and_reconnect(entry);
    return;
}

int transport_send_msg(transport_handle_t *ctl_hdl, void *data, size_t data_size)
{
    int ret;
    URPC_LIB_LOG_DEBUG(
        "task id: %d, send message phase: %d\n", ctl_hdl->send_record.head.task_id, ctl_hdl->send_record.phase);
    if (ctl_hdl->send_record.phase == TRANSMISSION_HEAD) {
        URPC_LIB_LOG_DEBUG("send message data size: %u\n", ctl_hdl->send_record.head.data_size);
        ret = ctl_hdl->send_async(ctl_hdl, ctl_hdl->event.func, &ctl_hdl->send_record.head, sizeof(urpc_ctl_head_t));
        if (ret == URPC_RUNNING) {
            URPC_LIB_LOG_DEBUG("send message head is running\n");
            return URPC_RUNNING;
        }
        ctl_hdl->send_record.offset = 0;
        if (ret == URPC_FAIL) {
            return URPC_FAIL;
        }
        if (data == NULL || data_size == 0) {
            // reset is_prepared_head
            ctl_hdl->send_record.is_prepared_head = URPC_FALSE;
            return URPC_SUCCESS;
        }
        ctl_hdl->send_record.phase = TRANSMISSION_DATA;
    }
    ret = ctl_hdl->send_async(ctl_hdl, ctl_hdl->event.func, data, data_size);
    if (ret == URPC_RUNNING) {
        URPC_LIB_LOG_DEBUG("send message packet is running\n");
        return URPC_RUNNING;
    }
    ctl_hdl->send_record.is_prepared_head = URPC_FALSE;
    ctl_hdl->send_record.phase = TRANSMISSION_HEAD;
    ctl_hdl->send_record.offset = 0;

    return ret;
}

int transport_init(void)
{
    if (urpc_hmap_init(&g_urpc_client_connect_hamp.hmap, TRANSPORT_MAX_CONNECTIONS) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server task table failed\n");
        return URPC_FAIL;
    }

    urpc_list_init(&g_urpc_server_accept_manager.list);
    if (urpc_hmap_init(&g_urpc_server_resource_hamp.hmap, URPC_MAX_CLIENTS) != URPC_SUCCESS) {
        urpc_hmap_uninit(&g_urpc_client_connect_hamp.hmap);
        URPC_LIB_LOG_ERR("init server resource table failed\n");
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

void transport_uninit(void)
{
    delayed_release_resources_ctx_t *cur_resource;
    delayed_release_resources_ctx_t *next_resource;
    URPC_HMAP_FOR_EACH_SAFE(cur_resource, next_resource, node, &g_urpc_server_resource_hamp.hmap) {
        task_engine_task_process(false, NULL, NULL, &cur_resource->base_task);
    }
    urpc_hmap_uninit(&g_urpc_server_resource_hamp.hmap);

    urpc_client_connect_entry_t *c_next;
    urpc_client_connect_entry_t *c_cur;
    URPC_HMAP_FOR_EACH_SAFE(c_cur, c_next, node, &g_urpc_client_connect_hamp.hmap) {
        transport_connection_shutdown(c_cur, false);
    }
    urpc_hmap_uninit(&g_urpc_client_connect_hamp.hmap);

    urpc_server_accept_entry_t *s_next;
    urpc_server_accept_entry_t *s_cur;
    URPC_LIST_FOR_EACH_SAFE(s_cur, s_next, node, &g_urpc_server_accept_manager.list) {
        transport_acception_shutdown(s_cur, false, false);
    }
}

urpc_client_connect_entry_t *transport_connection_get(urpc_host_info_t *server)
{
    return client_connect_entry_get(server);
}

static int resource_releaser_new(urpc_server_accept_entry_t *entry)
{
    delayed_release_resources_ctx_t *ctx = (delayed_release_resources_ctx_t *)urpc_dbuf_calloc(
        URPC_DBUF_TYPE_CP, 1, sizeof(delayed_release_resources_ctx_t));
    if (ctx == NULL) {
        URPC_LIB_LOG_ERR("create server resource releaser failed\n");
        return URPC_FAIL;
    }
    ctx->base_task.is_server = URPC_TRUE;
    ctx->base_task.workflow_type = WORKFLOW_TYPE_RELEASE_RESOURCE;
    ctx->base_task.ctx = (void *)entry;
    ctx->base_task.key.identity = entry->client_key;
    ctx->base_task.key.task_id = URPC_INVALID_TASK_ID;
    urpc_list_init(&ctx->server_channel_list);

    // linked list node transfer
    urpc_server_channel_info_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list)
    {
        urpc_list_remove(&cur->node);
        urpc_list_push_back(&ctx->server_channel_list, &cur->node);
    }

    urpc_list_init(&entry->server_channel_list);
    // delay release time (s), [1, 3600], urpc_init already check
    ctx->base_task.timeout = (int)urpc_keepalive_release_time_get() * MS_PER_SEC;
    ctx->base_task.timestamp = get_timestamp_ms() + (uint64_t)(ctx->base_task.timeout);

    uint32_t hash = urpc_hash_bytes(&entry->client_key, sizeof(urpc_instance_key_t), 0);
    // server single-threaded processing, and does not require locking
    urpc_hmap_insert(&g_urpc_server_resource_hamp.hmap, &ctx->node, hash);
    ctx->base_task.ref_cnt++;
    task_manager_timeout_manager_lock();
    task_manager_timeout_manager_insert(&ctx->base_task);
    task_manager_timeout_manager_unlock();
    return URPC_SUCCESS;
}

static void heartbeat_loss(urpc_server_accept_entry_t *entry)
{
    uint64_t keepalive_attr = 0;
    bool has_server_channel = false;
    urpc_server_channel_info_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list)
    {
        has_server_channel = true;
        keepalive_attr = cur->keepalive_attr;
    }

    if (has_server_channel) {
        if (resource_releaser_new(entry) != URPC_SUCCESS) {
            URPC_LIST_FOR_EACH_SAFE(cur, next, node, &entry->server_channel_list)
            {
                (void)server_channel_free(cur->id, false);
            }
        }
    }

    uint32_t time = 0;
    struct tcp_info tcp_statistic;
    socklen_t len = (socklen_t)sizeof(struct tcp_info);
    if (getsockopt(entry->conn_handle.fd, IPPROTO_TCP, TCP_INFO, &tcp_statistic, &len) == -1) {
        URPC_LIB_LOG_WARN("get tcp socket statistic failed, err: %s\n", strerror(errno));
    } else {
        // get resent active time
        time = tcp_statistic.tcpi_last_data_sent > tcp_statistic.tcpi_last_data_recv
                   ? tcp_statistic.tcpi_last_data_recv / MS_PER_SEC
                   : tcp_statistic.tcpi_last_data_sent / MS_PER_SEC;
    }

    urpc_keepalive_event_info_t info = {
        .user_ctx = keepalive_attr,
        .inactivated_time = time,
        .peer_pid = entry->client_key.pid,
    };

    if (has_server_channel && is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        URPC_LIB_LOG_WARN("keepalive timeout, " EID_FMT ", pid: %u, user info %lu, inactivated for %u seconds\n",
            EID_ARGS(entry->client_key.eid), entry->client_key.pid, info.user_ctx, info.inactivated_time);
        urpc_keepalive_callback_get()(URPC_KEEPALIVE_FAILED, info);
    }
}

void transport_server_release_resource(urpc_async_task_ctx_t *task)
{
    delayed_release_resources_ctx_t *ctx = CONTAINER_OF_FIELD(task, delayed_release_resources_ctx_t, base_task);
    urpc_server_channel_info_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &ctx->server_channel_list)
    {
        URPC_LIB_LOG_DEBUG("delayed activation triggers resource release\n");
        (void)server_channel_free(cur->id, false);
    }
}

void transport_server_releaser_remove(urpc_async_task_ctx_t *task)
{
    delayed_release_resources_ctx_t *ctx = CONTAINER_OF_FIELD(task, delayed_release_resources_ctx_t, base_task);
    if (task->ref_cnt > 0) {
        task->ref_cnt--;
    }
    urpc_hmap_remove(&g_urpc_server_resource_hamp.hmap, &ctx->node);
}
