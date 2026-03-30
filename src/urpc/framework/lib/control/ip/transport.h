/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define transport function
 */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <unistd.h>

#include "crypto.h"
#include "keepalive.h"
#include "protocol.h"
#include "task_engine.h"
#include "urpc_epoll.h"
#include "urpc_hmap.h"
#include "urpc_list.h"
#include "urpc_socket.h"
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_CTL_BUF_MAX_LEN                    (1UL << 24)

struct transport_handle;
typedef int (*transport_send_async)(
    struct transport_handle *ctl_hdl, urpc_epoll_event_func_t func, void *data, size_t data_size);
typedef int (*transport_recv_async)(struct transport_handle *ctl_hdl, void *data, size_t data_size);

typedef enum data_transmission_phase {
    TRANSMISSION_HEAD = 0,
    TRANSMISSION_DATA,
    TRANSMISSION_MAX,
} data_transmission_phase_t;

typedef struct io_buf_record {
    urpc_ctl_head_t head; // cache message header
    size_t offset;
    int task_id; // recv record task id unused
    data_transmission_phase_t phase; // messages is divided into two stages: message header and data packet
    void *data;
    uint8_t is_prepared_head : 1; // has the header been initialized when sending
    uint8_t rsvd : 7;
} io_buf_record_t;

typedef enum transport_tcp_state {
    TCP_UNINITIALIZED = 0,
    TCP_CONNECTING,
    TLS_CONNECTING,
    TCP_CONNECTED,
    TCP_CLOSED,
    TCP_ERROR,
} transport_tcp_state_t;

static inline bool transport_should_stop(transport_tcp_state_t state)
{
    return (state == TCP_CLOSED || state == TCP_ERROR);
}

typedef struct transport_handle {
    int fd;
    SSL *ssl;
    transport_send_async send_async;
    transport_recv_async recv_async;
    urpc_epoll_event_t event;
    io_buf_record_t send_record;
    io_buf_record_t recv_record;
    transport_tcp_state_t state;
    uint8_t is_write_buffer_full : 1;
    uint8_t is_epoll_registered : 1;
    uint8_t rsvd : 6;
} transport_handle_t;

typedef struct urpc_client_connect_table {
    struct urpc_hmap hmap;
} urpc_client_connect_table_t;

typedef struct urpc_client_connect_entry {
    struct urpc_hmap_node node;
    urpc_list_t list; // all task under the TCP channel
    urpc_list_t channel_list;  // all channel instances under the TCP channel
    urpc_host_info_inner_t server_inner;
    urpc_host_info_t local;
    socket_addr_t tcp_addr;
    transport_handle_t conn_handle;
    urpc_instance_key_t client_key;
    urpc_connect_msg_t *msg;
    uint32_t ref_cnt;
    uint32_t server_chid;
    uint32_t retry_times; // in a disconnected state, initiate reconnection attempts
    uint32_t error_cnt; // error count after successful connection
    uint8_t is_bind_local : 1;
    uint8_t rsvd : 7;
} urpc_client_connect_entry_t;

typedef struct urpc_server_accept_manager {
    urpc_list_t list;
} urpc_server_accept_manager_t;

typedef struct urpc_server_accept_entry {
    urpc_list_t node;
    urpc_list_t list;
    transport_handle_t conn_handle;
    urpc_instance_key_t client_key;
    urpc_list_t server_channel_list; // record the server channel, used to release resources when heartbeat is lost
    uint32_t ref_cnt;
    void *user_ctx;
} urpc_server_accept_entry_t;

urpc_client_connect_entry_t *transport_connection_establish(urpc_async_task_ctx_t *task);
urpc_server_accept_entry_t *transport_connection_accept(int listen_fd, void *user_ctx);
int transport_send_msg(transport_handle_t *ctl_hdl, void *data, size_t data_size);
void transport_client_task_unregister(urpc_async_task_ctx_t *task, urpc_client_connect_entry_t *entry);
void transport_server_task_unregister(urpc_async_task_ctx_t *task, urpc_server_accept_entry_t *entry);
void transport_client_task_register(urpc_async_task_ctx_t *task, urpc_client_connect_entry_t *entry);
void transport_server_task_register(urpc_async_task_ctx_t *task, urpc_server_accept_entry_t *entry);
int transport_init(void);
void transport_uninit(void);
urpc_client_connect_entry_t *transport_connection_get(urpc_host_info_t *server);
void transport_server_release_resource(urpc_async_task_ctx_t *task);
void transport_server_releaser_remove(urpc_async_task_ctx_t *task);

#ifdef __cplusplus
}
#endif

#endif