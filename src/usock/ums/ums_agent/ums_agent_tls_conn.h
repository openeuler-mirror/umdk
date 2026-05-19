/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS connection and connection pool module for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-11
 * Note:
 * History: 2026-05-11  Create File
 */

#ifndef UMS_AGENT_TLS_CONN_H
#define UMS_AGENT_TLS_CONN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

#include "ums_agent_types.h"
#include "ums_agent_list.h"

#define UMS_AGENT_TLS_HANDSHAKE_TIMEOUT_SEC    10
#define UMS_AGENT_TLS_IDLE_TIMEOUT_SEC         1800
#define UMS_AGENT_TLS_EMPTY_CONN_TIMEOUT_SEC   30
#define UMS_AGENT_TLS_CONN_TTL_SEC             86400
#define UMS_AGENT_TLS_SHUTDOWN_TIMEOUT_SEC     5

#define UMS_AGENT_TLS_TCP_KEEPALIVE_IDLE_SEC   60
#define UMS_AGENT_TLS_TCP_KEEPALIVE_INTVL_SEC  10
#define UMS_AGENT_TLS_TCP_KEEPALIVE_CNT        3

#define UMS_AGENT_TLS_TCP_RECV_TIMEOUT_SEC     30
#define UMS_AGENT_TLS_TCP_SEND_TIMEOUT_SEC     30

#define UMS_AGENT_TLS_MAX_ERR_BUF_LEN          256

enum ums_agent_tls_conn_state {
    UMS_AGENT_TLS_CONN_HANDSHAKING = 0,
    UMS_AGENT_TLS_CONN_CONNECTED,
    UMS_AGENT_TLS_CONN_SHUTTING_DOWN,
    UMS_AGENT_TLS_CONN_CLOSED,
    UMS_AGENT_TLS_CONN_ERROR
};

struct ums_agent_tls_conn {
    SSL *ssl;
    int fd;
    bool is_server;
    bool ever_used;
    enum ums_agent_tls_conn_state state;
    struct timespec create_time;
    struct timespec handshake_start_time;
    struct timespec handshake_complete_time;
    struct timespec last_active_time;
    struct timespec shutdown_start_time;
    uint32_t conn_ttl_sec;
    uint32_t ref_count;
    struct ums_agent_ip_addr peer_addr;
    uint16_t peer_port;
    bool close_pending;
    struct ums_agent_list_node node;
};

struct ums_agent_tls_conn_ops {
    void (*on_connect_complete)(struct ums_agent_tls_conn *conn, int status,
        void *user_data);
    void (*on_data_available)(struct ums_agent_tls_conn *conn, void *user_data);
    void (*on_writable)(struct ums_agent_tls_conn *conn, void *user_data);
    void (*on_close)(struct ums_agent_tls_conn *conn, void *user_data);
    void *user_data;
};

int ums_agent_tls_conn_pool_init(uint32_t max_conns, const struct ums_agent_tls_conn_ops *ops);
void ums_agent_tls_conn_pool_deinit(void);

void ums_agent_tls_conn_register_ops(const struct ums_agent_tls_conn_ops *ops);
void ums_agent_tls_conn_unregister_ops(void);

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_get(
    const struct ums_agent_ip_addr *peer_addr);
void ums_agent_tls_conn_pool_put(struct ums_agent_tls_conn *conn);

/*
 * ums_agent_tls_conn_connect - Initiate a TLS connection to the specified peer.
 * Returns 0 if the connection was successfully initiated or an existing
 * connection to the same peer was reused. Note: for a new connection,
 * returning 0 does NOT mean the TLS connection is fully established;
 * the handshake may still be in progress. The actual completion (or
 * failure) is reported asynchronously via the on_connect_complete callback.
 * Returns -1 on failure (invalid params, pool full, socket/SSL error).
 */
int ums_agent_tls_conn_connect(const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port);
int ums_agent_tls_conn_accept(int listen_fd);
void ums_agent_tls_conn_shutdown(struct ums_agent_tls_conn *conn);

int ums_agent_tls_conn_send(struct ums_agent_tls_conn *conn, const void *data, uint32_t len);
int ums_agent_tls_conn_recv(struct ums_agent_tls_conn *conn, void *buf, uint32_t buf_len);

void ums_agent_tls_conn_handle_event(struct ums_agent_tls_conn *conn,
    uint32_t events);
void ums_agent_tls_conn_pool_timer_tick(void);

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_find_by_fd(int fd);
enum ums_agent_tls_conn_state ums_agent_tls_conn_get_state(const struct ums_agent_tls_conn *conn);
const struct ums_agent_ip_addr *ums_agent_tls_conn_get_peer_addr(const struct ums_agent_tls_conn *conn);
uint16_t ums_agent_tls_conn_get_peer_port(const struct ums_agent_tls_conn *conn);
uint32_t ums_agent_tls_conn_pool_get_count(void);
bool ums_agent_tls_conn_pool_is_full(void);
const char *ums_agent_tls_conn_state_to_str(enum ums_agent_tls_conn_state state);

#endif /* UMS_AGENT_TLS_CONN_H */
