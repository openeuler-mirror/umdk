/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS connection and connection pool module implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-11
 * Note:
 * History: 2026-05-11  Create File
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <glib.h>

#include "ums_agent_log.h"
#include "ums_agent_epoll.h"
#include "ums_agent_utils.h"
#include "ums_agent_tls_ctx.h"
#include "ums_agent_tls_conn.h"

struct ums_agent_tls_conn_pool {
    struct ums_agent_tls_conn *head;
    uint32_t conn_count;
    uint32_t max_conns;
    GHashTable *fd_ht;
    struct ums_agent_tls_conn_ops ops;
};

static struct ums_agent_tls_conn_pool g_ums_agent_tls_conn_pool;

const char *ums_agent_tls_conn_state_to_str(enum ums_agent_tls_conn_state state)
{
    switch (state) {
        case UMS_AGENT_TLS_CONN_HANDSHAKING:
            return "HANDSHAKING";
        case UMS_AGENT_TLS_CONN_CONNECTED:
            return "CONNECTED";
        case UMS_AGENT_TLS_CONN_SHUTTING_DOWN:
            return "SHUTTING_DOWN";
        case UMS_AGENT_TLS_CONN_CLOSED:
            return "CLOSED";
        case UMS_AGENT_TLS_CONN_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

enum ums_agent_tls_conn_state ums_agent_tls_conn_get_state(
    const struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return UMS_AGENT_TLS_CONN_ERROR;
    }
    return conn->state;
}

const struct ums_agent_ip_addr *ums_agent_tls_conn_get_peer_addr(
    const struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return NULL;
    }
    return &conn->peer_addr;
}

uint16_t ums_agent_tls_conn_get_peer_port(const struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return 0;
    }
    return conn->peer_port;
}

static int ums_agent_tls_conn_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        UMS_AGENT_LOG_ERR("fcntl F_GETFL failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        UMS_AGENT_LOG_ERR("fcntl F_SETFL O_NONBLOCK failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }
    return 0;
}

static int ums_agent_tls_conn_set_tcp_keepalive(int fd)
{
    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt SO_KEEPALIVE failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    optval = UMS_AGENT_TLS_TCP_KEEPALIVE_IDLE_SEC;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt TCP_KEEPIDLE failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    optval = UMS_AGENT_TLS_TCP_KEEPALIVE_INTVL_SEC;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt TCP_KEEPINTVL failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    optval = UMS_AGENT_TLS_TCP_KEEPALIVE_CNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt TCP_KEEPCNT failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int ums_agent_tls_conn_set_socket_timeout(int fd)
{
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = UMS_AGENT_TLS_TCP_RECV_TIMEOUT_SEC;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt SO_RCVTIMEO failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = UMS_AGENT_TLS_TCP_SEND_TIMEOUT_SEC;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt SO_SNDTIMEO failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int ums_agent_tls_conn_setup_socket_options(int fd)
{
    if (ums_agent_tls_conn_set_nonblocking(fd) < 0) {
        return -1;
    }

    if (ums_agent_tls_conn_set_tcp_keepalive(fd) < 0) {
        UMS_AGENT_LOG_WARN("failed to set TCP keepalive on fd=%d", fd);
    }

    if (ums_agent_tls_conn_set_socket_timeout(fd) < 0) {
        UMS_AGENT_LOG_WARN("failed to set socket timeout on fd=%d", fd);
    }

    return 0;
}

static void ums_agent_tls_conn_parse_peer_address(const struct sockaddr *peer_addr,
    socklen_t peer_addr_len, struct ums_agent_ip_addr *peer_ip, uint16_t *peer_port)
{
    if (peer_addr->sa_family == AF_INET6) {
        if (peer_addr_len < (socklen_t)sizeof(struct sockaddr_in6)) {
            return;
        }
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)peer_addr;
        peer_ip->family = AF_INET6;
        peer_ip->ip.in6 = addr6->sin6_addr;
        *peer_port = ntohs(addr6->sin6_port);
    } else if (peer_addr->sa_family == AF_INET) {
        if (peer_addr_len < (socklen_t)sizeof(struct sockaddr_in)) {
            return;
        }
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)peer_addr;
        peer_ip->family = AF_INET;
        peer_ip->ip.in4 = addr4->sin_addr;
        *peer_port = ntohs(addr4->sin_port);
    } else {
        return;
    }

    ums_agent_ip_addr_normalize(peer_ip);
}

static SSL *ums_agent_tls_conn_create_server_ssl(int fd)
{
    SSL_CTX *ctx = ums_agent_tls_get_server_ssl_ctx();
    if (!ctx) {
        UMS_AGENT_LOG_ERR("server SSL_CTX not initialized");
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        UMS_AGENT_LOG_ERR("SSL_new for server failed");
        return NULL;
    }

    if (SSL_set_fd(ssl, fd) != 1) {
        UMS_AGENT_LOG_ERR("SSL_set_fd failed for fd=%d", fd);
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_accept_state(ssl);
    return ssl;
}

static SSL *ums_agent_tls_conn_create_client_ssl(int fd)
{
    SSL_CTX *ctx = ums_agent_tls_get_client_ssl_ctx();
    if (!ctx) {
        UMS_AGENT_LOG_ERR("client SSL_CTX not initialized");
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        UMS_AGENT_LOG_ERR("SSL_new for client failed");
        return NULL;
    }

    if (SSL_set_fd(ssl, fd) != 1) {
        UMS_AGENT_LOG_ERR("SSL_set_fd failed for fd=%d", fd);
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_connect_state(ssl);

    return ssl;
}

static struct ums_agent_tls_conn *ums_agent_tls_conn_alloc(int fd, SSL *ssl,
    bool is_server, const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port)
{
    struct ums_agent_tls_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        UMS_AGENT_LOG_ERR("failed to allocate TLS connection");
        return NULL;
    }

    conn->ssl = ssl;
    conn->fd = fd;
    conn->is_server = is_server;
    conn->state = UMS_AGENT_TLS_CONN_HANDSHAKING;
    conn->ref_count = 0;
    conn->conn_ttl_sec = UMS_AGENT_TLS_CONN_TTL_SEC;
    conn->close_pending = false;
    conn->peer_addr = *peer_addr;
    conn->peer_port = peer_port;

    ums_agent_get_monotonic_time(&conn->create_time);
    ums_agent_get_monotonic_time(&conn->handshake_start_time);
    ums_agent_get_monotonic_time(&conn->last_active_time);

    return conn;
}

static void ums_agent_tls_conn_destroy(struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return;
    }

    if (conn->fd >= 0) {
        (void)ums_agent_epoll_del_fd(conn->fd);
        (void)close(conn->fd);
        conn->fd = -1;
    }
    if (conn->ssl) {
        if (conn->state == UMS_AGENT_TLS_CONN_CONNECTED ||
            conn->state == UMS_AGENT_TLS_CONN_SHUTTING_DOWN) {
            SSL_set_quiet_shutdown(conn->ssl, 1);
            (void)SSL_shutdown(conn->ssl);
        }
        SSL_free(conn->ssl);
    }
    free(conn);
}

static void ums_agent_tls_conn_pool_add(struct ums_agent_tls_conn *conn)
{
    conn->next = g_ums_agent_tls_conn_pool.head;
    conn->prev = NULL;
    if (g_ums_agent_tls_conn_pool.head) {
        g_ums_agent_tls_conn_pool.head->prev = conn;
    }
    g_ums_agent_tls_conn_pool.head = conn;
    g_ums_agent_tls_conn_pool.conn_count++;

    if (conn->fd >= 0 && g_ums_agent_tls_conn_pool.fd_ht) {
        g_hash_table_insert(g_ums_agent_tls_conn_pool.fd_ht, GINT_TO_POINTER(conn->fd), conn);
    }
}

static void ums_agent_tls_conn_pool_remove(struct ums_agent_tls_conn *conn)
{
    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        g_ums_agent_tls_conn_pool.head = conn->next;
    }
    if (conn->next) {
        conn->next->prev = conn->prev;
    }
    conn->next = NULL;
    conn->prev = NULL;
    g_ums_agent_tls_conn_pool.conn_count--;

    if (conn->fd >= 0 && g_ums_agent_tls_conn_pool.fd_ht) {
        g_hash_table_remove(g_ums_agent_tls_conn_pool.fd_ht, GINT_TO_POINTER(conn->fd));
    }
}

static struct ums_agent_tls_conn *ums_agent_tls_pool_find(const struct ums_agent_ip_addr *peer_addr,
    uint16_t peer_port)
{
    struct ums_agent_tls_conn *conn = g_ums_agent_tls_conn_pool.head;
    while (conn) {
        if (conn->peer_port == peer_port &&
            ums_agent_ip_addr_equal(&conn->peer_addr, peer_addr) &&
            conn->state == UMS_AGENT_TLS_CONN_CONNECTED &&
            conn->ref_count == 0 &&
            !conn->close_pending) {
            return conn;
        }
        conn = conn->next;
    }
    return NULL;
}

static void ums_agent_tls_pool_foreach(void (*cb)(struct ums_agent_tls_conn *conn, void *user_data),
    void *user_data)
{
    struct ums_agent_tls_conn *conn = g_ums_agent_tls_conn_pool.head;
    while (conn) {
        struct ums_agent_tls_conn *next = conn->next;
        cb(conn, user_data);
        conn = next;
    }
}

static int ums_agent_tls_conn_do_handshake(struct ums_agent_tls_conn *conn)
{
    int ret = SSL_do_handshake(conn->ssl);
    if (ret == 1) {
        conn->state = UMS_AGENT_TLS_CONN_CONNECTED;
        ums_agent_get_monotonic_time(&conn->handshake_complete_time);

        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));

        UMS_AGENT_LOG_DEBUG("TLS handshake completed, peer=%s:%u, is_server=%d",
            ip_str, conn->peer_port, conn->is_server);

        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN);
        return 0;
    }

    int ssl_err = SSL_get_error(conn->ssl, ret);
    if (ssl_err == SSL_ERROR_WANT_READ) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN);
        return 1;
    } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN | EPOLLOUT);
        return 1;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
    unsigned long err = ERR_get_error();
    char err_buf[UMS_AGENT_TLS_MAX_ERR_BUF_LEN];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    UMS_AGENT_LOG_ERR("SSL_do_handshake failed, peer=%s:%u, ssl_err=%d, "
        "openssl_err='%s'", ip_str, conn->peer_port, ssl_err, err_buf);
    ERR_clear_error();
    conn->state = UMS_AGENT_TLS_CONN_ERROR;
    return -1;
}

static int ums_agent_tls_conn_do_shutdown(struct ums_agent_tls_conn *conn)
{
    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));

    int ret = SSL_shutdown(conn->ssl);
    if (ret == 1) {
        conn->state = UMS_AGENT_TLS_CONN_CLOSED;
        return 0;
    }

    if (ret == 0) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN);
        return 1;
    }

    int ssl_err = SSL_get_error(conn->ssl, ret);
    if (ssl_err == SSL_ERROR_WANT_READ) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN);
        return 1;
    } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLOUT);
        return 1;
    }

    conn->state = UMS_AGENT_TLS_CONN_CLOSED;
    return -1;
}

static void ums_agent_tls_conn_close(struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return;
    }

    ums_agent_tls_conn_pool_remove(conn);
    ums_agent_tls_conn_destroy(conn);
}

int ums_agent_tls_conn_pool_init(uint32_t max_conns,
    const struct ums_agent_tls_conn_ops *ops)
{
    GHashTable *fd_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal,
        NULL, NULL);
    if (!fd_ht) {
        UMS_AGENT_LOG_ERR("failed to create fd hash table");
        return -1;
    }

    g_ums_agent_tls_conn_pool.head = NULL;
    g_ums_agent_tls_conn_pool.conn_count = 0;
    g_ums_agent_tls_conn_pool.max_conns = max_conns;
    g_ums_agent_tls_conn_pool.fd_ht = fd_ht;

    if (ops) {
        g_ums_agent_tls_conn_pool.ops = *ops;
    } else {
        memset(&g_ums_agent_tls_conn_pool.ops, 0, sizeof(g_ums_agent_tls_conn_pool.ops));
    }

    return 0;
}

void ums_agent_tls_conn_pool_deinit(void)
{
    struct ums_agent_tls_conn *conn = g_ums_agent_tls_conn_pool.head;
    while (conn) {
        struct ums_agent_tls_conn *next = conn->next;
        ums_agent_tls_conn_close(conn);
        conn = next;
    }
    g_ums_agent_tls_conn_pool.head = NULL;
    g_ums_agent_tls_conn_pool.conn_count = 0;
    if (g_ums_agent_tls_conn_pool.fd_ht) {
        g_hash_table_destroy(g_ums_agent_tls_conn_pool.fd_ht);
        g_ums_agent_tls_conn_pool.fd_ht = NULL;
    }
    memset(&g_ums_agent_tls_conn_pool.ops, 0, sizeof(g_ums_agent_tls_conn_pool.ops));
}

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_get(
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port)
{
    if (!peer_addr) {
        return NULL;
    }

    struct ums_agent_tls_conn *conn = ums_agent_tls_pool_find(peer_addr, peer_port);
    if (!conn) {
        return NULL;
    }

    conn->ref_count++;
    conn->ever_used = true;
    ums_agent_get_monotonic_time(&conn->last_active_time);
    return conn;
}

void ums_agent_tls_conn_pool_put(struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return;
    }
    if (conn->ref_count > 0) {
        conn->ref_count--;
    }
    ums_agent_get_monotonic_time(&conn->last_active_time);
    if (conn->ref_count == 0 && conn->close_pending) {
        ums_agent_tls_conn_shutdown(conn);
    }
}

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_find_by_fd(int fd)
{
    if (!g_ums_agent_tls_conn_pool.fd_ht || fd < 0) {
        return NULL;
    }
    return g_hash_table_lookup(g_ums_agent_tls_conn_pool.fd_ht, GINT_TO_POINTER(fd));
}

uint32_t ums_agent_tls_conn_pool_get_count(void)
{
    return g_ums_agent_tls_conn_pool.conn_count;
}

bool ums_agent_tls_conn_pool_is_full(void)
{
    return g_ums_agent_tls_conn_pool.conn_count >= g_ums_agent_tls_conn_pool.max_conns;
}
