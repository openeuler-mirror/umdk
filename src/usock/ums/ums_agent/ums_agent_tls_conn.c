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

static bool ums_agent_tls_conn_is_unexpected_eof(int ssl_err, int ret)
{
    if (ssl_err == SSL_ERROR_SYSCALL && ret == 0) {
        return true;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101050L
    if (ssl_err == SSL_ERROR_SSL) {
        int reason = ERR_GET_REASON(ERR_peek_error());
        if (reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
            return true;
        }
    }
#endif

    return false;
}

static int ums_agent_tls_conn_check_connect_result(struct ums_agent_tls_conn *conn)
{
    int sock_err = 0;
    socklen_t err_len = sizeof(sock_err);
    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) < 0) {
        UMS_AGENT_LOG_ERR("getsockopt SO_ERROR failed for fd=%d: %s (errno=%d)",
            conn->fd, strerror(errno), errno);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        return -1;
    }
    if (sock_err != 0) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_ERR("non-blocking connect failed for peer=%s:%u: %s (errno=%d)",
            ip_str, conn->peer_port, strerror(sock_err), sock_err);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        return -1;
    }
    return 0;
}

static void ums_agent_tls_conn_close(struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return;
    }

    ums_agent_tls_conn_pool_remove(conn);
    ums_agent_tls_conn_destroy(conn);
}

static int ums_agent_tls_conn_handle_write_error(struct ums_agent_tls_conn *conn,
    int ssl_ret, const char *ip_str)
{
    int saved_errno = errno;
    int ssl_err = SSL_get_error(conn->ssl, ssl_ret);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN | EPOLLOUT);
        return -EAGAIN;
    }
    if (ssl_err == SSL_ERROR_SYSCALL) {
        if (ssl_ret == 0) {
            UMS_AGENT_LOG_WARN("SSL_write received unexpected EOF, peer=%s:%u",
                ip_str, conn->peer_port);
            conn->state = UMS_AGENT_TLS_CONN_ERROR;
            return -1;
        }
        if (saved_errno == EINTR || saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            ums_agent_epoll_mod_fd(conn->fd, EPOLLIN | EPOLLOUT);
            return -EAGAIN;
        }
        UMS_AGENT_LOG_ERR("SSL_write syscall error, peer=%s:%u: %s (errno=%d)",
            ip_str, conn->peer_port, strerror(saved_errno), saved_errno);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        return -1;
    }

    unsigned long err = ERR_get_error();
    char err_buf[UMS_AGENT_TLS_MAX_ERR_BUF_LEN];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    UMS_AGENT_LOG_ERR("SSL_write failed, peer=%s:%u, ssl_err=%d, "
        "openssl_err='%s'", ip_str, conn->peer_port, ssl_err, err_buf);
    ERR_clear_error();
    conn->state = UMS_AGENT_TLS_CONN_ERROR;
    return -1;
}

static int ums_agent_tls_conn_handle_read_error(struct ums_agent_tls_conn *conn,
    int ssl_ret, const char *ip_str)
{
    int saved_errno = errno;
    int ssl_err = SSL_get_error(conn->ssl, ssl_ret);
    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        UMS_AGENT_LOG_DEBUG("peer sent close_notify, peer=%s:%u",
            ip_str, conn->peer_port);
        conn->state = UMS_AGENT_TLS_CONN_SHUTTING_DOWN;
        return 0;
    }
    if (ssl_err == SSL_ERROR_WANT_READ) {
        return -EAGAIN;
    } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN | EPOLLOUT);
        return -EAGAIN;
    }

    if (ums_agent_tls_conn_is_unexpected_eof(ssl_err, ssl_ret)) {
        UMS_AGENT_LOG_WARN("unexpected EOF on TLS connection, peer=%s:%u",
            ip_str, conn->peer_port);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        return -1;
    }

    if (ssl_err == SSL_ERROR_SYSCALL) {
        if (ssl_ret == 0) {
            UMS_AGENT_LOG_WARN("SSL_read received unexpected EOF, peer=%s:%u",
                ip_str, conn->peer_port);
            conn->state = UMS_AGENT_TLS_CONN_ERROR;
            return -1;
        }
        if (saved_errno == EINTR || saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            return -EAGAIN;
        }
        UMS_AGENT_LOG_ERR("SSL_read syscall error, peer=%s:%u: %s (errno=%d)",
            ip_str, conn->peer_port, strerror(saved_errno), saved_errno);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        return -1;
    }

    unsigned long err = ERR_get_error();
    char err_buf[UMS_AGENT_TLS_MAX_ERR_BUF_LEN];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    UMS_AGENT_LOG_ERR("SSL_read failed, peer=%s:%u, ssl_err=%d, "
        "openssl_err='%s'", ip_str, conn->peer_port, ssl_err, err_buf);
    ERR_clear_error();
    conn->state = UMS_AGENT_TLS_CONN_ERROR;
    return -1;
}

static void ums_agent_tls_conn_notify_connect_complete(struct ums_agent_tls_conn *conn, int status)
{
    if (g_ums_agent_tls_conn_pool.ops.on_connect_complete) {
        g_ums_agent_tls_conn_pool.ops.on_connect_complete(conn, status,
            g_ums_agent_tls_conn_pool.ops.user_data);
    }
}

static void ums_agent_tls_conn_notify_data_available(struct ums_agent_tls_conn *conn)
{
    if (g_ums_agent_tls_conn_pool.ops.on_data_available) {
        g_ums_agent_tls_conn_pool.ops.on_data_available(conn,
            g_ums_agent_tls_conn_pool.ops.user_data);
    }
}

static void ums_agent_tls_conn_handle_handshaking(struct ums_agent_tls_conn *conn,
    uint32_t events)
{
    if (!conn->is_server && (events & EPOLLOUT)) {
        if (ums_agent_tls_conn_check_connect_result(conn) != 0) {
            ums_agent_tls_conn_notify_connect_complete(conn, -1);
            ums_agent_tls_conn_close(conn);
            return;
        }
    }

    int ret = ums_agent_tls_conn_do_handshake(conn);
    if (ret < 0) {
        ums_agent_tls_conn_notify_connect_complete(conn, -1);
        ums_agent_tls_conn_close(conn);
    } else if (ret == 0) {
        ums_agent_tls_conn_notify_connect_complete(conn, 0);
    }
}

static void ums_agent_tls_conn_handle_shutting_down(struct ums_agent_tls_conn *conn)
{
    int ret = ums_agent_tls_conn_do_shutdown(conn);
    if (ret == 1) {
        return;
    }

    if (ret < 0) {
        UMS_AGENT_LOG_DEBUG("TLS shutdown error, force closing fd=%d", conn->fd);
    }
    conn->state = UMS_AGENT_TLS_CONN_CLOSED;
    ums_agent_tls_conn_close(conn);
}

static void ums_agent_tls_conn_handle_connected(struct ums_agent_tls_conn *conn,
    uint32_t events)
{
    if (events & EPOLLERR) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_WARN("connection error, peer=%s:%u, events=0x%x",
            ip_str, conn->peer_port, events);
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        ums_agent_tls_conn_shutdown(conn);
        return;
    }

    if (events & EPOLLHUP) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_WARN("peer hangup on TLS connection, peer=%s:%u",
            ip_str, conn->peer_port);
        conn->state = UMS_AGENT_TLS_CONN_SHUTTING_DOWN;
        ums_agent_get_monotonic_time(&conn->shutdown_start_time);
        int ret = ums_agent_tls_conn_do_shutdown(conn);
        if (ret == 1) {
            return;
        }
        if (ret < 0) {
            UMS_AGENT_LOG_DEBUG("TLS shutdown error on EPOLLHUP, force closing fd=%d", conn->fd);
        }
        conn->state = UMS_AGENT_TLS_CONN_CLOSED;
        ums_agent_tls_conn_close(conn);
        return;
    }

    if (events & EPOLLOUT) {
        ums_agent_epoll_mod_fd(conn->fd, EPOLLIN);
    }

    if (events & EPOLLIN) {
        ums_agent_get_monotonic_time(&conn->last_active_time);
        ums_agent_tls_conn_notify_data_available(conn);
    }
}

static bool ums_agent_tls_conn_check_handshake_timeout(const struct ums_agent_tls_conn *conn,
    const struct timespec *now, const char **reason)
{
    if (conn->state != UMS_AGENT_TLS_CONN_HANDSHAKING) {
        return false;
    }

    int64_t elapsed = ums_agent_timespec_diff_sec(&conn->handshake_start_time, now);
    if (elapsed > UMS_AGENT_TLS_HANDSHAKE_TIMEOUT_SEC) {
        *reason = "handshake timeout";
        return true;
    }
    return false;
}

static bool ums_agent_tls_conn_check_idle_timeout(const struct ums_agent_tls_conn *conn,
    const struct timespec *now, const char **reason)
{
    if (conn->state != UMS_AGENT_TLS_CONN_CONNECTED || conn->ref_count != 0) {
        return false;
    }

    int64_t idle_elapsed = ums_agent_timespec_diff_sec(&conn->last_active_time, now);
    if (idle_elapsed > UMS_AGENT_TLS_IDLE_TIMEOUT_SEC) {
        *reason = "idle timeout";
        return true;
    }

    if (!conn->ever_used) {
        int64_t empty_elapsed = ums_agent_timespec_diff_sec(
            &conn->handshake_complete_time, now);
        if (empty_elapsed > UMS_AGENT_TLS_EMPTY_CONN_TIMEOUT_SEC) {
            *reason = "empty connection timeout";
            return true;
        }
    }
    return false;
}

static bool ums_agent_tls_conn_check_ttl_timeout(const struct ums_agent_tls_conn *conn,
    const struct timespec *now, const char **reason)
{
    if (conn->state != UMS_AGENT_TLS_CONN_CONNECTED) {
        return false;
    }

    int64_t ttl_elapsed = ums_agent_timespec_diff_sec(&conn->create_time, now);
    if (ttl_elapsed > (int64_t)conn->conn_ttl_sec) {
        *reason = "TTL expired";
        return true;
    }
    return false;
}

static bool ums_agent_tls_conn_check_shutdown_timeout(const struct ums_agent_tls_conn *conn,
    const struct timespec *now, const char **reason)
{
    if (conn->state != UMS_AGENT_TLS_CONN_SHUTTING_DOWN) {
        return false;
    }

    int64_t shut_elapsed = ums_agent_timespec_diff_sec(
        &conn->shutdown_start_time, now);
    if (shut_elapsed > UMS_AGENT_TLS_SHUTDOWN_TIMEOUT_SEC) {
        *reason = "shutdown timeout";
        return true;
    }
    return false;
}

static bool ums_agent_tls_conn_check_timeout(const struct ums_agent_tls_conn *conn,
    const struct timespec *now, const char **reason)
{
    if (conn->state == UMS_AGENT_TLS_CONN_ERROR) {
        *reason = "connection error";
        return true;
    }

    if (ums_agent_tls_conn_check_handshake_timeout(conn, now, reason)) {
        return true;
    }

    if (ums_agent_tls_conn_check_idle_timeout(conn, now, reason)) {
        return true;
    }

    if (ums_agent_tls_conn_check_ttl_timeout(conn, now, reason)) {
        return true;
    }

    if (ums_agent_tls_conn_check_shutdown_timeout(conn, now, reason)) {
        return true;
    }

    return false;
}

static void ums_agent_tls_conn_abort(struct ums_agent_tls_conn *conn, const char *reason)
{
    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));

    if (conn->ref_count > 0) {
        conn->state = UMS_AGENT_TLS_CONN_ERROR;
        conn->close_pending = true;
        UMS_AGENT_LOG_WARN("deferring close, connection has active references, "
            "peer=%s:%u, reason=%s, ref_count=%u",
            ip_str, conn->peer_port, reason, conn->ref_count);
    } else {
        UMS_AGENT_LOG_WARN("closing connection, peer=%s:%u, reason=%s",
            ip_str, conn->peer_port, reason);
        ums_agent_tls_conn_close(conn);
    }
}

static void ums_agent_tls_conn_check_timeout_cb(struct ums_agent_tls_conn *conn, void *user_data)
{
    const struct timespec *now = user_data;
    const char *reason = NULL;

    if (ums_agent_tls_conn_check_timeout(conn, now, &reason)) {
        ums_agent_tls_conn_abort(conn, reason);
    }
}

static struct ums_agent_tls_conn *ums_agent_tls_conn_create_server(int fd,
    const struct sockaddr *peer_addr, socklen_t peer_addr_len)
{
    if (ums_agent_tls_conn_setup_socket_options(fd) < 0) {
        (void)close(fd);
        return NULL;
    }

    SSL *ssl = ums_agent_tls_conn_create_server_ssl(fd);
    if (!ssl) {
        (void)close(fd);
        return NULL;
    }

    struct ums_agent_ip_addr peer_ip;
    uint16_t peer_port = 0;
    ums_agent_tls_conn_parse_peer_address(peer_addr, peer_addr_len, &peer_ip, &peer_port);

    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_alloc(fd, ssl, true, &peer_ip, peer_port);
    if (!conn) {
        SSL_free(ssl);
        (void)close(fd);
        return NULL;
    }

    if (ums_agent_epoll_add_fd(fd, EPOLLIN) < 0) {
        ums_agent_tls_conn_destroy(conn);
        return NULL;
    }

    ums_agent_tls_conn_pool_add(conn);

    int handshake_ret = ums_agent_tls_conn_do_handshake(conn);
    if (handshake_ret < 0) {
        ums_agent_tls_conn_pool_remove(conn);
        ums_agent_tls_conn_destroy(conn);
        return NULL;
    }

    return conn;
}

static struct ums_agent_tls_conn *ums_agent_tls_conn_create_client(int fd,
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port, int connect_ret)
{
    SSL *ssl = ums_agent_tls_conn_create_client_ssl(fd);
    if (!ssl) {
        (void)close(fd);
        return NULL;
    }

    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_alloc(fd, ssl, false, peer_addr, peer_port);
    if (!conn) {
        SSL_free(ssl);
        (void)close(fd);
        return NULL;
    }

    uint32_t events = (connect_ret == 0) ? EPOLLIN : (EPOLLIN | EPOLLOUT);
    if (ums_agent_epoll_add_fd(conn->fd, events) < 0) {
        ums_agent_tls_conn_destroy(conn);
        return NULL;
    }

    ums_agent_tls_conn_pool_add(conn);

    if (connect_ret == 0) {
        int handshake_ret = ums_agent_tls_conn_do_handshake(conn);
        if (handshake_ret < 0) {
            ums_agent_tls_conn_pool_remove(conn);
            ums_agent_tls_conn_destroy(conn);
            return NULL;
        }
    }

    return conn;
}

static int ums_agent_tls_conn_create_client_socket(const struct ums_agent_ip_addr *peer_addr,
    uint16_t peer_port, int *connect_ret)
{
    struct sockaddr_storage sa_storage;
    socklen_t sa_len = 0;
    if (ums_agent_ip_addr_to_sockaddr(peer_addr, peer_port,
        (struct sockaddr *)&sa_storage, &sa_len) != 0) {
        UMS_AGENT_LOG_ERR("invalid IP address family");
        return -1;
    }

    int fd = socket(peer_addr->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        UMS_AGENT_LOG_ERR("socket failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    *connect_ret = connect(fd, (struct sockaddr *)&sa_storage, sa_len);
    if (*connect_ret < 0 && errno != EINPROGRESS) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_ERR("connect to %s:%u failed: %s (errno=%d)",
            ip_str, peer_port, strerror(errno), errno);
        (void)close(fd);
        return -1;
    }

    return fd;
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

int ums_agent_tls_conn_connect(const struct ums_agent_ip_addr *peer_addr,
    uint16_t peer_port)
{
    if (!peer_addr) {
        UMS_AGENT_LOG_ERR("peer_addr is NULL");
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));

    struct ums_agent_tls_conn *existing = ums_agent_tls_pool_find(peer_addr, peer_port);
    if (existing) {
        UMS_AGENT_LOG_DEBUG("reusing existing TLS connection to %s:%u",
            ip_str, peer_port);
        return 0;
    }

    if (ums_agent_tls_conn_pool_is_full()) {
        UMS_AGENT_LOG_WARN("connection pool full (%u), cannot connect "
            "to %s:%u", ums_agent_tls_conn_pool_get_count(), ip_str, peer_port);
        return -1;
    }

    int connect_ret = 0;
    int fd = ums_agent_tls_conn_create_client_socket(peer_addr, peer_port, &connect_ret);
    if (fd < 0) {
        return -1;
    }

    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_create_client(fd, peer_addr, peer_port,
        connect_ret);
    if (!conn) {
        return -1;
    }

    UMS_AGENT_LOG_DEBUG("initiating TLS connection to %s:%u, fd=%d",
        ip_str, peer_port, conn->fd);
    return 0;
}

int ums_agent_tls_conn_accept(int listen_fd)
{
    struct sockaddr_storage peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));

    socklen_t peer_len = sizeof(peer_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0;
        }
        UMS_AGENT_LOG_ERR("accept failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    if (ums_agent_tls_conn_pool_is_full()) {
        UMS_AGENT_LOG_WARN("connection pool full (%u), rejecting new connection",
            ums_agent_tls_conn_pool_get_count());
        (void)close(client_fd);
        return 0;
    }

    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_create_server(client_fd,
        (struct sockaddr *)&peer_addr, peer_len);
    if (!conn) {
        return -1;
    }

    if (conn->state == UMS_AGENT_TLS_CONN_CONNECTED) {
        ums_agent_tls_conn_notify_connect_complete(conn, 0);
    }

    return 1;
}

int ums_agent_tls_conn_send(struct ums_agent_tls_conn *conn,
    const void *data, uint32_t len)
{
    if (!conn || !data || len == 0) {
        UMS_AGENT_LOG_ERR("invalid parameters");
        return -1;
    }

    if (len > INT_MAX) {
        UMS_AGENT_LOG_ERR("data too long (%u)", len);
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));

    if (conn->state != UMS_AGENT_TLS_CONN_CONNECTED) {
        UMS_AGENT_LOG_ERR("connection not in CONNECTED state, peer=%s:%u, "
            "state=%s", ip_str, conn->peer_port,
            ums_agent_tls_conn_state_to_str(conn->state));
        return -1;
    }

    int ret = SSL_write(conn->ssl, data, (int)len);
    if (ret > 0) {
        ums_agent_get_monotonic_time(&conn->last_active_time);
        return ret;
    }

    return ums_agent_tls_conn_handle_write_error(conn, ret, ip_str);
}

int ums_agent_tls_conn_recv(struct ums_agent_tls_conn *conn,
    void *buf, uint32_t buf_len)
{
    if (!conn || !buf || buf_len == 0) {
        UMS_AGENT_LOG_ERR("invalid parameters");
        return -1;
    }

    if (buf_len > INT_MAX) {
        UMS_AGENT_LOG_ERR("buffer too long (%u)", buf_len);
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));

    if (conn->state != UMS_AGENT_TLS_CONN_CONNECTED &&
        conn->state != UMS_AGENT_TLS_CONN_SHUTTING_DOWN) {
        UMS_AGENT_LOG_ERR("connection not in CONNECTED/SHUTTING_DOWN state, "
            "peer=%s:%u, state=%s", ip_str, conn->peer_port,
            ums_agent_tls_conn_state_to_str(conn->state));
        return -1;
    }

    int ret = SSL_read(conn->ssl, buf, (int)buf_len);
    if (ret > 0) {
        ums_agent_get_monotonic_time(&conn->last_active_time);
        return ret;
    }

    return ums_agent_tls_conn_handle_read_error(conn, ret, ip_str);
}

void ums_agent_tls_conn_shutdown(struct ums_agent_tls_conn *conn)
{
    if (!conn) {
        return;
    }

    if (conn->ref_count > 0) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_WARN("deferring close, connection has active references, "
            "peer=%s:%u, ref_count=%u",
            ip_str, conn->peer_port, conn->ref_count);
        conn->close_pending = true;
        return;
    }

    if (conn->state == UMS_AGENT_TLS_CONN_CONNECTED) {
        conn->state = UMS_AGENT_TLS_CONN_SHUTTING_DOWN;
        ums_agent_get_monotonic_time(&conn->shutdown_start_time);

        int ret = ums_agent_tls_conn_do_shutdown(conn);
        if (ret == 1) {
            return;
        }
    } else if (conn->state == UMS_AGENT_TLS_CONN_SHUTTING_DOWN) {
        int ret = ums_agent_tls_conn_do_shutdown(conn);
        if (ret == 1) {
            return;
        }
    }

    conn->state = UMS_AGENT_TLS_CONN_CLOSED;
    ums_agent_tls_conn_pool_remove(conn);
    ums_agent_tls_conn_destroy(conn);
}

void ums_agent_tls_conn_handle_event(struct ums_agent_tls_conn *conn,
    uint32_t events)
{
    if (!conn) {
        return;
    }

    switch (conn->state) {
        case UMS_AGENT_TLS_CONN_HANDSHAKING:
            ums_agent_tls_conn_handle_handshaking(conn, events);
            break;
        case UMS_AGENT_TLS_CONN_SHUTTING_DOWN:
            ums_agent_tls_conn_handle_shutting_down(conn);
            break;
        case UMS_AGENT_TLS_CONN_CONNECTED:
            ums_agent_tls_conn_handle_connected(conn, events);
            break;
        case UMS_AGENT_TLS_CONN_ERROR:
            UMS_AGENT_LOG_DEBUG("ignoring event on ERROR connection, fd=%d", conn->fd);
            break;
        default:
            UMS_AGENT_LOG_WARN("event on connection in unexpected state, fd=%d, state=%s",
                conn->fd, ums_agent_tls_conn_state_to_str(conn->state));
            break;
    }
}

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_find_by_fd(int fd)
{
    if (!g_ums_agent_tls_conn_pool.fd_ht || fd < 0) {
        return NULL;
    }
    return g_hash_table_lookup(g_ums_agent_tls_conn_pool.fd_ht, GINT_TO_POINTER(fd));
}

void ums_agent_tls_conn_pool_timer_tick(void)
{
    struct timespec now;
    ums_agent_get_monotonic_time(&now);
    ums_agent_tls_pool_foreach(ums_agent_tls_conn_check_timeout_cb, &now);
}

uint32_t ums_agent_tls_conn_pool_get_count(void)
{
    return g_ums_agent_tls_conn_pool.conn_count;
}

bool ums_agent_tls_conn_pool_is_full(void)
{
    return g_ums_agent_tls_conn_pool.conn_count >= g_ums_agent_tls_conn_pool.max_conns;
}
