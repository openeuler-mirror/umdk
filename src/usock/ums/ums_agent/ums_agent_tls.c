/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS module implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-07
 * Note:
 * History: 2026-05-07  Create File
 */

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ums_agent_log.h"
#include "ums_agent_epoll.h"
#include "ums_agent_utils.h"
#include "ums_agent_tls_ctx.h"
#include "ums_agent_tls_conn.h"
#include "ums_agent_tls.h"

struct ums_agent_tls {
    int listen_fd;
    bool initialized;
};

static struct ums_agent_tls g_ums_agent_tls = {
    .listen_fd = -1,
    .initialized = false,
};

static int ums_agent_tls_start_listen(const struct ums_agent_ip_addr *addr, int port)
{
    if (g_ums_agent_tls.listen_fd >= 0) {
        UMS_AGENT_LOG_WARN("TLS already listening on fd=%d", g_ums_agent_tls.listen_fd);
        return 0;
    }

    struct sockaddr_storage sa_storage;
    socklen_t sa_len = 0;
    ums_agent_ip_addr_to_sockaddr(addr, (uint16_t)port,
        (struct sockaddr *)&sa_storage, &sa_len);

    int fd = socket(addr->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        UMS_AGENT_LOG_ERR("socket failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        UMS_AGENT_LOG_ERR("setsockopt SO_REUSEADDR failed: %s (errno=%d)",
            strerror(errno), errno);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa_storage, sa_len) < 0) {
        UMS_AGENT_LOG_ERR("bind %s:%d failed: %s (errno=%d)",
            ums_agent_ip_addr_fmt(addr).str, port, strerror(errno), errno);
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0) {
        UMS_AGENT_LOG_ERR("listen %s:%d failed: %s (errno=%d)",
            ums_agent_ip_addr_fmt(addr).str, port, strerror(errno), errno);
        close(fd);
        return -1;
    }

    if (ums_agent_epoll_add_fd(fd, EPOLLIN) < 0) {
        close(fd);
        return -1;
    }

    g_ums_agent_tls.listen_fd = fd;
    UMS_AGENT_LOG_DEBUG("TLS listening on %s:%d, fd=%d",
        ums_agent_ip_addr_fmt(addr).str, port, fd);
    return 0;
}

static void ums_agent_tls_stop_listen(void)
{
    if (g_ums_agent_tls.listen_fd >= 0) {
        (void)ums_agent_epoll_del_fd(g_ums_agent_tls.listen_fd);
        close(g_ums_agent_tls.listen_fd);
        g_ums_agent_tls.listen_fd = -1;
        UMS_AGENT_LOG_DEBUG("TLS listener stopped");
    }
}

int ums_agent_tls_init(const struct ums_agent_config *config)
{
    if (g_ums_agent_tls.initialized) {
        UMS_AGENT_LOG_WARN("TLS already initialized");
        return 0;
    }

    if (ums_agent_tls_check_certs_expiry(config->server.certificate,
        config->client.certificate, true) != 0) {
        UMS_AGENT_LOG_ERR("certificate expiry check failed");
        return -1;
    }

    if (ums_agent_tls_ctx_init(config) != 0) {
        UMS_AGENT_LOG_ERR("TLS ctx init failed");
        return -1;
    }

    if (ums_agent_tls_conn_pool_init((uint32_t)config->max_conns, NULL) != 0) {
        UMS_AGENT_LOG_ERR("ums_agent_tls_conn_pool_init failed, max_conns=%d", config->max_conns);
        ums_agent_tls_ctx_deinit();
        return -1;
    }

    if (ums_agent_tls_start_listen(&config->listen_addr, config->listen_port) != 0) {
        UMS_AGENT_LOG_ERR("TLS listen failed on %s:%d",
            ums_agent_ip_addr_fmt(&config->listen_addr).str, config->listen_port);
        ums_agent_tls_conn_pool_deinit();
        ums_agent_tls_ctx_deinit();
        return -1;
    }

    g_ums_agent_tls.initialized = true;
    return 0;
}

void ums_agent_tls_deinit(void)
{
    if (!g_ums_agent_tls.initialized) {
        return;
    }

    ums_agent_tls_stop_listen();
    ums_agent_tls_conn_pool_deinit();
    ums_agent_tls_ctx_deinit();

    g_ums_agent_tls.initialized = false;
}

void ums_agent_tls_handle_event(int fd, uint32_t events)
{
    if (fd == g_ums_agent_tls.listen_fd) {
        if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
            UMS_AGENT_LOG_ERR("epoll error on listen fd=%d, events=0x%x, stopping listener",
                fd, events);
            ums_agent_tls_stop_listen();
            return;
        }

        if ((events & EPOLLIN) != 0) {
            int ret;
            do {
                ret = ums_agent_tls_conn_accept(fd);
            } while (ret > 0);

            if (ret < 0) {
                UMS_AGENT_LOG_ERR("accept loop terminated due to error");
            }
        }
        return;
    }

    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_pool_find_by_fd(fd);
    if (!conn) {
        UMS_AGENT_LOG_WARN("epoll event for unknown fd=%d", fd);
        return;
    }

    ums_agent_tls_conn_handle_event(conn, events);
}

void ums_agent_tls_timer_tick(const struct ums_agent_config *config)
{
    ums_agent_tls_conn_pool_timer_tick();

    (void)ums_agent_tls_check_certs_expiry(config->server.certificate,
        config->client.certificate, false);
}
