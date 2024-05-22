/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa sock implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2022-09-07
 * Note:
 * History: 2023-1-18: Rename tpsa_connect to tpsa_sock, porting sock function from daemon here
 */

#include <errno.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "ub_util.h"
#include "ub_hash.h"
#include "tpsa_log.h"
#include "tpsa_ioctl.h"
#include "uvs_protocol.h"
#include "uvs_security.h"

#include "tpsa_sock.h"

#define UVS_SOCK_TABLE_SIZE     2048

#define TPSA_SOCK_KEEP_IDLE     5   // if no data exchanged within 5 seconds, start detection.
#define TPSA_SOCK_KEEP_INTERVAL 5   // interval for sending detection packets is 5 seconds.
#define TPSA_SOCK_KEEP_COUNT    3   // number of detection retry times.
#define TPSA_SOCK_TIMEOUT       10  // 10s
#define TPSA_SOCK_IPV6_TENTAIVE_TIME 2

static inline void *fill_uvs_base_header(struct uvs_base_header *hdr, uint8_t version, uint8_t msg_type,
    uint16_t length, uint32_t msn, uint16_t cap, uint16_t flag)
{
    hdr->version = version;
    hdr->msg_type = msg_type;
    hdr->length = length;
    hdr->msn = msn;
    hdr->cap = cap;
    hdr->flag = flag;
    return (void *)(hdr + 1);
}
static inline void *fill_uvs_general_ack(struct uvs_general_ack *hdr, uint8_t ack_code)
{
    hdr->code = ack_code;
    return (void *)(hdr + 1);
}

static ssize_t secure_socket_send(uvs_sock_node_t *node, void *buf, size_t len, int timeout)
{
    struct timespec start = {0};
    struct timespec end = {0};
    SSL *ssl = node->ssl;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    int sent = 0;
    do {
        /* OpenSSL requires the same parameters when sending again. */
        sent = SSL_write(ssl, buf, len);
        int ret = SSL_get_error(ssl, sent);
        if (ret == SSL_ERROR_NONE) {
            /* OpenSSL ensures "sent == len". */
            break;
        }
        if (ret != SSL_ERROR_WANT_WRITE) {
            TPSA_LOG_ERR("SSL_write() fail, sent=%d, SSL_get_error=%d", sent, ret);
            break;
        }
        /* Just repeat with the same function call on nonblocking mode. */
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
    } while (end.tv_sec - start.tv_sec < timeout);

    return sent;
}

static ssize_t secure_socket_recv(uvs_sock_node_t *node, void *buf, size_t len, int timeout)
{
    struct timespec start = {0};
    struct timespec end = {0};
    SSL *ssl = node->ssl;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    int received = 0;
    do {
        /* OpenSSL requires the same parameters when receving again. */
        received = SSL_read(ssl, buf, len);
        int ret = SSL_get_error(ssl, received);
        if (ret == SSL_ERROR_NONE) {
            /* OpenSSL ensures "received == len". */
            break;
        }
        if (ret == SSL_ERROR_ZERO_RETURN) {
            TPSA_LOG_ERR("SSL peer has closed the TLS connection.\n");
            break;
        }
        if (ret != SSL_ERROR_WANT_READ) {
            TPSA_LOG_ERR("SSL_read() fail, received=%d, SSL_get_error=%d", received, ret);
            break;
        }
        /* Just repeat with the same function call on nonblocking mode. */
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
    } while (end.tv_sec - start.tv_sec < timeout);

    return received;
}

static ssize_t normal_socket_send(uvs_sock_node_t *node, void *buf, size_t len, int timeout)
{
    struct timespec start = {0};
    struct timespec end = {0};
    int fd = node->fd;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    size_t remain = len;
    char *addr = (char *)buf;
    do {
        ssize_t ret = send(fd, addr, remain, 0);
        if (ret > 0) {
            remain -= ret;
            addr += ret;
        } else if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                /* Try to send again on nonblocking mode. */
            } else {
                TPSA_LOG_ERR("Fail to send message, fd=%d, err=%s.\n", fd, ub_strerror(errno));
                break;
            }
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
    } while ((remain > 0) && (end.tv_sec - start.tv_sec < timeout));

    return (ssize_t)(len - remain);
}

static ssize_t normal_socket_recv(uvs_sock_node_t *node, void *buf, size_t len, int timeout)
{
    struct timespec start = {0};
    struct timespec end = {0};
    int fd = node->fd;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    size_t remain = len;
    char *addr = (char *)buf;
    do {
        ssize_t ret = recv(fd, addr, remain, 0);
        if (ret > 0) {
            remain -= ret;
            addr += ret;
        } else if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                /* Try to receive again on nonblocking mode. */
            } else {
                TPSA_LOG_ERR("Fail to receive message, fd: %d, err: %s.\n", fd, ub_strerror(errno));
                break;
            }
        } else {
            TPSA_LOG_ERR("The peer closes the connection, fd=%d).\n", fd);
            break;
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &end);
    } while ((remain > 0) && (end.tv_sec - start.tv_sec < timeout));

    return (ssize_t)(len - remain);
}

static bool tpsa_addr_is_ipv6(const uvs_net_addr_t *server_ip)
{
    if (server_ip->in4.resv == 0 && server_ip->in4.prefix == htonl(URMA_IPV4_MAP_IPV6_PREFIX)) {
        return false;
    }
    return true;
}

/* Set fd to be keepalive */
int tpsa_set_keepalive_opt(int fd)
{
    int ret;
    int keep_alive = 1;
    int keep_idle = TPSA_SOCK_KEEP_IDLE;
    int keep_interval = TPSA_SOCK_KEEP_INTERVAL;
    int keep_count = TPSA_SOCK_KEEP_COUNT;

    ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(keep_alive));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set keepalive, ret: %d, err: %d.\n", ret, errno);
        return ret;
    }
    ret = setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keep_idle, sizeof(keep_idle));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set keep_idle, ret: %d, err: %d.\n", ret, errno);
        return ret;
    }
    ret = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keep_interval, sizeof(keep_interval));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set keep_interval, ret: %d, err: %d.\n", ret, errno);
        return ret;
    }
    ret = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set keep_count, ret: %d, err: %d.\n", ret, errno);
        return ret;
    }
    return 0;
}

/* Set fd to be nonblocking */
int uvs_set_nonblock_opt(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        TPSA_LOG_ERR("Failed to get flags of fd, err: %d.\n", errno);
        return -1;
    }
    if (fcntl(fd, F_SETFL, (uint32_t)flags | O_NONBLOCK) == -1) {
        TPSA_LOG_ERR("Failed to set fd to non block, err: %d.\n", errno);
        return -1;
    }
    return 0;
}

/* Set socket to be nonblocking and tcp_nodelay */
static int uvs_set_socket_opt(int fd, bool is_noblock)
{
    int ret;

    if (is_noblock) {
        ret = uvs_set_nonblock_opt(fd);
        if (ret != 0) {
            TPSA_LOG_ERR("Failed to set socket nonblock, ret: %d, err: %d.\n", ret, errno);
            return ret;
        }
    }
    ret = tpsa_set_keepalive_opt(fd);
    if (ret != 0) {
        return ret;
    }

    int reuse = 1;
    /* Set socket reuse. When the server is restarted,
     * the problem of address already in use is solved */
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set reuse port, enable_reuse:%d, ret: %d, err: %d.\n",
            SO_REUSEPORT, ret, errno);
        return ret;
    }

    int nodelay = 1;
    ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set nodelay, enable_nodely:%d, ret: %d, err: %d.\n", TCP_NODELAY, ret, errno);
        return ret;
    }
    return 0;
}

int uvs_add_epoll_event(int epollfd, int fd, uint32_t events)
{
    struct epoll_event ev = {0};
    int ret;

    ev.events = events;
    ev.data.fd = fd;

    /* epoll_wait will always report for EPOLLERR and EPOLLHUP,
    it is not necessary to set it in events when calling epoll_ctl */
    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if (ret < 0) {
        TPSA_LOG_ERR("epoll_ctl(ep_fd=%d, ADD, fd=%d) failed, ret: %d, err: %s.\n", epollfd,
            ev.data.fd, ret, ub_strerror(errno));
        return -1;
    }
    TPSA_LOG_INFO("epoll_ctl(ep_fd=%d, ADD, fd=%d) succeed", epollfd, ev.data.fd);
    return 0;
}

static int tpsa_sock_bind(tpsa_sock_ctx_t *sock_ctx, uvs_socket_init_attr_t *attr)
{
    bool is_ipv6 = tpsa_addr_is_ipv6(&attr->server_ip);
    sa_family_t domain = is_ipv6 ? AF_INET6 : AF_INET;
    struct sockaddr_in6 src_addr6 = {0};
    struct sockaddr_in src_addr4 = {0};
    socklen_t addr_len;
    void *src_addr;
    int ret = 0;

    int fd = socket(domain, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create fd, ret: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    if (uvs_set_socket_opt(fd, true) != 0) {
        (void)close(fd);
        return -1;
    }

    if (is_ipv6) {
        addr_len = (socklen_t)sizeof(struct sockaddr_in6);
        src_addr = &src_addr6;
        src_addr6.sin6_family = domain;
        (void)memcpy(&src_addr6.sin6_addr, &attr->server_ip, sizeof(uvs_net_addr_t));
        src_addr6.sin6_port = attr->server_port;
    } else {
        addr_len = (socklen_t)sizeof(struct sockaddr_in);
        src_addr = &src_addr4;
        src_addr4.sin_family = domain;
        src_addr4.sin_addr.s_addr = attr->server_ip.in4.addr;
        src_addr4.sin_port = attr->server_port;
    }

    ret = bind(fd, (struct sockaddr *)src_addr, addr_len);
    if (ret != 0 && is_ipv6) {
        TPSA_LOG_WARN("Failed to bind port, err: [%d]%s, retry once.\n", errno, ub_strerror(errno));
        sleep(TPSA_SOCK_IPV6_TENTAIVE_TIME);
        ret = bind(fd, (struct sockaddr *)src_addr, addr_len);
    }
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to bind port, err: [%d]%s.\n", errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    sock_ctx->is_ipv6 = is_ipv6;
    sock_ctx->listen_fd = fd;
    sock_ctx->local_ip = attr->server_ip;
    sock_ctx->local_port = attr->server_port;
    return 0;
}

static inline void tpsa_sock_unbind(tpsa_sock_ctx_t *sock_ctx)
{
    (void)close(sock_ctx->listen_fd);
    sock_ctx->listen_fd = -1;
}

static int uvs_sock_connect(const uvs_net_addr_t *remote_uvs_ip, uint32_t cfg_port)
{
    bool is_ipv6 = tpsa_addr_is_ipv6(remote_uvs_ip);
    sa_family_t domain = is_ipv6 ? AF_INET6 : AF_INET;
    struct sockaddr_in6 addr6 = {0};
    struct sockaddr_in addr4 = {0};
    socklen_t addr_len;
    void *addr;
    int fd = socket(domain, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create socket, fd: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    if (is_ipv6) {
        addr_len = (socklen_t)sizeof(struct sockaddr_in6);
        addr = &addr6;
        addr6.sin6_family = domain;
        (void)memcpy(&addr6.sin6_addr, remote_uvs_ip, sizeof(uvs_net_addr_t));
        addr6.sin6_port = (uint16_t)cfg_port;
    } else {
        addr_len = (socklen_t)sizeof(struct sockaddr_in);
        addr = &addr4;
        addr4.sin_family = domain;
        addr4.sin_addr.s_addr = remote_uvs_ip->in4.addr;
        addr4.sin_port = (uint16_t)cfg_port;
    }
    int ret = connect(fd, (struct sockaddr *)addr, addr_len);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to connect socket to IP " EID_FMT " cfg_port 0x%x, ret: %d, err: [%d]%s.\n",
            EID_ARGS(*remote_uvs_ip), cfg_port, ret, errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }

    return fd;
}

static int tpsa_get_accept_fd(int listen_fd, bool is_ipv6, uvs_net_addr_t *remote_uvs_ip)
{
    struct sockaddr_in6 client_addr6 = {0};
    struct sockaddr_in client_addr4 = {0};
    socklen_t client_addr_len;
    void *client_addr;
    if (is_ipv6) {
        client_addr = &client_addr6;
        client_addr_len = sizeof(struct sockaddr_in6);
    } else {
        client_addr = &client_addr4;
        client_addr_len = sizeof(struct sockaddr_in);
    }
    int fd = accept(listen_fd, (struct sockaddr*)client_addr, &client_addr_len);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to accept socket, fd = %d, ret: %d, err: [%d]%s.\n",
            listen_fd, fd, errno, ub_strerror(errno));
        return -1;
    }

    if (is_ipv6) {
        (void)memcpy(remote_uvs_ip, &client_addr6.sin6_addr, sizeof(struct in6_addr));
    } else {
        remote_uvs_ip->in4.prefix = htonl(URMA_IPV4_MAP_IPV6_PREFIX);
        remote_uvs_ip->in4.addr = (uint32_t)client_addr4.sin_addr.s_addr;
    }
    return fd;
}

static uvs_sock_node_t *uvs_sock_tbl_lookup_by_ip(tpsa_sock_ctx_t *ctx, const uvs_net_addr_t *remote_ip)
{
    uint32_t hash = ub_hash_bytes(remote_ip, sizeof(uvs_net_addr_t), 0);
    uvs_sock_node_t *cur;
    uvs_sock_node_t *target = NULL;

    HMAP_FOR_EACH_WITH_HASH(cur, ip_node, hash, &ctx->ip_tbl) {
        if (memcmp(&cur->remote_ip, remote_ip, sizeof(uvs_net_addr_t)) == 0) {
            target = cur;
            break;
        }
    }
    return target;
}

static bool uvs_sock_node_in_fd_tbl(tpsa_sock_ctx_t *ctx, uvs_sock_node_t *node)
{
    uint32_t hash = ub_hash_bytes(&node->remote_ip, sizeof(uvs_net_addr_t), 0);
    uvs_sock_node_t *cur = NULL;

    HMAP_FOR_EACH_WITH_HASH(cur, ip_node, hash, &ctx->ip_tbl) {
        if (cur == node) {
            return true;
        }
    }
    return false;
}

static uvs_sock_node_t *uvs_sock_tbl_lookup_by_fd(tpsa_sock_ctx_t *ctx, int fd)
{
    uint32_t hash = (uint32_t)fd;
    uvs_sock_node_t *cur;
    uvs_sock_node_t *target = NULL;

    HMAP_FOR_EACH_WITH_HASH(cur, fd_node, hash, &ctx->fd_tbl) {
        if (cur->fd == fd) {
            target = cur;
            break;
        }
    }
    return target;
}

static uvs_sock_node_t *uvs_add_sock_node(tpsa_sock_ctx_t *ctx, int fd, SSL *ssl,
    const uvs_net_addr_t *remote_ip)
{
    uvs_sock_node_t *node = (uvs_sock_node_t *)calloc(1, sizeof(uvs_sock_node_t));
    if (node == NULL) {
        return NULL;
    }
    node->fd = fd;
    node->ssl = ssl;
    node->remote_ip = *remote_ip;

    ub_hmap_insert(&ctx->fd_tbl, &node->fd_node, (uint32_t)fd);

    /* When uvs1 and uvs2 concurrent connect,
       thd fds get from accept() can not add to ip_table, only use as receiver fd. */
    if (uvs_sock_tbl_lookup_by_ip(ctx, remote_ip) == NULL) {
        ub_hmap_insert(&ctx->ip_tbl, &node->ip_node, ub_hash_bytes(remote_ip, sizeof(uvs_net_addr_t), 0));
    } else {
        TPSA_LOG_INFO("uvs concurrent connect, remote_ip: " EID_FMT " not add to ip_table\n", EID_ARGS(*remote_ip));
    }
    return node;
}

static void uvs_rmv_sock_node(tpsa_sock_ctx_t *ctx, uvs_sock_node_t *node)
{
    ub_hmap_remove(&ctx->fd_tbl, &node->fd_node);

    // In uvs concurrent conncet case, sock node may not in ip_tbl.
    if (uvs_sock_node_in_fd_tbl(ctx, node)) {
        ub_hmap_remove(&ctx->ip_tbl, &node->ip_node);
    }
    free(node);
}

static void uvs_sock_tbl_remove_by_fd(tpsa_sock_ctx_t *ctx, int fd)
{
    uint32_t hash = (uint32_t)fd;
    uvs_sock_node_t *cur;

    HMAP_FOR_EACH_WITH_HASH(cur, fd_node, hash, &ctx->fd_tbl) {
        if (cur->fd == fd) {
            uvs_destroy_secure_socket(cur->ssl);
            uvs_rmv_sock_node(ctx, cur);
            break;
        }
    }
}

static void uvs_destroy_socket_node(tpsa_sock_ctx_t *ctx, uvs_sock_node_t *node)
{
    uvs_destroy_secure_socket(node->ssl);
    (void)epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, node->fd, NULL);
    (void)close(node->fd);
    uvs_rmv_sock_node(ctx, node);
}

void uvs_destroy_socket(tpsa_sock_ctx_t *ctx, int fd)
{
    uvs_sock_tbl_remove_by_fd(ctx, fd);
    (void)epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, fd, NULL);
    (void)close(fd);
}

static uvs_sock_node_t *uvs_get_sock_node(tpsa_sock_ctx_t *ctx, uvs_net_addr_t remote_ip, uint32_t port)
{
    /* Caution: accessing node outside lock causes contetion, e.g., another thread tries to delete this node.
     * Change it when UVS uses multiple working threads. */
    uvs_sock_node_t *node = uvs_sock_tbl_lookup_by_ip(ctx, &remote_ip);
    if (node != NULL) {
        return node;
    }

    int fd = uvs_sock_connect(&remote_ip, port);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to connect.\n");
        return NULL;
    }

    SSL *ssl = NULL;
    /* Self connection do not need SSL. */
    if (ctx->enable_ssl && memcmp(&ctx->local_ip, &remote_ip, sizeof(uvs_net_addr_t)) != 0) {
        ssl = uvs_create_secure_socket(fd, &ctx->ssl_cfg, false);
        if (ssl == NULL) {
            TPSA_LOG_ERR("Fail to create secure socket.\n");
            goto ERR_FD;
        }
    }

    if (uvs_set_socket_opt(fd, true) != 0) {
        TPSA_LOG_ERR("Fail to set socket option.\n");
        goto ERR_SSL;
    }

    node = uvs_add_sock_node(ctx, fd, ssl, &remote_ip);
    if (node == NULL) {
        TPSA_LOG_ERR("Failed to add to socket table.");
        goto ERR_SSL;
    }

    /* Upon receiving, socket node is to be found in the first place.
     * Therefore, adding epoll event should be the last step. */
    if (uvs_add_epoll_event(ctx->epollfd, fd, EPOLLIN | EPOLLRDHUP) != 0) {
        TPSA_LOG_ERR("Failed to add epoll event.\n");
        goto ERR_NODE;
    }

    TPSA_LOG_INFO("new connect IP: 0x" EID_FMT ", port: %d, fd: %d.\n", EID_ARGS(remote_ip), port, fd);
    return node;

ERR_NODE:
    uvs_rmv_sock_node(ctx, node);
ERR_SSL:
    uvs_destroy_secure_socket(ssl);
ERR_FD:
    (void)close(fd);
    return NULL;
}

int tpsa_handle_accept_fd(tpsa_sock_ctx_t *ctx)
{
    uvs_net_addr_t remote_ip = {0};
    uvs_sock_node_t *node = NULL;
    int fd = tpsa_get_accept_fd(ctx->listen_fd, ctx->is_ipv6, &remote_ip);
    if (fd < 0) {
        TPSA_LOG_ERR("Fail to get accept fd.\n");
        return -1;
    }
    TPSA_LOG_INFO("Socket accepted, remote_ip: " EID_FMT ", local_port=%d, fd=%d\n",
        EID_ARGS(remote_ip), ctx->local_port, fd);

    SSL *ssl = NULL;
    if (ctx->enable_ssl && memcmp(&remote_ip, &ctx->local_ip, sizeof(uvs_net_addr_t)) != 0) {
        ssl = uvs_create_secure_socket(fd, &ctx->ssl_cfg, true);
        if (ssl == NULL) {
            TPSA_LOG_ERR("Fail to create secure socket.\n");
            goto ERR_FD;
        }
    }

    if (uvs_set_socket_opt(fd, true) != 0) {
        TPSA_LOG_ERR("Fail to set socket option.\n");
        goto ERR_SSL;
    }

    node = uvs_add_sock_node(ctx, fd, ssl, &remote_ip);
    if (node == NULL) {
        TPSA_LOG_ERR("Failed to create socket node.\n");
        goto ERR_SSL;
    }

    if (uvs_add_epoll_event(ctx->epollfd, fd, EPOLLIN | EPOLLRDHUP) != 0) {
        TPSA_LOG_ERR("Failed to add epoll event.\n");
        goto ERR_NODE;
    }

    return 0;

ERR_NODE:
    uvs_rmv_sock_node(ctx, node);
ERR_SSL:
    uvs_destroy_secure_socket(ssl);
ERR_FD:
    (void)close(fd);
    return -1;
}

int tpsa_sock_send_msg(tpsa_sock_ctx_t *ctx, tpsa_sock_msg_t *msg,
    size_t len, uvs_net_addr_t remote_uvs_ip)
{
    if (len > sizeof(tpsa_sock_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    /* Always us remote_ip to the Sender fd */
    uvs_sock_node_t *node = uvs_get_sock_node(ctx, remote_uvs_ip, ctx->local_port);
    if (node == NULL) {
        TPSA_LOG_ERR("Failed to get socket to IP 0x" EID_FMT ", port 0x%x\n",
                     EID_ARGS(remote_uvs_ip), ctx->local_port);
        return -1;
    }

    /* For request, msn should be set using a global atomic variable.
     * For response, msn should be copied in each message handler.
     * Currently, msn is ignored. Fill it when message context is introduced. */
    if (node->negotiated) {
        (void)fill_uvs_base_header(&msg->base, node->version, (uint8_t)msg->msg_type,
            sizeof(tpsa_sock_msg_t) - sizeof(struct uvs_base_header), 0, node->cap, 0);
    } else {
        (void)fill_uvs_base_header(&msg->base, UVS_PROTO_CUR_VERSION, (uint8_t)msg->msg_type,
            sizeof(tpsa_sock_msg_t) - sizeof(struct uvs_base_header), 0, UVS_PROTO_CAP, 0);
    }

    if (ctx->sock_send(node, msg, len, TPSA_SOCK_TIMEOUT) != (ssize_t)len) {
        TPSA_LOG_ERR("Fail to send message, err: [%d]%s.\n", errno, ub_strerror(errno));
        uvs_destroy_socket_node(ctx, node);
        return -1;
    }
    return 0;
}

int uvs_send_general_ack(tpsa_sock_ctx_t *ctx, tpsa_sock_msg_t *in, int fd, uint8_t ack_code)
{
    uvs_sock_node_t *node = uvs_sock_tbl_lookup_by_fd(ctx, fd);
    if (node == NULL) {
        TPSA_LOG_ERR("Fail to find socket node, fd=%d.\n", fd);
        return -1;
    }

    uint32_t tx_size = sizeof(struct uvs_base_header) + sizeof(struct uvs_general_ack);
    void *tx_buf = malloc(tx_size);
    if (tx_buf == NULL) {
        TPSA_LOG_ERR("Fail to malloc TX buffer.\n");
        return -ENOMEM;
    }

    void *ptr = tx_buf;
    ptr = fill_uvs_base_header((struct uvs_base_header *)ptr, node->version, UVS_GENERAL_ACK,
        sizeof(struct uvs_general_ack), in->base.msn, node->cap, 0);
    (void)fill_uvs_general_ack((struct uvs_general_ack *)ptr, UVS_PROTO_ACK_VER_NOT_SUPPORT);

    int rc = 0;
    if (ctx->sock_send(node, tx_buf, tx_size, TPSA_SOCK_TIMEOUT) != tx_size) {
        TPSA_LOG_ERR("Fail to send msg, err: [%d]%s.\n", errno, ub_strerror(errno));
        uvs_destroy_socket_node(ctx, node);
        rc = -1;
    }

    free(tx_buf);
    return rc;
}

/* RX buffers for UVS header and payload should be separated when UVS protocol is ready. */
int uvs_socket_recv(tpsa_sock_ctx_t *ctx, int fd, void *buf, uint32_t len)
{
    struct uvs_base_header *base = (struct uvs_base_header *)buf;

    uvs_sock_node_t *node = uvs_sock_tbl_lookup_by_fd(ctx, fd);
    if (node == NULL) {
        return -1;
    }

    ssize_t recv_len = ctx->sock_recv(node, buf, sizeof(struct uvs_base_header), TPSA_SOCK_TIMEOUT);
    if (recv_len != sizeof(struct uvs_base_header)) {
        TPSA_LOG_ERR("Fail to receive UVS base header.\n");
        goto ERR;
    }

    if (sizeof(struct uvs_base_header) + base->length > len) {
        TPSA_LOG_ERR("RX buffer too small, buf_size=%u, msg_size=%u.\n",
            len, sizeof(struct uvs_base_header) + base->length);
        goto ERR;
    }

    recv_len = ctx->sock_recv(node, (char *)buf + sizeof(struct uvs_base_header), base->length, TPSA_SOCK_TIMEOUT);
    if (recv_len != base->length) {
        TPSA_LOG_ERR("Fail to receive UVS message payload.\n");
        goto ERR;
    }

    return 0;

ERR:
    uvs_destroy_socket_node(ctx, node);
    return -1;
}

/* Return incoming request's version. */
int uvs_proto_nego_for_req(tpsa_sock_ctx_t *ctx, int fd, struct uvs_base_header *req)
{
    uvs_sock_node_t *node = uvs_sock_tbl_lookup_by_fd(ctx, fd);
    if (node == NULL) {
        TPSA_LOG_ERR("Fail to lookup socket node by FD(%d).\n", fd);
        return -1;
    }

    if (node->negotiated) {
        return node->version;
    }

    int rc = 0;
    if (req->version == UVS_PROTO_CUR_VERSION) {
        node->version = UVS_PROTO_CUR_VERSION;
        rc = UVS_PROTO_CUR_VERSION;
    } else {
        node->version = UVS_PROTO_BASE_VERSION;
        if (req->version == UVS_PROTO_BASE_VERSION) {
            rc = UVS_PROTO_BASE_VERSION;
        } else {
            rc = (int)UVS_PROTO_INVALID_VERSION;
        }
    }

    node->cap = req->cap & UVS_PROTO_CAP;
    node->negotiated = true;
    TPSA_LOG_INFO("UVS protocol version negotiation, req_ver=%u, local_cur_ver=%u, local_base_ver=%u.\n",
        req->version, UVS_PROTO_CUR_VERSION, UVS_PROTO_BASE_VERSION);

    return rc;
}

int uvs_proto_nego_for_rsp(tpsa_sock_ctx_t *ctx, int fd, struct uvs_base_header *rsp)
{
    uvs_sock_node_t *node = uvs_sock_tbl_lookup_by_fd(ctx, fd);
    if (node == NULL) {
        TPSA_LOG_ERR("Fail to lookup socket node by FD(%d).\n", fd);
        return -1;
    }

    if (node->negotiated) {
        return 0;
    }

    /* Version negotiation fails only when target sends general ack.
     * Thus, remove below statement when UVS protocol is completed. */
    if (rsp->version != UVS_PROTO_CUR_VERSION && rsp->version != UVS_PROTO_BASE_VERSION) {
        TPSA_LOG_ERR("UVS protocol version negotiation fails, remote_ver=%u, local_cur_ver=%u, local_base_ver=%u.\n",
            rsp->version, UVS_PROTO_CUR_VERSION, UVS_PROTO_BASE_VERSION);
        return -1;
    }

    node->version = rsp->version;
    node->cap = rsp->cap;
    node->negotiated = true;
    TPSA_LOG_INFO("UVS protocol version negotiation, rsp_ver=%u, local_cur_ver=%u, local_base_ver=%u.\n",
        rsp->version, UVS_PROTO_CUR_VERSION, UVS_PROTO_BASE_VERSION);
    return 0;
}

static int uvs_sock_table_init(tpsa_sock_ctx_t *ctx)
{
    if (ub_hmap_init(&ctx->fd_tbl, UVS_SOCK_TABLE_SIZE) != 0) {
        return -1;
    }
    if (ub_hmap_init(&ctx->ip_tbl, UVS_SOCK_TABLE_SIZE) != 0) {
        ub_hmap_destroy(&ctx->fd_tbl);
        return -1;
    }

    return 0;
}

static void uvs_sock_table_uninit(tpsa_sock_ctx_t *ctx)
{
    uvs_sock_node_t *cur, *next;

    HMAP_FOR_EACH_SAFE(cur, next, fd_node, &ctx->fd_tbl) {
        ub_hmap_remove(&ctx->fd_tbl, &cur->fd_node);
        ub_hmap_remove(&ctx->ip_tbl, &cur->ip_node);
        (void)epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, cur->fd, NULL);
        (void)close(cur->fd);
        free(cur);
    }
    ub_hmap_destroy(&ctx->fd_tbl);
    ub_hmap_destroy(&ctx->ip_tbl);
}

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx, uvs_socket_init_attr_t *attr)
{
    if (attr != NULL && attr->ssl_cfg != NULL) {
        if (uvs_ssl_init(attr->ssl_cfg) != 0) {
            TPSA_LOG_ERR("Fail to initialize SSL.\n");
            return -1;
        }
        sock_ctx->ssl_cfg = *attr->ssl_cfg;
        sock_ctx->enable_ssl = true;
        sock_ctx->sock_send = secure_socket_send;
        sock_ctx->sock_recv = secure_socket_recv;
    } else {
        sock_ctx->sock_send = normal_socket_send;
        sock_ctx->sock_recv = normal_socket_recv;
    }

    if (uvs_sock_table_init(sock_ctx) != 0) {
        TPSA_LOG_ERR("Failed to init sock table");
        return -1;
    }

    if (attr == NULL || tpsa_sock_bind(sock_ctx, attr) != 0) {
        TPSA_LOG_ERR("Failed to tpsa bind.\n");
        uvs_sock_table_uninit(sock_ctx);
        return -1;
    }

    return 0;
}

void tpsa_sock_server_uninit(tpsa_sock_ctx_t *sock_ctx)
{
    tpsa_sock_unbind(sock_ctx);
    uvs_sock_table_uninit(sock_ctx);
}

static void tpsa_sock_init_content_param(tpsa_sock_msg_t *req, tpsa_init_sock_req_param_t *param,
    tpsa_create_param_t *cparam)
{
    req->content.req.msg_id = cparam->msg_id;
    req->content.req.nlmsg_seq = cparam->nlmsg_seq;
    req->content.req.src_function_id = cparam->fe_idx;
    req->content.req.tpg_cfg = param->tpg_cfg;
    (void)memcpy(req->content.req.dev_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
    req->content.req.cc_array_cnt = param->cc_array_cnt;
    (void)memcpy(req->content.req.cc_result_array,
        param->cc_result_array, sizeof(tpsa_tp_cc_entry_t) * param->cc_array_cnt);
    req->content.req.cc_en = param->cc_en;
    req->content.req.share_mode = cparam->share_mode;
    req->content.req.pattern = cparam->pattern;
    req->content.req.ta_data = cparam->ta_data;
    req->content.req.udrv_in_len = cparam->udrv_in_len;
    req->content.req.ext_len = cparam->ext_len;
    (void)memcpy(req->content.req.udrv_ext, cparam->udrv_ext, cparam->udrv_in_len + cparam->ext_len);

    req->content.req.tp_param.com.local_net_addr_idx = param->local_net_addr_idx; /* Need to fix */
    req->content.req.tp_param.com.peer_net_addr = param->peer_net_addr;
    req->content.req.tp_param.com.state = UVS_TP_STATE_RTR;
    req->content.req.tp_param.com.tx_psn = 0;
    req->content.req.tp_param.com.rx_psn = param->rx_psn;
    req->content.req.tp_param.com.local_mtu = param->local_mtu;
    req->content.req.tp_param.com.peer_mtu = param->local_mtu;
    req->content.req.tp_param.com.local_seg_size = param->local_seg_size;
    req->content.req.tp_param.com.peer_seg_size = 0;
    req->content.req.tp_param.com.local_tp_cfg = param->local_tp_cfg;
    req->content.req.tp_param.com.remote_tp_cfg = param->local_tp_cfg;

    uint32_t i = 0;
    for (; i < param->tp_cnt && i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        req->content.req.tp_param.uniq[i].local_tpn = param->local_tpn[i];
        req->content.req.tp_param.uniq[i].peer_tpn = 0;
    }
}

tpsa_sock_msg_t *tpsa_sock_init_create_req(tpsa_create_param_t *cparam, tpsa_init_sock_req_param_t *param,
    uvs_net_addr_info_t *sip, uvs_socket_init_attr_t *tpsa_attr)
{
    tpsa_sock_msg_t *req = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        return NULL;
    }
    if (cparam->udrv_in_len + cparam->ext_len > TPSA_UDRV_DATA_LEN) {
        TPSA_LOG_ERR("udrv data buffer is short\n");
        goto free_req;
    }

    req->msg_type = TPSA_CREATE_REQ;
    req->trans_mode = cparam->trans_mode;
    req->src_uvs_ip = tpsa_attr->server_ip;
    req->migrate_third = cparam->migrate_third;
    req->sip = *sip;

    req->local_eid = cparam->local_eid;
    req->peer_eid = cparam->peer_eid;
    req->local_jetty = cparam->local_jetty;
    req->peer_jetty = cparam->peer_jetty;
    req->vtpn = cparam->vtpn;
    req->local_tpgn = param->tpgn;
    req->peer_tpgn = 0;
    req->upi = param->upi;
    req->live_migrate = cparam->live_migrate;

    tpsa_sock_init_content_param(req, param, cparam);

    return req;

free_req:
    free(req);
    return NULL;
}

void tpsa_sock_init_destroy_resp(tpsa_sock_msg_t *resp)
{
    free(resp);
}

tpsa_sock_msg_t *tpsa_sock_init_create_resp(tpsa_sock_msg_t* msg, struct tpsa_init_sock_resp_param* param)
{
    tpsa_create_req_t *req = &msg->content.req;

    tpsa_sock_msg_t *resp = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (resp == NULL) {
        return NULL;
    }
    resp->content.resp.is_target = param->is_target;
    resp->msg_type = TPSA_CREATE_RESP;
    resp->trans_mode = msg->trans_mode;
    resp->src_uvs_ip = param->src_uvs_ip;
    resp->migrate_third = msg->migrate_third;
    resp->sip = param->sip;
    resp->local_eid = msg->local_eid;
    resp->peer_eid = msg->peer_eid;
    resp->local_jetty = msg->local_jetty;
    resp->peer_jetty = msg->peer_jetty;
    resp->vtpn = msg->vtpn;
    resp->local_tpgn = msg->local_tpgn;
    resp->peer_tpgn = param->tpgn;
    resp->upi = msg->upi;
    resp->live_migrate = msg->live_migrate;
    resp->content.resp.tpg_cfg = *param->tpg_cfg;
    resp->content.resp.msg_id = req->msg_id;
    resp->content.resp.nlmsg_seq = req->nlmsg_seq;
    resp->content.resp.src_function_id = req->src_function_id;
    (void)memcpy(resp->content.resp.dev_name, req->dev_name, UVS_MAX_DEV_NAME);
    resp->content.resp.target_cc_cnt = param->resp_param->target_cc_cnt;
    (void)memcpy(resp->content.resp.target_cc_arr, param->resp_param->cc_result_array,
        param->resp_param->target_cc_cnt * sizeof(tpsa_tp_cc_entry_t));

    if (req->cc_array_cnt > TPSA_CC_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid cc array cnt:%d\n", req->cc_array_cnt);
        free(resp);
        return NULL;
    }
    resp->content.resp.target_cc_en = param->resp_param->target_cc_en;
    resp->content.resp.local_cc_cnt = req->cc_array_cnt;
    (void)memcpy(resp->content.resp.local_cc_arr,
        req->cc_result_array, req->cc_array_cnt * sizeof(tpsa_tp_cc_entry_t));
    resp->content.resp.local_cc_en = req->cc_en;
    resp->content.resp.share_mode = param->share_mode;
    resp->content.resp.ta_data = req->ta_data;
    (void)memcpy((char *)resp->content.resp.ext, (char *)req->udrv_ext, TPSA_UDRV_DATA_LEN);

    resp->content.resp.tp_param.com.local_tp_cfg = req->tp_param.com.local_tp_cfg;
    resp->content.resp.tp_param.com.remote_tp_cfg = req->tp_param.com.remote_tp_cfg;
    resp->content.resp.tp_param.com.local_net_addr_idx = req->tp_param.com.local_net_addr_idx;
    resp->content.resp.tp_param.com.peer_net_addr = req->tp_param.com.peer_net_addr; /* Need to fix */
    resp->content.resp.tp_param.com.state = UVS_TP_STATE_RTR;
    resp->content.resp.tp_param.com.tx_psn = 0; /* Need to check */
    resp->content.resp.tp_param.com.rx_psn = req->tp_param.com.rx_psn;
    resp->content.resp.tp_param.com.local_mtu = req->tp_param.com.local_mtu;
    resp->content.resp.tp_param.com.peer_mtu = param->mtu;
    resp->content.resp.tp_param.com.local_seg_size = req->tp_param.com.local_seg_size;
    resp->content.resp.tp_param.com.peer_seg_size = SEG_SIZE;

    uint32_t i = 0;
    for (; i < req->tpg_cfg.tp_cnt && i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        resp->content.resp.tp_param.uniq[i].local_tpn = req->tp_param.uniq[i].local_tpn;
        resp->content.resp.tp_param.uniq[i].peer_tpn = param->tp[i].tpn;
    }

    return resp;
}

int tpsa_sock_send_create_ack(tpsa_sock_ctx_t *sock_ctx, tpsa_sock_msg_t *msg, uvs_net_addr_info_t *sip,
    uvs_socket_init_attr_t *tpsa_attr, uvs_net_addr_t *remote_uvs_ip)
{
    tpsa_create_resp_t *resp = &msg->content.resp;
    tpsa_sock_msg_t *ack = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (ack == NULL) {
        return -1;
    }

    ack->msg_type = TPSA_CREATE_ACK;
    ack->trans_mode = msg->trans_mode;
    ack->src_uvs_ip = tpsa_attr->server_ip;
    ack->migrate_third = msg->migrate_third;
    ack->sip = *sip;

    ack->local_eid = msg->local_eid;
    ack->peer_eid = msg->peer_eid;
    ack->local_jetty = msg->local_jetty;
    ack->peer_jetty = msg->peer_jetty;
    ack->vtpn = msg->vtpn;
    ack->local_tpgn = msg->local_tpgn;
    ack->peer_tpgn = msg->peer_tpgn;
    ack->upi = msg->upi;
    ack->live_migrate = msg->live_migrate;
    ack->content.ack.msg_id = msg->content.resp.msg_id;
    ack->content.ack.nlmsg_seq = msg->content.resp.nlmsg_seq;
    (void)memcpy(ack->content.ack.dev_name, msg->content.resp.dev_name, UVS_MAX_DEV_NAME);
    ack->content.ack.src_function_id = msg->content.resp.src_function_id;
    ack->content.ack.share_mode = msg->content.resp.share_mode;
    ack->content.ack.tpg_cfg = msg->content.resp.tpg_cfg;
    ack->content.ack.is_target = msg->content.resp.is_target;
    ack->content.ack.ta_data = resp->ta_data;

    ack->content.ack.tp_param.com = msg->content.resp.tp_param.com;
    uint32_t i = 0;
    for (; i < msg->content.resp.tpg_cfg.tp_cnt && i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        ack->content.ack.tp_param.uniq[i] = msg->content.resp.tp_param.uniq[i];
    }

    int ret = tpsa_sock_send_msg(sock_ctx, ack, sizeof(tpsa_sock_msg_t), *remote_uvs_ip);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send create vtp ack in worker\n");
    }

    free(ack);
    return ret;
}

tpsa_sock_msg_t *tpsa_sock_init_destroy_finish(tpsa_sock_msg_t* msg, uvs_net_addr_info_t *sip)
{
    tpsa_sock_msg_t *finish = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (finish == NULL) {
        return NULL;
    }

    finish->msg_type = TPSA_DESTROY_FINISH;
    finish->trans_mode = msg->trans_mode;
    finish->sip = *sip;
    finish->local_eid = msg->local_eid;
    finish->peer_eid = msg->peer_eid;
    finish->local_jetty = msg->local_jetty;
    finish->peer_jetty = msg->peer_jetty;
    finish->vtpn = msg->vtpn;
    finish->local_tpgn = msg->local_tpgn;
    finish->peer_tpgn = msg->peer_tpgn;
    finish->upi = msg->upi;
    finish->live_migrate = msg->live_migrate;
    finish->content.dfinish.resp_id = msg->content.dreq.resp_id;
    finish->content.dfinish.ta_data = msg->content.dreq.ta_data;
    finish->content.dfinish.src_fe_idx = msg->content.dreq.src_fe_idx;
    (void)memcpy(finish->content.dfinish.src_tpf_name,
        msg->content.dreq.src_tpf_name, UVS_MAX_DEV_NAME);
    return finish;
}

tpsa_sock_msg_t *tpsa_sock_init_table_sync(tpsa_create_param_t *cparam, tpsa_table_opcode_t opcode, uint32_t src_vtpn,
                                           uvs_net_addr_info_t *sip, uvs_socket_init_attr_t *tpsa_attr)
{
    tpsa_sock_msg_t *tsync = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (tsync == NULL) {
        return NULL;
    }

    tsync->msg_type = TPSA_TABLE_SYC;
    tsync->trans_mode = cparam->trans_mode;
    tsync->sip = *sip;
    tsync->src_uvs_ip = tpsa_attr->server_ip;
    tsync->local_eid = cparam->local_eid;
    tsync->peer_eid = cparam->peer_eid;
    tsync->local_jetty = cparam->local_jetty;
    tsync->peer_jetty = cparam->peer_jetty;
    tsync->vtpn = src_vtpn;
    tsync->local_tpgn = 0;
    tsync->peer_tpgn = 0;
    tsync->upi = cparam->upi;
    tsync->live_migrate = cparam->live_migrate;

    tsync->content.tsync.opcode = opcode;
    tsync->content.tsync.nl_resp_id.is_need_resp = !cparam->live_migrate; // live migrate not need to resp nl
    tsync->content.tsync.nl_resp_id.msg_id = cparam->msg_id;
    tsync->content.tsync.nl_resp_id.nlmsg_seq = cparam->nlmsg_seq;
    tsync->content.tsync.nl_resp_id.src_fe_idx = cparam->fe_idx;
    (void)memcpy(tsync->content.tsync.dev_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
    tsync->content.tsync.share_mode = cparam->share_mode;

    return tsync;
}
