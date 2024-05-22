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
#include "tpsa_net.h"
#include "tpsa_ioctl.h"
#include "tpsa_sock.h"

#define TPSA_SOCK_TABLE_SIZE 10240

#define TPSA_SOCK_KEEP_IDLE      (5)     // if no data exchanged within 5 seconds, start detection.
#define TPSA_SOCK_KEEP_INTERVAL  (5)     // interval for sending detection packets is 5 seconds.
#define TPSA_SOCK_KEEP_COUNT     (3)     // number of detection retry times.

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
int tpsa_set_nonblock_opt(int fd)
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
static int tpsa_set_socket_opt(int fd, bool is_noblock)
{
    int ret;

    if (is_noblock) {
        ret = tpsa_set_nonblock_opt(fd);
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

int tpsa_add_epoll_event(int epollfd, int fd, uint32_t events)
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
    int fd = socket(domain, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create fd, ret: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_set_socket_opt(fd, true) != 0) {
        (void)close(fd);
        return -1;
    }

    if (is_ipv6) {
        addr_len = sizeof(struct sockaddr_in6);
        src_addr = &src_addr6;
        src_addr6.sin6_family = domain;
        (void)memcpy(&src_addr6.sin6_addr, &attr->server_ip, sizeof(uvs_net_addr_t));
        src_addr6.sin6_port = attr->server_port;
    } else {
        addr_len = sizeof(struct sockaddr_in);
        src_addr = &src_addr4;
        src_addr4.sin_family = domain;
        src_addr4.sin_addr.s_addr = attr->server_ip.in4.addr;
        src_addr4.sin_port = attr->server_port;
    }

    if (bind(fd, (struct sockaddr *)src_addr, addr_len) != 0) {
        TPSA_LOG_ERR("Failed to bind port, err: [%d]%s.\n", errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    sock_ctx->is_ipv6 = is_ipv6;
    sock_ctx->listen_fd = fd;
    sock_ctx->listen_port = attr->server_port;
    return 0;
}

static inline void tpsa_sock_unbind(tpsa_sock_ctx_t *sock_ctx)
{
    (void)close(sock_ctx->listen_fd);
    sock_ctx->listen_fd = -1;
}

static int tpsa_sock_connect(const uvs_net_addr_t *remote_uvs_ip, uint32_t cfg_port)
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
        addr_len = sizeof(struct sockaddr_in6);
        addr = &addr6;
        addr6.sin6_family = domain;
        (void)memcpy(&addr6.sin6_addr, remote_uvs_ip, sizeof(uvs_net_addr_t));
        addr6.sin6_port = (uint16_t)cfg_port;
    } else {
        addr_len = sizeof(struct sockaddr_in);
        addr = &addr4;
        addr4.sin_family = domain;
        addr4.sin_addr.s_addr = remote_uvs_ip->in4.addr;
        addr4.sin_port = (uint16_t)cfg_port;
    }
    int ret = connect(fd, (struct sockaddr *)addr, addr_len);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to connect socket to eid 0x" EID_FMT " cfg_port 0x%x, ret: %d, err: [%d]%s.\n",
            EID_ARGS(*remote_uvs_ip), cfg_port, ret, errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    if (tpsa_set_socket_opt(fd, false) != 0) {
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
    if (tpsa_set_socket_opt(fd, true) != 0) {
        (void)close(fd);
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

/* Return the socket fd to reach the remote node with remote_eid */
static tpsa_sock_client_node_t *tpsa_lookup_client_socket(sock_table_t *table,
    const uvs_net_addr_t *remote_uvs_ip)
{
    uint32_t hash = ub_hash_bytes(remote_uvs_ip, sizeof(uvs_net_addr_t), 0);
    tpsa_sock_client_node_t *cur;
    tpsa_sock_client_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&table->rwlock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &table->hmap) {
        if (memcmp(&cur->uvs_ip, remote_uvs_ip, sizeof(uvs_net_addr_t)) == 0) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&table->rwlock);
    return target;
}

static tpsa_sock_node_t *tpsa_lookup_socket(sock_table_t *table, int fd)
{
    uint32_t hash = (uint32_t)fd;
    tpsa_sock_node_t *cur;
    tpsa_sock_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&table->rwlock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &table->hmap) {
        if (cur->fd == fd) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&table->rwlock);
    return target;
}

static tpsa_sock_node_t *tpsa_add_socket(sock_table_t *table, int fd)
{
    tpsa_sock_node_t *sock_node = (tpsa_sock_node_t *)calloc(1, sizeof(tpsa_sock_node_t));
    if (sock_node == NULL) {
        return NULL;
    }
    sock_node->fd = fd;

    (void)pthread_rwlock_wrlock(&table->rwlock);
    ub_hmap_insert(&table->hmap, &sock_node->node, (uint32_t)fd);
    (void)pthread_rwlock_unlock(&table->rwlock);
    return sock_node;
}

static inline void tpsa_del_client_socket_node(sock_table_t *table, tpsa_sock_client_node_t *sock_node)
{
    (void)pthread_rwlock_wrlock(&table->rwlock);
    ub_hmap_remove(&table->hmap, &sock_node->node);
    (void)pthread_rwlock_unlock(&table->rwlock);
    free(sock_node);
}

static inline void tpsa_del_socket_node(tpsa_sock_ctx_t *sock_ctx, tpsa_sock_node_t *sock_node)
{
    (void)pthread_rwlock_wrlock(&sock_ctx->sock_table.rwlock);
    ub_hmap_remove(&sock_ctx->sock_table.hmap, &sock_node->node);
    (void)pthread_rwlock_unlock(&sock_ctx->sock_table.rwlock);
    free(sock_node);
}

void tpsa_del_socket(tpsa_sock_ctx_t *sock_ctx, int fd)
{
    tpsa_sock_node_t *sock_node = tpsa_lookup_socket(&sock_ctx->sock_table, fd);
    if (sock_node == NULL) {
        TPSA_LOG_WARN("Failed to find sock node, fd = %d.\n", fd);
        return;
    }

    tpsa_del_socket_node(sock_ctx, sock_node);
}

static tpsa_sock_client_node_t *tpsa_add_client_socket(sock_table_t *table, int fd,
    const uvs_net_addr_t *remote_uvs_ip)
{
    tpsa_sock_client_node_t *sock_node =
        (tpsa_sock_client_node_t *)calloc(1, sizeof(tpsa_sock_client_node_t));
    if (sock_node == NULL) {
        return NULL;
    }
    sock_node->uvs_ip = *remote_uvs_ip;
    sock_node->fd = fd;

    (void)pthread_rwlock_wrlock(&table->rwlock);
    ub_hmap_insert(&table->hmap, &sock_node->node,
                   ub_hash_bytes(remote_uvs_ip, sizeof(uvs_net_addr_t), 0));
    (void)pthread_rwlock_unlock(&table->rwlock);
    return sock_node;
}

/* Return the socket node to reach the remote node with remote_eid */
static tpsa_sock_client_node_t *tpsa_get_conn_fd(tpsa_sock_ctx_t *sock_ctx, uvs_net_addr_t remote_uvs_ip,
    uint32_t cfg_port)
{
    if (sock_ctx == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    /* Lookup socket table for a socket to reach the remote process */
    tpsa_sock_client_node_t *client_node =
        tpsa_lookup_client_socket(&sock_ctx->client_table, &remote_uvs_ip);
    if (client_node != NULL) {
        return client_node;
    }

    int fd = tpsa_sock_connect(&remote_uvs_ip, cfg_port);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to tpsa sock connect.\n");
        return NULL;
    }

    client_node = tpsa_add_client_socket(&sock_ctx->client_table, fd, &remote_uvs_ip);
    if (client_node == NULL) {
        TPSA_LOG_ERR("Failed to add fd to client node.");
        (void)close(fd);
        return NULL;
    }

    TPSA_LOG_INFO("new connect eid: 0x" EID_FMT ", port: %d, fd: %d.\n", EID_ARGS(remote_uvs_ip), cfg_port, fd);
    return client_node;
}

int tpsa_handle_accept_fd(int epollfd, tpsa_sock_ctx_t *sock_ctx)
{
    uvs_net_addr_t remote_uvs_ip;
    char remote_uvs_ip_str[INET6_ADDRSTRLEN];
    void *in_addr;
    const char *ret;
    (void)memset(&remote_uvs_ip, 0, sizeof(uvs_net_addr_t));
    int fd = tpsa_get_accept_fd(sock_ctx->listen_fd, sock_ctx->is_ipv6, &remote_uvs_ip);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to get accept fd.\n");
        return -1;
    }
    if (sock_ctx->is_ipv6) {
        in_addr = &remote_uvs_ip;
        ret = inet_ntop(AF_INET6, in_addr, remote_uvs_ip_str, sizeof(remote_uvs_ip_str));
    } else {
        in_addr = &remote_uvs_ip.in4.addr;
        ret = inet_ntop(AF_INET, in_addr, remote_uvs_ip_str, sizeof(remote_uvs_ip_str));
    }
    if (ret != NULL) {
        TPSA_LOG_INFO("new accept ip: %s, port: %d, fd: %d\n", remote_uvs_ip_str, sock_ctx->listen_port, fd);
    }

    if (tpsa_add_epoll_event(epollfd, fd, EPOLLIN | EPOLLRDHUP) != 0) {
        TPSA_LOG_ERR("Failed to add epoll event.\n");
        (void)close(fd);
        return -1;
    }

    tpsa_sock_node_t *sock_node = tpsa_add_socket(&sock_ctx->sock_table, fd);
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Failed to add sock fd.\n");
        (void)epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
        (void)close(fd);
        return -1;
    }
    return 0;
}

static int tpsa_sock_send_msg_impl(tpsa_sock_ctx_t *sock_ctx, const tpsa_sock_msg_t *msg,
                                   size_t len, uvs_net_addr_t remote_uvs_ip)
{
    if (len > sizeof(tpsa_sock_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    tpsa_sock_client_node_t *sock_node = tpsa_get_conn_fd(sock_ctx, remote_uvs_ip, sock_ctx->listen_port);
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Failed to get socket to eid 0x" EID_FMT ", port 0x%x\n",
                     EID_ARGS(remote_uvs_ip), sock_ctx->listen_port);
        return -1;
    }
    if (send(sock_node->fd, msg, len, 0) < 0) {
        TPSA_LOG_ERR("Failed to send msg, err: [%d]%s\n", errno, ub_strerror(errno));
        int fd = sock_node->fd;
        tpsa_del_client_socket_node(&sock_ctx->client_table, sock_node);
        (void)epoll_ctl(sock_ctx->epollfd, EPOLL_CTL_DEL, fd, NULL);
        (void)close(fd);
        return -1;
    }
    return 0;
}

int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, const tpsa_sock_msg_t *msg,
                       size_t len, uvs_net_addr_t remote_uvs_ip)
{
    /* tcp keep alive will detech bad connection, and close socket.
    *  Add one more try when send msg failed
    */
    int ret = tpsa_sock_send_msg_impl(sock_ctx, msg, len, remote_uvs_ip);
    if (ret == 0) {
        return ret;
    }

    return tpsa_sock_send_msg_impl(sock_ctx, msg, len, remote_uvs_ip);
}


int tpsa_sock_recv_msg_timeout(int fd, char *buf, uint32_t len, int timeout, tpsa_sock_ctx_t *sock_ctx)
{
    struct timespec time_start = {0};
    struct timespec time_end = {0};
    ssize_t needed_len = len;
    ssize_t recv_msg = 0;
    char *addr = buf;

    if (clock_gettime(CLOCK_REALTIME, &time_start) != 0) {
        TPSA_LOG_ERR("Failed to clock_gettime.\n");
        return -1;
    }
    while (recv_msg < len && time_end.tv_sec - time_start.tv_sec < timeout) {
        ssize_t ret = recv(fd, addr, (size_t)needed_len, 0);
        if (clock_gettime(CLOCK_REALTIME, &time_end) != 0) {
            TPSA_LOG_ERR("Failed to clock_gettime.\n");
            return -1;
        }
        if (ret > 0 && ret <= needed_len) {
            recv_msg += ret;
            addr += ret;
            needed_len -= ret;
        } else if (ret == -1) {
            /* The recving buffer is empty. Please try again. */
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                continue;
            } else {
                TPSA_LOG_ERR("Failed to recv msg, fd: %d, err: %s, .\n", fd, ub_strerror(errno));
                goto ERR;
            }
        } else {
            TPSA_LOG_ERR("The peer end closes the connection (fd = %d), ret : %d\n", fd, ret);
            goto ERR;
        }
    }
    if (time_end.tv_sec - time_start.tv_sec >= timeout) {
        TPSA_LOG_ERR("Packet received timed out.\n");
        return -1;
    }
    return 0;

ERR:
    tpsa_del_socket(sock_ctx, fd);
    (void)epoll_ctl(sock_ctx->epollfd, EPOLL_CTL_DEL, fd, NULL);
    (void)close(fd);
    return -1;
}

static int tpsa_create_sock_table(sock_table_t *table)
{
    (void)pthread_rwlock_init(&table->rwlock, NULL);
    if (ub_hmap_init(&table->hmap, TPSA_SOCK_TABLE_SIZE) != 0) {
        (void)pthread_rwlock_destroy(&table->rwlock);
        return -1;
    }

    return 0;
}

static void tpsa_destroy_client_table(sock_table_t *table)
{
    tpsa_sock_client_node_t *cur, *next;

    /* destroy client/server sock table */
    (void)pthread_rwlock_wrlock(&table->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &table->hmap) {
        ub_hmap_remove(&table->hmap, &cur->node);
        if (cur->fd >= 0) {
            (void)close(cur->fd);
        }
        free(cur);
    }
    ub_hmap_destroy(&table->hmap);
    (void)pthread_rwlock_unlock(&table->rwlock);
    (void)pthread_rwlock_destroy(&table->rwlock);
}

static inline void tpsa_close_sockfd(int fd, int epollfd)
{
    if (fd < 0) {
        return;
    }

    if (epollfd != -1) {
        (void)epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
    }
    (void)close(fd);
}

static void tpsa_destroy_sock_table(sock_table_t *table, int epollfd)
{
    tpsa_sock_node_t *cur, *next;

    (void)pthread_rwlock_wrlock(&table->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &table->hmap) {
        ub_hmap_remove(&table->hmap, &cur->node);
        tpsa_close_sockfd(cur->fd, epollfd);
        free(cur);
    }
    ub_hmap_destroy(&table->hmap);
    (void)pthread_rwlock_unlock(&table->rwlock);
    (void)pthread_rwlock_destroy(&table->rwlock);
}

static int tpsa_sock_table_init(tpsa_sock_ctx_t *sock_ctx)
{
    if (tpsa_create_sock_table(&sock_ctx->client_table) != 0) {
        TPSA_LOG_ERR("Failed to create client table");
        return -1;
    }
    if (tpsa_create_sock_table(&sock_ctx->sock_table) != 0) {
        tpsa_destroy_client_table(&sock_ctx->client_table);
        TPSA_LOG_ERR("Failed to create server table");
        return -1;
    }
    return 0;
}

static void tpsa_sock_table_uninit(tpsa_sock_ctx_t *sock_ctx)
{
    tpsa_destroy_sock_table(&sock_ctx->sock_table, sock_ctx->epollfd);
    tpsa_destroy_client_table(&sock_ctx->client_table);
}

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx, uvs_socket_init_attr_t *attr)
{
    if (tpsa_sock_table_init(sock_ctx) != 0) {
        TPSA_LOG_ERR("Failed to init sock table");
        return -1;
    }

    if (attr == NULL || tpsa_sock_bind(sock_ctx, attr) != 0) {
        TPSA_LOG_ERR("Failed to tpsa bind.\n");
        tpsa_sock_table_uninit(sock_ctx);
        return -1;
    }
    return 0;
}

void tpsa_sock_server_uninit(tpsa_sock_ctx_t *sock_ctx)
{
    tpsa_sock_unbind(sock_ctx);
    tpsa_sock_table_uninit(sock_ctx);
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
    req->content.req.tp_param.com.state = TPSA_TP_STATE_RTR;
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
    /* For lm scenario, the local IP information is sent to the peer. */
    if (cparam->live_migrate) {
        req->dip = *sip;
    }

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
    if (msg->live_migrate) {
        resp->dip = param->sip;
    }
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
    resp->content.resp.tp_param.com.state = TPSA_TP_STATE_RTR;
    resp->content.resp.tp_param.com.tx_psn = 0; /* Need to check */
    resp->content.resp.tp_param.com.rx_psn = req->tp_param.com.rx_psn;
    resp->content.resp.tp_param.com.local_mtu = req->tp_param.com.local_mtu;
    resp->content.resp.tp_param.com.peer_mtu = param->mtu;
    resp->content.resp.tp_param.com.local_seg_size = req->tp_param.com.local_seg_size;
    resp->content.resp.tp_param.com.peer_seg_size = SEG_SIZE;

    uint32_t i = 0;
    for (; i < req->tpg_cfg.tp_cnt && i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        resp->content.resp.tp_param.uniq[i].local_tpn = req->tp_param.uniq[i].local_tpn;
        resp->content.resp.tp_param.uniq[i].peer_tpn = param->tpn[i];
    }

    return resp;
}

tpsa_sock_msg_t *tpsa_sock_init_create_ack(tpsa_sock_msg_t *msg, uvs_net_addr_info_t *sip,
    uvs_socket_init_attr_t *tpsa_attr)
{
    tpsa_create_resp_t *resp = &msg->content.resp;
    tpsa_sock_msg_t *ack = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (ack == NULL) {
        return NULL;
    }

    ack->msg_type = TPSA_CREATE_ACK;
    ack->trans_mode = msg->trans_mode;
    ack->src_uvs_ip = tpsa_attr->server_ip;
    ack->migrate_third = msg->migrate_third;
    if (msg->live_migrate) {
        ack->dip = *sip;
    }
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
    for (; i < msg->content.resp.tpg_cfg.tp_cnt; i++) {
        ack->content.ack.tp_param.uniq[i] = msg->content.resp.tp_param.uniq[i];
    }

    return ack;
}

tpsa_sock_msg_t *tpsa_sock_init_create_finish(tpsa_sock_msg_t* msg, uvs_net_addr_info_t *sip)
{
    tpsa_sock_msg_t *finish = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (finish == NULL) {
        return NULL;
    }

    finish->msg_type = TPSA_CREATE_FINISH;
    finish->trans_mode = msg->trans_mode;
    finish->migrate_third = msg->migrate_third;
    finish->dip = *sip;
    finish->local_eid = msg->local_eid;
    finish->peer_eid = msg->peer_eid;
    finish->local_jetty = msg->local_jetty;
    finish->peer_jetty = msg->peer_jetty;
    finish->vtpn = msg->vtpn;
    finish->local_tpgn = msg->local_tpgn;
    finish->peer_tpgn = msg->peer_tpgn;
    finish->upi = msg->upi;
    finish->live_migrate = msg->live_migrate;
    finish->content.finish.msg_id = msg->content.ack.msg_id;
    finish->content.finish.nlmsg_seq = msg->content.ack.nlmsg_seq;
    finish->content.finish.src_function_id = msg->content.ack.src_function_id;
    (void)memcpy(finish->content.finish.dev_name, msg->content.ack.dev_name, UVS_MAX_DEV_NAME);
    finish->content.finish.ta_data = msg->content.ack.ta_data;
    finish->content.finish.tpg_cfg = msg->content.ack.tpg_cfg;
    finish->content.finish.share_mode = msg->content.ack.share_mode;

    uint32_t i = 0;
    for (; i < msg->content.ack.tpg_cfg.tp_cnt; i++) {
        finish->content.finish.tp_param.uniq[i] = msg->content.ack.tp_param.uniq[i];
    }

    return finish;
}

tpsa_sock_msg_t *tpsa_sock_init_destroy_finish(tpsa_sock_msg_t* msg, uvs_net_addr_info_t *sip)
{
    tpsa_sock_msg_t *finish = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (finish == NULL) {
        return NULL;
    }

    finish->msg_type = TPSA_DESTROY_FINISH;
    finish->trans_mode = msg->trans_mode;
    finish->dip = *sip;
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
    tsync->dip = *sip;
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
