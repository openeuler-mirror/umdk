/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa sock implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2022-09-07
 * Note:
 * History: 2023-1-18: Rename tpsa_connect to tpsa_sock, porting sock function from daemon here
 */

#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <errno.h>

#include "ub_util.h"
#include "ub_hash.h"
#include "tpsa_config.h"
#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_sock.h"

#define TPSA_SOCK_TABLE_SIZE 10240

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
static int tpsa_set_socket_opt(int fd)
{
    int ret;

    ret = tpsa_set_nonblock_opt(fd);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get flags of client socket, ret: %d, err: %d.\n", ret, errno);
        return -1;
    }

    int reuse = 1;
    /* Set socket reuse. When the server is restarted,
     * the problem of address already in use is solved */
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (ret < 0) {
        TPSA_LOG_ERR("server socket set_opt failed. enable_reuse:%d, ret: %d, err: %d.\n",
            SO_REUSEADDR, ret, errno);
        return ret;
    }

    int nodelay = 1;
    ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to setsockopt. opt:%d, ret: %d, err: %d.\n", TCP_NODELAY, ret, errno);
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

static int tpsa_sock_bind(tpsa_sock_ctx_t *sock_ctx)
{
    int fd = socket(AF_INET, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create fd, ret: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_set_socket_opt(fd) != 0) {
        TPSA_LOG_ERR("Set socket nonblock failed.\n");
        (void)close(fd);
        return -1;
    }

    struct sockaddr_in src_addr = {0};
    src_addr.sin_family = AF_INET;
    if (tpsa_get_server_ip(&src_addr.sin_addr) != 0 || tpsa_get_server_port(&src_addr.sin_port) != 0) {
        TPSA_LOG_ERR("Failed to get server ip:%d and port: %d");
        (void)close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&src_addr, sizeof(struct sockaddr)) != 0) {
        TPSA_LOG_ERR("Failed to bind port, err: [%d]%s.\n", errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    sock_ctx->listen_fd = fd;
    sock_ctx->listen_port = src_addr.sin_port;
    return 0;
}

static void tpsa_sock_unbind(tpsa_sock_ctx_t *sock_ctx)
{
    (void)close(sock_ctx->listen_fd);
    sock_ctx->listen_fd = -1;
}

static int tpsa_sock_connect(const urma_eid_t *remote_eid, uint32_t cfg_port)
{
    int fd = socket(AF_INET, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create socket, fd: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = remote_eid->in4.addr;
    addr.sin_port = (uint16_t)cfg_port;
    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to connect socket to eid 0x"EID_FMT" cfg_port 0x%x, ret: %d, err: [%d]%s.\n",
            EID_ARGS(*remote_eid), cfg_port, ret, errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    if (tpsa_set_socket_opt(fd) != 0) {
        TPSA_LOG_ERR("Set socket nonblock failed.\n");
        (void)close(fd);
        return -1;
    }

    return fd;
}

static int tpsa_get_accept_fd(int listen_fd, urma_eid_t *remote_eid)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to accept socket, fd = %d, ret: %d, err: [%d]%s.\n",
            listen_fd, fd, errno, ub_strerror(errno));
        return -1;
    }
    if (tpsa_set_socket_opt(fd) != 0) {
        TPSA_LOG_ERR("Set socket nonblock failed.\n");
        (void)close(fd);
        return -1;
    }

    remote_eid->in4.addr = (uint32_t)client_addr.sin_addr.s_addr;
    return fd;
}

/* Return the socket fd to reach the remote node with remote_eid */
static tpsa_sock_node_t *tpsa_lookup_socket(sock_table_t *table, const urma_eid_t *remote_eid)
{
    uint32_t hash = ub_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    tpsa_sock_node_t *cur;
    tpsa_sock_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&table->rwlock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &table->hmap) {
        if (memcmp(&cur->eid, remote_eid, sizeof(urma_eid_t)) == 0) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&table->rwlock);
    return target;
}

static tpsa_sock_node_t *tpsa_add_socket(sock_table_t *table, int fd, const urma_eid_t *remote_eid)
{
    tpsa_sock_node_t *sock_node = calloc(1, sizeof(tpsa_sock_node_t));
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Memory allocation failed.\n");
        return NULL;
    }
    sock_node->eid = *remote_eid;
    sock_node->fd = fd;

    (void)pthread_rwlock_wrlock(&table->rwlock);
    ub_hmap_insert(&table->hmap, &sock_node->node, ub_hash_bytes(remote_eid, sizeof(urma_eid_t), 0));
    (void)pthread_rwlock_unlock(&table->rwlock);
    return sock_node;
}

static void tpsa_remove_socket(sock_table_t *table, tpsa_sock_node_t *sock_node)
{
    (void)pthread_rwlock_wrlock(&table->rwlock);
    ub_hmap_remove(&table->hmap, &sock_node->node);
    (void)pthread_rwlock_unlock(&table->rwlock);
}

/* Return the socket node to reach the remote node with remote_eid */
static tpsa_sock_node_t *tpsa_get_conn_fd(tpsa_sock_ctx_t *sock_ctx, urma_eid_t remote_eid, uint32_t cfg_port)
{
    if (sock_ctx == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    /* Lookup socket table for a socket to reach the remote process */
    tpsa_sock_node_t *sock_node = tpsa_lookup_socket(&sock_ctx->client_table, &remote_eid);
    if (sock_node != NULL) {
        return sock_node;
    }

    int fd = tpsa_sock_connect(&remote_eid, cfg_port);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to tpsa sock connect.\n");
        return NULL;
    }

    sock_node = tpsa_add_socket(&sock_ctx->client_table, fd, &remote_eid);
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Failed to add fd.");
        (void)close(fd);
        return NULL;
    }
    TPSA_LOG_INFO("new connect eid: %x, port: %d, fd: %d.\n", remote_eid.in4.addr, cfg_port, fd);
    return sock_node;
}

int tpsa_handle_accept_fd(int epollfd, tpsa_sock_ctx_t *sock_ctx)
{
    urma_eid_t remote_eid;
    int fd = tpsa_get_accept_fd(sock_ctx->listen_fd, &remote_eid);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to get accept fd.\n");
        return -1;
    }
    TPSA_LOG_INFO("new accept eid: %x, port: %d, fd: %d\n", remote_eid.in4.addr, sock_ctx->listen_port, fd);

    if (tpsa_add_epoll_event(epollfd, fd, EPOLLIN | EPOLLRDHUP) != 0) {
        TPSA_LOG_ERR("Failed to add epoll event.\n");
        (void)close(fd);
        return -1;
    }

    if (tpsa_add_socket(&sock_ctx->server_table, fd, &remote_eid) == NULL) {
        TPSA_LOG_ERR("Failed to add sock fd.\n");
        (void)epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
        (void)close(fd);
        return -1;
    }
    return 0;
}

int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, const tpsa_nl_msg_t *msg, size_t len)
{
    tpsa_netaddr_entry_t *remote_underlay;
    urma_eid_t remote_eid = msg->dst_eid;

    if (len > sizeof(tpsa_nl_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    remote_underlay = tpsa_lookup_underlay_info(&remote_eid);
    if (remote_underlay == NULL) {
        TPSA_LOG_WARN("Failed to get remote underlay info\n");
    } else {
        remote_eid = remote_underlay->underlay.peer_tps;
    }

    tpsa_sock_node_t *sock_node = tpsa_get_conn_fd(sock_ctx, remote_eid, sock_ctx->listen_port);
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Failed to get socket to eid 0x%x, port 0x%x\n", msg->dst_eid.in4.addr, sock_ctx->listen_port);
        return -1;
    }
    if (send(sock_node->fd, msg, len, 0) < 0) {
        TPSA_LOG_ERR("Failed to send msg, err: [%d]%s\n", errno, ub_strerror(errno));
        tpsa_remove_socket(&sock_ctx->client_table, sock_node);
        (void)close(sock_node->fd);
        free(sock_node);
        return -1;
    }
    TPSA_LOG_INFO("[send_sock_ctx_msg:2]---msg_id: %d, msg_type: %d, transport_type: %d. fd: %d\n",
        msg->nlmsg_seq, msg->msg_type, msg->transport_type, sock_node->fd);
    return 0;
}

int tpsa_sock_recv_msg_timeout(int fd, char *buf, uint32_t len, int timeout, int epollfd)
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
                (void)epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                (void)close(fd);
                TPSA_LOG_ERR("Failed to recv msg, fd: %d, err: %s, .\n", fd, ub_strerror(errno));
                return -1;
            }
        } else {
            (void)epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
            (void)close(fd);
            TPSA_LOG_ERR("The peer end closes the connection (fd = %d), ret : %d\n", fd, ret);
            return -1;
        }
    }
    if (time_end.tv_sec - time_start.tv_sec >= timeout) {
        TPSA_LOG_ERR("Packet received timed out.\n");
        return -1;
    }
    return 0;
}

static int tpsa_create_sock_table(sock_table_t *table)
{
    (void)pthread_rwlock_init(&table->rwlock, NULL);
    return ub_hmap_init(&table->hmap, TPSA_SOCK_TABLE_SIZE);
}

static void tpsa_destory_sock_table(sock_table_t *table)
{
    tpsa_sock_node_t *cur, *next;

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

static int tpsa_sock_table_init(tpsa_sock_ctx_t *sock_ctx)
{
    if (tpsa_create_sock_table(&sock_ctx->client_table) != 0) {
        TPSA_LOG_ERR("Failed to create client table");
        return -1;
    }
    if (tpsa_create_sock_table(&sock_ctx->server_table) != 0) {
        tpsa_destory_sock_table(&sock_ctx->client_table);
        TPSA_LOG_ERR("Failed to create server table");
        return -1;
    }
    return 0;
}

static void tpsa_sock_table_uninit(tpsa_sock_ctx_t *sock_ctx)
{
    tpsa_destory_sock_table(&sock_ctx->client_table);
    tpsa_destory_sock_table(&sock_ctx->server_table);
}

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx)
{
    if (tpsa_sock_table_init(sock_ctx) != 0) {
        TPSA_LOG_ERR("Failed to init sock table");
        return -1;
    }

    if (tpsa_sock_bind(sock_ctx) != 0) {
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
