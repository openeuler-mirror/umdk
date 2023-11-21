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
#include "tpsa_config.h"
#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_ioctl.h"
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
static int tpsa_set_socket_opt(int fd, bool is_noblock)
{
    int ret;

    if (is_noblock) {
        ret = tpsa_set_nonblock_opt(fd);
        if (ret != 0) {
            TPSA_LOG_ERR("Failed to set socket nonblock, ret: %d, err: %d.\n", ret, errno);
            return -1;
        }
    }

    int reuse = 1;
    /* Set socket reuse. When the server is restarted,
     * the problem of address already in use is solved */
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to set reuse port, enable_reuse:%d, ret: %d, err: %d.\n",
            SO_REUSEADDR, ret, errno);
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

static int tpsa_sock_bind(tpsa_sock_ctx_t *sock_ctx, uvs_init_attr_t *attr)
{
    int fd = socket(AF_INET, (int)SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to create fd, ret: %d, err: %s.\n", fd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_set_socket_opt(fd, true) != 0) {
        (void)close(fd);
        return -1;
    }

    struct sockaddr_in src_addr = {0};
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr = attr->server_ip;
    src_addr.sin_port = attr->server_port;

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
    if (tpsa_set_socket_opt(fd, false) != 0) {
        (void)close(fd);
        return -1;
    }

    return fd;
}

static int tpsa_get_accept_fd(int listen_fd, urma_eid_t *remote_eid)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = (socklen_t)sizeof(struct sockaddr_in);
    int fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (fd < 0) {
        TPSA_LOG_ERR("Failed to accept socket, fd = %d, ret: %d, err: [%d]%s.\n",
            listen_fd, fd, errno, ub_strerror(errno));
        return -1;
    }
    if (tpsa_set_socket_opt(fd, true) != 0) {
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

int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, const tpsa_sock_msg_t *msg,
                       size_t len, urma_eid_t remote_eid)
{
    if (len > sizeof(tpsa_sock_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    tpsa_sock_node_t *sock_node = tpsa_get_conn_fd(sock_ctx, remote_eid, sock_ctx->listen_port);
    if (sock_node == NULL) {
        TPSA_LOG_ERR("Failed to get socket to eid 0x"EID_FMT", port 0x%x\n",
                     EID_ARGS(remote_eid), sock_ctx->listen_port);
        return -1;
    }
    if (send(sock_node->fd, msg, len, 0) < 0) {
        TPSA_LOG_ERR("Failed to send msg, err: [%d]%s\n", errno, ub_strerror(errno));
        tpsa_remove_socket(&sock_ctx->client_table, sock_node);
        (void)close(sock_node->fd);
        free(sock_node);
        return -1;
    }
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

static void tpsa_destroy_sock_table(sock_table_t *table)
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
        tpsa_destroy_sock_table(&sock_ctx->client_table);
        TPSA_LOG_ERR("Failed to create server table");
        return -1;
    }
    return 0;
}

static void tpsa_sock_table_uninit(tpsa_sock_ctx_t *sock_ctx)
{
    tpsa_destroy_sock_table(&sock_ctx->client_table);
    tpsa_destroy_sock_table(&sock_ctx->server_table);
}

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx, uvs_init_attr_t *attr)
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

tpsa_sock_msg_t *tpsa_sock_init_create_req(tpsa_create_param_t *cparam, tpsa_init_sock_param_t *param)
{
    tpsa_sock_msg_t *req = calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        TPSA_LOG_ERR("Fail to create tp request req");
        return NULL;
    }
    if (cparam->udrv_ext_len > TPSA_UDRV_DATA_LEN) {
        TPSA_LOG_ERR("udrv data buffer is short\n");
        return NULL;
    }

    req->msg_type = TPSA_CREATE_REQ;
    req->trans_mode = cparam->trans_mode;
    req->dip = cparam->dip;
    req->local_eid = cparam->local_eid;
    req->peer_eid = cparam->peer_eid;
    req->local_jetty = cparam->local_jetty;
    req->peer_jetty = cparam->peer_jetty;
    req->vtpn = cparam->vtpn;
    req->local_tpgn = param->tpgn;
    req->peer_tpgn = 0;
    req->upi = param->upi;
    req->liveMigrate = cparam->liveMigrate;
    req->migrateThird = cparam->migrateThird;
    req->content.req.msg_id = cparam->msg_id;
    req->content.req.nlmsg_seq = cparam->nlmsg_seq;
    req->content.req.src_function_id = cparam->fe_idx;
    req->content.req.tpg_cfg = param->tpg_cfg;
    (void)strcpy(req->content.req.dev_name, cparam->dev_name);
    req->content.req.cc_array_cnt = param->cc_array_cnt;
    (void)memcpy(req->content.req.cc_result_array,
        param->cc_result_array, sizeof(tpsa_tp_cc_entry_t) * param->cc_array_cnt);
    req->content.req.cc_en = param->cc_en;
    req->content.req.ta_data = cparam->ta_data;
    req->content.req.udrv_in_len = cparam->udrv_in_len;
    req->content.req.udrv_out_len = cparam->udrv_out_len;
    req->content.req.udrv_ext_len = cparam->udrv_ext_len;
    (void)memcpy(req->content.req.udrv_data, cparam->udrv_data, TPSA_UDRV_DATA_LEN);

    uint32_t i = 0;
    for (; i < param->tp_cnt; i++) {
        req->content.req.tp_param[i].local_net_addr_idx = param->local_net_addr_idx; /* Need to fix */
        req->content.req.tp_param[i].peer_net_addr = param->peer_net_addr;
        req->content.req.tp_param[i].state = TPSA_TP_STATE_RTR;
        req->content.req.tp_param[i].tx_psn = 0;
        req->content.req.tp_param[i].rx_psn = param->rx_psn;
        req->content.req.tp_param[i].local_mtu = param->local_mtu;
        req->content.req.tp_param[i].peer_mtu = param->local_mtu;
        req->content.req.tp_param[i].local_tpn = param->local_tpn[i];
        req->content.req.tp_param[i].peer_tpn = 0;
        req->content.req.tp_param[i].local_seg_size = param->local_seg_size;
        req->content.req.tp_param[i].peer_seg_size = 0;
        req->content.req.tp_param[i].local_tp_cfg = param->local_tp_cfg;
        req->content.req.tp_param[i].remote_tp_cfg = param->local_tp_cfg;
    }

    return req;
}

tpsa_sock_msg_t *tpsa_sock_init_create_resp(tpsa_sock_msg_t* msg, uint32_t tpgn, uint32_t *tpn,
    tpsa_tpg_cfg_t *tpg_cfg, uvs_mtu_t mtu, tpsa_cc_param_t *resp_param)
{
    tpsa_create_req_t *req = &msg->content.req;

    tpsa_sock_msg_t *resp = calloc(1, sizeof(tpsa_sock_msg_t));
    if (resp == NULL) {
        TPSA_LOG_ERR("Fail to create tp request resp");
        return NULL;
    }

    resp->msg_type = TPSA_CREATE_RESP;
    resp->trans_mode = msg->trans_mode;
    resp->dip = msg->dip;
    resp->local_eid = msg->local_eid;
    resp->peer_eid = msg->peer_eid;
    resp->local_jetty = msg->local_jetty;
    resp->peer_jetty = msg->peer_jetty;
    resp->vtpn = msg->vtpn;
    resp->local_tpgn = msg->local_tpgn;
    resp->peer_tpgn = tpgn;
    resp->upi = msg->upi;
    resp->liveMigrate = msg->liveMigrate;
    resp->migrateThird = msg->migrateThird;
    resp->content.resp.tpg_cfg = *tpg_cfg;
    resp->content.resp.msg_id = req->msg_id;
    resp->content.resp.nlmsg_seq = req->nlmsg_seq;
    resp->content.resp.src_function_id = req->src_function_id;
    (void)memcpy(resp->content.resp.dev_name, req->dev_name, TPSA_MAX_DEV_NAME);
    resp->content.resp.target_cc_cnt = resp_param->target_cc_cnt;
    (void)memcpy(resp->content.resp.target_cc_arr,
        resp_param->cc_result_array, resp_param->target_cc_cnt * sizeof(tpsa_tp_cc_entry_t));
    resp->content.resp.target_cc_en = resp_param->target_cc_en;
    resp->content.resp.local_cc_cnt = req->cc_array_cnt;
    (void)memcpy(resp->content.resp.local_cc_arr,
        req->cc_result_array, req->cc_array_cnt * sizeof(tpsa_tp_cc_entry_t));
    resp->content.resp.local_cc_en = req->cc_en;
    resp->content.resp.ta_data = req->ta_data;

    uint32_t i = 0;
    for (; i < req->tpg_cfg.tp_cnt; i++) {
        resp->content.resp.tp_param[i].local_tp_cfg = req->tp_param[i].local_tp_cfg;
        resp->content.resp.tp_param[i].remote_tp_cfg = req->tp_param[i].remote_tp_cfg;
        resp->content.resp.tp_param[i].local_net_addr_idx = req->tp_param[i].local_net_addr_idx;
        resp->content.resp.tp_param[i].peer_net_addr = req->tp_param[i].peer_net_addr; /* Need to fix */
        resp->content.resp.tp_param[i].state = TPSA_TP_STATE_RTR;
        resp->content.resp.tp_param[i].tx_psn = 0; /* Need to check */
        resp->content.resp.tp_param[i].rx_psn = req->tp_param[i].rx_psn;
        resp->content.resp.tp_param[i].local_mtu = req->tp_param[i].local_mtu;
        resp->content.resp.tp_param[i].peer_mtu = mtu;
        resp->content.resp.tp_param[i].local_tpn = req->tp_param[i].local_tpn;
        resp->content.resp.tp_param[i].peer_tpn = tpn[i];
        resp->content.resp.tp_param[i].local_seg_size = req->tp_param[i].local_seg_size;
        resp->content.resp.tp_param[i].peer_seg_size = SEG_SIZE;
    }

    return resp;
}

tpsa_sock_msg_t *tpsa_sock_init_create_ack(tpsa_sock_msg_t* msg)
{
    tpsa_create_resp_t *resp = &msg->content.resp;
    tpsa_sock_msg_t *ack = calloc(1, sizeof(tpsa_sock_msg_t));
    if (ack == NULL) {
        TPSA_LOG_ERR("Fail to create tp request ack");
        return NULL;
    }

    ack->msg_type = TPSA_CREATE_ACK;
    ack->trans_mode = msg->trans_mode;
    ack->dip = msg->dip;
    ack->local_eid = msg->local_eid;
    ack->peer_eid = msg->peer_eid;
    ack->local_jetty = msg->local_jetty;
    ack->peer_jetty = msg->peer_jetty;
    ack->vtpn = msg->vtpn;
    ack->local_tpgn = msg->local_tpgn;
    ack->peer_tpgn = msg->peer_tpgn;
    ack->upi = msg->upi;
    ack->liveMigrate = msg->liveMigrate;
    ack->migrateThird = msg->migrateThird;
    ack->content.ack.msg_id = msg->content.resp.msg_id;
    ack->content.ack.nlmsg_seq = msg->content.resp.nlmsg_seq;
    (void)memcpy(ack->content.ack.dev_name, msg->content.resp.dev_name, TPSA_MAX_DEV_NAME);
    ack->content.ack.src_function_id = msg->content.resp.src_function_id;
    ack->content.ack.tpg_cfg = msg->content.resp.tpg_cfg;
    ack->content.ack.is_target = msg->content.resp.is_target;
    ack->content.ack.ta_data = resp->ta_data;
    ack->content.ack.udrv_in_len = resp->udrv_in_len;
    ack->content.ack.udrv_out_len = resp->udrv_out_len;
    ack->content.ack.udrv_ext_len = resp->udrv_ext_len;
    (void)memcpy((char*)ack->content.ack.udrv_data,
        (char*)resp->udrv_data, TPSA_UDRV_DATA_LEN);

    uint32_t i = 0;
    for (; i < msg->content.resp.tpg_cfg.tp_cnt; i++) {
        ack->content.ack.tp_param[i] = msg->content.resp.tp_param[i];
    }

    return ack;
}

tpsa_sock_msg_t *tpsa_sock_init_create_finish(tpsa_sock_msg_t* msg)
{
    tpsa_sock_msg_t *finish = calloc(1, sizeof(tpsa_sock_msg_t));
    if (finish == NULL) {
        TPSA_LOG_ERR("Fail to create tp request finish");
        return NULL;
    }

    finish->msg_type = TPSA_CREATE_FINISH;
    finish->trans_mode = msg->trans_mode;
    finish->local_eid = msg->local_eid;
    finish->peer_eid = msg->peer_eid;
    finish->local_jetty = msg->local_jetty;
    finish->peer_jetty = msg->peer_jetty;
    finish->vtpn = msg->vtpn;
    finish->local_tpgn = msg->local_tpgn;
    finish->peer_tpgn = msg->peer_tpgn;
    finish->upi = msg->upi;
    finish->liveMigrate = msg->liveMigrate;
    finish->content.finish.msg_id = msg->content.ack.msg_id;
    finish->content.finish.nlmsg_seq = msg->content.ack.nlmsg_seq;
    finish->content.finish.src_function_id = msg->content.ack.src_function_id;
    (void)memcpy(finish->content.finish.dev_name, msg->content.ack.dev_name, TPSA_MAX_DEV_NAME);
    finish->content.finish.ta_data = msg->content.ack.ta_data;
    finish->content.finish.udrv_in_len = msg->content.ack.udrv_in_len;
    finish->content.finish.udrv_out_len = msg->content.ack.udrv_out_len;
    finish->content.finish.udrv_ext_len = msg->content.ack.udrv_ext_len;
    (void)memcpy((char*)finish->content.finish.udrv_data,
        (char*)msg->content.ack.udrv_data, TPSA_UDRV_DATA_LEN);

    return finish;
}

tpsa_sock_msg_t *tpsa_sock_init_table_sync(tpsa_create_param_t *cparam, uint32_t vtpn, tpsa_table_opcode_t opcode,
                                           uint32_t upi, vport_table_t *vport_table)
{
    tpsa_sock_msg_t *tsync = calloc(1, sizeof(tpsa_sock_msg_t));
    if (tsync == NULL) {
        TPSA_LOG_ERR("Fail to create tp request ack");
        return NULL;
    }

    tsync->msg_type = TPSA_TABLE_SYC;
    tsync->trans_mode = cparam->trans_mode;
    tsync->dip = cparam->dip;
    tsync->local_eid = cparam->local_eid;
    tsync->peer_eid = cparam->peer_eid;
    tsync->local_jetty = cparam->local_jetty;
    tsync->peer_jetty = cparam->peer_jetty;
    tsync->vtpn = vtpn;
    tsync->local_tpgn = 0;
    tsync->peer_tpgn = 0;
    tsync->upi = upi;
    tsync->liveMigrate = cparam->liveMigrate;
    tsync->migrateThird = cparam->migrateThird;
 
    tsync->content.tsync.opcode = opcode;

    return tsync;
}

static void tpsa_swap_jetty(struct tpsa_jetty_id *jetty, struct tpsa_jetty_id *tjetty)
{
    struct tpsa_jetty_id tmp;

    tmp = *jetty;
    *jetty = *tjetty;
    *tjetty = tmp;
}

tpsa_sock_msg_t *tpsa_sock_init_destroy_req(tpsa_nl_msg_t *nlmsg, uint32_t tpgn,
    tpsa_net_addr_t *dip, uint32_t upi, uint32_t tp_cnt, struct tpsa_ta_data *ta_data)
{
    tpsa_msg_t *msg = (tpsa_msg_t *)nlmsg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)msg->data;

    tpsa_sock_msg_t *req = calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        TPSA_LOG_ERR("Fail to create tp request req");
        return NULL;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));
 
    req->msg_type = TPSA_DESTROY_REQ;
    req->local_eid = nlreq->local_eid;
    req->peer_eid = nlreq->peer_eid;
    req->local_jetty = nlreq->local_jetty;
    req->peer_jetty = nlreq->peer_jetty;
    req->trans_mode = nlreq->trans_mode;
    req->dip = lmdip;
    req->vtpn = nlreq->vtpn;
    req->local_tpgn = tpgn;
    req->peer_tpgn = 0;
    req->upi = upi;
    req->liveMigrate = false;
    req->migrateThird = false;
    req->content.dreq.trans_type = TPSA_TRANSPORT_UB;
    req->content.dreq.net_addr = *dip;
    req->content.dreq.msg_id = msg->hdr.msg_id;
    req->content.dreq.nlmsg_seq = nlmsg->nlmsg_seq;
    req->content.dreq.src_function_id = msg->hdr.ep.src_function_id;
    req->content.dreq.tp_cnt = tp_cnt;
    req->content.dreq.ta_data = *ta_data;
    req->content.dreq.ta_data.is_target = true;
    tpsa_swap_jetty(&req->content.dreq.ta_data.jetty_id, &req->content.dreq.ta_data.tjetty_id);

    return req;
}