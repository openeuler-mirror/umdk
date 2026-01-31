/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq example
 * Create: 2026-1-27
 * Note:
 * History: 2026-1-27
 */

#include <stdatomic.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "umq_api.h"
#include "umq_pro_api.h"
#include "umq_example_common.h"
#include "threadpool.h"
#include "connection_setup_tool.h"

#define TOOL_SOCKET_SEND_RECV_TIMEOUT   10
#define TOOL_EXAMPLE_BUFFER_SIZE        8192
#define TOOL_EXAMPLE_DEPTH              128
#define TOOL_SERVER_RX_EXAMPLE_DEPTH    (2048 * 4)
#define TOOL_MAX_POLL_BATCH             64
#define TOOL_INITIAL_CREDIT             4
#define TOOL_REQIEST_CREDITS            4

#define CONNETION_SETUP_MSG_SZIE    100
#define CONNECTION_SETUP_LISTEN     128
#define UMQ_MAX_BIND_INFO_SIZE      512
#define EAGAIN_WAIT_TIME_U          (400 * 1000)
#define SEND_REQ_SLEEP_TIME_S       3
#define INTERRUPT_WAIT_TIME_MS      300
#define STATE_SLEEP_TIME_S          10

#define DEFAULT_THREAD_COUNT 16
#define DEFAULT_QUEUE_CNT 16
#define QUEUE_SIZE 2048
#define MAIN_QUEUE_CNT EXAMPLE_MAX_DEV_NUM

static umq_info_t g_tatal_umq_info_list;
static umq_info_t g_umq_info_list[CONNECTION_SETUP_LISTEN];
static volatile uint32_t g_umq_cnt = 0;
struct urpc_example_config *g_cfg;
int g_epoll_fd = -1;
threadpool_t *g_threadpool;

static volatile uint32_t g_state_total_conn_cnt = 0;
static volatile uint32_t g_state_conn_cnt[MAIN_QUEUE_CNT];
static uint64_t g_main_umq[MAIN_QUEUE_CNT];

static int fill_umq_rx_buff(uint64_t umqh, uint32_t buf_cnt)
{
    uint32_t need_post = buf_cnt;
    while (need_post > 0) {
        uint32_t alloc_rx_buf = need_post < TOOL_MAX_POLL_BATCH ? need_post : TOOL_MAX_POLL_BATCH;
        umq_buf_t *rx_buf = umq_buf_alloc(TOOL_EXAMPLE_BUFFER_SIZE, alloc_rx_buf, umqh, NULL);
        if (rx_buf == NULL) {
            LOG_PRINT_ERR("umq_buf_alloc failed\n");
            return -1;
        }
        umq_buf_t *bad_buf;
        if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != 0) {
            umq_buf_free(bad_buf);
            LOG_PRINT_ERR("umq_post failed\n");
            return -1;
        }
        need_post -= alloc_rx_buf;
    }
    return 0;
}

static int parse_m_trans_info(struct urpc_example_config *cfg, umq_init_cfg_t *init_cfg)
{
    uint32_t idx = 0;
    while (cfg->m_eid_idx[idx] != 0) {
        init_cfg->trans_info[idx].trans_mode = (umq_trans_mode_t)cfg->trans_mode;
        if (cfg->dev_name != NULL) {
            init_cfg->trans_info[idx].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
            strcpy(init_cfg->trans_info[idx].dev_info.dev.dev_name, cfg->m_dev_name[idx]);
            init_cfg->trans_info[idx].dev_info.dev.eid_idx = cfg->m_eid_idx[idx];
        } else {
            break;
        }
        idx++;
    }
    init_cfg->trans_info_num = idx;
    return 0;
}

static int init_umq(struct urpc_example_config *cfg)
{
    umq_init_cfg_t *init_cfg = (umq_init_cfg_t *)(uintptr_t)calloc(1, sizeof(umq_init_cfg_t));
    if (init_cfg == NULL) {
        LOG_PRINT_ERR("calloc init cfg failed\n");
        return -1;
    }
    init_cfg->feature = cfg->feature;
    init_cfg->flow_control.use_atomic_window = true;
    init_cfg->flow_control.initial_credit = TOOL_INITIAL_CREDIT;
    init_cfg->flow_control.credits_per_request = TOOL_REQIEST_CREDITS;

    if (cfg->instance_mode == SERVER) {
        if (parse_m_trans_info(cfg, init_cfg) != 0) {
            LOG_PRINT_ERR("parse_trans_info failed\n");
            goto FREE_CFG;
        }
    } else {
        if (parse_trans_info(cfg, init_cfg) != 0) {
            LOG_PRINT_ERR("parse_trans_info failed\n");
            goto FREE_CFG;
        }
    }

    if (umq_init(init_cfg) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_init failed\n");
        goto FREE_CFG;
    }
    return 0;

FREE_CFG:
    free(init_cfg);
    return -1;
}

static uint64_t find_main_umq(char *dev_name, uint32_t eid_idx)
{
    uint32_t idx = 0;
    while (g_main_umq[idx] != 0) {
        if (strcmp(g_cfg->m_dev_name[idx], dev_name) == 0 && g_cfg->m_eid_idx[idx] == eid_idx) {
            return g_main_umq[idx];
        }
        idx++;
    }
    return 0;
}

static uint32_t find_main_umq_idx(char *dev_name, uint32_t eid_idx)
{
    uint32_t idx = 0;
    while (g_main_umq[idx] != 0) {
        if (strcmp(g_cfg->m_dev_name[idx], dev_name) == 0 && g_cfg->m_eid_idx[idx] == eid_idx) {
            return idx;
        }
        idx++;
    }
    return UINT32_MAX;
}

static umq_info_t *create_one_umq(struct urpc_example_config *cfg, bool is_main_queue, char *dev_name, uint32_t eid_idx)
{
    if (g_umq_cnt == CONNECTION_SETUP_LISTEN) {
        LOG_PRINT_ERR("umq cnt has reached its maximum\n");
        return NULL;
    }
    uint32_t umq_id = __atomic_fetch_add(&g_umq_cnt, 1, __ATOMIC_RELAXED);
    umq_create_option_t option = {
        .trans_mode = (umq_trans_mode_t)cfg->trans_mode,
        .create_flag = UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_TX_BUF_SIZE | UMQ_CREATE_FLAG_RX_DEPTH |
                       UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_QUEUE_MODE | UMQ_CREATE_FLAG_TP_MODE |
                       UMQ_CREATE_FLAG_TP_TYPE,
        .rx_buf_size = TOOL_EXAMPLE_BUFFER_SIZE,
        .tx_buf_size = TOOL_EXAMPLE_BUFFER_SIZE,
        .rx_depth = TOOL_EXAMPLE_DEPTH,
        .tx_depth = TOOL_EXAMPLE_DEPTH,
        .mode = cfg->poll_mode,
        .tp_mode = cfg->tp_mode,
        .tp_type = cfg->tp_type,
    };

    umq_ctx_t *umq_ctx = NULL;
    if (!is_main_queue) {
        option.create_flag |= UMQ_CREATE_FLAG_SUB_UMQ | UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_UMQ_CTX;
        option.share_rq_umqh = find_main_umq(dev_name, eid_idx);
        umq_ctx = (umq_ctx_t *)malloc(sizeof(umq_ctx_t));
        if (umq_ctx == NULL) {
            LOG_PRINT_ERR("umq_ctx malloc failed\n");
            return NULL;
        }
        umq_ctx->umqh = 0;
        option.umq_ctx = (uint64_t)(uintptr_t)umq_ctx;
    }

    if (cfg->instance_mode == SERVER) {
        option.rx_depth = TOOL_SERVER_RX_EXAMPLE_DEPTH;
    }

    if (cfg->instance_mode == SERVER) {
        if (sprintf(option.name, "%s", "server") <= 0) {
            LOG_PRINT_ERR("set name failed\n");
            goto FREE_UMQ_CTX;
        }
    } else {
        if (sprintf(option.name, "%s", "client") <= 0) {
            LOG_PRINT_ERR("set name failed\n");
            goto FREE_UMQ_CTX;
        }
    }

    option.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
    if (cfg->instance_mode == SERVER) {
        strcpy(option.dev_info.dev.dev_name, dev_name);
        option.dev_info.dev.eid_idx = eid_idx;
    } else {
        strcpy(option.dev_info.dev.dev_name, cfg->dev_name);
        option.dev_info.dev.eid_idx = cfg->eid_idx;
    }
    uint64_t umqh = umq_create(&option);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("umq_create failed\n");
        goto FREE_UMQ_CTX;
    }

    if (umq_ctx != NULL) {
        umq_ctx->umqh = umqh;
        umq_ctx->main_umq_idx = find_main_umq_idx(dev_name, eid_idx);
        if (umq_ctx->main_umq_idx == UINT32_MAX) {
            goto DESTROY_UMQ;
        }
    }

    // insert tx fd
    umq_interrupt_option_t tx_interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };

    int tx_fd = umq_interrupt_fd_get(umqh, &tx_interrupt_option);
    if (tx_fd < 0) {
        LOG_PRINT_ERR("umq_interrupt_fd_get failed\n");
        goto DESTROY_UMQ;
    }

    fd_ctx_t *tx_fd_ctx = (fd_ctx_t *)(uintptr_t)malloc(sizeof(fd_ctx_t));
    if (tx_fd_ctx == NULL) {
        LOG_PRINT_ERR("malloc fd ctx failed\n");
        goto DESTROY_UMQ;
    }
    tx_fd_ctx->umqh = umqh;
    tx_fd_ctx->type = FD_CTX_TYPE_INTERRUPT_TX;
    tx_fd_ctx->fd = tx_fd;
    tx_fd_ctx->processing = false;

    struct epoll_event tx_ev = {
        .data.ptr = (void *)tx_fd_ctx,
        .events = EPOLLIN,
    };
    int ret = epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, tx_fd, &tx_ev);
    if (ret != 0) {
        LOG_PRINT_ERR("epoll add failed errno %d, ret %d\n", errno, ret);
        goto FREE_TX_FD_CTX;
    }

    if (umq_rearm_interrupt(umqh, false, &tx_interrupt_option) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_rearm_interrupt tx failed\n");
        goto EPOLL_DEL_TX;
    }

    // insert rx fd
    umq_interrupt_option_t rx_interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };

    int rx_fd = umq_interrupt_fd_get(umqh, &rx_interrupt_option);
    if (rx_fd < 0) {
        LOG_PRINT_ERR("umq_interrupt_rx_fd_get failed, rx fd %d\n", rx_fd);
        goto EPOLL_DEL_TX;
    }

    fd_ctx_t *rx_fd_ctx = (fd_ctx_t *)(uintptr_t)malloc(sizeof(fd_ctx_t));
    if (rx_fd_ctx == NULL) {
        LOG_PRINT_ERR("malloc fd ctx failed\n");
        goto EPOLL_DEL_TX;
    }
    rx_fd_ctx->umqh = umqh;
    rx_fd_ctx->type = FD_CTX_TYPE_INTERRUPT_RX;
    rx_fd_ctx->fd = rx_fd;
    rx_fd_ctx->processing = false;

    struct epoll_event rx_ev = {
        .data.ptr = (void *)rx_fd_ctx,
        .events = EPOLLIN,
    };

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, rx_fd, &rx_ev) != 0) {
        LOG_PRINT_ERR("epoll add failed\n");
        goto FREE_RX_FD_CTX;
    }

    if (umq_rearm_interrupt(umqh, false, &rx_interrupt_option) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_rearm_interrupt rx failed\n");
        goto EPOLL_DEL_RX;
    }

    g_umq_info_list[umq_id].umqh = umqh;
    g_umq_info_list[umq_id].enable = true;
    g_umq_info_list[umq_id].is_main_umq = is_main_queue;
    g_umq_info_list[umq_id].rx_fd_ctx = rx_fd_ctx;
    g_umq_info_list[umq_id].tx_fd_ctx = tx_fd_ctx;
    g_umq_info_list[umq_id].umq_ctx = umq_ctx;
    return &g_umq_info_list[umq_id];

EPOLL_DEL_RX:
    (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, rx_fd, NULL);

FREE_RX_FD_CTX:
    free(rx_fd_ctx);
    rx_fd_ctx = NULL;

EPOLL_DEL_TX:
    (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, tx_fd, NULL);

FREE_TX_FD_CTX:
    free(tx_fd_ctx);
    tx_fd_ctx = NULL;

DESTROY_UMQ:
    umq_destroy(umqh);

FREE_UMQ_CTX:
    if (!is_main_queue) {
        free(umq_ctx);
        umq_ctx = NULL;
    }
    return NULL;
}

static void destroy_one_umq(umq_info_t *umq_info)
{
    if (!umq_info->enable) {
        return;
    }

    (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, umq_info->rx_fd_ctx->fd, NULL);
    free(umq_info->rx_fd_ctx);
    umq_info->rx_fd_ctx = NULL;
    (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, umq_info->tx_fd_ctx->fd, NULL);
    free(umq_info->tx_fd_ctx);
    umq_info->tx_fd_ctx = NULL;
    umq_destroy(umq_info->umqh);

    if (!umq_info->is_main_umq) {
        free(umq_info->umq_ctx);
        umq_info->umq_ctx = NULL;
    }
    umq_info->enable = false;
}

static int client_bind_umq(uint64_t umqh, ip_info_t *ip_info)
{
    int ret = -1;
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        LOG_PRINT_ERR("create socket failed\n");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = TOOL_SOCKET_SEND_RECV_TIMEOUT;
    timeout.tv_usec = 0;
    ret = setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket recv timeout failed\n");
        goto CLOSE_SOC;
    }

    ret = setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket send timeout failed\n");
        goto CLOSE_SOC;
    }

    int reuse = 1;
    ret = setsockopt(client_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket port reuse failed\n");
        goto CLOSE_SOC;
    }

    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons(ip_info->port),
    };
    if (inet_pton(AF_INET, ip_info->ip, &server.sin_addr) != 1) {
        LOG_PRINT_ERR("ip[%s] not valid\n", ip_info->ip);
        ret = -1;
        goto CLOSE_SOC;
    }
    if (connect(client_fd, (struct sockaddr*)(uintptr_t)&server, sizeof(server)) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] connect failed\n", ip_info->ip, ip_info->port);
        ret = -1;
        goto CLOSE_SOC;
    }
    LOG_PRINT("server connected, ip: %s, port: %u\n", ip_info->ip, ip_info->port);

    uint8_t send_data[UMQ_MAX_BIND_INFO_SIZE + sizeof(connection_bind_info_t)];
    connection_bind_info_t *conn_bind_info = (connection_bind_info_t *)send_data;
    strcpy(conn_bind_info->dev_name, g_cfg->dev_name);
    conn_bind_info->eid_idx = g_cfg->eid_idx;
    uint32_t bind_info_size = umq_bind_info_get(umqh, conn_bind_info->umq_bind_info, UMQ_MAX_BIND_INFO_SIZE);
    if (bind_info_size == 0) {
        LOG_PRINT_ERR("umq_bind_info_get failed\n");
        return -1;
    }
    conn_bind_info->bind_info_size = bind_info_size;

    if (send_exchange_data(client_fd, send_data, bind_info_size + sizeof(connection_bind_info_t)) != 0) {
        LOG_PRINT_ERR("send_exchange_data failed\n");
        ret = -1;
        goto CLOSE_SOC;
    }

    uint8_t recv_data[UMQ_MAX_BIND_INFO_SIZE];
    uint32_t recv_len = UMQ_MAX_BIND_INFO_SIZE;
    if (recv_exchange_data(client_fd, recv_data, &recv_len) != 0) {
        LOG_PRINT_ERR("recv_exchange_data failed\n");
        ret = -1;
        goto CLOSE_SOC;
    }

    if (umq_bind(umqh, recv_data, recv_len) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_bind failed\n");
        ret = -1;
        goto CLOSE_SOC;
    }
    if (fill_umq_rx_buff(umqh, TOOL_EXAMPLE_DEPTH) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_bind failed\n");
        ret = -1;
        goto UNBIND;
    }
    return 0;

UNBIND:
    umq_unbind(umqh);

CLOSE_SOC:
    close(client_fd);
    return ret;
}

static bool is_post_rx[MAIN_QUEUE_CNT];
void serever_bind_one_client(void *bind_fd)
{
    int client_fd = *(int *)bind_fd;
    uint8_t recv_data[UMQ_MAX_BIND_INFO_SIZE];
    uint32_t recv_len = UMQ_MAX_BIND_INFO_SIZE;
    if (recv_exchange_data(client_fd, recv_data, &recv_len) != 0) {
        LOG_PRINT("recv_data failed\n");
        return;
    }

    connection_bind_info_t *conn_bind_info = (connection_bind_info_t *)recv_data;
    umq_info_t *umq_info = create_one_umq(g_cfg, false, conn_bind_info->dev_name, conn_bind_info->eid_idx);
    if (umq_info == NULL) {
        LOG_PRINT("create_one_umq failed\n");
        goto CLOSE_FD;
    }

    uint64_t umqh = umq_info->umqh;
    uint8_t send_data[UMQ_MAX_BIND_INFO_SIZE];
    uint32_t bind_info_size = umq_bind_info_get(umqh, send_data, UMQ_MAX_BIND_INFO_SIZE);
    if (bind_info_size == 0) {
        LOG_PRINT("umq_bind_info_get failed\n");
        goto DESTROY_UMQ;
    }
    
    if (umq_bind(umqh, conn_bind_info->umq_bind_info, conn_bind_info->bind_info_size) != UMQ_SUCCESS) {
        LOG_PRINT("umq_bind failed\n");
        goto DESTROY_UMQ;
    }

    if (send_exchange_data(client_fd, send_data, bind_info_size) != 0) {
        LOG_PRINT("send_exchange_data failed\n");
        goto UNBIND_UMQ;
    }

    uint32_t main_umq_idx = find_main_umq_idx(conn_bind_info->dev_name, conn_bind_info->eid_idx);
    if (!is_post_rx[main_umq_idx]) {
        is_post_rx[main_umq_idx] = true;
        if (fill_umq_rx_buff(umqh, TOOL_SERVER_RX_EXAMPLE_DEPTH) != UMQ_SUCCESS) {
            LOG_PRINT("fill_umq_rx_buff failed\n");
            is_post_rx[main_umq_idx] = false;
            goto UNBIND_UMQ;
        }
    }

    (void)__atomic_fetch_add(&g_state_total_conn_cnt, 1, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(&g_state_conn_cnt[main_umq_idx], 1, __ATOMIC_RELAXED);
    return;

UNBIND_UMQ:
    umq_unbind(umqh);

DESTROY_UMQ:
    destroy_one_umq(umq_info);

CLOSE_FD:
    close(client_fd);
}

void *start_server_lisent(void *arg)
{
    threadpool_t *pool = (threadpool_t *)arg;
    int ret = -1;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG_PRINT_ERR("create socket failed\n");
        return NULL;
    }

    struct timeval timeout;
    timeout.tv_sec = TOOL_SOCKET_SEND_RECV_TIMEOUT;
    timeout.tv_usec = 0;

    ret = setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket send timeout failed\n");
        goto CLOSE_SERVER;
    }

    int reuse = 1;
    ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket port reuse failed\n");
        goto CLOSE_SERVER;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_cfg->tcp_port),
    };
    if (inet_pton(AF_INET, g_cfg->server_ip, &addr.sin_addr) != 1) {
        LOG_PRINT_ERR("ip[%s] not valid\n", g_cfg->server_ip);
        goto CLOSE_SERVER;
    }

    if (bind(server_fd, (struct sockaddr*)(uintptr_t)&addr, sizeof(addr)) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] bind failed\n", g_cfg->server_ip, g_cfg->tcp_port);
        goto CLOSE_SERVER;
    }

    if (listen(server_fd, CONNECTION_SETUP_LISTEN) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] listen failed\n", g_cfg->server_ip, g_cfg->tcp_port);
        goto CLOSE_SERVER;
    }
    LOG_PRINT("Server listening on ip[%s] port[%u]...\n", g_cfg->server_ip, g_cfg->tcp_port);

    while (true) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            LOG_PRINT_ERR("ip[%s] port[%u] accept failed\n", g_cfg->server_ip, g_cfg->tcp_port);
            goto CLOSE_SERVER;
        }
        if (threadpool_add(pool, serever_bind_one_client,
            (void *)(uintptr_t)&client_fd, sizeof(client_fd)) != UMQ_SUCCESS) {
            LOG_PRINT_ERR("threadpool_add failed\n");
            goto CLOSE_SERVER;
        }
    }

CLOSE_SERVER:
    close(server_fd);
    return NULL;
}

static int send_req(umq_info_t *umq_info)
{
    uint64_t umqh = umq_info->umqh;
    umq_interrupt_option_t tx_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };
    umq_wait_interrupt(umqh, INTERRUPT_WAIT_TIME_MS, &tx_option);
    umq_rearm_interrupt(umqh, false, &tx_option);

    umq_interrupt_option_t rx_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    umq_wait_interrupt(umqh, INTERRUPT_WAIT_TIME_MS, &rx_option);
    umq_rearm_interrupt(umqh, false, &rx_option);

    umq_buf_t *bad_buf;
    umq_buf_t *poll_buf[32];
    int poll_cnt = umq_poll(umqh, UMQ_IO_ALL, poll_buf, 32);
    for (int i = 0; i < poll_cnt; i++) {
        if (poll_buf[i]->status == UMQ_FAKE_BUF_FC_UPDATE) {
            g_tatal_umq_info_list.fc_update++;
            umq_buf_free(poll_buf[i]);
            continue;
        }

        if (poll_buf[i]->io_direction == UMQ_IO_RX) {
            umq_buf_reset(poll_buf[i]);
            if (umq_post(umqh, poll_buf[i], UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
                umq_buf_free(bad_buf);
                LOG_PRINT_ERR("post rx failed\n");
                return -1;
            }
            umq_info->recv_rsp_cnt++;
            g_tatal_umq_info_list.recv_rsp_cnt++;
            continue;
        }
        umq_buf_free(poll_buf[i]);
    }

    umq_buf_t *tx_post_buf = umq_buf_alloc(CONNETION_SETUP_MSG_SZIE, 1, umqh, NULL);
    (void)sprintf(tx_post_buf->buf_data, "hello server i am client");
    umq_buf_pro_t *pro = (umq_buf_pro_t *)tx_post_buf->qbuf_ext;
    pro->opcode = UMQ_OPC_SEND;
    int ret = umq_post(umqh, tx_post_buf, UMQ_IO_TX, &bad_buf);
    if (ret != UMQ_SUCCESS) {
        umq_buf_free(bad_buf);
        if (ret == -UMQ_ERR_EAGAIN) {
            g_tatal_umq_info_list.eagain_cnt++;
        }
        return ret;
    }
    umq_info->send_req_cnt++;
    g_tatal_umq_info_list.send_req_cnt++;
    return 0;
}

static void return_rsp(void *arg)
{
    umq_ctx_t *umq_ctx = *(umq_ctx_t **)arg;
    uint64_t umqh = umq_ctx->umqh;
    umq_buf_t *tx_post_buf = umq_buf_alloc(CONNETION_SETUP_MSG_SZIE, 1, umqh, NULL);
    (void)sprintf(tx_post_buf->buf_data, "hello client i am server");
    umq_buf_pro_t *pro = (umq_buf_pro_t *)tx_post_buf->qbuf_ext;
    pro->opcode = UMQ_OPC_SEND;
    umq_buf_t *bad_buf;
    int ret = umq_post(umqh, tx_post_buf, UMQ_IO_TX, &bad_buf);
    if (ret != UMQ_SUCCESS) {
        umq_buf_free(bad_buf);
        if (ret == -UMQ_ERR_EAGAIN) {
            g_umq_info_list[umq_ctx->main_umq_idx].eagain_cnt++;
        } else {
            LOG_PRINT_ERR("umq post failed\n");
        }
    }
    g_umq_info_list[umq_ctx->main_umq_idx].send_rsp_cnt++;
}

static void process_tx_interrupt(void *arg)
{
    fd_ctx_t *fd_ctx = (fd_ctx_t *)(uintptr_t)(*(uint64_t *)(uintptr_t)arg);
    uint64_t umqh = fd_ctx->umqh;
    umq_interrupt_option_t option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };

    int ret = umq_wait_interrupt(umqh, INTERRUPT_WAIT_TIME_MS, &option);
    if (ret < 0) {
        fd_ctx->processing = false;
        return;
    }

    int tx_cnt = 0;
    umq_buf_t *buf;
    do {
        tx_cnt = umq_poll(umqh, UMQ_IO_TX, &buf, 1);
        if (tx_cnt == 1) {
            umq_buf_free(buf);
        }
    } while (tx_cnt > 0);
    umq_rearm_interrupt(umqh, false, &option);
    fd_ctx->processing = false;
}

static void process_rx_interrupt(void *arg)
{
    fd_ctx_t *fd_ctx = (fd_ctx_t *)(uintptr_t)(*(uint64_t *)(uintptr_t)arg);
    uint64_t umqh = fd_ctx->umqh;
    umq_interrupt_option_t option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };

    int ret = umq_wait_interrupt(umqh, INTERRUPT_WAIT_TIME_MS, &option);
    if (ret != 1) {
        fd_ctx->processing = false;
        return;
    }

    int rx_cnt = 0;
    umq_buf_t *buf;
    do {
        rx_cnt = umq_poll(umqh, UMQ_IO_RX, &buf, 1);
        if (rx_cnt == 1) {
            if (buf->status == UMQ_FAKE_BUF_FC_UPDATE) {
                umq_buf_free(buf);
                continue;
            }

            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(uintptr_t)buf->qbuf_ext;
            umq_ctx_t *umq_ctx = (umq_ctx_t *)(uintptr_t)buf_pro->umq_ctx;
            g_umq_info_list[umq_ctx->main_umq_idx].recv_req_cnt++;
            threadpool_add(g_threadpool, return_rsp, &umq_ctx, sizeof(uint64_t));
            umq_buf_reset(buf);
            umq_buf_t *bad_buf;
            if (umq_post(umq_ctx->umqh, buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
                umq_buf_free(bad_buf);
                LOG_PRINT_ERR("post rx failed\n");
            }
        }
    } while (rx_cnt > 0);
    umq_rearm_interrupt(umqh, false, &option);
    fd_ctx->processing = false;
}

static int wait_work(threadpool_t *pool)
{
    struct epoll_event events[CONNECTION_SETUP_LISTEN] = {0};
    fd_ctx_t *fd_ctx;
    while (1) {
        int num = epoll_wait(g_epoll_fd, events, CONNECTION_SETUP_LISTEN, -1);
        if (num < 0 || num > CONNECTION_SETUP_LISTEN) {
            LOG_PRINT_ERR("Epoll wait err, ret:%d.\n", num);
            return -1;
        }

        for (int i = 0; i < num; i++) {
            fd_ctx = (fd_ctx_t *)events[i].data.ptr;
            if (fd_ctx == NULL) {
                LOG_PRINT_ERR("fd_ctx inval\n");
                return -1;
            }
            switch (fd_ctx->type) {
                case FD_CTX_TYPE_INTERRUPT_TX:
                    if (fd_ctx->processing) {
                        continue;
                    }
                    fd_ctx->processing = true;
                    threadpool_add(pool, process_tx_interrupt, &fd_ctx, sizeof(uint64_t));
                    break;
                case FD_CTX_TYPE_INTERRUPT_RX:
                    if (fd_ctx->processing) {
                        continue;
                    }
                    fd_ctx->processing = true;
                    threadpool_add(pool, process_rx_interrupt, &fd_ctx, sizeof(uint64_t));
                    break;
                default:
                    LOG_PRINT_ERR("unknow type\n");
                    break;
            }
        }
    }
    return 0;
}

static void *server_state_conn_info(void *arg)
{
    while (1) {
        sleep(STATE_SLEEP_TIME_S);
        printf("=======================================================\n");
        printf("conn cnt: %u \n", g_state_total_conn_cnt);
        for (uint32_t i = 0; i < g_umq_cnt && i < MAIN_QUEUE_CNT && g_main_umq[i] != 0; i++) {
            printf("--------------------------------------------------\n");
            printf("    main umq id: %u\n", i);
            printf("    connect cnt: %u\n", g_state_conn_cnt[i]);
            printf("    recv cnt: %u\n", g_umq_info_list[i].recv_req_cnt);
            printf("    send cnt: %u\n", g_umq_info_list[i].send_rsp_cnt);
            printf("    eagain cnt: %u\n", g_umq_info_list[i].eagain_cnt);
            printf("--------------------------------------------------\n");
        }
        printf("=======================================================\n");
    }
    return NULL;
}

static int run_server(struct urpc_example_config *cfg)
{
    int ret = 0;
    g_cfg = cfg;
    g_epoll_fd = epoll_create(1);
    if (g_epoll_fd < 0) {
        LOG_PRINT_ERR("epoll_createl failed\n");
        return -1;
    }

    g_threadpool = threadpool_create(cfg->thread_poll_size, QUEUE_SIZE);
    if (g_threadpool == NULL) {
        LOG_PRINT_ERR("threadpool_create failed\n");
        ret = -1;
        goto CLOSE_FD;
    }

    if (init_umq(cfg) != 0) {
        LOG_PRINT_ERR("init_umq failed\n");
        ret = -1;
        goto DESTROY_THREADPOOL;
    }

    // create main umq
    uint32_t idx = 0;
    while (idx < cfg->m_dev_num) {
        umq_info_t *umq_info = create_one_umq(g_cfg, true, cfg->m_dev_name[idx], cfg->m_eid_idx[idx]);
        if (umq_info == NULL) {
            LOG_PRINT("create_g_main_umq failed\n");
            ret = -1;
            goto UNINIT_UMQ;
        }
        g_main_umq[idx] = umq_info->umqh;
        idx++;
    }

    // wait client
    pthread_t lisent_threads;
    if (pthread_create(&lisent_threads, NULL, start_server_lisent, (void *)g_threadpool) != 0) {
        LOG_PRINT_ERR("pthread_create failed\n");
        ret = -1;
        goto UNBIND_DESTROY_UMQ;
    }

    pthread_t state_threads;
    if (pthread_create(&state_threads, NULL, server_state_conn_info, NULL) != 0) {
        LOG_PRINT_ERR("pthread_create failed\n");
        ret = -1;
        goto JION_STATE_THREAD;
    }

    if (wait_work(g_threadpool) != 0) {
        LOG_PRINT_ERR("wait_work failed\n");
    }

    pthread_join(lisent_threads, NULL);

JION_STATE_THREAD:
    pthread_join(state_threads, NULL);

UNBIND_DESTROY_UMQ:
    // destroy sub q
    for (uint32_t i = 0; i < g_umq_cnt; i++) {
        if (!g_umq_info_list[i].enable || g_umq_info_list[i].is_main_umq) {
            continue;
        }
        umq_unbind(g_umq_info_list[i].umqh);
        destroy_one_umq(&g_umq_info_list[i]);
    }

    // destroy main q
    for (uint32_t i = 0; i < MAIN_QUEUE_CNT; i++) {
        if (!g_umq_info_list[i].is_main_umq) {
            continue;
        }
        destroy_one_umq(&g_umq_info_list[i]);
    }

UNINIT_UMQ:
    umq_uninit();

DESTROY_THREADPOOL:
    threadpool_destroy(g_threadpool);

CLOSE_FD:
    close(g_epoll_fd);
    return ret;
}

static void *client_state_conn_info(void *arg)
{
    while (1) {
        sleep(STATE_SLEEP_TIME_S);
        printf("=======================================================\n");
        printf("connect cnt:\t %u \n", g_umq_cnt);
        printf("send cnt:\t %u\n", g_tatal_umq_info_list.send_req_cnt);
        printf("recv cnt:\t %u\n", g_tatal_umq_info_list.recv_rsp_cnt);
        printf("fc update cnt:\t %u\n", g_tatal_umq_info_list.fc_update);
        printf("eagain cnt:\t %u\n", g_tatal_umq_info_list.eagain_cnt);
        printf("=======================================================\n");
    }
    return NULL;
}

static int run_client(struct urpc_example_config *cfg)
{
    int ret = 0;
    g_epoll_fd = epoll_create(1);
    if (g_epoll_fd < 0) {
        LOG_PRINT_ERR("epoll_createl failed\n");
        return -1;
    }

    g_cfg = cfg;
    if (init_umq(cfg) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("init_umq failed\n");
        ret = -1;
        goto CLOSE_FD;
    }

    pthread_t state_threads;
    if (pthread_create(&state_threads, NULL, client_state_conn_info, NULL) != 0) {
        LOG_PRINT_ERR("pthread_create failed\n");
        ret = -1;
        goto UNINIT_UMQ;
    }

    for (uint32_t i = 0; i < cfg->queue_num; i++) {
        umq_info_t *umq_info = create_one_umq(cfg, true, NULL, 0);
        if (umq_info == NULL) {
            LOG_PRINT_ERR("create_one_umq failed");
            ret = -1;
            goto UNBIND_DESTROY_UMQ;
        }

        ip_info_t ip_info = {
            .ip = cfg->server_ip,
            .port = cfg->tcp_port,
        };
        if (client_bind_umq(umq_info->umqh, &ip_info) != 0) {
            LOG_PRINT_ERR("bind umq[%u] failed\n", i);
        }
    }

    while (1) {
        for (uint32_t i = 0; i < g_umq_cnt; i++) {
            if (!g_umq_info_list[i].enable) {
                continue;
            }
            ret = send_req(&g_umq_info_list[i]);
            if (ret == -UMQ_ERR_EAGAIN) {
                usleep(EAGAIN_WAIT_TIME_U);
            } else if (ret != UMQ_SUCCESS) {
                LOG_PRINT_ERR("send req failed, ret %d\n", ret);
                goto UNBIND_DESTROY_UMQ;
            }
        }
        sleep(SEND_REQ_SLEEP_TIME_S);
    }

UNBIND_DESTROY_UMQ:
    for (uint32_t i = 0; i < g_umq_cnt; i++) {
        if (!g_umq_info_list[i].enable) {
            continue;
        }
        umq_unbind(g_umq_info_list[i].umqh);
        destroy_one_umq(&g_umq_info_list[i]);
    }
    pthread_join(state_threads, NULL);

UNINIT_UMQ:
    umq_uninit();

CLOSE_FD:
    close(g_epoll_fd);
    return 0;
}

int connection_setup_tool(struct urpc_example_config *cfg)
{
    if (cfg->instance_mode == SERVER) {
        if (cfg->thread_poll_size == 0) {
            cfg->thread_poll_size = DEFAULT_THREAD_COUNT;
        }
        return run_server(cfg);
    } else if (cfg->instance_mode == CLIENT) {
        if (cfg->queue_num == 0) {
            cfg->queue_num = DEFAULT_QUEUE_CNT;
        }
        return run_client(cfg);
    }
    return -1;
}