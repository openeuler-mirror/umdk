/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa sock header file
 * Author: Chen Wen
 * Create: 2022-09-07
 * Note:
 * History: 2023-1-18: Rename tpsa_connect to tpsa_sock, porting sock function from daemon here
 */

#ifndef TPSA_SOCK_H
#define TPSA_SOCK_H

#include "ub_hmap.h"
#include "tpsa_nl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_sock_node {
    int fd;
    urma_eid_t eid;
    struct ub_hmap_node node;
} tpsa_sock_node_t;

typedef struct sock_table {
    pthread_rwlock_t rwlock;
    struct ub_hmap hmap;
} sock_table_t;

typedef struct tpsa_sock_context {
    int listen_fd;
    uint16_t listen_port;
    sock_table_t client_table;
    sock_table_t server_table;
} tpsa_sock_ctx_t;

int tpsa_add_epoll_event(int epollfd, int fd, uint32_t events);
int tpsa_set_nonblock_opt(int fd);

int tpsa_handle_accept_fd(int epollfd, tpsa_sock_ctx_t *sock_ctx);

/* Send req or response msg to peer TPS, close fd if faild */
int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, const tpsa_nl_msg_t *msg, size_t len);
int tpsa_sock_recv_msg_timeout(int fd, char *buf, uint32_t len, int timeout, int epollfd);

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx);
void tpsa_sock_server_uninit(tpsa_sock_ctx_t *sock_ctx);

#ifdef __cplusplus
}
#endif

#endif