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
#include "urma_types.h"
#include "uvs_types.h"
#include "tpsa_types.h"
#include "tpsa_table.h"
#include "tpsa_config.h"

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

/* Struct used for init create socket message */
typedef struct tpsa_init_sock_req_param {
    tpsa_tp_mod_cfg_t local_tp_cfg;
    tpsa_net_addr_t peer_net_addr;
    uvs_mtu_t local_mtu;
    tpsa_tpg_cfg_t tpg_cfg;
    uint32_t *local_tpn;
    uint32_t local_net_addr_idx;
    uint32_t rx_psn;
    uint64_t local_seg_size;
    uint32_t upi;
    uint32_t tpgn;
    uint32_t tp_cnt;
    uint32_t cc_array_cnt;
    tpsa_tp_cc_entry_t cc_result_array[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool cc_en;
} tpsa_init_sock_req_param_t;

struct tpsa_init_sock_resp_param {
    uint32_t tpgn;
    uint32_t *tpn;
    tpsa_tpg_cfg_t *tpg_cfg;
    uvs_mtu_t mtu;
    tpsa_cc_param_t *resp_param;
    bool is_target;
    tpsa_net_addr_t sip;
};

int tpsa_add_epoll_event(int epollfd, int fd, uint32_t events);
int tpsa_set_nonblock_opt(int fd);

int tpsa_handle_accept_fd(int epollfd, tpsa_sock_ctx_t *sock_ctx);

/* Send req or response msg to peer TPS, close fd if failed */
int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, const tpsa_sock_msg_t *msg,
                       size_t len, urma_eid_t remote_eid);
int tpsa_sock_recv_msg_timeout(int fd, char *buf, uint32_t len, int timeout, int epollfd);

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx, uvs_init_attr_t *attr);
void tpsa_sock_server_uninit(tpsa_sock_ctx_t *sock_ctx);

/* socket msg init */
tpsa_sock_msg_t *tpsa_sock_init_create_req(tpsa_create_param_t *cparam, tpsa_init_sock_req_param_t *param);
tpsa_sock_msg_t *tpsa_sock_init_create_resp(tpsa_sock_msg_t *msg, struct tpsa_init_sock_resp_param* param);
void tpsa_sock_init_destroy_resp(tpsa_sock_msg_t *resp);
tpsa_sock_msg_t *tpsa_sock_init_create_ack(tpsa_sock_msg_t *msg, tpsa_net_addr_t *sip);
tpsa_sock_msg_t *tpsa_sock_init_create_finish(tpsa_sock_msg_t* msg, tpsa_net_addr_t *sip);
tpsa_sock_msg_t *tpsa_sock_init_table_sync(tpsa_create_param_t *cparam, uint32_t vtpn, tpsa_table_opcode_t opcode,
                                           uint32_t upi, vport_table_t *vport_table);
tpsa_sock_msg_t *tpsa_sock_init_destroy_req(tpsa_create_param_t *cparam, uint32_t tpgn,
                                            tpsa_net_addr_t *sip, uint32_t tp_cnt, bool delete_trigger);

#ifdef __cplusplus
}
#endif

#endif
