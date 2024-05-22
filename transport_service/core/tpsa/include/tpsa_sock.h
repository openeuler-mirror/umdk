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

#include <openssl/ssl.h>

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

typedef struct uvs_sock_node {
    int fd;
    SSL *ssl;
    uvs_net_addr_t remote_ip;
    bool negotiated;            // indicate if "version" and "cap" are valid
    uint8_t version;            // negotiated version
    uint16_t cap;               // negotiated capability
    /* Currently, epoll_event only records 'fd'. Thus, sock_node should be indexed by 'fd' as well.
     * Remove it if necessary when epoll_event records 'ip'. */
    struct ub_hmap_node fd_node;
    struct ub_hmap_node ip_node;
} uvs_sock_node_t;

typedef struct tpsa_sock_context {
    bool is_ipv6;
    int listen_fd;
    int epollfd;
    uvs_net_addr_t local_ip;
    uint16_t local_port;
    /* Add lock when UVS has multiple working threads. */
    struct ub_hmap fd_tbl;          // Receiver needs to find sock_node to delete, when error occurs
    struct ub_hmap ip_tbl;          // Sender needs to lookup fd, contained by sock_node, using IP address
    bool enable_ssl;
    uvs_ssl_cfg_t ssl_cfg;
    ssize_t (*sock_send)(uvs_sock_node_t *node, void *buf, size_t len, int timeout);
    ssize_t (*sock_recv)(uvs_sock_node_t *node, void *buf, size_t len, int timeout);
} tpsa_sock_ctx_t;

/* Struct used for init create socket message */
typedef struct tpsa_init_sock_req_param {
    tpsa_tp_mod_cfg_t local_tp_cfg;
    uvs_net_addr_info_t peer_net_addr;
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
    tp_entry_t *tp;
    tpsa_tpg_cfg_t *tpg_cfg;
    uvs_mtu_t mtu;
    tpsa_cc_param_t *resp_param;
    bool is_target;
    uvs_net_addr_info_t sip;
    uvs_net_addr_t src_uvs_ip;
    bool share_mode;
};

int uvs_proto_nego_for_req(tpsa_sock_ctx_t *ctx, int fd, struct uvs_base_header *req);
int uvs_proto_nego_for_rsp(tpsa_sock_ctx_t *ctx, int fd, struct uvs_base_header *rsp);

int uvs_add_epoll_event(int epollfd, int fd, uint32_t events);
int uvs_set_nonblock_opt(int fd);

void uvs_destroy_socket(tpsa_sock_ctx_t *ctx, int fd);
int tpsa_handle_accept_fd(tpsa_sock_ctx_t *sock_ctx);

/* Send req or response msg to peer TPS, close fd if failed */
int tpsa_sock_send_msg(tpsa_sock_ctx_t *sock_ctx, tpsa_sock_msg_t *msg,
                       size_t len, uvs_net_addr_t remote_uvs_ip);
int uvs_send_general_ack(tpsa_sock_ctx_t *ctx, tpsa_sock_msg_t *in, int fd, uint8_t ack_code);
int uvs_socket_recv(tpsa_sock_ctx_t *ctx, int fd, void *buf, uint32_t len);

int tpsa_sock_server_init(tpsa_sock_ctx_t *sock_ctx, uvs_socket_init_attr_t *attr);
void tpsa_sock_server_uninit(tpsa_sock_ctx_t *sock_ctx);

/* socket msg init */
tpsa_sock_msg_t *tpsa_sock_init_create_req(tpsa_create_param_t *cparam, tpsa_init_sock_req_param_t *param,
    uvs_net_addr_info_t *sip, uvs_socket_init_attr_t *tpsa_attr);
tpsa_sock_msg_t *tpsa_sock_init_create_resp(tpsa_sock_msg_t *msg, struct tpsa_init_sock_resp_param* param);
void tpsa_sock_init_destroy_resp(tpsa_sock_msg_t *resp);
int tpsa_sock_send_create_ack(tpsa_sock_ctx_t *sock_ctx, tpsa_sock_msg_t *msg, uvs_net_addr_info_t *sip,
    uvs_socket_init_attr_t *tpsa_attr, uvs_net_addr_t *remote_uvs_ip);
tpsa_sock_msg_t *tpsa_sock_init_destroy_finish(tpsa_sock_msg_t* msg, uvs_net_addr_info_t *sip);

tpsa_sock_msg_t *tpsa_sock_init_table_sync(tpsa_create_param_t *cparam, tpsa_table_opcode_t opcode, uint32_t src_vtpn,
                                           uvs_net_addr_info_t *sip, uvs_socket_init_attr_t *tpsa_attr);
#ifdef __cplusplus
}
#endif

#endif
