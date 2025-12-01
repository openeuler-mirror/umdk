/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: common functions and components based on jetty
 */

#ifndef JETTY_PUBLIC_FUNC_H
#define JETTY_PUBLIC_FUNC_H

#include "queue.h"
#include "dp.h"
#include "provider_ops_jetty.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JFS_SIZE 1024
#define JFR_SIZE 1024
#define MAX_RX_BUF_SIZE 65536
#define MEM_HMAP_SIZE 1024
#define MAX_CR 32
#define URPC_READ_SGE_NUM 1
#define MODERATE_COUNT 1
#define MODERATE_PERIOD 65535
#define URPC_MEM_ENTRY_AGING_PERIOD_S (300) // 5min
/* TA timeout interval, 0b00 means 128ms, 0b01 means 1s, 0b10 means 8s, 0b11 means 64s */
#define URPC_UB_TYPICAL_ERR_TIMEOUT 2
#define URPC_UB_TYPICAL_MIN_RNR_TIMER 19 // RNR single retransmission time: 2us*2^19 = 1.049s
#define URPC_UB_TYPICAL_RNR_RETRY 6 // Retry 6 times

#define URPC_UB_FLUSH_TIMEOUT_S 1

typedef struct jfce_ctx {
    ce_ctx_t ctx;
    urma_jfce_t *jfce;
} jfce_ctx_t;

typedef struct jfc_ctx {
    cq_ctx_t ctx;
    urma_jfc_t *jfc;
} jfc_ctx_t;

typedef struct jfr_ctx {
    rq_ctx_t ctx;
    urma_jfr_t *jfr;
} jfr_ctx_t;

typedef struct send_recv_queue_local {
    queue_local_t local_q;              // placed at the beginning of the definition to facilitate conversion of types
    urma_jetty_t *jetty;
    urma_jfc_t *jfs_jfc;
    urma_jfc_t *jfr_jfc;
    urma_jfce_t *jfce;
    atomic_uint in_restore_process;
} send_recv_queue_local_t;

typedef struct remote_queue_flag {
    uint8_t is_imported : 1;
    uint8_t is_quick_reply : 1;
} send_recv_remote_queue_flag_t;

typedef struct send_recv_queue_remote {
    queue_remote_t remote_q;            // placed at the beginning of the definition to facilitate conversion of types
    union {
        urma_rjetty_t *rjetty;
        urma_target_jetty_t *tjetty;
    };
    urma_token_t token;
    send_recv_remote_queue_flag_t flag;
} send_recv_queue_remote_t;

typedef struct send_recv_queue_info {
    queue_info_t queue_info;
} send_recv_queue_info_t;

typedef struct qsrc_ctx {
    send_recv_queue_remote_t rq;
    urma_target_jetty_t tjetty;
} qsrc_ctx_t;

typedef struct create_jetty_cfg {
    urma_jfc_t *jfs_jfc;
    urma_jfc_t *jfr_jfc;
} create_jetty_cfg_t;

static ALWAYS_INLINE bool is_interrupt_mode(queue_local_t *local_q)
{
    return local_q->cfg.mode == QUEUE_MODE_INTERRUPT;
}

int send_recv_mem_seg_token_get(uint64_t mem_h, mem_seg_token_t *token);

bool local_queue_normal_cfg_invalid(jetty_provider_t *provider, urpc_qcfg_create_t *cfg);
int send_recv_set_local_queue_normal_cfg(
    jetty_provider_t *provider, urpc_qcfg_get_t *cfg_get, urpc_qcfg_create_t *cfg, urpc_queue_trans_mode_t trans_mode);
void send_recv_local_q_init(send_recv_queue_local_t *send_recv_local_q, jetty_provider_t *provider, queue_ops_t *ops,
                            uint16_t flag, uint32_t qid);

uint32_t send_recv_tx_depth_get(urpc_qcfg_get_t *local_q_cfg);

jfce_ctx_t *send_recv_get_jfce_ctx(jetty_provider_t *provider, urpc_qcfg_create_t *cfg);
jfc_ctx_t *send_recv_get_jfs_jfc_ctx(jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *cfg,
                                     urma_jfce_t *jfce);
jfc_ctx_t *send_recv_get_jfr_jfc_ctx(
    jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *cfg, urma_jfce_t *jfce);
void send_recv_put_jfc_ctx(cq_ctx_t *ctx, uint32_t cq_depth);
void send_recv_put_jfce_ctx(q_res_ref_t *ref);

bool send_recv_rearm_jfc(jetty_provider_t *provider, urma_jfc_t *jfs_jfc, urma_jfc_t *jfr_jfc);

jfr_ctx_t *send_recv_get_jfr_ctx(jetty_provider_t *provider,
    urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *qcfg, create_jetty_cfg_t *cfg);
void send_recv_put_jfr_ctx(q_res_ref_t *ref, queue_local_t *local_q);

urma_jetty_t *send_recv_create_jetty(
    jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, create_jetty_cfg_t *cfg, urma_jfr_t *jfr);

int send_recv_query_local_queue(queue_t *l_queue, void *ptr);
uint32_t send_recv_query_trans_info(queue_t *queue, queue_query_trans_type_t type, void *ptr);

queue_t *send_recv_create_quick_reply_remote_queue(qr_queue_info_t *qr_queue_info);

queue_t *send_recv_create_remote_queue(void *ptr, uint32_t remote_chid, uint16_t flag);
void send_recv_delete_remote_queue(queue_t *r_queue);

int send_recv_import_remote_queue(queue_t *r_queue, provider_t *provider);
int send_recv_unimport_queue(queue_t *r_queue);
int send_recv_update_queue_status(queue_t *r_queue, queue_import_async_info_t *async_info);
bool send_recv_is_same_queue(queue_t *queue, void *info, queue_authn_mode_t mode);

void get_source_queue_info(urma_cr_t *cr, queue_local_t *local_q, uint8_t *src_q_info);

int mem_hmap_init(void);
void mem_hmap_uninit(void);

int trans_urma_cr_status_to_urpc(int urma_cr_status);
int send_recv_process_tx_cr(queue_msg_t *msg, urma_cr_t *cr);
void send_recv_process_rx_cr(send_recv_queue_local_t *local_queue, queue_msg_t *msg, urma_cr_t *cr);
void send_recv_jetty_reset(send_recv_queue_local_t *local_queue);
void send_recv_jetty_up(send_recv_queue_local_t *local_queue);

int send_recv_flush_jetty(queue_local_t *local_q, urma_jetty_t *jetty, urma_jfc_t *jfs_jfc, bool modify,
                          uint64_t (*user_ctx_get)(uint64_t cr_user_ctx));

void tx_wr_cnt_add(queue_local_t *local_q);
void tx_wr_cnt_dec(queue_local_t *local_q, tx_ctx_t *tx_ctx);

int send_recv_send(queue_t *l_queue, queue_wr_t *wr);
int send_recv_post(queue_t *l_queue, queue_wr_t *wr);
int send_recv_wait(queue_t *l_queue, int timeout);
int send_recv_read(queue_t *l_queue, queue_wr_t *wr);

int send_recv_jfr_state_validate_and_set(queue_t *l_queue, urma_jfr_state_t jfr_state, urma_jfr_state_t *old_jfr_state);
int send_recv_poll_flush_done(queue_local_t *l_queue, queue_msg_t *msg);

tseg_handle_t *imported_tseg_find(uint32_t server_chid, uint32_t token_id, uint32_t token_value);
void mem_hmap_rdlcok(void);
void mem_hmap_unlcok(void);

int jetty_provider_import_mem(provider_t *provider, xchg_mem_info_t *mem_info, uint32_t server_chid);
int jetty_provider_unimport_mem(provider_t *provider, mem_hmap_key_t *mem_key);

#ifdef __cplusplus
}
#endif

#endif
