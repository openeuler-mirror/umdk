/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: common functions and components based on jetty
 */

#include <string.h>

#include "urma_api.h"
#include "urpc_lib_log.h"
#include "urpc_framework_api.h"
#include "urpc_hash.h"
#include "provider_ops_jetty.h"
#include "perf.h"
#include "jetty_public_func.h"

typedef struct send_recv_src_queue_info {
    urma_jetty_id_t remote_id;
    queue_t *l_queue;
    uint32_t tpn;
} send_recv_src_queue_info_t;
_Static_assert(sizeof(send_recv_src_queue_info_t) <= QUEUE_MSG_SRC_QUEUE_INFO_SIZE,
               "send_recv_src_queue_info_t > QUEUE_MSG_SRC_QUEUE_INFO_SIZE");

static mem_hmap_t g_urpc_ip_mem_hmap;

int send_recv_mem_seg_token_get(uint64_t mem_h, mem_seg_token_t *token)
{
    provider_t *provider = get_provider(NULL);
    if (provider == NULL) {
        URPC_LIB_LOG_ERR("get provider failed\n");
        return URPC_FAIL;
    }

    mem_handle_t *tseg = (mem_handle_t *)(uintptr_t)mem_h;
    if (provider->idx >= tseg->num) {
        URPC_LIB_LOG_ERR("provider idx %u >= tseg->num %u\n", provider->idx, tseg->num);
        return URPC_FAIL;
    }
    urma_target_seg_t *local_seg = (urma_target_seg_t *)(uintptr_t)tseg->handle[provider->idx];

    token->token_id = local_seg->seg.token_id;
    token->token_value = local_seg->user_ctx;
    return URPC_SUCCESS;
}

// use max urpc hdr size as min rx_buf_size
static inline uint32_t min_rx_buf_size_get(void)
{
    uint32_t len = 0;
    for (urpc_hdr_type_t type = URPC_REQ; type <= URPC_RSP; type++) {
        if (len < urpc_hdr_size_get(type, 0)) {
            len = urpc_hdr_size_get(type, 0);
        }
    }

    return len;
}

bool local_queue_normal_cfg_invalid(jetty_provider_t *provider, urpc_qcfg_create_t *cfg)
{
    if ((cfg->create_flag & QCREATE_FLAG_RX_BUF_SIZE) != 0 &&
        (cfg->rx_buf_size > MAX_RX_BUF_SIZE || cfg->rx_buf_size > provider->dev_attr.dev_cap.max_msg_size ||
         cfg->rx_buf_size < min_rx_buf_size_get())) {
        URPC_LIB_LOG_ERR("queue config rx_buf_size %u invalid\n", cfg->rx_buf_size);
        return true;
    }

    return false;
}

static int send_recv_rx_cq_depth_set(urpc_qcfg_get_t *cfg_get, urpc_qcfg_create_t *cfg)
{
    // if share rq, ignore local queue rx_cq_depth
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) != 0) {
        queue_local_t *local_q = CONTAINER_OF_FIELD((queue_t *)(uintptr_t)cfg->urpc_qh_share_rq, queue_local_t, queue);
        cfg_get->rx_cq_depth = local_q->cfg.rx_cq_depth;
        return URPC_SUCCESS;
    }

    // 2. disorder and normal queue, use rx_depth as rx_cq_depth
    if ((cfg->create_flag & QCREATE_FLAG_RX_CQ_DEPTH) != 0) {
        if (cfg->rx_cq_depth < cfg->rx_depth) {
            URPC_LIB_LOG_ERR("rx_cq_depth %u, rx_depth %u, tx_depth %u in trans_mode %d is invalid\n",
                cfg->rx_cq_depth, cfg->rx_depth, cfg->tx_depth, cfg_get->trans_mode);
            return URPC_FAIL;
        }

        cfg_get->rx_cq_depth = cfg->rx_cq_depth;
    } else {
        cfg_get->rx_cq_depth = cfg->rx_depth;
    }

    return URPC_SUCCESS;
}

static int send_recv_tx_cq_depth_set(urpc_qcfg_get_t *cfg_get, urpc_qcfg_create_t *cfg)
{
    // if share tx_cq, ignore local queue tx_cq_depth
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_TX_CQ) != 0) {
        queue_local_t *local_q =
            CONTAINER_OF_FIELD((queue_t *)(uintptr_t)cfg->urpc_qh_share_tx_cq, queue_local_t, queue);
        cfg_get->tx_cq_depth = local_q->cfg.tx_cq_depth;
        return URPC_SUCCESS;
    }

    // 1. normal queue use tx_depth + 1 as minimal tx_cq_depth
    uint32_t tx_depth = cfg->tx_depth + 1;

    // UB mode: jfc depth should be equal to the total depth of jfs/jetty/jfr associated with it + number of jetty
    if ((cfg->create_flag & QCREATE_FLAG_TX_CQ_DEPTH) != 0) {
            if (cfg->tx_cq_depth < tx_depth) {
                URPC_LIB_LOG_ERR("tx_cq_depth %u, rx_depth %u, tx_depth %u in trans_mode %d is invalid\n",
                    cfg->tx_cq_depth, cfg->rx_depth, cfg->tx_depth, cfg_get->trans_mode);
                return URPC_FAIL;
            }

        cfg_get->tx_cq_depth = cfg->tx_cq_depth;
    } else {
        // tx_cq_depth use one more to support flush_done
        cfg_get->tx_cq_depth = tx_depth;
    }

    return URPC_SUCCESS;
}

// cfg_get->trans_mode is set
static inline int send_recv_set_cq_depth(urpc_qcfg_get_t *cfg_get, urpc_qcfg_create_t *cfg)
{
    if (send_recv_rx_cq_depth_set(cfg_get, cfg) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    return send_recv_tx_cq_depth_set(cfg_get, cfg);
}

int send_recv_set_local_queue_normal_cfg(
    jetty_provider_t *provider, urpc_qcfg_get_t *cfg_get, urpc_qcfg_create_t *cfg, urpc_queue_trans_mode_t trans_mode)
{
    cfg_get->rx_buf_size =
        (cfg->create_flag & QCREATE_FLAG_RX_BUF_SIZE) != 0 ? cfg->rx_buf_size : min_rx_buf_size_get();
    cfg_get->rx_depth = (cfg->create_flag & QCREATE_FLAG_RX_DEPTH) != 0 ? cfg->rx_depth : 0;
    cfg_get->tx_depth = (cfg->create_flag & QCREATE_FLAG_TX_DEPTH) != 0 ? cfg->tx_depth : 0;
    cfg_get->custom_flag = (cfg->create_flag & QCREATE_FLAG_CUSTOM_FLAG) != 0 ? cfg->custom_flag : 0;
    cfg_get->priority = (cfg->create_flag & QCREATE_FLAG_PRIORITY) != 0 ? cfg->priority : URPC_PLOG_PRIORITY;
    cfg_get->type = QUEUE_TYPE_NORMAL;
    cfg_get->max_rx_sge =
        (cfg->create_flag & QCREATE_FLAG_MAX_RX_SGE) != 0 ? cfg->max_rx_sge : provider->dev_attr.dev_cap.max_jfr_sge;
    cfg_get->max_tx_sge =
        (cfg->create_flag & QCREATE_FLAG_MAX_TX_SGE) != 0 ? cfg->max_tx_sge : provider->dev_attr.dev_cap.max_jfs_sge;
    cfg_get->lock_free = (cfg->create_flag & QCREATE_FLAG_LOCK_FREE) != 0 ? cfg->lock_free : 0;
    cfg_get->mode = (cfg->create_flag & QCREATE_FLAG_MODE) != 0 ? cfg->mode : QUEUE_MODE_POLLING;
    cfg_get->trans_mode = trans_mode;
    cfg_get->skip_post_rx = (cfg->create_flag & QCREATE_FLAG_SKIP_POST_RX) != 0 ? cfg->skip_post_rx : 0;
    cfg_get->err_timeout =
        (cfg->create_flag & QCREATE_FLAG_ERR_TIMEOUT) != 0 ? cfg->err_timeout : URPC_UB_TYPICAL_ERR_TIMEOUT;
    cfg_get->rnr_retry = (cfg->create_flag & QCREATE_FLAG_RNR_RETRY) != 0 ? cfg->rnr_retry : URPC_UB_TYPICAL_RNR_RETRY;
    cfg_get->min_rnr_timer =
        (cfg->create_flag & QCREATE_FLAG_MIN_RNR_TIMER) != 0 ? cfg->min_rnr_timer : URPC_UB_TYPICAL_MIN_RNR_TIMER;

    return send_recv_set_cq_depth(cfg_get, cfg);
}

void send_recv_local_q_init(send_recv_queue_local_t *send_recv_local_q, jetty_provider_t *provider, queue_ops_t *ops,
                            uint16_t flag, uint32_t qid)
{
    send_recv_local_q->local_q.queue.status = QUEUE_STATUS_READY;
    send_recv_local_q->local_q.queue.provider = (provider_t *)(uintptr_t)provider;
    send_recv_local_q->local_q.queue.ops = ops;
    send_recv_local_q->local_q.queue.flag.is_remote = URPC_FALSE;
    send_recv_local_q->local_q.queue.flag.is_keepalive = (flag & URPC_QUEUE_FLAG_KEEPALIVE) ? URPC_TRUE : URPC_FALSE;
    send_recv_local_q->local_q.timestamp = get_timestamp();
    send_recv_local_q->local_q.qid = qid;
    send_recv_local_q->local_q.cfg.qid = qid;
    send_recv_local_q->local_q.tx_flush_done = URPC_FALSE;
    send_recv_local_q->local_q.rx_flush_done = URPC_FALSE;
    send_recv_local_q->local_q.is_damage = URPC_FALSE;
    send_recv_local_q->local_q.err_timestamp = 0;
    send_recv_local_q->local_q.is_binded = URPC_FALSE;
    atomic_init(&send_recv_local_q->local_q.err_msg_num, 0);
    atomic_init(&send_recv_local_q->in_restore_process, 0);
}

static jfc_ctx_t *send_recv_create_jfc_ctx(jetty_provider_t *provider, urma_jfc_cfg_t *jfc_cfg)
{
    jfc_ctx_t *jfc_ctx = (jfc_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(jfc_ctx_t));
    if (jfc_ctx == NULL) {
        URPC_LIB_LOG_ERR("calloc failed\n");
        return NULL;
    }

    jfc_ctx->jfc = urma_create_jfc(provider->urma_ctx, jfc_cfg);
    if (jfc_ctx->jfc == NULL) {
        URPC_LIB_LOG_ERR("create jfc failed\n");
        urpc_dbuf_free(jfc_ctx);
        return NULL;
    }

    q_res_ref_init(&jfc_ctx->ctx.ctx_ref);
    atomic_init(&jfc_ctx->ctx.expect_cq_depth, 0);

    return jfc_ctx;
}

static send_recv_queue_local_t *send_recv_get_share_queue(urpc_qcfg_create_t *cfg, uint32_t share_flag)
{
    queue_t *share_cq_qh = NULL;
    if (share_flag == QCREATE_FLAG_QH_SHARE_RQ) {
        share_cq_qh = (queue_t *)(uintptr_t)cfg->urpc_qh_share_rq;
    } else if (share_flag == QCREATE_FLAG_QH_SHARE_TX_CQ) {
        share_cq_qh = (queue_t *)(uintptr_t)cfg->urpc_qh_share_tx_cq;
    }
    if (share_cq_qh == NULL) {
        URPC_LIB_LOG_ERR("urpc_qh_share_xx is invalid\n");
        return NULL;
    }

    send_recv_queue_local_t *send_recv_share_cq_q = (send_recv_queue_local_t *)(uintptr_t)share_cq_qh;
    if (send_recv_share_cq_q->local_q.cfg.lock_free) {
        URPC_LIB_LOG_WARN("urpc_qh_share_cq is lock-free. Pay attention to concurrency issues\n");
    }
    return send_recv_share_cq_q;
}

uint32_t send_recv_tx_depth_get(urpc_qcfg_get_t *local_q_cfg)
{
    return local_q_cfg->tx_depth + 1;
}

jfce_ctx_t *send_recv_get_jfce_ctx(jetty_provider_t *provider, urpc_qcfg_create_t *cfg)
{
    uint32_t share_flag = 0;
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_TX_CQ) != 0) {
        share_flag = QCREATE_FLAG_QH_SHARE_TX_CQ;
    } else if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) != 0) {
        share_flag = QCREATE_FLAG_QH_SHARE_RQ;
    }

    if (share_flag == 0) {
        jfce_ctx_t *jfce_ctx = (jfce_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(jfce_ctx_t));
        if (jfce_ctx == NULL) {
            URPC_LIB_LOG_ERR("get_jfce_ctx calloc failed\n");
            return NULL;
        }
        jfce_ctx->jfce = urma_create_jfce(provider->urma_ctx);
        if (jfce_ctx->jfce == NULL) {
            URPC_LIB_LOG_ERR("create jfce failed\n");
            urpc_dbuf_free(jfce_ctx);
            return NULL;
        }
        q_res_ref_init(&jfce_ctx->ctx.ctx_ref);
        return jfce_ctx;
    }
    send_recv_queue_local_t *send_recv_share_cq_q = send_recv_get_share_queue(cfg, share_flag);
    if (send_recv_share_cq_q == NULL) {
        return NULL;
    }

    jfce_ctx_t *jfce_ctx = CONTAINER_OF_FIELD(send_recv_share_cq_q->local_q.ce_ctx, jfce_ctx_t, ctx);
    if (q_res_ref_get(&jfce_ctx->ctx.ctx_ref) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("shared jfce context is invalid\n");
        return NULL;
    }
    return jfce_ctx;
}

// only normal queue use this jfs_jfc
jfc_ctx_t *send_recv_get_jfs_jfc_ctx(jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *cfg,
                                     urma_jfce_t *jfce)
{
    jfc_ctx_t *jfc_ctx;
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_TX_CQ) == 0) {
        urma_jfc_cfg_t jfc_cfg = {.depth = local_q_cfg->tx_cq_depth, .jfce = jfce};
        jfc_ctx = send_recv_create_jfc_ctx(provider, &jfc_cfg);
        if (jfc_ctx == NULL) {
            return NULL;
        }

        atomic_fetch_add(&jfc_ctx->ctx.expect_cq_depth, send_recv_tx_depth_get(local_q_cfg));

        return jfc_ctx;
    }

    /* When shared jfs_jfc is used, the same jfc bound to this jfr must be used. */
    send_recv_queue_local_t *send_recv_share_cq_q = send_recv_get_share_queue(cfg, QCREATE_FLAG_QH_SHARE_TX_CQ);
    if (send_recv_share_cq_q == NULL) {
        return NULL;
    }

    jfc_ctx = CONTAINER_OF_FIELD(send_recv_share_cq_q->local_q.tx_cq_ctx, jfc_ctx_t, ctx);
    if (q_res_ref_get(&jfc_ctx->ctx.ctx_ref) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("shared jfs_jfc context is invalid\n");
        return NULL;
    }

    // add tx_depth to expect_cq_depth, and expect_cq_depth should <= local_q_cfg->tx_cq_depth
    uint32_t desired_depth;
    uint32_t expect_depth = atomic_load(&jfc_ctx->ctx.expect_cq_depth);
    do {
        desired_depth = expect_depth + send_recv_tx_depth_get(local_q_cfg);
        if (desired_depth > local_q_cfg->tx_cq_depth) {
            // put res_ref
            send_recv_put_jfc_ctx(&jfc_ctx->ctx, 0);
            URPC_LIB_LOG_ERR("get shared jfs_jfc failed, tx_cq_depth %u is not enough, expect %u\n",
                local_q_cfg->tx_cq_depth, desired_depth);
            return NULL;
        }
    } while (atomic_compare_exchange_strong(&jfc_ctx->ctx.expect_cq_depth, &expect_depth, desired_depth));

    return jfc_ctx;
}

// jfr don't need to check rx_cq_depth, because we only support shared jfr + jfr_jfc
jfc_ctx_t *send_recv_get_jfr_jfc_ctx(
    jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *cfg, urma_jfce_t *jfce)
{
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) == 0) {
        // for SoftUB, tx & rx share the jfc, sum the depth of them
        urma_jfc_cfg_t jfc_cfg = {.depth = local_q_cfg->rx_cq_depth, .jfce = jfce};
        return send_recv_create_jfc_ctx(provider, &jfc_cfg);
    }

    /* When shared jfr is used, the same jfc bound to this jfr must be used. */
    send_recv_queue_local_t *send_recv_share_cq_q = send_recv_get_share_queue(cfg, QCREATE_FLAG_QH_SHARE_RQ);
    if (send_recv_share_cq_q == NULL) {
        return NULL;
    }

    jfc_ctx_t *jfc_ctx = CONTAINER_OF_FIELD(send_recv_share_cq_q->local_q.cq_ctx, jfc_ctx_t, ctx);
    if (q_res_ref_get(&jfc_ctx->ctx.ctx_ref) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("shared jfr_jfc context is invalid\n");
        return NULL;
    }

    return jfc_ctx;
}

static ALWAYS_INLINE void send_recv_destroy_jfce_ctx(q_res_ref_t *ref, void *args)
{
    ce_ctx_t *ce_ctx = CONTAINER_OF_FIELD(ref, ce_ctx_t, ctx_ref);
    jfce_ctx_t *jfce_ctx = CONTAINER_OF_FIELD(ce_ctx, jfce_ctx_t, ctx);
    (void)urma_delete_jfce(jfce_ctx->jfce);
    urpc_dbuf_free(jfce_ctx);
}

static ALWAYS_INLINE void send_recv_destroy_jfc_ctx(q_res_ref_t *ref, void *args)
{
    cq_ctx_t *cq_ctx = CONTAINER_OF_FIELD(ref, cq_ctx_t, ctx_ref);
    jfc_ctx_t *jfc_ctx = CONTAINER_OF_FIELD(cq_ctx, jfc_ctx_t, ctx);
    (void)urma_delete_jfc(jfc_ctx->jfc);
    urpc_dbuf_free(jfc_ctx);
}

void send_recv_put_jfc_ctx(cq_ctx_t *ctx, uint32_t cq_depth)
{
    atomic_fetch_sub(&ctx->expect_cq_depth, cq_depth);
    (void)q_res_ref_put(&ctx->ctx_ref, send_recv_destroy_jfc_ctx, NULL);
}

void send_recv_put_jfce_ctx(q_res_ref_t *ref)
{
    (void)q_res_ref_put(ref, send_recv_destroy_jfce_ctx, NULL);
}

bool send_recv_rearm_jfc(jetty_provider_t *provider, urma_jfc_t *jfs_jfc, urma_jfc_t *jfr_jfc)
{
    if (provider->urma_dev->type == URMA_TRANSPORT_UB) {
        urma_jfc_attr_t jfc_attr = {
            .mask = JFC_MODERATE_COUNT,
            .moderate_count = MODERATE_COUNT,
        };
        if (urma_modify_jfc(jfs_jfc, &jfc_attr) != URMA_SUCCESS) {
            URPC_LIB_LOG_ERR("modify jfs jfc failed\n");
            return false;
        }
        if (urma_modify_jfc(jfr_jfc, &jfc_attr) != URMA_SUCCESS) {
            URPC_LIB_LOG_ERR("modify jfr jfc failed\n");
            return false;
        }
    }

    if (urma_rearm_jfc(jfs_jfc, false) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("rearm jfs jfc failed\n");
        return false;
    }

    if (urma_rearm_jfc(jfr_jfc, false) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("rearm jfr jfc failed\n");
        return false;
    }

    return true;
}

static jfr_ctx_t *send_recv_create_jfr_ctx(jetty_provider_t *provider, urma_jfr_cfg_t *jfr_cfg, uint8_t lock_free)
{
    jfr_ctx_t *jfr_ctx = (jfr_ctx_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(jfr_ctx_t));
    if (jfr_ctx == NULL) {
        URPC_LIB_LOG_ERR("calloc failed\n");
        return NULL;
    }

    if (rx_user_ctx_init(&jfr_ctx->ctx.rx_user_ctx_slab, jfr_cfg->depth) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("rx user context init failed\n");
        urpc_dbuf_free(jfr_ctx);
        return NULL;
    }

    jfr_ctx->jfr = urma_create_jfr(provider->urma_ctx, jfr_cfg);
    if (jfr_ctx->jfr == NULL) {
        URPC_LIB_LOG_ERR("create jfr failed\n");
        rx_user_ctx_uninit(&jfr_ctx->ctx.rx_user_ctx_slab);
        urpc_dbuf_free(jfr_ctx);
        return NULL;
    }

    q_res_ref_init(&jfr_ctx->ctx.ctx_ref);
    (void)pthread_spin_init(&jfr_ctx->ctx.lock, PTHREAD_PROCESS_PRIVATE);
    jfr_ctx->ctx.ready_cnt = 0;
    jfr_ctx->ctx.lock_free = lock_free;

    return jfr_ctx;
}

jfr_ctx_t *send_recv_get_jfr_ctx(jetty_provider_t *provider,
    urpc_qcfg_get_t *local_q_cfg, urpc_qcfg_create_t *qcfg, create_jetty_cfg_t *cfg)
{
    jfr_ctx_t *jfr_ctx = NULL;
    if ((qcfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) == 0) {
        urma_jfr_cfg_t jfr_cfg = {
            .flag.bs.token_policy = token_policy_get(),
            .flag.bs.order_type = URMA_DEF_ORDER,
            .trans_mode = URMA_TM_RC,
            .depth = local_q_cfg->rx_depth,
            .max_sge = local_q_cfg->max_rx_sge, .min_rnr_timer = local_q_cfg->min_rnr_timer, .jfc = cfg->jfr_jfc,
            .token_value = { .token = crypto_gen_rand_token(), }
        };
        jfr_ctx = send_recv_create_jfr_ctx(provider, &jfr_cfg, local_q_cfg->lock_free);
    } else {
        queue_t *share_rq_qh = (queue_t *)(uintptr_t)qcfg->urpc_qh_share_rq;
        if (share_rq_qh == NULL) {
            URPC_LIB_LOG_ERR("urpc_qh_share_rq is invalid\n");
            return NULL;
        }

        send_recv_queue_local_t *send_recv_share_rq_q = (send_recv_queue_local_t *)(uintptr_t)share_rq_qh;
        jfr_ctx = CONTAINER_OF_FIELD(send_recv_share_rq_q->local_q.rq_ctx, jfr_ctx_t, ctx);
        if (q_res_ref_get(&jfr_ctx->ctx.ctx_ref) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("shared jfr context is invalid\n");
            return NULL;
        }

        /* Ignore user settings for RX, use the settings from 'send_recv_share_rq_q' instead. */
        local_q_cfg->rx_depth = send_recv_share_rq_q->local_q.cfg.rx_depth;
        local_q_cfg->rx_buf_size = send_recv_share_rq_q->local_q.cfg.rx_buf_size;
        local_q_cfg->max_rx_sge = send_recv_share_rq_q->local_q.cfg.max_rx_sge;
    }

    return jfr_ctx;
}

static void send_recv_flush_jfr(queue_local_t *local_q)
{
    urma_jfr_attr_t attr = { 0 };
    attr.mask &= ~JETTY_RX_THRESHOLD;
    attr.mask |= JETTY_STATE;
    attr.state = URMA_JFR_STATE_ERROR;
    urma_jfr_t *jfr = ((jfr_ctx_t *)(void *)local_q->rq_ctx)->jfr;
    urma_status_t status = urma_modify_jfr(jfr, &attr);
    if (status != URMA_SUCCESS) {
        URPC_LIB_LOG_DEBUG("urma_modify_jetty fail\n");
        return;
    }

    int poll_num = 0;
    int poll_cnt = 0;
    urma_jfc_t *jfc = ((jfc_ctx_t *)(void *)local_q->cq_ctx)->jfc;
    int num = (int)local_q->rq_ctx->rx_wr_cnt;
    uint64_t flush_begin = urpc_get_cpu_cycles();
    urma_cr_t cr[MAX_CR];
    do {
        memset(cr, 0, sizeof(urma_cr_t) * MAX_CR);
        poll_cnt = urma_poll_jfc(jfc, MAX_CR, cr);
        for (int i = 0; i < poll_cnt; i++) {
            flush_callback(&local_q->queue, (void *)(uintptr_t)cr[i].user_ctx, cr[i].status, RX);
        }
        poll_num += poll_cnt;
    } while (poll_cnt >= 0 && poll_num < num &&
             ((urpc_get_cpu_cycles() - flush_begin) < urpc_get_cpu_hz() * URPC_UB_FLUSH_TIMEOUT_S));

    if (num != poll_num) {
        URPC_LIB_LOG_WARN("The number of buffers flushed from the UDMA is incorrect."
                          "ret %d, cost %lu ms, rx num = %d, flush num = %d\n",
                          poll_cnt, (urpc_get_cpu_cycles() - flush_begin) * MS_PER_SEC / urpc_get_cpu_hz(), num,
                          poll_num);
    } else {
        URPC_LIB_LOG_DEBUG("rx num = %d, flush num = %d, send_recv_flush_jfr success\n", num, poll_num);
    }
}

static ALWAYS_INLINE void send_recv_destroy_jfr_ctx(q_res_ref_t *ref, void *args)
{
    queue_local_t *local_q = (queue_local_t *)args;
    if (local_q != NULL && is_manager_queue(local_q->queue.flag)) {
        send_recv_flush_jfr(local_q);
    }

    rq_ctx_t *rq_ctx = CONTAINER_OF_FIELD(ref, rq_ctx_t, ctx_ref);
    jfr_ctx_t *jfr_ctx = CONTAINER_OF_FIELD(rq_ctx, jfr_ctx_t, ctx);
    if (jfr_ctx->jfr != NULL) {
        (void)urma_delete_jfr(jfr_ctx->jfr);
    }

    pthread_spin_destroy(&jfr_ctx->ctx.lock);
    rx_user_ctx_uninit(&jfr_ctx->ctx.rx_user_ctx_slab);
    urpc_dbuf_free(jfr_ctx);
}

void send_recv_put_jfr_ctx(q_res_ref_t *ref, queue_local_t *local_q)
{
    (void)q_res_ref_put(ref, send_recv_destroy_jfr_ctx, (void *)local_q);
}

urma_jetty_t *send_recv_create_jetty(
    jetty_provider_t *provider, urpc_qcfg_get_t *local_q_cfg, create_jetty_cfg_t *cfg, urma_jfr_t *jfr)
{
    urma_jetty_cfg_t jetty_cfg = {
        .jfs_cfg = {
            .flag.bs.order_type = URMA_DEF_ORDER,
            .trans_mode = URMA_TM_RC,
            .depth = local_q_cfg->tx_depth,
            .priority = local_q_cfg->priority,
            .max_sge = local_q_cfg->max_tx_sge,
            .max_inline_data = provider->dev_attr.dev_cap.max_jfs_inline_len,
            .jfc = cfg->jfs_jfc,
            .rnr_retry = local_q_cfg->rnr_retry,
            .err_timeout = local_q_cfg->err_timeout,
        },
        .id = 0,
    };

    jetty_cfg.flag.bs.share_jfr = true;
    jetty_cfg.shared.jfr = jfr;

    return urma_create_jetty(provider->urma_ctx, &jetty_cfg);
}

int send_recv_query_local_queue(queue_t *l_queue, void *ptr)
{
    if (l_queue == NULL) {
        URPC_LIB_LOG_ERR("local queue is null\n");
        return -URPC_ERR_EINVAL;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    send_recv_queue_info_t *info = (send_recv_queue_info_t *)ptr;
    send_recv_queue_local_t *send_recv_local_q = CONTAINER_OF_FIELD(local_q, send_recv_queue_local_t, local_q);
    info->queue_info.mode_jetty.jetty_id = send_recv_local_q->jetty->jetty_id;
    info->queue_info.mode_jetty.type = URMA_JETTY;
    if (send_recv_local_q->jetty->jetty_cfg.flag.bs.share_jfr) {
        info->queue_info.mode_jetty.token = send_recv_local_q->jetty->jetty_cfg.shared.jfr->jfr_cfg.token_value;
    } else {
        info->queue_info.mode_jetty.token = send_recv_local_q->jetty->jetty_cfg.jfr_cfg->token_value;
    }
    info->queue_info.type = (uint8_t)local_q->cfg.type;
    info->queue_info.trans_mode = local_q->cfg.trans_mode;
    info->queue_info.mode_jetty.order_type = send_recv_local_q->jetty->jetty_cfg.jfs_cfg.flag.bs.order_type;
    info->queue_info.priority = local_q->cfg.priority;
    info->queue_info.rx_buf_size = local_q->cfg.rx_buf_size;
    info->queue_info.custom_flag = local_q->cfg.custom_flag;
    info->queue_info.timestamp = local_q->timestamp;
    info->queue_info.qid = local_q->qid;
    info->queue_info.queue_flag = local_q->queue.flag_val;

    return URPC_SUCCESS;
}

uint32_t send_recv_query_trans_info(queue_t *queue, queue_query_trans_type_t type, void *ptr)
{
    uint32_t data_size = (uint32_t)(sizeof(queue_trans_info_t) + sizeof(queue_trans_resource_spec_t));
    if (type == QUEUE_QUERY_TRANS_INFO_SIZE) {
        return data_size;
    }

    queue_trans_info_t *trans_info = (queue_trans_info_t *)ptr;
    trans_info->flag = queue->flag;
    trans_info->trans_spec_cnt = 1;
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)queue->provider;
    bool is_ub = provider->urma_dev->type == URMA_TRANSPORT_UB;
    if (queue->flag.is_remote) {
        send_recv_queue_remote_t *remote = (send_recv_queue_remote_t *)(uintptr_t)queue;
        if (remote->flag.is_imported == URPC_TRUE) {
            memcpy(&trans_info->eid, &remote->tjetty->id.eid, sizeof(urpc_eid_t));
            trans_info->trans_spec[0].id = remote->tjetty->id.id;
            trans_info->trans_spec[0].uasid = is_ub ? URPC_U32_FAIL : remote->tjetty->id.uasid;
            trans_info->trans_spec[0].tpn = is_ub ? remote->tjetty->tp.tpn : URPC_U32_FAIL;
        } else {
            memcpy(&trans_info->eid, &remote->rjetty->jetty_id.eid, sizeof(urpc_eid_t));
            trans_info->trans_spec[0].id = remote->rjetty->jetty_id.id;
            trans_info->trans_spec[0].uasid = is_ub ? URPC_U32_FAIL : remote->rjetty->jetty_id.uasid;
            trans_info->trans_spec[0].tpn = URPC_U32_FAIL;
        }
        trans_info->custom_flag = remote->remote_q.cfg.custom_flag;
        trans_info->qid = remote->remote_q.qid;

        return data_size;
    }

    send_recv_queue_local_t *local = (send_recv_queue_local_t *)(uintptr_t)queue;
    memcpy(&trans_info->eid, &local->jetty->jetty_id.eid, sizeof(urpc_eid_t));
    trans_info->trans_spec[0].id = local->jetty->jetty_id.id;
    trans_info->trans_spec[0].uasid = is_ub ? URPC_U32_FAIL : local->jetty->jetty_id.uasid;
    trans_info->trans_spec[0].tpn = URPC_U32_FAIL;
    trans_info->custom_flag = local->local_q.cfg.custom_flag;
    trans_info->qid = local->local_q.qid;

    return data_size;
}

queue_t *send_recv_create_quick_reply_remote_queue(qr_queue_info_t *qr_queue_info)
{
    send_recv_src_queue_info_t *src_queue_info = (send_recv_src_queue_info_t *)(void *)qr_queue_info->src_q_info;
    queue_t *l_queue = src_queue_info->l_queue;
    qsrc_ctx_t *ctx = queue_ctx_get(l_queue, QUEUE_CTX_TYPE_QSRC);
    if (ctx == NULL) {
        URPC_LIB_LOG_DEBUG("malloc import queue failed\n");
        return NULL;
    }

    send_recv_queue_remote_t *imported = &ctx->rq;
    imported->flag.is_quick_reply = URPC_TRUE;
    imported->flag.is_imported = URPC_TRUE;
    imported->tjetty = &ctx->tjetty;
    imported->tjetty->id = src_queue_info->remote_id;
    imported->tjetty->tp.tpn = src_queue_info->tpn;

    imported->remote_q.queue.flag.is_remote = URPC_TRUE;
    imported->remote_q.queue.ops = queue_get_ops(QUEUE_TRANS_MODE_JETTY);
    imported->remote_q.qid = qr_queue_info->qid;
    return &imported->remote_q.queue;
}

static inline void send_recv_delete_quick_reply_remote_queue(send_recv_queue_remote_t *imported)
{
    qsrc_ctx_t *ctx = CONTAINER_OF_FIELD(imported, qsrc_ctx_t, rq);
    queue_ctx_put(QUEUE_CTX_TYPE_QSRC, ctx);
}

queue_t *send_recv_create_remote_queue(void *ptr, uint32_t remote_chid, uint16_t flag)
{
    if ((flag & URPC_QUEUE_FLAG_QUICK_REPLY) != 0) {
        return send_recv_create_quick_reply_remote_queue((qr_queue_info_t *)(uintptr_t)ptr);
    }

    send_recv_queue_remote_t *send_recv_remote_q = (send_recv_queue_remote_t *)
            urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(send_recv_queue_remote_t));
    if (send_recv_remote_q == NULL) {
        URPC_LIB_LOG_ERR("malloc remote queue failed\n");
        return NULL;
    }

    send_recv_remote_q->rjetty =
            (urma_rjetty_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(urma_rjetty_t));
    if (send_recv_remote_q->rjetty == NULL) {
        URPC_LIB_LOG_ERR("malloc rjetty failed\n");
        goto FREE_REMOTE;
    }

    send_recv_queue_info_t *info = (send_recv_queue_info_t *)ptr;
    send_recv_remote_q->remote_q.cfg.trans_mode = info->queue_info.trans_mode;
    send_recv_remote_q->remote_q.cfg.type = info->queue_info.type;
    send_recv_remote_q->remote_q.cfg.rx_buf_size = info->queue_info.rx_buf_size;
    send_recv_remote_q->remote_q.cfg.custom_flag = info->queue_info.custom_flag;
    send_recv_remote_q->remote_q.cfg.remote_chid = remote_chid;
    send_recv_remote_q->rjetty->jetty_id = info->queue_info.mode_jetty.jetty_id;
    send_recv_remote_q->rjetty->trans_mode = URMA_TM_RC;
    send_recv_remote_q->rjetty->flag.bs.order_type = info->queue_info.mode_jetty.order_type;
    send_recv_remote_q->rjetty->type = info->queue_info.mode_jetty.type;
    send_recv_remote_q->rjetty->flag.bs.token_policy = token_policy_get();
    send_recv_remote_q->token = info->queue_info.mode_jetty.token;

    send_recv_remote_q->remote_q.queue.flag_val = info->queue_info.queue_flag;
    send_recv_remote_q->remote_q.queue.flag.is_remote = URPC_TRUE;

    send_recv_remote_q->remote_q.queue.ops = queue_get_ops(QUEUE_TRANS_MODE_JETTY);
    send_recv_remote_q->remote_q.queue.status = QUEUE_STATUS_IDLE;
    send_recv_remote_q->remote_q.timestamp = info->queue_info.timestamp;
    send_recv_remote_q->remote_q.qid = info->queue_info.qid;
    send_recv_remote_q->remote_q.bind_local_qid = QUEUE_ID_MAX;

    URPC_LIB_LOG_DEBUG("create rjetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u\n",
                      EID_ARGS(send_recv_remote_q->rjetty->jetty_id.eid), send_recv_remote_q->rjetty->jetty_id.id,
                      send_recv_remote_q->rjetty->jetty_id.uasid);

    return &send_recv_remote_q->remote_q.queue;

FREE_REMOTE:
    urpc_dbuf_free(send_recv_remote_q);
    return NULL;
}

void send_recv_delete_remote_queue(queue_t *r_queue)
{
    send_recv_queue_remote_t *remote = (send_recv_queue_remote_t *)(uintptr_t)r_queue;

    if (remote->flag.is_quick_reply == URPC_TRUE) {
        send_recv_delete_quick_reply_remote_queue(remote);
        return;
    }

    if (remote->flag.is_imported == URPC_FALSE) {
        URPC_LIB_LOG_INFO("delete rjetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u\n",
            EID_ARGS(remote->rjetty->jetty_id.eid), remote->rjetty->jetty_id.id, remote->rjetty->jetty_id.uasid);
        urpc_dbuf_free(remote->rjetty);
    }

    urpc_dbuf_free(remote);
}

int send_recv_import_remote_queue(queue_t *r_queue, provider_t *provider)
{
    send_recv_queue_remote_t *remote = (send_recv_queue_remote_t *)(uintptr_t)r_queue;
    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;

    urma_target_jetty_t *tjetty = urma_import_jetty(jetty_provider->urma_ctx, remote->rjetty, &remote->token);
    if (tjetty == NULL) {
        URPC_LIB_LOG_ERR(
            "import jetty failed, remote queue EID: " EID_FMT "\n", EID_ARGS(remote->rjetty->jetty_id.eid));
        return -URPC_ERR_EINVAL;
    }
    urpc_dbuf_free(remote->rjetty);
    remote->tjetty = tjetty;
    remote->flag.is_imported = URPC_TRUE;
    r_queue->status = QUEUE_STATUS_READY;
    r_queue->provider = provider;

    URPC_LIB_LOG_DEBUG("create tjetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u, Tpn: %u\n",
        EID_ARGS(tjetty->id.eid), tjetty->id.id, tjetty->id.uasid, tjetty->tp.tpn);

    return URPC_SUCCESS;
}

int send_recv_unimport_queue(queue_t *r_queue)
{
    send_recv_queue_remote_t *imported = (send_recv_queue_remote_t *)(uintptr_t)r_queue;

    if (imported->flag.is_quick_reply == URPC_TRUE) {
        return URPC_SUCCESS;
    }

    urma_rjetty_t *rjetty = (urma_rjetty_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(urma_rjetty_t));
    if (rjetty == NULL) {
        URPC_LIB_LOG_ERR("malloc rjetty failed\n");
        return -URPC_ERR_ENOMEM;
    }

    rjetty->jetty_id = imported->tjetty->id;
    rjetty->trans_mode = URMA_TM_RC;
    rjetty->flag.bs.order_type = imported->tjetty->flag.bs.order_type;
    rjetty->type = imported->tjetty->type;
    rjetty->flag.bs.token_policy = token_policy_get();
    URPC_LIB_LOG_INFO("delete tjetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u, Tpn: %u\n",
        EID_ARGS(imported->tjetty->id.eid), imported->tjetty->id.id, imported->tjetty->id.uasid,
        imported->tjetty->tp.tpn);

    (void)urma_unimport_jetty(imported->tjetty);

    imported->rjetty = rjetty;
    imported->flag.is_imported = URPC_FALSE;
    r_queue->status = QUEUE_STATUS_IDLE;

    return URPC_SUCCESS;
}

int send_recv_update_queue_status(queue_t *r_queue, queue_import_async_info_t *async_info)
{
    send_recv_queue_remote_t *imported = (send_recv_queue_remote_t *)(uintptr_t)r_queue;
    if (async_info->status == QUEUE_IMPORT_SUCCESS) {
        urpc_dbuf_free(imported->rjetty);
        imported->tjetty = (urma_target_jetty_t*)(uintptr_t)async_info->t_jetty_handle;
        imported->flag.is_imported = URPC_TRUE;
        r_queue->status = QUEUE_STATUS_READY;
        if (imported->tjetty != NULL) {
            URPC_LIB_LOG_DEBUG("create tjetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u, Tpn: %u\n",
                EID_ARGS(imported->tjetty->id.eid), imported->tjetty->id.id, imported->tjetty->id.uasid,
                imported->tjetty->tp.tpn);
        }
    } else {
        URPC_LIB_LOG_ERR("import jetty failed, remote queue EID: " EID_FMT ", Jetty id: %u, Uasid: %u\n",
            EID_ARGS(imported->rjetty->jetty_id.eid), imported->rjetty->jetty_id.id);
        imported->flag.is_imported = URPC_FALSE;
        r_queue->status = QUEUE_STATUS_IDLE;
    }
    return URPC_SUCCESS;
}

bool send_recv_is_same_queue(queue_t *queue, void *info, queue_authn_mode_t mode)
{
    uint32_t target_jetty_id;
    if (queue->flag.is_remote == URPC_FALSE) {
        // only support URPC_QUEUE_LOCAL in control plane!!
        send_recv_queue_local_t *queue_local = (send_recv_queue_local_t *)(uintptr_t)queue;
        uint32_t jetty_id = queue_local->jetty->jetty_id.id;
        queue_info_t *queue_info = (queue_info_t *)(uintptr_t)info;
        target_jetty_id = queue_info->mode_jetty.jetty_id.id;
        return (jetty_id == target_jetty_id);
    }
    send_recv_queue_remote_t *queue_remote = (send_recv_queue_remote_t *)(uintptr_t)queue;
    uint32_t jetty_id =
        (queue_remote->flag.is_imported == URPC_TRUE) ? queue_remote->tjetty->id.id : queue_remote->rjetty->jetty_id.id;
    uint32_t timestamp = queue_remote->remote_q.timestamp;

    uint32_t target_timestamp;
    if (mode == QUEUE_AUTHN_BY_QUEUE_INFO) {
        queue_info_t *queue_info = (queue_info_t *)(uintptr_t)info;
        target_jetty_id = queue_info->mode_jetty.jetty_id.id;
        target_timestamp = queue_info->timestamp;
    } else {
        send_recv_queue_remote_t *src_queue = (send_recv_queue_remote_t *)(uintptr_t)info;
        if (src_queue->remote_q.queue.flag.is_remote == URPC_FALSE) {
            // only support URPC_QUEUE_REMOTE judge now
            return false;
        }

        if (src_queue->remote_q.qid != QUEUE_ID_INVALID) {
            return src_queue->remote_q.qid == queue_remote->remote_q.qid;
        }

        target_jetty_id = src_queue->tjetty->id.id;
        target_timestamp = timestamp;
    }
    return ((jetty_id == target_jetty_id) && (timestamp == target_timestamp));
}

void get_source_queue_info(urma_cr_t *cr, queue_local_t *local_q, uint8_t *src_q_info)
{
    send_recv_src_queue_info_t *src_queue_info = (send_recv_src_queue_info_t *)(uintptr_t)src_q_info;

    /* Note: src_q_info is a 'QUEUE_MSG_SRC_QUEUE_INFO_SIZE' bytes buffer. Beware of memory overflow. */
    src_queue_info->remote_id = cr->remote_id;
    src_queue_info->l_queue = &local_q->queue;
    src_queue_info->tpn = cr->tpn;
}

void tx_wr_cnt_add(queue_local_t *local_q)
{
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        local_q->tx_wr_cnt++;
    } else {
        (void)__sync_fetch_and_add(&local_q->tx_wr_cnt, 1);
    }
}

void tx_wr_cnt_dec(queue_local_t *local_q, tx_ctx_t *tx_ctx)
{
    if (tx_ctx != NULL) {
        if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
            --((queue_local_t *)(uintptr_t)(tx_ctx->l_qh))->tx_wr_cnt;
        } else {
            (void)__sync_fetch_and_sub(&((queue_local_t *)(uintptr_t)(tx_ctx->l_qh))->tx_wr_cnt, 1);
        }
    }
}

int send_recv_send(queue_t *l_queue, queue_wr_t *wr)
{
    uint16_t real_send_cnt = 0;

    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    send_recv_queue_remote_t *imported_queue = (send_recv_queue_remote_t *)(uintptr_t)(wr->r_queue);
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)l_queue->provider;
    uint32_t provider_idx = provider->provider.idx;

    urma_sge_t sges[URPC_SGE_NUM];
    for (uint32_t i = 0; i < wr->sge_num; i++) {
        if (URPC_UNLIKELY(wr->sge[i].flag & SGE_FLAG_DATA_ZONE)) {
            continue;
        }

        if (URPC_UNLIKELY(wr->sge[i].mem_h == 0 ||
            provider_idx >= ((mem_handle_t *)(uintptr_t)wr->sge[i].mem_h)->num)) {
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
            URPC_LIB_LIMIT_LOG_DEBUG("memory handle is invalid\n");
            return URPC_ERR_EINVAL;
        }

        sges[real_send_cnt].addr = wr->sge[i].addr;
        sges[real_send_cnt].len = wr->sge[i].length;
        sges[real_send_cnt].user_tseg = NULL;
        sges[real_send_cnt++].tseg =
            (urma_target_seg_t *)(uintptr_t)((mem_handle_t *)(uintptr_t)wr->sge[i].mem_h)->handle[provider_idx];

        if (URPC_UNLIKELY(real_send_cnt >= URPC_SGE_NUM)) {
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
            URPC_LIB_LIMIT_LOG_ERR("max send sge is %d\n", URPC_SGE_NUM);
            return URPC_ERR_EINVAL;
        }
    }

    urma_jfs_wr_t urma_wr = {.send = {.src = {.sge = sges, .num_sge = real_send_cnt}},
        .user_ctx = (uint64_t)(uintptr_t)wr->ctx,
        .opcode = URMA_OPC_SEND,
        .flag = {
            .bs = {
                .complete_enable = 1,
                .inline_flag = wr->total_size > provider->dev_attr.dev_cap.max_jfs_inline_len ? 0 : 1
            }
        },
        .tjetty = imported_queue->tjetty};
    urma_jfs_wr_t *bad_wr = NULL;

    uint64_t urma_send_start = urpc_perf_record_begin(PERF_RECORD_POINT_TRANSPORT_SEND);
    int ret = urma_post_jetty_send_wr(local_queue->jetty, &urma_wr, &bad_wr);
    urpc_perf_record_end(PERF_RECORD_POINT_TRANSPORT_SEND, urma_send_start);
    if (URPC_UNLIKELY(ret != URMA_SUCCESS)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_SEND);
        URPC_LIB_LIMIT_LOG_ERR("post jetty send failed, jetty id[%u], ret[%d]\n", local_queue->jetty->jetty_id.id, ret);
        return ret;
    }
    tx_wr_cnt_add(&local_queue->local_q);

    return URPC_SUCCESS;
}

int send_recv_post(queue_t *l_queue, queue_wr_t *wr)
{
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    uint32_t provider_idx = l_queue->provider->idx;

    urma_jfr_wr_t *bad_wr = NULL;
    urma_jfr_wr_t urma_wr;
    urma_sge_t sges[wr->sge_num];

    for (uint32_t i = 0; i < wr->sge_num; i++) {
        if (URPC_UNLIKELY(wr->sge[i].mem_h == 0 || wr->sge[i].length == 0 || wr->sge[i].addr == 0 ||
            provider_idx >= ((mem_handle_t *)(uintptr_t)wr->sge[i].mem_h)->num)) {
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
            URPC_LIB_LOG_DEBUG("the param of sge is invalid\n");
            return -URPC_ERR_EINVAL;
        }

        sges[i].addr = wr->sge[i].addr;
        sges[i].len = wr->sge[i].length;
        sges[i].user_tseg = NULL;
        sges[i].tseg =
            (urma_target_seg_t *)(uintptr_t)((mem_handle_t *)(uintptr_t)wr->sge[i].mem_h)->handle[provider_idx];
    }
    urma_wr.src.sge = sges;
    urma_wr.src.num_sge = wr->sge_num;
    urma_wr.user_ctx = (uint64_t)(uintptr_t)wr->ctx;
    urma_wr.next = NULL;

    uint64_t urma_post_start = urpc_perf_record_begin(PERF_RECORD_POINT_TRANSPORT_POST);
    int ret = urma_post_jetty_recv_wr(local_queue->jetty, &urma_wr, &bad_wr);
    urpc_perf_record_end(PERF_RECORD_POINT_TRANSPORT_POST, urma_post_start);
    if (URPC_UNLIKELY(ret != URMA_SUCCESS)) {
        URPC_LIB_LOG_DEBUG("post jetty recv failed, jetty id[%u], ret[%d]\n", local_queue->jetty->jetty_id.id, ret);
        return -URPC_ERR_TRANSPORT_ERR;
    }

    return URPC_SUCCESS;
}

int send_recv_wait(queue_t *l_queue, int timeout)
{
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    urma_jfc_t *jfc;
    urma_jfce_t *jfce = local_queue->jfs_jfc->jfc_cfg.jfce;
    int cnt = urma_wait_jfc(jfce, 1, timeout, &jfc);
    if (cnt < 0) {
        URPC_LIB_LOG_ERR("urma_wait_jfc failed\n");
        queue_error_stats_record(&local_queue->local_q.queue, ERR_STATS_TYPE_POLL);
        return -1;
    } else if (cnt == 0) {
        return 0;
    }

    uint32_t ack_cnt = 1;
    urma_ack_jfc(&jfc, &ack_cnt, 1);

    if (urma_rearm_jfc(jfc, false) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("urma_rearm_jfc failed\n");
        queue_error_stats_record(&local_queue->local_q.queue, ERR_STATS_TYPE_POLL);
        return -1;
    }

    return cnt;
}

int send_recv_read(queue_t *l_queue, queue_wr_t *wr)
{
    if (URPC_UNLIKELY(l_queue == URPC_INVALID_HANDLE || wr == NULL ||
                      wr->sge == NULL || wr->sge_num > URPC_READ_SGE_NUM ||
                      wr->dst_sge == NULL || wr->dst_sge_num > URPC_READ_SGE_NUM ||
                      wr->r_queue == URPC_INVALID_HANDLE)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_READ_PARM_INVALID);
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return URPC_ERR_EINVAL;
    }

    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    send_recv_queue_remote_t *imported_queue = (send_recv_queue_remote_t *)(uintptr_t)wr->r_queue;
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)l_queue->provider;
    uint32_t provider_idx = provider->provider.idx;
    if (URPC_UNLIKELY(wr->dst_sge[0].mem_h == 0 ||
        provider_idx >= ((mem_handle_t *)(uintptr_t)wr->dst_sge[0].mem_h)->num)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_READ_PROVIDER_INVALID);
        URPC_LIB_LIMIT_LOG_ERR("memory handle is invalid\n");
        return URPC_ERR_EINVAL;
    }

    /* currently, only support 1 sge to read */
    urma_sge_t src_sge = {
        .addr = wr->sge[0].addr,
        .len = wr->sge[0].length,
    };

    urma_sge_t dst_sge = {
        .addr = wr->dst_sge[0].addr,
        .len = wr->dst_sge[0].length,
        .tseg = (urma_target_seg_t *)(uintptr_t)((mem_handle_t *)(uintptr_t)wr->dst_sge[0].mem_h)->handle[provider_idx]
    };

    // notice: only send operation support inline, URMA_OPC_READ means receive
    urma_jfs_wr_t urma_wr = {.rw = {.src = {.sge = &src_sge, .num_sge = wr->sge_num},
        .dst = {.sge = &dst_sge, .num_sge = wr->dst_sge_num}},
        .user_ctx = (uint64_t)(uintptr_t)wr->ctx,
        .opcode = URMA_OPC_READ,
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 0}},
        .tjetty = imported_queue->tjetty};

    urma_jfs_wr_t *bad_wr = NULL;

    mem_hmap_rdlcok();
    tseg_handle_t *tseg = imported_tseg_find(wr->server_chid, wr->token_id, wr->token_value);
    if (tseg == NULL) {
        mem_hmap_unlcok();
        URPC_LIB_LIMIT_LOG_DEBUG("tseg is not found\n");
        return URPC_ERR_EINVAL;
    }
    src_sge.tseg = (urma_target_seg_t *)(uintptr_t)tseg->handle[provider_idx];
    if (src_sge.tseg == NULL) {
        mem_hmap_unlcok();
        URPC_LIB_LIMIT_LOG_DEBUG("memory handle not exist\n");
        return URPC_ERR_EINVAL;
    }
    uint64_t post_start = urpc_perf_record_begin(PERF_RECORD_POINT_TRANSPORT_READ);
    int ret = urma_post_jetty_send_wr(local_queue->jetty, &urma_wr, &bad_wr);
    mem_hmap_unlcok();
    urpc_perf_record_end(PERF_RECORD_POINT_TRANSPORT_READ, post_start);
    if (URPC_UNLIKELY(ret != URMA_SUCCESS)) {
        if (ret == URMA_EAGAIN || ret == URMA_ENOMEM) {
            /* UB mode: URMA_EAGAIN will be returned when send queue is full. */
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_READ_EAGAIN);
            URPC_LIB_LIMIT_LOG_DEBUG("post jetty read failed and need retry, jetty id[%u], ret[%d]\n",
                                     local_queue->jetty->jetty_id.id, ret);
            return URMA_EAGAIN;
        }
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_READ);
        URPC_LIB_LIMIT_LOG_ERR("post jetty read failed, jetty id[%u], ret[%d]\n",
                               local_queue->jetty->jetty_id.id, ret);
        return ret;
    }
    tx_wr_cnt_add(&local_queue->local_q);

    return URPC_SUCCESS;
}

int mem_hmap_init(void)
{
    if (g_urpc_ip_mem_hmap.ref_cnt == 0) {
        (void)pthread_rwlock_init(&g_urpc_ip_mem_hmap.lock, NULL);

        if (urpc_hmap_init(&g_urpc_ip_mem_hmap.hmap, MEM_HMAP_SIZE) != URPC_SUCCESS) {
            (void)pthread_rwlock_destroy(&g_urpc_ip_mem_hmap.lock);
            URPC_LIB_LOG_ERR("hmap init failed\n");
            return -1;
        }
    }

    g_urpc_ip_mem_hmap.ref_cnt++;
    return 0;
}

void mem_hmap_uninit(void)
{
    if (--g_urpc_ip_mem_hmap.ref_cnt != 0) {
        return;
    }

    mem_entry_t *entry, *entry_next;
    URPC_HMAP_FOR_EACH_SAFE(entry, entry_next, node, &g_urpc_ip_mem_hmap.hmap) {
        for (uint32_t i = 0; i < entry->tseg_h->num; i++) {
            (void)urma_unimport_seg((urma_target_seg_t *)(uintptr_t)entry->tseg_h->handle[i]);
        }
        urpc_hmap_remove(&g_urpc_ip_mem_hmap.hmap, &entry->node);
        urpc_dbuf_free(entry);
    }
    urpc_hmap_uninit(&g_urpc_ip_mem_hmap.hmap);
    (void)pthread_rwlock_destroy(&g_urpc_ip_mem_hmap.lock);
}

int trans_urma_cr_status_to_urpc(int urma_cr_status)
{
    switch (urma_cr_status) {
        case URMA_CR_SUCCESS:
            return URPC_SUCCESS;
        case URMA_CR_UNSUPPORTED_OPCODE_ERR:
            return URPC_ERR_CR_UNSUPPORTED_OPCODE_ERR;
        case URMA_CR_LOC_LEN_ERR:
            return URPC_ERR_CR_LOC_LEN_ERR;
        case URMA_CR_LOC_OPERATION_ERR:
            return URPC_ERR_CR_LOC_OPERATION_ERR;
        case URMA_CR_LOC_ACCESS_ERR:
            return URPC_ERR_CR_LOC_ACCESS_ERR;
        case URMA_CR_REM_RESP_LEN_ERR:
            return URPC_ERR_CR_REM_RESP_LEN_ERR;
        case URMA_CR_REM_UNSUPPORTED_REQ_ERR:
            return URPC_ERR_CR_REM_UNSUPPORTED_REQ_ERR;
        case URMA_CR_REM_OPERATION_ERR:
            return URPC_ERR_CR_REM_OPERATION_ERR;
        case URMA_CR_REM_ACCESS_ABORT_ERR:
            return URPC_ERR_CR_REM_ACCESS_ABORT_ERR;
        case URMA_CR_ACK_TIMEOUT_ERR:
            return URPC_ERR_CR_ACK_TIMEOUT_ERR;
        case URMA_CR_RNR_RETRY_CNT_EXC_ERR:
            return URPC_ERR_CR_RNR_RETRY_CNT_EXC_ERR;
        case URMA_CR_WR_FLUSH_ERR:
            return URPC_ERR_CR_WR_FLUSH_ERR;
        case URMA_CR_WR_SUSPEND_DONE:
            return URPC_ERR_CR_WR_SUSPEND_DONE;
        case URMA_CR_WR_FLUSH_ERR_DONE:
            return URPC_ERR_CR_WR_FLUSH_ERR_DONE;
        case URMA_CR_WR_UNHANDLED:
            return URPC_ERR_CR_WR_UNHANDLED;
        case URMA_CR_LOC_DATA_POISON:
            return URPC_ERR_CR_LOC_DATA_POISON;
        case URMA_CR_REM_DATA_POISON:
            return URPC_ERR_CR_REM_DATA_POISON;
        default:
            return URPC_ERR_CR_UNDEFINED;
    }
}

int send_recv_process_tx_cr(queue_msg_t *msg, urma_cr_t *cr)
{
    msg->ev = TX_SEND;
    msg->status = trans_urma_cr_status_to_urpc(cr->status);
    msg->data = (void *)(uintptr_t)cr->user_ctx;
    msg->len = cr->completion_len;
    return 1;
}

void send_recv_process_rx_cr(send_recv_queue_local_t *local_queue, queue_msg_t *msg, urma_cr_t *cr)
{
    msg->ev = RX_RECV;
    get_source_queue_info(cr, &local_queue->local_q, msg->src_q_info.info);
    msg->status = trans_urma_cr_status_to_urpc(cr->status);
    msg->data = (void *)(uintptr_t)cr->user_ctx;
    msg->len = cr->completion_len;
}

void send_recv_jetty_reset(send_recv_queue_local_t *local_queue)
{
    if (URPC_LIKELY(atomic_exchange(&local_queue->in_restore_process, 1) == 1)) {
        /* already in restore process */
        return;
    }

    urma_jetty_attr_t attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_SUSPENDED
    };
    urma_status_t status = urma_modify_jetty(local_queue->jetty, &attr);
    if (status == URMA_SUCCESS) {
        local_queue->local_q.queue.status = QUEUE_STATUS_FAULT;
    } else {
        local_queue->local_q.queue.status = QUEUE_STATUS_ERR;
        URPC_LIB_LOG_ERR("failed to reset jetty through UDMA, jetty eid: "EID_FMT", id: %u\n",
                         EID_ARGS(local_queue->jetty->jetty_id.eid), local_queue->jetty->jetty_id.id);
    }
}

void send_recv_jetty_up(send_recv_queue_local_t *local_queue)
{
    if (local_queue->local_q.queue.status == QUEUE_STATUS_ERR) {
        return;
    }
    urma_jetty_attr_t attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_READY
    };
    urma_status_t status = urma_modify_jetty(local_queue->jetty, &attr);
    if (status == URMA_SUCCESS) {
        local_queue->local_q.queue.status = QUEUE_STATUS_READY;
        atomic_store(&local_queue->in_restore_process, 0);
    } else {
        local_queue->local_q.queue.status = QUEUE_STATUS_ERR;
        URPC_LIB_LOG_ERR("failed to up jetty through UDMA, jetty eid: "EID_FMT", id: %u\n",
                         EID_ARGS(local_queue->jetty->jetty_id.eid), local_queue->jetty->jetty_id.id);
    }
}

int send_recv_flush_jetty(queue_local_t *local_q, urma_jetty_t *jetty, urma_jfc_t *jfs_jfc, bool modify,
                          uint64_t (*user_ctx_get)(uint64_t cr_user_ctx))
{
    // only manage queue need flush, user queue flush by user
    if (!is_manager_queue(local_q->queue.flag)) {
        return URPC_SUCCESS;
    }

    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)local_q->queue.provider;
    /* skip post rx means URPC will not operate this queue in datapath, no need flush */
    if (provider->urma_dev->type != URMA_TRANSPORT_UB || local_q->cfg.skip_post_rx) {
        return URPC_SUCCESS;
    }

    if (modify) {
        urma_jetty_attr_t attr = { 0 };
        attr.mask |= JETTY_STATE;
        attr.state = URMA_JETTY_STATE_ERROR;
        urma_status_t status = urma_modify_jetty(jetty, &attr);
        if (status != URMA_SUCCESS) {
            URPC_LIB_LOG_ERR("urma_modify_jetty fail, jetty id[%u]\n", jetty->jetty_id.id);
            return (int)status;
        }
    }

    int count = 0;
    uint64_t flush_begin = urpc_get_cpu_cycles();
    urma_cr_t cr = { 0 };
    while ((urpc_get_cpu_cycles() - flush_begin) < urpc_get_cpu_hz() * URPC_UB_FLUSH_TIMEOUT_S) {
        count = urma_poll_jfc(jfs_jfc, 1, &cr);
        URPC_LIB_LIMIT_LOG_DEBUG("urma poll jfc cnt = %d\n", count);
        if (count < 0) {
            break;
        }

        if (count == 1) {
            if (cr.status == URMA_CR_WR_FLUSH_ERR_DONE) {
                break;
            }
            if (cr.status == URMA_CR_WR_SUSPEND_DONE) {
                URPC_LIB_LIMIT_LOG_DEBUG("urma poll jfc status code is suspend\n");
                continue;
            }
            void *data =
                user_ctx_get == NULL ? (void *)(uintptr_t)cr.user_ctx : (void *)(uintptr_t)user_ctx_get(cr.user_ctx);
            // currently, softub in shared jfr mode, will only report tx err cr here
            flush_callback(&local_q->queue, data, cr.status, TX);
        }
    }

    if (cr.status != URMA_CR_WR_FLUSH_ERR_DONE) {
        URPC_LIB_LOG_WARN("urma poll jfc ret %d, cr status %d, cost %lu ms, but not finish\n", count, (int)cr.status,
                          (urpc_get_cpu_cycles() - flush_begin) * MS_PER_SEC / urpc_get_cpu_hz());
    }

    return URPC_SUCCESS;
}

/**
 * jfr state machine
 * Obtain the next state unconditionally through a given state
 */
static ALWAYS_INLINE int send_recv_jfr_state_machine(urma_jfr_state_t src_jfr_state, urma_jfr_state_t *dst_jfr_state)
{
    switch (src_jfr_state) {
        case URMA_JFR_STATE_READY:
            *dst_jfr_state = URMA_JFR_STATE_ERROR;
            break;
        case URMA_JFR_STATE_ERROR:
            *dst_jfr_state = URMA_JFR_STATE_RESET;
            break;
        case URMA_JFR_STATE_RESET:
            *dst_jfr_state = URMA_JFR_STATE_READY;
            break;
        default:
            return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

int send_recv_jfr_state_validate_and_set(queue_t *l_queue, urma_jfr_state_t jfr_state, urma_jfr_state_t *old_jfr_state)
{
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)l_queue->provider;
    if (provider->urma_dev->type != URMA_TRANSPORT_UB) {
        return URPC_SUCCESS;
    }
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)l_queue;
    (void)pthread_spin_lock(&local_q->rq_ctx->lock);

    urma_jfr_t *jfr = ((jfr_ctx_t *)(void *)local_q->rq_ctx)->jfr;
    urma_jfr_cfg_t jfr_cfg = {0};
    urma_jfr_attr_t jfr_attr = {0};
    urma_status_t ret = urma_query_jfr(jfr, &jfr_cfg, &jfr_attr);
    if (ret != URMA_SUCCESS) {
        (void)pthread_spin_unlock(&local_q->rq_ctx->lock);
        URPC_LIB_LOG_ERR("query jfr attr failed\n");
        return ret;
    }

    if (old_jfr_state != NULL) {
        *old_jfr_state = jfr_attr.state;
    }

    urma_jfr_attr_t attr = { 0 };
    attr.mask |= JETTY_STATE;
    attr.state = jfr_attr.state;
    while (attr.state != jfr_state) {
        if (send_recv_jfr_state_machine(attr.state, &attr.state) != URPC_SUCCESS) {
            (void)pthread_spin_unlock(&local_q->rq_ctx->lock);
            URPC_LIB_LOG_ERR("src state [%u] invalid \n", attr.state);
            return URPC_FAIL;
        }

        ret = urma_modify_jfr(jfr, &attr);
        if (ret != URMA_SUCCESS) {
            (void)pthread_spin_unlock(&local_q->rq_ctx->lock);
            URPC_LIB_LOG_ERR("modify jfr fail status %u\n", ret);
            return ret;
        }
    }
    (void)pthread_spin_unlock(&local_q->rq_ctx->lock);
    return URPC_SUCCESS;
}

int send_recv_poll_flush_done(queue_local_t *l_queue, queue_msg_t *msg)
{
    int report = 0;
    if (l_queue->queue.status != QUEUE_STATUS_ERR) {
        return report;
    }

    if (l_queue->tx_wr_cnt == 0) {
        if (l_queue->rx_flush_done == URPC_TRUE && l_queue->tx_flush_done != URPC_TRUE) {
            report = 1;
        }
        l_queue->tx_flush_done = URPC_TRUE;
    }

    if (l_queue->rq_ctx->ready_cnt != 0 || l_queue->rq_ctx->rx_wr_cnt == 0) {
        if (l_queue->tx_flush_done == URPC_TRUE && l_queue->rx_flush_done != URPC_TRUE) {
            report = 1;
        }
        l_queue->rx_flush_done = URPC_TRUE;
    }

    if (report > 0) {
        msg->ev = TX_SEND;
        msg->status = URPC_ERR_CR_WR_FLUSH_ERR_DONE;
        msg->data = NULL;
        msg->len = 0;
        return report;
    }

    void *rx_ctx = rx_user_ctx_flush(&l_queue->queue);
    if (rx_ctx != NULL) {
        msg->ev = RX_RECV;
        msg->status = URPC_ERR_CR_WR_FLUSH_ERR;
        msg->data = rx_ctx;
        msg->len = 0;
        report++;
    }

    return report;
}

void mem_hmap_rdlcok(void)
{
    (void)pthread_rwlock_rdlock(&g_urpc_ip_mem_hmap.lock);
}

void mem_hmap_unlcok(void)
{
    (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
}

tseg_handle_t *imported_tseg_find(uint32_t server_chid, uint32_t token_id, uint32_t token_value)
{
    mem_entry_t *entry = NULL;
    mem_hmap_key_t key = {
        .server_chid = server_chid,
        .token_id = token_id,
        .token_value = token_value,
    };
    uint32_t hash_key = urpc_hash_bytes(&key, sizeof(mem_hmap_key_t), 0);
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash_key, &g_urpc_ip_mem_hmap.hmap) {
        if ((entry->mem_key.server_chid == server_chid) && (entry->mem_key.token_id == token_id) &&
            (entry->mem_key.token_value == token_value)) {
            return entry->tseg_h;
        }
    }
    return NULL;
}

int jetty_provider_import_mem(provider_t *provider, xchg_mem_info_t *mem_info, uint32_t server_chid)
{
    bool new_tsge_handle = false;
    (void)pthread_rwlock_wrlock(&g_urpc_ip_mem_hmap.lock);

    tseg_handle_t *tseg_handle = imported_tseg_find(server_chid, mem_info->seg_token_id, mem_info->token.token);
    if (tseg_handle == NULL) {
        uint32_t list_size = provider_get_list_size();
        if (list_size == 0) {
            (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
            URPC_LIB_LOG_ERR("no provider is avaliable, please init urpc at first\n");
            return URPC_FAIL;
        }
        size_t size = sizeof(tseg_handle_t) + list_size * sizeof(uint64_t);
        tseg_handle = (tseg_handle_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_ALLOCATOR, 1, size);
        if (tseg_handle == NULL) {
            (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
            URPC_LIB_LOG_ERR("tseg hanle calloc failed\n");
            return -URPC_ERR_ENOMEM;
        }
        new_tsge_handle = true;
        for (uint32_t i = 0; i < list_size; i++) {
            tseg_handle->handle[i] = URPC_INVALID_HANDLE;
        }
    } else if (tseg_handle->handle[provider->idx] != URPC_INVALID_HANDLE) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_INFO("import segment memory extis\n");
        return -URPC_ERR_EEXIST;
    }

    urma_seg_t remote_seg;
    remote_seg.attr.value = mem_info->seg_flag.value;
    remote_seg.len = mem_info->seg_len;
    remote_seg.token_id = mem_info->seg_token_id;
    urma_token_t token = mem_info->token;
    remote_seg.ubva = mem_info->ubva;
    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };

    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;
    if (jetty_provider->urma_ctx == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_ERR("urma context is null\n");
        return URPC_FAIL;
    }

    urma_target_seg_t *import_tseg = urma_import_seg(jetty_provider->urma_ctx, &remote_seg, &token, 0, flag);
    if (import_tseg == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_ERR("urma import segment failed\n");
        return URPC_FAIL;
    }

    tseg_handle->handle[provider->idx] = (uint64_t)(uintptr_t)import_tseg;
    if (!new_tsge_handle) {
        tseg_handle->num++;
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        return URPC_SUCCESS;
    }

    tseg_handle->num = 1;
    mem_entry_t *entry = (mem_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(mem_entry_t));
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        urpc_dbuf_free(tseg_handle);
        URPC_LIB_LOG_ERR("malloc hash entry failed\n");
        return -URPC_ERR_ENOMEM;
    }

    mem_hmap_key_t key = {
        .server_chid = server_chid,
        .token_id = mem_info->seg_token_id,
        .token_value = mem_info->token.token,
    };
    entry->tseg_h = tseg_handle;
    entry->mem_key = key;
    uint32_t hash_key = urpc_hash_bytes(&key, sizeof(mem_hmap_key_t), 0);
    urpc_hmap_insert(&g_urpc_ip_mem_hmap.hmap, &entry->node, hash_key);

    (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);

    return URPC_SUCCESS;
}

int jetty_provider_unimport_mem(provider_t *provider, mem_hmap_key_t *mem_key)
{
    (void)pthread_rwlock_wrlock(&g_urpc_ip_mem_hmap.lock);
    tseg_handle_t *tseg_handle = imported_tseg_find(mem_key->server_chid, mem_key->token_id, mem_key->token_value);
    if (tseg_handle == NULL || tseg_handle->handle[provider->idx] == URPC_INVALID_HANDLE) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_INFO("imported tseg not exist\n");
        return URPC_SUCCESS;
    }

    urma_target_seg_t *import_tseg = (urma_target_seg_t *)(uintptr_t)tseg_handle->handle[provider->idx];
    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;
    if (jetty_provider->urma_ctx == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_ERR("urma context is null\n");
        return -URPC_ERR_EINVAL;
    }
    int ret = urma_unimport_seg(import_tseg);
    if (ret != URMA_SUCCESS) {
        (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
        URPC_LIB_LOG_ERR("urma unimport segment failed urma status %u\n", ret);
        return ret;
    }
    tseg_handle->handle[provider->idx] = URPC_INVALID_HANDLE;

    tseg_handle->num--;
    mem_entry_t *entry = NULL;
    if (tseg_handle->num == 0) {
        uint32_t hash_key = urpc_hash_bytes(mem_key, sizeof(mem_hmap_key_t), 0);
        URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash_key, &g_urpc_ip_mem_hmap.hmap) {
            if ((entry->mem_key.server_chid == mem_key->server_chid) &&
                (entry->mem_key.token_id == mem_key->token_id) &&
                (entry->mem_key.token_value == mem_key->token_value)) {
                urpc_hmap_remove(&g_urpc_ip_mem_hmap.hmap, &entry->node);
                urpc_dbuf_free(entry);
                break;
            }
        }
        urpc_dbuf_free(tseg_handle);
    }
    (void)pthread_rwlock_unlock(&g_urpc_ip_mem_hmap.lock);
    URPC_LIB_LOG_INFO("unimport segment memory successful\n");
    return URPC_SUCCESS;
}