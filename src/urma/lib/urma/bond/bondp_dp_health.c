/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check v2 implementation (per-context)
 *   - Node-granularity health probing (one-to-many / many-to-one)
 *   - Out-of-band jetty per path, isolated from user datapath
 *   - Driven by bondp_worker (epoll + timewheel)
 */

#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ub_list.h"
#include "urma_api.h"
#include "urma_log.h"

#include "bondp_context_table.h"
#include "bondp_cp_tjetty.h"
#include "bondp_topo_info.h"
#include "bondp_types.h"
#include "bondp_worker.h"

#include "bondp_dp_health.h"

#define HC_CQE_BATCH         (8)
#define HC_PROBE_BUF_LEN     (1)
#define HC_PROBE_QUEUE_DEPTH (1024)
/* ummu_grant requires page-aligned VA and a length multiple of the page size.
 * The probe payload is only HC_PROBE_BUF_LEN bytes, but the registered segment
 * must cover a full page; the data path keeps its 1-byte sge length. */
#define HC_PROBE_SEG_LEN     (getpagesize())

typedef struct bondp_hc_ctx bondp_hc_ctx_t;

typedef struct bondp_probe_res {
    int local_idx;
    void *buf;
    urma_jfc_t *jfc;
    urma_jfr_t *jfr;
    urma_target_seg_t *seg;
    urma_jetty_t *jetty;
    /* Number of probe WRs posted but not yet completed. Only touched on the
     * single worker thread, so a plain counter is safe. Used to stop posting
     * when the probe SQ nears capacity, otherwise urma_post_jetty_send_wr
     * returns ENOMEM and the SQ wedges. */
    uint32_t inflight;
} bondp_probe_res_t;

typedef struct bondp_hc_node {
    uint32_t node_idx;

#ifndef __cplusplus
    atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#else
    std::atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#endif

    pthread_rwlock_t lock; /* Protects tjetty_list, hc_tjetty and hc_tseg */
    struct bondp_target_jetty *hc_tjetty[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    urma_target_seg_t *hc_tseg[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    struct ub_list tjetty_list;
    uint8_t no_cqe_round[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    bool probe_checked[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
} bondp_hc_node_t;

/* Per-context health-check context */
struct bondp_hc_ctx {
    bondp_hc_cfg_t cfg;
    uint8_t priority;
    bondp_probe_res_t probes[URMA_UBAGG_DEV_MAX_NUM];
    atomic_uint_fast64_t probe_task_id;
    atomic_bool started;    /* Probe jettys and task are started lazily by bondp_hc_start */
    atomic_bool stopping;   /* Set by uninit to stop the probe task from rescheduling */
    uint32_t probe_cur_idx; /* Current polling position for batched node probing */
    uint32_t node_num;
    bondp_hc_node_t nodes[MAX_NODE_NUM];
};

/*
 * Health probe user_ctx layout:
 *   bits [63:32]: node_idx, used to find the remote node health context.
 *   bits [31:0] : target_idx, used with local_idx to find the checked path.
 */
#define HC_USER_CTX_TARGET_BITS (32)

static inline uint64_t hc_encode_user_ctx(uint32_t node_idx, uint32_t target_idx)
{
    return ((uint64_t)node_idx << HC_USER_CTX_TARGET_BITS) | target_idx;
}

static inline void hc_decode_user_ctx(uint64_t user_ctx, uint32_t *node_idx, uint32_t *target_idx)
{
    *node_idx = (uint32_t)(user_ctx >> HC_USER_CTX_TARGET_BITS);
    *target_idx = (uint32_t)user_ctx;
}

static urma_jetty_t *hc_create_probe_jetty(urma_context_t *p_ctx, urma_jfc_t *jfc,
                                           urma_jfr_t *jfr, int local_idx, uint8_t priority)
{
    urma_jetty_cfg_t p_cfg = {
        .flag = {.bs = {.share_jfr = URMA_SHARE_JFR}},
        .jfs_cfg = {
            .depth = HC_PROBE_QUEUE_DEPTH,
            .trans_mode = URMA_TM_RM,
            .priority = priority,
            .max_sge = 1,
            .rnr_retry = URMA_TYPICAL_RNR_RETRY,
            .err_timeout = 0,
            .jfc = jfc,
        },
        .shared.jfr = jfr,
        .shared.jfc = NULL,
        .jetty_grp = NULL,
    };
    urma_jetty_t *jetty = urma_create_jetty(p_ctx, &p_cfg);
    if (jetty == NULL) {
        URMA_LOG_ERR("Failed to create health probe jetty, local_idx=%d.\n", local_idx);
    }
    return jetty;
}

static void hc_rebuild_probe_jetty(bondp_hc_ctx_t *hc_ctx, bondp_probe_res_t *res)
{
    int local_idx = res->local_idx;
    if (res->jfc == NULL || res->jfc->urma_ctx == NULL || res->jfr == NULL) {
        URMA_LOG_ERR("Invalid health probe resource for jetty rebuild, local_idx=%d.\n", local_idx);
        return;
    }
    if (res->jetty == NULL) {
        return;
    }

    urma_context_t *p_ctx = res->jfc->urma_ctx;
    urma_jetty_attr_t attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_ERROR,
    };

    urma_status_t ret = urma_modify_jetty(res->jetty, &attr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_WARN("Failed to modify health probe jetty to error, local_idx=%d, ret=%d.\n",
                      local_idx, ret);
    }
    ret = urma_delete_jetty(res->jetty);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete old health probe jetty, local_idx=%d, ret=%d.\n",
                     local_idx, ret);
        return;
    }
    res->jetty = NULL;
    res->inflight = 0; /* The old SQ is gone; its outstanding WRs are flushed. */
    for (uint32_t i = 0; i < hc_ctx->node_num; ++i) {
        bondp_hc_node_t *node = &hc_ctx->nodes[i];

        pthread_rwlock_wrlock(&node->lock);
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            node->no_cqe_round[local_idx][j] = 0;
        }
        pthread_rwlock_unlock(&node->lock);
    }

    res->jetty = hc_create_probe_jetty(p_ctx, res->jfc, res->jfr, local_idx, hc_ctx->priority);
    if (res->jetty == NULL) {
        URMA_LOG_ERR("Failed to rebuild health probe jetty, local_idx=%d.\n", local_idx);
    }
}

static void hc_set_tjetty_list_target_valid(bondp_hc_node_t *node, uint32_t local_idx, uint32_t target_idx)
{
    bondp_target_jetty_t *bdp_tjetty = NULL;
    uint32_t recovered_cnt = 0;

    pthread_rwlock_rdlock(&node->lock);
    UB_LIST_FOR_EACH (bdp_tjetty, hc_entry, &node->tjetty_list) {
        bondp_p_target_jetty_t *p_tjetty = bondp_find_p_tjetty(bdp_tjetty, local_idx, target_idx);
        if (p_tjetty != NULL) {
            atomic_store(&p_tjetty->valid, true);
            recovered_cnt++;
        }
    }
    pthread_rwlock_unlock(&node->lock);

    if (recovered_cnt != 0) {
        URMA_LOG_INFO("Path restored: target jettys recovered, node_idx=%u, "
                      "path=[%u, %u], cnt=%u\n",
                      node->node_idx, local_idx, target_idx, recovered_cnt);
    }
}

static void hc_set_local_idx_jettys_hc_valid(bondp_context_t *bdp_ctx, uint32_t local_idx)
{
    if (bdp_ctx == NULL || local_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }

    uint32_t ready_cnt = 0;
    bdp_p_vjetty_id_t *item = NULL;

    pthread_rwlock_rdlock(&bdp_ctx->p_vjetty_id_table.lock);
    HMAP_FOR_EACH (item, hmap_node, &bdp_ctx->p_vjetty_id_table.hmap) {
        bondp_comp_t *comp = item->comp;
        if (item->key.type != JETTY || comp == NULL ||
            comp->p_jetty[local_idx] == NULL) {
            continue;
        }
        if (!atomic_exchange(&comp->rebuild_done[local_idx], false)) {
            continue;
        }
        atomic_store(&comp->hc_valid[local_idx], true);
        ready_cnt++;
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);

    if (ready_cnt != 0) {
        URMA_LOG_INFO("Path ready: local jettys ready for failback, "
                      "local_idx=%u, cnt=%u\n",
                      local_idx, ready_cnt);
    }
}

static void hc_process_probe_cr(bondp_hc_ctx_t *hc_ctx, int local_idx, const urma_cr_t *cr)
{
    uint32_t node_idx;
    uint32_t target_idx;

    hc_decode_user_ctx(cr->user_ctx, &node_idx, &target_idx);

    if (node_idx >= hc_ctx->node_num) {
        return;
    }
    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

    if (target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }
    bool ok = (cr->status == URMA_CR_SUCCESS);
    bondp_target_jetty_t *bdp_tjetty = node->hc_tjetty[local_idx][target_idx];
    bool prev = true;
    if (bdp_tjetty != NULL) {
        const bondp_p_target_jetty_t *p_tjetty = bondp_find_p_tjetty_const(bdp_tjetty, local_idx, target_idx);
        prev = (p_tjetty != NULL) ? atomic_load(&p_tjetty->valid) : true;
    }
    atomic_store(&node->valid[local_idx][target_idx], ok);
    if (ok && !prev) {
        URMA_LOG_INFO("Health probe link [%d, %d] recovered.\n", local_idx, target_idx);
        hc_set_tjetty_list_target_valid(node, local_idx, target_idx);
    }
    if (ok && bdp_tjetty != NULL) {
        bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(bdp_tjetty->v_tjetty.urma_ctx,
                                                      bondp_context_t, v_ctx);
        hc_set_local_idx_jettys_hc_valid(bdp_ctx, (uint32_t)local_idx);
    }

    node->no_cqe_round[local_idx][target_idx] = 0;
    node->probe_checked[local_idx][target_idx] = true;
}

static void hc_poll_probe_cq(bondp_hc_ctx_t *hc_ctx, int local_idx)
{
    if (hc_ctx == NULL || local_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }
    bondp_probe_res_t *res = &hc_ctx->probes[local_idx];
    if (res->jfc == NULL) {
        return;
    }

    bool has_timeout_cqe = false;
    urma_cr_t cr[HC_CQE_BATCH];

    while (true) {
        int n = urma_poll_jfc(res->jfc, HC_CQE_BATCH, cr);
        if (n <= 0) {
            break;
        }
        for (int i = 0; i < n; i++) {
            if (!has_timeout_cqe) {
                hc_process_probe_cr(hc_ctx, local_idx, &cr[i]);
            }
            if (cr[i].status == URMA_CR_ACK_TIMEOUT_ERR) { /* status 9 */
                has_timeout_cqe = true;
            }
        }
        if ((uint32_t)n > res->inflight) {
            URMA_LOG_WARN("Health probe inflight underflow, local_idx=%d, inflight=%u, poll_cnt=%d.\n",
                          local_idx, res->inflight, n);
            res->inflight = 0;
        } else {
            res->inflight -= (uint32_t)n;
        }
    }
    if (has_timeout_cqe) {
        hc_rebuild_probe_jetty(hc_ctx, res);
    }
}

static void hc_probe_link(bondp_hc_ctx_t *hc_ctx, bondp_hc_node_t *node,
                          int local_idx, int target_idx)
{
    if (hc_ctx == NULL || node == NULL ||
        local_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM ||
        target_idx < 0 || target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }

    bondp_probe_res_t *res = &hc_ctx->probes[local_idx];
    if (res->jetty == NULL || res->seg == NULL || res->buf == NULL) {
        return;
    }

    if (res->inflight >= HC_PROBE_QUEUE_DEPTH) {
        return;
    }
    if (node->no_cqe_round[local_idx][target_idx] != 0) {
        if (node->no_cqe_round[local_idx][target_idx] != UINT8_MAX) {
            node->no_cqe_round[local_idx][target_idx]++;
        }
        return;
    }

    bondp_target_jetty_t *bdp_tjetty = node->hc_tjetty[local_idx][target_idx];
    if (bdp_tjetty == NULL) {
        return;
    }

    bondp_p_target_jetty_t *p_tjetty = bondp_find_p_tjetty(bdp_tjetty, local_idx, target_idx);
    if (p_tjetty == NULL) {
        return;
    }

    urma_target_jetty_t *tjetty = p_tjetty->p_tjetty;
    urma_target_seg_t *tseg = node->hc_tseg[local_idx][target_idx];
    if (tjetty == NULL || tseg == NULL) {
        return;
    }

    urma_sge_t src_sge = {
        .addr = (uint64_t)res->buf,
        .len = HC_PROBE_BUF_LEN,
        .tseg = res->seg,
        .user_tseg = NULL,
    };
    urma_sge_t dst_sge = {
        .addr = tseg->seg.ubva.va,
        .len = HC_PROBE_BUF_LEN,
        .tseg = tseg,
        .user_tseg = NULL,
    };

    uint64_t user_ctx = hc_encode_user_ctx(node->node_idx, (uint32_t)target_idx);

    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_WRITE,
        .flag.bs.complete_enable = 1,
        .tjetty = tjetty,
        .user_ctx = user_ctx,
        .rw = {
            .src = {.sge = &src_sge, .num_sge = 1},
            .dst = {.sge = &dst_sge, .num_sge = 1},
        },
        .next = NULL,
    };

    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t ret = urma_post_jetty_send_wr(res->jetty, &wr, &bad_wr);
    if (ret == URMA_SUCCESS) {
        res->inflight++;
        node->no_cqe_round[local_idx][target_idx] = 1;
    } else {
        URMA_LOG_WARN("Failed to send health probe, node_idx=%u, local_idx=%d, target_idx=%d, ret=%d.\n",
                      node->node_idx, local_idx, target_idx, ret);
        atomic_store(&node->valid[local_idx][target_idx], false);
    }
}

static bool hc_probe_node(bondp_hc_ctx_t *hc_ctx, bondp_hc_node_t *node)
{
    bool any_connected = false;
    bool all_checked = true;

    pthread_rwlock_rdlock(&node->lock);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (node->hc_tjetty[i][j] == NULL) {
                continue;
            }
            any_connected = true;
            if (node->probe_checked[i][j]) {
                continue;
            }
            all_checked = false;
            hc_probe_link(hc_ctx, node, i, j);
        }
    }

    if (any_connected && all_checked) {
        for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
            for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
                node->probe_checked[i][j] = false;
            }
        }
    }
    pthread_rwlock_unlock(&node->lock);

    return any_connected;
}

static void hc_probe_fn(bondp_worker_task_reason_t reason, void *arg)
{
    bondp_hc_ctx_t *hc_ctx = (bondp_hc_ctx_t *)arg;
    /* Cancelled (e.g. by bondp_hc_uninit) or already stopping: do not run
     * probes and, crucially, do not reschedule. Otherwise the next firing
     * accesses hc_ctx after it has been freed. */
    if (reason == BONDP_WORKER_TASK_CANCELED || hc_ctx == NULL ||
        atomic_load(&hc_ctx->stopping)) {
        return;
    }
    if (hc_ctx->node_num == 0) {
        return;
    }

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (hc_ctx->probes[i].jetty == NULL) {
            continue;
        }
        hc_poll_probe_cq(hc_ctx, (int)i);
    }

    uint32_t batch_cnt = MIN(hc_ctx->cfg.batch_node_num, hc_ctx->node_num);
    uint32_t node_idx = hc_ctx->probe_cur_idx % hc_ctx->node_num;
    uint32_t probe_cnt = 0;
    for (uint32_t scan_cnt = 0; scan_cnt < hc_ctx->node_num && probe_cnt < batch_cnt; ++scan_cnt) {
        bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];
        if (hc_probe_node(hc_ctx, node)) {
            probe_cnt++;
        }
        node_idx = (node_idx + 1) % hc_ctx->node_num;
    }
    hc_ctx->probe_cur_idx = node_idx;

    /* Reschedule next global probe only if not being torn down. The
     * stopping flag is checked again to close the window between a concurrent
     * uninit and this reschedule. */
    if (atomic_load(&hc_ctx->stopping)) {
        return;
    }
    bondp_worker_task_id_t task_id = 0;
    int ret = bondp_worker_schedule(hc_ctx->cfg.probe_interval_ms,
                                    hc_probe_fn, hc_ctx, &task_id);
    if (ret == 0) {
        atomic_store(&hc_ctx->probe_task_id, task_id);
    } else {
        URMA_LOG_ERR("Failed to reschedule health probe task, ret=%d.\n", ret);
    }
}

static int hc_init_node(bondp_hc_node_t *node, uint32_t node_idx)
{
    node->node_idx = node_idx;
    ub_list_init(&node->tjetty_list);
    (void)memset(node->hc_tjetty, 0, sizeof(node->hc_tjetty));
    (void)memset(node->hc_tseg, 0, sizeof(node->hc_tseg));
    (void)memset(node->no_cqe_round, 0, sizeof(node->no_cqe_round));
    (void)memset(node->probe_checked, 0, sizeof(node->probe_checked));
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            atomic_store(&node->valid[i][j], true);
        }
    }

    if (pthread_rwlock_init(&node->lock, NULL) != 0) {
        return -1;
    }
    return 0;
}

static void hc_destroy_node(bondp_hc_node_t *node)
{
    if (node == NULL) {
        return;
    }

    bondp_target_jetty_t *tjetty = NULL;
    bondp_target_jetty_t *next = NULL;
    UB_LIST_FOR_EACH_SAFE (tjetty, next, hc_entry, &node->tjetty_list) {
        ub_list_remove(&tjetty->hc_entry);
        tjetty->mask &= ~BONDP_TJETTY_FLAG_HC_REGISTERED;
        tjetty->hc_node_idx = 0;
    }

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (node->hc_tseg[i][j] == NULL) {
                continue;
            }
            if (urma_unimport_seg(node->hc_tseg[i][j]) == URMA_SUCCESS) {
                node->hc_tseg[i][j] = NULL;
            } else {
                URMA_LOG_ERR("Failed to unimport health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
            }
        }
    }

    pthread_rwlock_destroy(&node->lock);
}

static void hc_destroy_nodes(bondp_hc_ctx_t *hc_ctx)
{
    if (hc_ctx == NULL || hc_ctx->node_num == 0) {
        return;
    }

    for (uint32_t i = 0; i < hc_ctx->node_num; ++i) {
        hc_destroy_node(&hc_ctx->nodes[i]);
    }
    hc_ctx->node_num = 0;
}

static int hc_init_nodes(bondp_hc_ctx_t *hc_ctx, bool *has_nodes)
{
    uint32_t node_num = bondp_topo_get_node_num();
    uint32_t init_node_num = 0;

    *has_nodes = false;
    if (node_num == 0) {
        URMA_LOG_DEBUG("No topo node for health check, skip probe task.\n");
        return 0;
    }
    if (node_num > MAX_NODE_NUM) {
        URMA_LOG_ERR("Invalid topo node num for health check, node_num=%u.\n", node_num);
        return -1;
    }

    for (uint32_t i = 0; i < node_num; ++i) {
        int ret = hc_init_node(&hc_ctx->nodes[i], i);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to init health check node, node_idx=%u.\n", i);
            goto ERR_DESTROY_NODES;
        }
        init_node_num++;
    }

    hc_ctx->node_num = node_num;
    *has_nodes = true;
    return 0;

ERR_DESTROY_NODES:
    for (uint32_t i = 0; i < init_node_num; ++i) {
        hc_destroy_node(&hc_ctx->nodes[i]);
    }
    hc_ctx->node_num = 0;
    return -1;
}

static void hc_destroy_probe_resource(bondp_hc_ctx_t *hc_ctx, int local_idx)
{
    bondp_probe_res_t *res = &hc_ctx->probes[local_idx];

    if (res->jetty != NULL) {
        urma_delete_jetty(res->jetty);
        res->jetty = NULL;
    }
    if (res->jfr != NULL) {
        urma_delete_jfr(res->jfr);
        res->jfr = NULL;
    }
    if (res->seg != NULL) {
        urma_unregister_seg(res->seg);
        res->seg = NULL;
    }
    if (res->buf != NULL) {
        free(res->buf);
        res->buf = NULL;
    }
    if (res->jfc != NULL) {
        urma_delete_jfc(res->jfc);
        res->jfc = NULL;
    }
    *res = (bondp_probe_res_t){0};
}

static int hc_init_probe_resource(urma_context_t *p_ctx, bondp_probe_res_t *res)
{
    int local_idx = res->local_idx;
    urma_jfc_cfg_t jfc_cfg = {
        .depth = HC_PROBE_QUEUE_DEPTH,
    };
    urma_jfc_t *jfc = urma_create_jfc(p_ctx, &jfc_cfg);
    if (jfc == NULL) {
        URMA_LOG_ERR("Failed to create health probe jfc, local_idx=%d.\n", local_idx);
        return -1;
    }

    urma_jfr_cfg_t jfr_cfg = {
        .depth = 1,
        .trans_mode = URMA_TM_RM,
        .max_sge = 1,
        .jfc = jfc,
    };
    urma_jfr_t *jfr = urma_create_jfr(p_ctx, &jfr_cfg);
    if (jfr == NULL) {
        URMA_LOG_ERR("Failed to create health probe jfr, local_idx=%d.\n", local_idx);
        goto DELETE_JFC;
    }

    void *buf = memalign(getpagesize(), HC_PROBE_SEG_LEN);
    if (buf == NULL) {
        URMA_LOG_ERR("Failed to alloc health probe buf, local_idx=%d.\n", local_idx);
        goto DELETE_JFR;
    }

    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)buf,
        .len = HC_PROBE_SEG_LEN,
        .flag = {
            .bs.token_policy = URMA_TOKEN_NONE,
            .bs.cacheable = URMA_NON_CACHEABLE,
            .bs.access = URMA_ACCESS_WRITE | URMA_ACCESS_READ,
        },
    };
    urma_target_seg_t *seg = urma_register_seg(p_ctx, &seg_cfg);
    if (seg == NULL) {
        URMA_LOG_ERR("Failed to register health probe seg, local_idx=%d.\n", local_idx);
        goto FREE_PROBE_BUF;
    }

    *res = (bondp_probe_res_t){
        .local_idx = local_idx,
        .buf = buf,
        .jfc = jfc,
        .jfr = jfr,
        .seg = seg,
        .jetty = NULL,
    };

    return 0;

FREE_PROBE_BUF:
    free(buf);
DELETE_JFR:
    urma_delete_jfr(jfr);
DELETE_JFC:
    urma_delete_jfc(jfc);
    return -1;
}

static void hc_init_cfg(bondp_hc_ctx_t *hc_ctx, const bondp_hc_cfg_t *cfg)
{
    hc_ctx->cfg.probe_interval_ms = BONDP_HC_DEFAULT_PROBE_INTERVAL_MS;
    hc_ctx->cfg.batch_node_num = BONDP_HC_DEFAULT_BATCH_NODE_NUM;

    if (cfg == NULL) {
        return;
    }

    if (cfg->probe_interval_ms != 0) {
        hc_ctx->cfg.probe_interval_ms = cfg->probe_interval_ms;
    }
    if (cfg->batch_node_num != 0) {
        hc_ctx->cfg.batch_node_num = cfg->batch_node_num;
    }
}

static void hc_destroy_probe_resources(bondp_hc_ctx_t *hc_ctx)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        hc_destroy_probe_resource(hc_ctx, (int)i);
    }
}

static int hc_init_probe_resources(bondp_context_t *bdp_ctx, bondp_hc_ctx_t *hc_ctx, bool *has_probe_res)
{
    bool has_res = false;

    *has_probe_res = false;

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        urma_context_t *p_ctx = bdp_ctx->p_ctxs[i];
        if (p_ctx == NULL) {
            continue;
        }
        hc_ctx->probes[i].local_idx = i;
        int ret = hc_init_probe_resource(p_ctx, &hc_ctx->probes[i]);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to create health probe resources, local_idx=%u.\n", i);
            goto ERR_DESTROY_PROBES;
        }
        has_res = true;
    }

    if (!has_res) {
        URMA_LOG_DEBUG("No health probe resource, skip probe task.\n");
        hc_destroy_probe_resources(hc_ctx);
        return 0;
    }

    *has_probe_res = true;
    return 0;

ERR_DESTROY_PROBES:
    hc_destroy_probe_resources(hc_ctx);
    return -1;
}

static void hc_destroy_probe_jettys(bondp_hc_ctx_t *hc_ctx)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        bondp_probe_res_t *res = &hc_ctx->probes[i];
        if (res->jetty == NULL) {
            continue;
        }
        urma_delete_jetty(res->jetty);
        res->jetty = NULL;
        res->inflight = 0;
    }
}

static int hc_create_probe_jettys(bondp_hc_ctx_t *hc_ctx)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        bondp_probe_res_t *res = &hc_ctx->probes[i];
        if (res->jfc == NULL) {
            continue;
        }
        urma_context_t *p_ctx = res->jfc->urma_ctx;
        if (p_ctx == NULL || res->jfr == NULL) {
            URMA_LOG_ERR("Invalid health probe resource, local_idx=%u.\n", i);
            goto ERR_DESTROY_JETTYS;
        }
        res->jetty = hc_create_probe_jetty(p_ctx, res->jfc, res->jfr, res->local_idx, hc_ctx->priority);
        if (res->jetty == NULL) {
            goto ERR_DESTROY_JETTYS;
        }
    }
    return 0;

ERR_DESTROY_JETTYS:
    hc_destroy_probe_jettys(hc_ctx);
    return -1;
}

int bondp_hc_init(bondp_context_t *bdp_ctx, const bondp_hc_cfg_t *cfg)
{
    int ret;

    if (bdp_ctx == NULL) {
        return -EINVAL;
    }

    if (bdp_ctx->hc_ctx != NULL) {
        return 0;
    }

    bondp_hc_ctx_t *hc_ctx = (bondp_hc_ctx_t *)calloc(1, sizeof(bondp_hc_ctx_t));
    if (hc_ctx == NULL) {
        URMA_LOG_ERR("Failed to alloc health check context.\n");
        return -1;
    }

    hc_init_cfg(hc_ctx, cfg);

    bool has_nodes = false;
    ret = hc_init_nodes(hc_ctx, &has_nodes);
    if (ret != 0) {
        goto ERR_FREE_CTX;
    }
    if (!has_nodes) {
        URMA_LOG_INFO("No topo node for health check, skip mounting context.\n");
        goto ERR_FREE_CTX;
    }

    bool has_probe_res = false;
    ret = hc_init_probe_resources(bdp_ctx, hc_ctx, &has_probe_res);
    if (ret != 0) {
        goto ERR_DESTROY_NODES;
    }
    if (!has_probe_res) {
        URMA_LOG_INFO("No health probe resource, skip mounting context.\n");
        goto ERR_DESTROY_NODES;
    }

    bdp_ctx->hc_ctx = hc_ctx;
    return 0;

ERR_DESTROY_NODES:
    hc_destroy_nodes(hc_ctx);
ERR_FREE_CTX:
    free(hc_ctx);
    return ret;
}

int bondp_hc_start(bondp_context_t *bdp_ctx, uint8_t priority)
{
    int ret;

    if (bdp_ctx == NULL || bdp_ctx->hc_ctx == NULL) {
        return 0;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&hc_ctx->started, &expected, true)) {
        return 0;
    }

    hc_ctx->priority = priority;

    ret = hc_create_probe_jettys(hc_ctx);
    if (ret != 0) {
        atomic_store(&hc_ctx->started, false);
        return ret;
    }

    bondp_worker_task_id_t task_id = 0;
    ret = bondp_worker_schedule(hc_ctx->cfg.probe_interval_ms,
                                hc_probe_fn, hc_ctx, &task_id);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to schedule health probe task, ret=%d.\n", ret);
        goto ERR_DESTROY_PROBES;
    }
    atomic_store(&hc_ctx->probe_task_id, task_id);
    URMA_LOG_INFO("Health probe task scheduled, interval=%lums, node_num=%u, priority=%u.\n",
                  hc_ctx->cfg.probe_interval_ms, hc_ctx->node_num, hc_ctx->priority);

    return 0;

ERR_DESTROY_PROBES:
    hc_destroy_probe_jettys(hc_ctx);
    atomic_store(&hc_ctx->started, false);
    return ret;
}

void bondp_hc_uninit(bondp_context_t *bdp_ctx)
{
    if (bdp_ctx == NULL || bdp_ctx->hc_ctx == NULL) {
        return;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    bdp_ctx->hc_ctx = NULL;

    /* Signal the probe task to stop running/rescheduling before cancelling it.
     * bondp_worker_cancel may invoke a concurrent hc_probe_fn(EXECUTED) to
     * completion (which would otherwise reschedule a new task that escapes
     * the cancel and fires after hc_ctx is freed). */
    atomic_store(&hc_ctx->stopping, true);
    bondp_worker_task_id_t task_id;
    while ((task_id = atomic_exchange(&hc_ctx->probe_task_id, 0)) != 0) {
        (void)bondp_worker_cancel(task_id);
    }
    hc_destroy_probe_resources(hc_ctx);
    hc_destroy_nodes(hc_ctx);

    free(hc_ctx);
    URMA_LOG_INFO("Health check resources cleaned up.\n");
}

int bondp_hc_fill_seg_info(const bondp_context_t *bdp_ctx,
                           urma_bond_seg_info_out_t *seg_info, bool *enabled)
{
    if (bdp_ctx == NULL || seg_info == NULL || enabled == NULL) {
        return -EINVAL;
    }

    *enabled = false;
    (void)memset(seg_info, 0, sizeof(*seg_info));
    if (bdp_ctx->hc_ctx == NULL) {
        return 0;
    }

    const bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (hc_ctx->probes[i].seg == NULL) {
            continue;
        }
        bondp_seg_to_base(&hc_ctx->probes[i].seg->seg, &seg_info->slaves[i]);
        *enabled = true;
    }
    return 0;
}

int bondp_hc_register_tjetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
                             const urma_bond_id_info_out_t *rjetty_info)
{
    if (bdp_ctx == NULL || bdp_tjetty == NULL || rjetty_info == NULL) {
        return -EINVAL;
    }
    if (bdp_ctx->hc_ctx == NULL || !rjetty_info->is_health_check_enable) {
        return 0;
    }
    if (bdp_tjetty->mask & BONDP_TJETTY_FLAG_HC_REGISTERED) {
        return -1;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;

    const urma_eid_t *dst_eid = &bdp_tjetty->v_tjetty.id.eid;
    uint32_t node_idx = 0;
    if (bondp_topo_query_node_idx(dst_eid, &node_idx) != 0) {
        URMA_LOG_WARN("Failed to resolve node id from eid, skip health check registration.\n");
        return 0;
    }
    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    };

    bool any_registered = false;

    /* Slot check and seg import must be atomic under the write lock to prevent
     * duplicate imports when multiple tjettys target the same [i][j] slot. */
    pthread_rwlock_wrlock(&node->lock);
    for (uint32_t k = 0; k < bdp_tjetty->p_tjetty_count; ++k) {
        bondp_p_target_jetty_t *path = &bdp_tjetty->p_tjettys[k];
        if (path->p_tjetty == NULL) {
            continue;
        }
        uint32_t i = path->local_indice;
        uint32_t j = path->remote_indice;
        const urma_seg_base_t *base = &rjetty_info->health_check_seg.slaves[j];
        if (bdp_ctx->p_ctxs[i] == NULL || base->len == 0) {
            continue;
        }
        any_registered = true;
        path->hc_va = base->ubva.va;
        path->hc_token_id = base->token_id;
        if (node->hc_tjetty[i][j] != NULL) {
            continue;
        }

        /* Register the tjetty at this path slot */
        node->hc_tjetty[i][j] = bdp_tjetty;
        node->no_cqe_round[i][j] = 0;

        /* Import health probe seg at node level if not already present */
        if (node->hc_tseg[i][j] == NULL) {
            urma_seg_t seg = {0};
            bondp_seg_base_to_seg(base, &seg);
            node->hc_tseg[i][j] = urma_import_seg(bdp_ctx->p_ctxs[i], &seg, NULL, 0, flag);
            if (node->hc_tseg[i][j] == NULL) {
                URMA_LOG_ERR("Failed to import health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
                /* Rollback: unregister paths and unimport segs from this call */
                for (uint32_t rk = 0; rk <= k; ++rk) {
                    uint32_t ri = bdp_tjetty->p_tjettys[rk].local_indice;
                    uint32_t rj = bdp_tjetty->p_tjettys[rk].remote_indice;
                    if (node->hc_tjetty[ri][rj] != bdp_tjetty) {
                        continue;
                    }
                    if (node->hc_tseg[ri][rj] != NULL) {
                        if (urma_unimport_seg(node->hc_tseg[ri][rj]) == URMA_SUCCESS) {
                            node->hc_tseg[ri][rj] = NULL;
                        } else {
                            URMA_LOG_ERR("Failed to unimport health probe seg, local_idx=%u, target_idx=%u.\n", ri, rj);
                        }
                    }
                    node->hc_tjetty[ri][rj] = NULL;
                }
                pthread_rwlock_unlock(&node->lock);
                return -1;
            }
        }
    }

    if (any_registered) {
        bdp_tjetty->mask |= BONDP_TJETTY_FLAG_HC_REGISTERED;
        bdp_tjetty->hc_node_idx = (uint16_t)node_idx;
        ub_list_push_back(&node->tjetty_list, &bdp_tjetty->hc_entry);
    }
    pthread_rwlock_unlock(&node->lock);

    URMA_LOG_DEBUG("Health check tjetty registered, node_idx=%u.\n", node->node_idx);
    return 0;
}

static bondp_target_jetty_t *hc_find_tjetty_for_path(bondp_hc_node_t *node, uint32_t local_idx,
                                                     uint32_t target_idx)
{
    bondp_target_jetty_t *tjetty = NULL;

    UB_LIST_FOR_EACH (tjetty, hc_entry, &node->tjetty_list) {
        const bondp_p_target_jetty_t *p_tjetty = bondp_find_p_tjetty_const(tjetty, local_idx, target_idx);
        if (p_tjetty != NULL && p_tjetty->p_tjetty != NULL && p_tjetty->hc_va != 0) {
            return tjetty;
        }
    }
    return NULL;
}

static void hc_unregister_tjetty_path(bondp_hc_node_t *node, bondp_target_jetty_t *bdp_tjetty,
                                      bondp_context_t *bdp_ctx)
{
    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    };

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (node->hc_tjetty[i][j] != bdp_tjetty) {
                continue;
            }
            if (node->hc_tseg[i][j] != NULL) {
                if (urma_unimport_seg(node->hc_tseg[i][j]) != URMA_SUCCESS) {
                    URMA_LOG_ERR("Failed to unimport health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
                    node->hc_tjetty[i][j] = NULL;
                    atomic_store(&node->valid[i][j], false);
                    continue;
                }
                node->hc_tseg[i][j] = NULL;
            }

            bondp_target_jetty_t *backup = hc_find_tjetty_for_path(node, i, j);
            node->hc_tjetty[i][j] = backup;
            node->no_cqe_round[i][j] = 0;

            if (backup == NULL) {
                continue;
            }

            /* Backup found: re-import seg using backup's va and token_id.
             * eid/uasid come from the backup's physical target jetty;
             * len and attr are fixed for health check segs. */
            const bondp_p_target_jetty_t *backup_path = bondp_find_p_tjetty_const(backup, i, j);
            if (backup_path == NULL || backup_path->p_tjetty == NULL || bdp_ctx->p_ctxs[i] == NULL) {
                continue;
            }
            urma_seg_t seg = {
                .ubva = {
                    .eid = backup_path->p_tjetty->id.eid,
                    .uasid = backup_path->p_tjetty->id.uasid,
                    .va = backup_path->hc_va,
                },
                .len = HC_PROBE_SEG_LEN,
                .attr = {
                    .bs = {
                        .token_policy = URMA_TOKEN_NONE,
                        .cacheable = URMA_NON_CACHEABLE,
                        .access = URMA_ACCESS_WRITE | URMA_ACCESS_READ,
                    },
                },
                .token_id = backup_path->hc_token_id,
            };
            node->hc_tseg[i][j] = urma_import_seg(bdp_ctx->p_ctxs[i], &seg, NULL, 0, flag);
            if (node->hc_tseg[i][j] == NULL) {
                URMA_LOG_ERR("Failed to re-import health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
                node->hc_tjetty[i][j] = NULL;
                atomic_store(&node->valid[i][j], false);
            }
        }
    }
}

void bondp_hc_unregister_tjetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    if (bdp_ctx == NULL || bdp_ctx->hc_ctx == NULL ||
        bdp_tjetty == NULL || (bdp_tjetty->mask & BONDP_TJETTY_FLAG_HC_REGISTERED) == 0) {
        return;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    uint32_t node_idx = bdp_tjetty->hc_node_idx;
    if (node_idx >= hc_ctx->node_num) {
        URMA_LOG_WARN("Invalid health check node idx, skip tjetty unregister, node_idx=%u, node_num=%u.\n",
                      node_idx, hc_ctx->node_num);
        bdp_tjetty->mask &= ~BONDP_TJETTY_FLAG_HC_REGISTERED;
        bdp_tjetty->hc_node_idx = 0;
        return;
    }
    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

    pthread_rwlock_wrlock(&node->lock);
    ub_list_remove(&bdp_tjetty->hc_entry);
    hc_unregister_tjetty_path(node, bdp_tjetty, bdp_ctx);
    bdp_tjetty->mask &= ~BONDP_TJETTY_FLAG_HC_REGISTERED;
    bdp_tjetty->hc_node_idx = 0;
    pthread_rwlock_unlock(&node->lock);
    URMA_LOG_DEBUG("Health check tjetty unregistered, node_idx=%u.\n", node->node_idx);
}

void bondp_hc_tjetty_sync_valid(const bondp_target_jetty_t *bdp_tjetty)
{
    if (bdp_tjetty == NULL || (bdp_tjetty->mask & BONDP_TJETTY_FLAG_HC_REGISTERED) == 0) {
        return;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(bdp_tjetty->v_tjetty.urma_ctx, bondp_context_t, v_ctx);
    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    if (hc_ctx == NULL) {
        return;
    }

    uint32_t node_idx = bdp_tjetty->hc_node_idx;
    if (node_idx >= hc_ctx->node_num) {
        return;
    }

    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];
    bondp_target_jetty_t *cur = NULL;
    pthread_rwlock_rdlock(&node->lock);
    UB_LIST_FOR_EACH (cur, hc_entry, &node->tjetty_list) {
        for (uint32_t li = 0; li < URMA_UBAGG_DEV_MAX_NUM; ++li) {
            for (uint32_t ti = 0; ti < URMA_UBAGG_DEV_MAX_NUM; ++ti) {
                if (node->hc_tjetty[li][ti] == NULL) {
                    continue;
                }
                bondp_p_target_jetty_t *p_tjetty = bondp_find_p_tjetty(cur, li, ti);
                if (p_tjetty == NULL) {
                    continue;
                }
                bool v = atomic_load(&node->valid[li][ti]);
                if (!v) {
                    atomic_store(&p_tjetty->valid, v);
                }
            }
        }
    }
    pthread_rwlock_unlock(&node->lock);
}
