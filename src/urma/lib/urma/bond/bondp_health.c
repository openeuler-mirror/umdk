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

#include "bondp_types.h"
#include "bondp_worker.h"
#include "topo_info.h"
#include "ub_list.h"
#include "urma_api.h"
#include "urma_log.h"
#include "bondp_health.h"

#define HC_CQE_BATCH     (8)
#define HC_PROBE_BUF_LEN (1)
#define HC_PROBE_DEPTH   (1024)
/* Stop posting probes when a local probe SQ has this many outstanding WRs,
 * leaving headroom so a batch cannot overflow the SQ (depth HC_PROBE_DEPTH) and
 * wedge urma_post_jetty_send_wr into ENOMEM. */
#define HC_PROBE_INFLIGHT_HI (HC_PROBE_DEPTH)
/* ummu_grant requires page-aligned VA and a length multiple of the page size.
 * The probe payload is only HC_PROBE_BUF_LEN bytes, but the registered segment
 * must cover a full page; the data path keeps its 1-byte sge length. */
#define HC_PROBE_SEG_LEN (getpagesize())

typedef struct bondp_hc_ctx bondp_hc_ctx_t;

typedef struct bondp_probe_res {
    bondp_hc_ctx_t *hc_ctx;
    int local_idx;
    void *buf;
    urma_jfce_t *jfce;
    urma_jfc_t *jfc;
    urma_jfr_t *jfr;
    urma_target_seg_t *seg;
    urma_jetty_t *jetty;
    int jfce_fd;
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

    pthread_rwlock_t lock; /* Protects tjetty_list and hc_tjetty */
    struct bondp_target_jetty *hc_tjetty[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    struct ub_list tjetty_list;
    bool probe_checked[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
} bondp_hc_node_t;

/* Per-context health-check context */
struct bondp_hc_ctx {
    bondp_hc_cfg_t cfg;
    bondp_probe_res_t probes[URMA_UBAGG_DEV_MAX_NUM];
    atomic_uint_fast64_t probe_task_id;
    atomic_bool stopping; /* Set by uninit to stop the probe task from rescheduling */
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
                                           urma_jfr_t *jfr, int local_idx)
{
    urma_jetty_cfg_t p_cfg = {
        .flag = {.bs = {.share_jfr = URMA_SHARE_JFR}},
        .jfs_cfg = {
            .depth = HC_PROBE_DEPTH,
            .trans_mode = URMA_TM_RM,
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

static void hc_rebuild_probe_jetty(bondp_probe_res_t *res)
{
    int local_idx = res->local_idx;
    if (res->jfc == NULL || res->jfc->urma_ctx == NULL || res->jfr == NULL) {
        URMA_LOG_ERR("Invalid health probe resource for jetty rebuild, local_idx=%d.\n", local_idx);
        return;
    }

    urma_context_t *p_ctx = res->jfc->urma_ctx;
    urma_jetty_attr_t attr = {
        .mask = JETTY_STATE,
        .state = URMA_JETTY_STATE_ERROR,
    };

    if (res->jetty != NULL) {
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
    }
    res->inflight = 0; /* The old SQ is gone; its outstanding WRs are flushed. */

    res->jetty = hc_create_probe_jetty(p_ctx, res->jfc, res->jfr, local_idx);
    if (res->jetty == NULL) {
        URMA_LOG_ERR("Failed to rebuild health probe jetty, local_idx=%d.\n", local_idx);
    }
}

static void hc_set_tjetty_list_target_valid(bondp_hc_node_t *node, uint32_t local_idx, uint32_t target_idx)
{
    bondp_target_jetty_t *bdp_tjetty = NULL;

    pthread_rwlock_rdlock(&node->lock);
    UB_LIST_FOR_EACH (bdp_tjetty, hc_entry, &node->tjetty_list) {
        atomic_store(&bdp_tjetty->valid[local_idx][target_idx], true);
    }
    pthread_rwlock_unlock(&node->lock);
}

static void hc_drain_probe_cq(bondp_probe_res_t *res)
{
    if (res == NULL || res->jfc == NULL || res->jfce == NULL) {
        return;
    }
    int local_idx = res->local_idx;
    bondp_hc_ctx_t *hc_ctx = res->hc_ctx;
    if (hc_ctx == NULL || local_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM ||
        res != &hc_ctx->probes[local_idx]) {
        return;
    }

    urma_jfc_t *jfc = res->jfc;
    urma_cr_t cr[HC_CQE_BATCH];
    bool need_rebuild = false;
    uint32_t drained = 0;

    while (true) {
        int n = urma_poll_jfc(jfc, HC_CQE_BATCH, cr);
        if (n <= 0) {
            break;
        }
        drained += (uint32_t)n;

        for (int k = 0; k < n; k++) {
            uint32_t node_idx;
            uint32_t target_idx;

            hc_decode_user_ctx(cr[k].user_ctx, &node_idx, &target_idx);

            if (node_idx >= hc_ctx->node_num) {
                continue;
            }
            bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

            if (target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
                continue;
            }
            bool ok = (cr[k].status == URMA_CR_SUCCESS);
            bondp_target_jetty_t *bdp_tjetty = node->hc_tjetty[local_idx][target_idx];
            bool prev = (bdp_tjetty != NULL) ?
                atomic_load(&bdp_tjetty->valid[local_idx][target_idx]) : true;
            atomic_store(&node->valid[local_idx][target_idx], ok);
            if (ok && !prev) {
                hc_set_tjetty_list_target_valid(node, local_idx, target_idx);
            }

            node->probe_checked[local_idx][target_idx] = true;

            if (cr[k].status == URMA_CR_ACK_TIMEOUT_ERR) { /* status 9 */
                need_rebuild = true;
                break;
            }
        }
    }
    if (drained >= res->inflight) {
        res->inflight = 0;
    } else {
        res->inflight -= drained;
    }

    urma_status_t ret = urma_rearm_jfc(jfc, false);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_WARN("Failed to rearm health probe jfc, local_idx=%d, ret=%d.\n", local_idx, ret);
    }

    if (need_rebuild) {
        hc_rebuild_probe_jetty(res);
    }
}

static void hc_jfce_handler(void *arg)
{
    /* The jfce fd fired: at least one CQE arrived since the last arm. Drain the
     * CQ and re-arm. */
    hc_drain_probe_cq((bondp_probe_res_t *)arg);
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

    /* Throttle: stop posting once the local probe SQ is close to capacity. The
     * worker is single-threaded, so completions cannot be reaped while this
     * batch is being posted; without throttling the SQ overflows and
     * urma_post_jetty_send_wr returns ENOMEM. Remaining paths are picked up by
     * the next firing after the CQ is drained. */
    if (res->inflight >= HC_PROBE_INFLIGHT_HI) {
        return;
    }

    bondp_target_jetty_t *bdp_tjetty = node->hc_tjetty[local_idx][target_idx];
    if (bdp_tjetty == NULL) {
        return;
    }

    urma_target_jetty_t *tjetty = bdp_tjetty->p_tjetty[local_idx][target_idx];
    urma_target_seg_t *tseg = bdp_tjetty->p_check_tseg[local_idx][target_idx];
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
    } else {
        URMA_LOG_WARN("Failed to send health probe, node_idx=%u, local_idx=%d, target_idx=%d, ret=%d.\n",
                      node->node_idx, local_idx, target_idx, ret);
        atomic_store(&node->valid[local_idx][target_idx], false);
    }
}

static bool hc_probe_sq_has_room(bondp_hc_ctx_t *hc_ctx)
{
    /* Return true if at least one local probe SQ still has room for a new WR.
     * Used to short-circuit the node scan once every local_idx is throttled. */
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (hc_ctx->probes[i].jetty != NULL && hc_ctx->probes[i].inflight < HC_PROBE_INFLIGHT_HI) {
            return true;
        }
    }
    return false;
}

static void hc_probe_node(bondp_hc_ctx_t *hc_ctx, bondp_hc_node_t *node)
{
    bool any_connected = false;
    bool all_checked = true;

    pthread_rwlock_rdlock(&node->lock);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (hc_ctx->probes[i].inflight >= HC_PROBE_INFLIGHT_HI) {
            all_checked = false;
            continue;
        }
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
            if (hc_ctx->probes[i].inflight >= HC_PROBE_INFLIGHT_HI) {
                break;
            }
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

    /* Drain pending completions before posting new probes. The worker thread
     * is single-threaded, so the jfce handler cannot run concurrently while
     * hc_probe_fn is posting. Without this drain, the probe SQ (depth
     * HC_PROBE_DEPTH) can overflow when a batch covers many nodes x paths,
     * causing urma_post_jetty_send_wr to return ENOMEM and leaving the SQ
     * wedged (completions never reaped). Draining here keeps the SQ below
     * capacity and processes ACK-timeout rebuilds promptly. */
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        hc_drain_probe_cq(&hc_ctx->probes[i]);
    }

    uint32_t probe_cnt = MIN(hc_ctx->cfg.probe_node_num, hc_ctx->node_num);
    uint32_t node_idx = hc_ctx->probe_cur_idx % hc_ctx->node_num;
    for (uint32_t i = 0; i < probe_cnt; ++i) {
        if (!hc_probe_sq_has_room(hc_ctx)) {
            /* All local probe SQs are at the throttle limit; the remaining nodes
             * will be probed on the next firing after the CQs are drained. */
            break;
        }
        bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];
        hc_probe_node(hc_ctx, node);
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
        tjetty->hc_registered = false;
        tjetty->hc_node_idx = 0;
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
        URMA_LOG_INFO("No topo node for health check, skip probe task.\n");
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

static void hc_detach_probe_fds(bondp_hc_ctx_t *hc_ctx)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        bondp_probe_res_t *res = &hc_ctx->probes[i];
        if (res->jfce != NULL && res->jfce_fd >= 0 &&
            bondp_worker_del_fd(res->jfce_fd) == 0) {
            res->jfce_fd = -1;
        }
    }
}

static void hc_destroy_probe_resource(bondp_hc_ctx_t *hc_ctx, int local_idx)
{
    bondp_probe_res_t *res = &hc_ctx->probes[local_idx];

    if (res->jfce != NULL && res->jfce_fd >= 0) {
        (void)bondp_worker_del_fd(res->jfce_fd);
    }

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
    if (res->jfce != NULL) {
        urma_delete_jfce(res->jfce);
        res->jfce = NULL;
    }
    *res = (bondp_probe_res_t){0};
}

static int hc_init_probe_resource(bondp_hc_ctx_t *hc_ctx, urma_context_t *p_ctx, bondp_probe_res_t *res)
{
    int local_idx = res->local_idx;
    urma_jfce_t *jfce = urma_create_jfce(p_ctx);
    if (jfce == NULL) {
        URMA_LOG_ERR("Failed to create health probe jfce, local_idx=%d.\n", local_idx);
        return -1;
    }

    urma_jfc_cfg_t jfc_cfg = {
        .depth = 4096,
        .jfce = jfce,
    };
    urma_jfc_t *jfc = urma_create_jfc(p_ctx, &jfc_cfg);
    if (jfc == NULL) {
        URMA_LOG_ERR("Failed to create health probe jfc, local_idx=%d.\n", local_idx);
        goto DELETE_JFCE;
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

    urma_jetty_t *jetty = hc_create_probe_jetty(p_ctx, jfc, jfr, local_idx);
    if (jetty == NULL) {
        goto UNREGISTER_SEG;
    }

    res->hc_ctx = hc_ctx;
    if (bondp_worker_add_fd(jfce->fd, hc_jfce_handler, res) != 0) {
        URMA_LOG_ERR("Failed to add health probe jfce fd to worker, local_idx=%d.\n", local_idx);
        goto DELETE_JETTY;
    }

    *res = (bondp_probe_res_t) {
        .hc_ctx = hc_ctx,
        .local_idx = local_idx,
        .buf = buf,
        .jfce = jfce,
        .jfc = jfc,
        .jfr = jfr,
        .seg = seg,
        .jetty = jetty,
        .jfce_fd = jfce->fd,
    };

    return 0;

DELETE_JETTY:
    urma_delete_jetty(jetty);
UNREGISTER_SEG:
    urma_unregister_seg(seg);
FREE_PROBE_BUF:
    free(buf);
DELETE_JFR:
    urma_delete_jfr(jfr);
DELETE_JFC:
    urma_delete_jfc(jfc);
DELETE_JFCE:
    urma_delete_jfce(jfce);
    return -1;
}

static void hc_init_cfg(bondp_hc_ctx_t *hc_ctx, const bondp_hc_cfg_t *cfg)
{
    hc_ctx->cfg.probe_interval_ms = BONDP_HC_DEFAULT_PROBE_INTERVAL_MS;
    hc_ctx->cfg.probe_node_num = BONDP_HC_DEFAULT_PROBE_NODE_NUM;

    if (cfg == NULL) {
        return;
    }

    if (cfg->probe_interval_ms != 0) {
        hc_ctx->cfg.probe_interval_ms = cfg->probe_interval_ms;
    }
    if (cfg->probe_node_num != 0) {
        hc_ctx->cfg.probe_node_num = cfg->probe_node_num;
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
        int ret = hc_init_probe_resource(hc_ctx, p_ctx, &hc_ctx->probes[i]);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to create health probe resources, local_idx=%u.\n", i);
            goto ERR_DESTROY_PROBES;
        }
        has_res = true;
    }

    if (!has_res) {
        URMA_LOG_INFO("No health probe resource, skip probe task.\n");
        hc_destroy_probe_resources(hc_ctx);
        return 0;
    }

    *has_probe_res = true;
    return 0;

ERR_DESTROY_PROBES:
    hc_destroy_probe_resources(hc_ctx);
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
    URMA_LOG_INFO("Health check config, probe_interval=%lums, probe_node_num=%u.\n",
                  hc_ctx->cfg.probe_interval_ms, hc_ctx->cfg.probe_node_num);

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

    bondp_worker_task_id_t task_id = 0;
    ret = bondp_worker_schedule(hc_ctx->cfg.probe_interval_ms,
                                hc_probe_fn, hc_ctx, &task_id);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to schedule health probe task, ret=%d.\n", ret);
        goto ERR_DESTROY_PROBES;
    }
    atomic_store(&hc_ctx->probe_task_id, task_id);
    URMA_LOG_INFO("Health probe task scheduled, interval=%lums, node_num=%u.\n",
                  hc_ctx->cfg.probe_interval_ms, hc_ctx->node_num);

    bdp_ctx->hc_ctx = hc_ctx;
    return 0;

ERR_DESTROY_PROBES:
    hc_destroy_probe_resources(hc_ctx);
ERR_DESTROY_NODES:
    hc_destroy_nodes(hc_ctx);
ERR_FREE_CTX:
    free(hc_ctx);
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
    /* Detach first; the synchronous cancel below then acts as a worker barrier. */
    hc_detach_probe_fds(hc_ctx);

    bondp_worker_task_id_t task_id;
    while ((task_id = atomic_exchange(&hc_ctx->probe_task_id, 0)) != 0) {
        (void)bondp_worker_cancel(task_id);
    }
    if (task_id == 0) {
        URMA_LOG_INFO("Health probe task cancelled.\n");
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

urma_status_t bondp_hc_unimport_tseg(bondp_target_jetty_t *bdp_tjetty)
{
    if (bdp_tjetty == NULL) {
        return URMA_FAIL;
    }

    urma_status_t ret = URMA_SUCCESS;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            urma_target_seg_t *tseg = bdp_tjetty->p_check_tseg[i][j];
            if (tseg == NULL) {
                continue;
            }
            bdp_tjetty->p_check_tseg[i][j] = NULL;
            if (urma_unimport_seg(tseg) != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unimport health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
                ret = URMA_FAIL;
            }
        }
    }
    return ret;
}

int bondp_hc_import_tseg(const bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
                         const urma_bond_id_info_out_t *rjetty_info)
{
    if (bdp_ctx == NULL || bdp_tjetty == NULL || rjetty_info == NULL) {
        return -EINVAL;
    }
    if (bdp_ctx->hc_ctx == NULL || !rjetty_info->is_health_check_enable) {
        return 0;
    }

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    };
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_tjetty[i][j] == NULL) {
                continue;
            }
            const urma_seg_base_t *base = &rjetty_info->health_check_seg.slaves[j];
            if (base->len == 0) {
                continue;
            }

            urma_seg_t seg = {0};
            bondp_seg_base_to_seg(base, &seg);
            bdp_tjetty->p_check_tseg[i][j] =
                urma_import_seg(bdp_ctx->p_ctxs[i], &seg, NULL, 0, flag);
            if (bdp_tjetty->p_check_tseg[i][j] == NULL) {
                URMA_LOG_ERR("Failed to import health probe seg, local_idx=%u, target_idx=%u.\n", i, j);
                (void)bondp_hc_unimport_tseg(bdp_tjetty);
                return -1;
            }
        }
    }
    return 0;
}

static bool hc_tjetty_has_probe_path(const bondp_target_jetty_t *bdp_tjetty)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_tjetty[i][j] != NULL && bdp_tjetty->p_check_tseg[i][j] != NULL) {
                return true;
            }
        }
    }
    return false;
}

static void hc_register_tjetty_path(bondp_hc_node_t *node, bondp_target_jetty_t *bdp_tjetty)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_tjetty[i][j] == NULL || bdp_tjetty->p_check_tseg[i][j] == NULL ||
                node->hc_tjetty[i][j] != NULL) {
                continue;
            }
            node->hc_tjetty[i][j] = bdp_tjetty;
        }
    }
}

static bondp_target_jetty_t *hc_find_tjetty_for_path(bondp_hc_node_t *node, uint32_t local_idx,
                                                     uint32_t target_idx)
{
    bondp_target_jetty_t *tjetty = NULL;

    UB_LIST_FOR_EACH (tjetty, hc_entry, &node->tjetty_list) {
        if (tjetty->p_tjetty[local_idx][target_idx] != NULL &&
            tjetty->p_check_tseg[local_idx][target_idx] != NULL) {
            return tjetty;
        }
    }
    return NULL;
}

static void hc_unregister_tjetty_path(bondp_hc_node_t *node, bondp_target_jetty_t *bdp_tjetty)
{
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (node->hc_tjetty[i][j] != bdp_tjetty) {
                continue;
            }
            node->hc_tjetty[i][j] = hc_find_tjetty_for_path(node, i, j);
        }
    }
}

int bondp_hc_register_tjetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    if (bdp_ctx == NULL || bdp_tjetty == NULL || bdp_tjetty->hc_registered) {
        return -1;
    }
    if (bdp_ctx->hc_ctx == NULL) {
        return 0;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;

    const urma_eid_t *dst_eid = &bdp_tjetty->v_tjetty.id.eid;
    uint32_t node_idx = 0;
    if (bondp_topo_query_node_idx(dst_eid, &node_idx) != 0) {
        URMA_LOG_WARN("Failed to resolve node id from eid, skip health check registration.\n");
        return 0;
    }
    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

    pthread_rwlock_wrlock(&node->lock);
    if (hc_tjetty_has_probe_path(bdp_tjetty)) {
        bdp_tjetty->hc_registered = true;
        bdp_tjetty->hc_node_idx = node_idx;
        ub_list_push_back(&node->tjetty_list, &bdp_tjetty->hc_entry);
        hc_register_tjetty_path(node, bdp_tjetty);
    }
    pthread_rwlock_unlock(&node->lock);
    URMA_LOG_INFO("Health check tjetty registered, node_idx=%u.\n", node->node_idx);
    return 0;
}

void bondp_hc_unregister_tjetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    if (bdp_ctx == NULL || bdp_ctx->hc_ctx == NULL ||
        bdp_tjetty == NULL || !bdp_tjetty->hc_registered) {
        return;
    }

    bondp_hc_ctx_t *hc_ctx = bdp_ctx->hc_ctx;
    uint32_t node_idx = bdp_tjetty->hc_node_idx;
    if (node_idx >= hc_ctx->node_num) {
        URMA_LOG_WARN("Invalid health check node idx, skip tjetty unregister, node_idx=%u, node_num=%u.\n",
                      node_idx, hc_ctx->node_num);
        bdp_tjetty->hc_registered = false;
        bdp_tjetty->hc_node_idx = 0;
        return;
    }
    bondp_hc_node_t *node = &hc_ctx->nodes[node_idx];

    pthread_rwlock_wrlock(&node->lock);
    ub_list_remove(&bdp_tjetty->hc_entry);
    hc_unregister_tjetty_path(node, bdp_tjetty);
    bdp_tjetty->hc_registered = false;
    bdp_tjetty->hc_node_idx = 0;
    pthread_rwlock_unlock(&node->lock);
    URMA_LOG_INFO("Health check tjetty unregistered, node_idx=%u.\n", node->node_idx);
}

void bondp_hc_tjetty_sync_valid(const bondp_target_jetty_t *bdp_tjetty,
                                uint32_t skip_local_idx, uint32_t skip_target_idx)
{
    if (bdp_tjetty == NULL || !bdp_tjetty->hc_registered) {
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
        atomic_store(&cur->valid[skip_local_idx][skip_target_idx], false);
        for (uint32_t li = 0; li < URMA_UBAGG_DEV_MAX_NUM; ++li) {
            for (uint32_t ti = 0; ti < URMA_UBAGG_DEV_MAX_NUM; ++ti) {
                if (li == skip_local_idx && ti == skip_target_idx) {
                    continue;
                }
                if (node->hc_tjetty[li][ti] == NULL) {
                    continue;
                }
                bool v = atomic_load(&node->valid[li][ti]);
                atomic_store(&cur->valid[li][ti], v);
            }
        }
    }
    pthread_rwlock_unlock(&node->lock);
}
