/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: ub management channel implementation for urma_perftest
 * Author: Qian Guoxin
 * Create: 2026-07-03
 * Note: UB mgmt channel over URMA RM. Local EID from --mgmt_addr.
 *       Single pair only. Server must start before client.
 * History: 2026-07-03   create file
 */

#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "urma_api.h"
#include "perftest_log.h"
#include "perftest_parameters.h"
#include "perftest_run_test.h"

#include "perftest_mgmt_ub.h"

#define UB_MGMT_TOKEN_VALUE        (0xABCDEF)  /* same as g_perftest_token in perftest_resources.c */
#define UB_MGMT_HANDSHAKE_SIZE     (1)
#define UB_MGMT_SEG_ALIGN          (4096)      /* UMMU table mode requires 4K-aligned VA */
#define UB_MGMT_BONDING_DEV_PREFIX "bonding_dev"
#define UB_MGMT_BONDING_DEV_PREFIX_LEN (11)

static urma_token_t g_ub_mgmt_token = {
    .token = UB_MGMT_TOKEN_VALUE,
};

typedef struct ub_jpair {
    urma_jetty_t         *jetty;     /* local mgmt jetty */
    urma_target_jetty_t  *tjetty;    /* peer mgmt jetty (after handshake) */
    /* comm_poll/comm_recv coordination: UB has no kernel-buffered "readable"
     * state; poll posts a 1B probe recv, the CQE+data remain for comm_recv. */
    bool                 have_pending_recv;  /* probe recv posted, not yet completed */
    bool                 have_pending_data;  /* probe recv completed, probe_buf has data */
    uint32_t             pending_data_len;   /* valid when have_pending_data == true */
    bool                 have_deferred_recv;  /* next-round recv CQE stashed for next sync */
    uint32_t             deferred_buf_idx;
} ub_jpair_t;

typedef struct ub_mgmt_ctx {
    urma_context_t    *urma_ctx;
    urma_device_t     *dev;
    urma_jfc_t        *jfc;          /* shared jfc for both send and recv CQE */
    urma_jfr_t        *jfr;          /* shared jfr (UB requires share_jfr) */
    char              *send_buf;     /* shared 4KB buffer for SEND */
    char              *probe_buf;    /* 1B probe RECV buffer for comm_poll/comm_recv */
    char              *recv_bufs;    /* data RECV ring: UB_MGMT_RQ_DEPTH * UB_MGMT_MSG_MAX_SIZE */
    char              *recv_buf_hs;  /* dedicated 4KB buffer for handshake RECV (server only) */
    urma_target_seg_t *tseg_send;    /* registered seg covering send_buf */
    urma_target_seg_t *tseg_probe;   /* registered seg covering probe_buf */
    urma_target_seg_t *tseg_recvs;   /* registered seg covering recv_bufs (data ring) */
    urma_target_seg_t *tseg_recv_hs; /* registered seg covering recv_buf_hs (server only) */
    bool               is_server;
    ub_jpair_t         pair;         /* single pair (UB mgmt does not support multi-pair) */
} ub_mgmt_ctx_t;

static ub_mgmt_ctx_t *g_ub_ctx = NULL;

/* ========================================================================== */
/* internal helpers                                                            */
/* ========================================================================== */

/* Build rjetty descriptor for importing peer mgmt jetty. tp_type=CTP. */
static void fill_rjetty(urma_eid_t peer_eid, uint32_t jetty_id, urma_rjetty_t *rjetty)
{
    (void)memset(rjetty, 0, sizeof(*rjetty));
    rjetty->jetty_id.eid = peer_eid;
    rjetty->jetty_id.id = jetty_id;
    rjetty->trans_mode = URMA_TM_RM;
    rjetty->type = URMA_JETTY;
    rjetty->tp_type = URMA_CTP;
}

static int poll_one_cqe(urma_jfc_t *jfc, urma_cr_t *cr, bool interruptible)
{
    while (true) {
        if (interruptible && g_exit_flag) {
            return -EINTR;
        }
        int n = urma_poll_jfc(jfc, 1, cr);
        if (n < 0) {
            LOG_ERROR("Failed to poll jfc.\n");
            return -1;
        }
        if (n == 1) {
            if (cr->status != URMA_CR_SUCCESS) {
                LOG_ERROR("mgmt CR status %d (s_r=%u).\n", (int)cr->status, cr->flag.bs.s_r);
                return -1;
            }
            return 0;
        }
    }
}

/* Post one max-size data RECV WR into ring slot buf_idx (0..RQ_DEPTH-1). */
static int ub_post_one_recv(ub_mgmt_ctx_t *ctx, int buf_idx)
{
    urma_sge_t sge = {0};
    urma_jfr_wr_t wr = {0};
    urma_jfr_wr_t *bad = NULL;
    sge.addr = (uint64_t)(ctx->recv_bufs + buf_idx * UB_MGMT_MSG_MAX_SIZE);
    sge.len = UB_MGMT_MSG_MAX_SIZE;
    sge.tseg = ctx->tseg_recvs;
    wr.src.sge = &sge;
    wr.src.num_sge = 1;
    wr.user_ctx = (uint64_t)buf_idx;
    wr.next = NULL;
    return (urma_post_jetty_recv_wr(ctx->pair.jetty, &wr, &bad) == URMA_SUCCESS) ? 0 : -1;
}

/* Resolve (dev, eid_index) from src EID string. Mirrors ping_run.c:init_urma_resource. */
static int ub_resolve_dev_and_eid_idx(const char *src_eid_str, urma_device_t **dev_out, uint32_t *eid_idx_out)
{
    urma_eid_t src_eid = {0};
    urma_device_t *dev = NULL;
    urma_eid_info_t *eid_list = NULL;
    uint32_t eid_cnt = 0;
    uint32_t i = 0;
    bool found = false;

    if (urma_str_to_eid(src_eid_str, &src_eid) != 0) {
        LOG_ERROR("Failed to parse src eid: %s\n", src_eid_str);
        return -1;
    }

    dev = urma_get_device_by_eid(src_eid, URMA_TRANSPORT_UB);
    if (dev == NULL) {
        LOG_ERROR("Failed to find UB device for src eid: %s\n", src_eid_str);
        return -1;
    }

    /* Reject bonding (aggregation) devices: mgmt channel needs a bare UB device. */
    if (strncmp(dev->name, UB_MGMT_BONDING_DEV_PREFIX, UB_MGMT_BONDING_DEV_PREFIX_LEN) == 0) {
        LOG_ERROR("UB mgmt channel does not support bonding device: %s\n", dev->name);
        return -1;
    }

    eid_list = urma_get_eid_list(dev, &eid_cnt);
    if (eid_list == NULL) {
        LOG_ERROR("Failed to get eid list from device: %s\n", dev->name);
        return -1;
    }
    for (i = 0; i < eid_cnt; i++) {
        if (memcmp(&src_eid, &eid_list[i].eid, sizeof(urma_eid_t)) == 0) {
            *eid_idx_out = eid_list[i].eid_index;
            found = true;
            break;
        }
    }
    urma_free_eid_list(eid_list);
    if (!found) {
        LOG_ERROR("Src eid not found in device eid list: dev=%s, eid=%s\n", dev->name, src_eid_str);
        return -1;
    }

    *dev_out = dev;
    return 0;
}

/* ========================================================================== */
/* establish / close                                                           */
/* ========================================================================== */

static int ub_create_local_resources(const comm_ub_cfg_t *cfg, ub_mgmt_ctx_t **ctx_out)
{
    urma_device_t *dev = NULL;
    urma_context_t *urma_ctx = NULL;
    urma_jfc_t *jfc = NULL;
    urma_jfr_t *jfr = NULL;
    urma_target_seg_t *tseg_send = NULL;
    urma_target_seg_t *tseg_probe = NULL;
    urma_target_seg_t *tseg_recvs = NULL;
    urma_target_seg_t *tseg_recv_hs = NULL;
    char *send_buf = NULL;
    char *probe_buf = NULL;
    char *recv_bufs = NULL;
    char *recv_buf_hs = NULL;
    urma_jfc_cfg_t jfc_cfg = {0};
    urma_seg_cfg_t seg_cfg = {0};
    urma_jfs_cfg_t jfs_cfg = {0};
    urma_jfr_cfg_t jfr_cfg = {0};
    urma_jetty_cfg_t jetty_cfg = {0};
    ub_mgmt_ctx_t *ctx = NULL;
    uint32_t local_jetty_id = 0;
    uint32_t eid_idx = 0;

    if (ub_resolve_dev_and_eid_idx(cfg->src_eid, &dev, &eid_idx) != 0) {
        return -1;
    }

    urma_ctx = urma_create_context(dev, eid_idx);
    if (urma_ctx == NULL) {
        LOG_ERROR("Failed to create urma context.\n");
        return -1;
    }

    jfc_cfg.depth = UB_MGMT_JFC_DEPTH;
    jfc_cfg.flag.value = 0;
    jfc_cfg.jfce = NULL;
    jfc_cfg.user_ctx = (uint64_t)NULL;
    /* urma_create_jfc (not alloc_jfc) initializes the CQ buffer; alloc_jfc leaves it NULL. */
    jfc = urma_create_jfc(urma_ctx, &jfc_cfg);
    if (jfc == NULL) {
        LOG_ERROR("Failed to create mgmt jfc.\n");
        goto delete_ctx;
    }

    send_buf = (char *)memalign(UB_MGMT_SEG_ALIGN, UB_MGMT_MSG_MAX_SIZE);
    probe_buf = (char *)memalign(UB_MGMT_SEG_ALIGN, UB_MGMT_MSG_MAX_SIZE);
    recv_bufs = (char *)memalign(UB_MGMT_SEG_ALIGN, UB_MGMT_MSG_MAX_SIZE * UB_MGMT_RQ_DEPTH);
    recv_buf_hs = (char *)memalign(UB_MGMT_SEG_ALIGN, UB_MGMT_MSG_MAX_SIZE);
    if (send_buf == NULL || probe_buf == NULL || recv_bufs == NULL || recv_buf_hs == NULL) {
        LOG_ERROR("Failed to alloc mgmt buffers.\n");
        goto free_jfc;
    }
    memset(send_buf, 0, UB_MGMT_MSG_MAX_SIZE);
    memset(probe_buf, 0, UB_MGMT_MSG_MAX_SIZE);
    memset(recv_bufs, 0, UB_MGMT_MSG_MAX_SIZE * UB_MGMT_RQ_DEPTH);
    memset(recv_buf_hs, 0, UB_MGMT_MSG_MAX_SIZE);

    seg_cfg.len = UB_MGMT_MSG_MAX_SIZE;
    seg_cfg.token_id = NULL;
    seg_cfg.token_value = g_ub_mgmt_token;
    seg_cfg.flag.value = 0;
    seg_cfg.flag.bs.access = URMA_ACCESS_LOCAL_ONLY;
    seg_cfg.user_ctx = (uint64_t)NULL;
    seg_cfg.iova = 0;

    seg_cfg.va = (uint64_t)send_buf;
    tseg_send = urma_register_seg(urma_ctx, &seg_cfg);
    if (tseg_send == NULL) {
        LOG_ERROR("Failed to register mgmt send seg.\n");
        goto free_bufs;
    }

    seg_cfg.va = (uint64_t)probe_buf;
    tseg_probe = urma_register_seg(urma_ctx, &seg_cfg);
    if (tseg_probe == NULL) {
        LOG_ERROR("Failed to register mgmt recv seg.\n");
        goto unregister_send;
    }

    /* Data RECV ring: one seg covers all slots, each WQE sge points into
     * its slot recv_bufs[idx * 4KB]. */
    seg_cfg.len = UB_MGMT_MSG_MAX_SIZE * UB_MGMT_RQ_DEPTH;
    seg_cfg.va = (uint64_t)recv_bufs;
    tseg_recvs = urma_register_seg(urma_ctx, &seg_cfg);
    if (tseg_recvs == NULL) {
        LOG_ERROR("Failed to register mgmt recv ring seg.\n");
        goto unregister_recv;
    }
    seg_cfg.len = UB_MGMT_MSG_MAX_SIZE;

    /* Dedicated handshake recv seg. recv_buf_hs is unused on client; allocated
     * unconditionally to keep ctx layout symmetric. */
    seg_cfg.va = (uint64_t)recv_buf_hs;
    tseg_recv_hs = urma_register_seg(urma_ctx, &seg_cfg);
    if (tseg_recv_hs == NULL) {
        LOG_ERROR("Failed to register mgmt handshake recv seg.\n");
        goto unregister_recvs;
    }

    jfs_cfg.depth = UB_MGMT_JFS_DEPTH;
    jfs_cfg.flag.value = 0;
    jfs_cfg.trans_mode = URMA_TM_RM;
    jfs_cfg.priority = 0;
    jfs_cfg.max_sge = 1;
    jfs_cfg.max_rsge = 1;
    jfs_cfg.max_inline_data = 0;  /* mgmt uses registered seg, no inline needed */
    jfs_cfg.rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg.err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    jfs_cfg.jfc = jfc;
    jfs_cfg.user_ctx = (uint64_t)NULL;

    jfr_cfg.id = 0;
    jfr_cfg.depth = UB_MGMT_JFR_DEPTH;
    jfr_cfg.flag.value = 0;
    jfr_cfg.trans_mode = URMA_TM_RM;
    jfr_cfg.max_sge = 1;
    jfr_cfg.min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg.jfc = jfc;
    jfr_cfg.token_value = g_ub_mgmt_token;
    jfr_cfg.user_ctx = (uint64_t)NULL;

    /* UB dev requires share_jfr (urma_cp_api.c:1563). Create 1 shared jfr
     * here, then attach it to the mgmt jetty via jetty_cfg.shared.jfr. */
    jfr = urma_create_jfr(urma_ctx, &jfr_cfg);
    if (jfr == NULL) {
        LOG_ERROR("Failed to create mgmt shared jfr.\n");
        goto unregister_recv_hs;
    }

    ctx = (ub_mgmt_ctx_t *)calloc(1, sizeof(ub_mgmt_ctx_t));
    if (ctx == NULL) {
        LOG_ERROR("Failed to alloc mgmt ctx.\n");
        goto delete_jfr;
    }
    ctx->urma_ctx = urma_ctx;
    ctx->dev = dev;
    ctx->jfc = jfc;
    ctx->jfr = jfr;
    ctx->send_buf = send_buf;
    ctx->probe_buf = probe_buf;
    ctx->recv_bufs = recv_bufs;
    ctx->recv_buf_hs = recv_buf_hs;
    ctx->tseg_send = tseg_send;
    ctx->tseg_probe = tseg_probe;
    ctx->tseg_recvs = tseg_recvs;
    ctx->tseg_recv_hs = tseg_recv_hs;
    ctx->is_server = (cfg->dst_eid == NULL);

    if (ctx->is_server) {
        local_jetty_id = cfg->dst_jetty_id;
    } else {
        local_jetty_id = 0;
    }

    jetty_cfg.id = local_jetty_id;
    jetty_cfg.flag.value = 0;
    jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jetty_cfg.jfs_cfg = jfs_cfg;
    jetty_cfg.shared.jfr = jfr;
    jetty_cfg.shared.jfc = jfc;
    jetty_cfg.jetty_grp = NULL;
    jetty_cfg.user_ctx = (uint64_t)NULL;

    ctx->pair.jetty = urma_create_jetty(urma_ctx, &jetty_cfg);
    if (ctx->pair.jetty == NULL) {
        LOG_ERROR("Failed to create mgmt jetty.\n");
        goto free_ctx;
    }
    ctx->pair.tjetty = NULL;

    *ctx_out = ctx;
    return 0;

free_ctx:
    free(ctx);
delete_jfr:
    (void)urma_delete_jfr(jfr);
unregister_recv_hs:
    (void)urma_unregister_seg(tseg_recv_hs);
unregister_recvs:
    (void)urma_unregister_seg(tseg_recvs);
unregister_recv:
    (void)urma_unregister_seg(tseg_probe);
unregister_send:
    (void)urma_unregister_seg(tseg_send);
free_bufs:
    free(send_buf);
    free(probe_buf);
    free(recv_bufs);
    free(recv_buf_hs);
free_jfc:
    (void)urma_delete_jfc(jfc);
delete_ctx:
    (void)urma_delete_context(urma_ctx);
    return -1;
}

/*
 * Server handshake: post [handshake recv (1B), data recv (4KB)] in FIFO order,
 * poll handshake CQE, then import peer jetty via cr.remote_id (HW-filled).
 * Data recv stays outstanding across handshake to avoid RNR race with the
 * first sync_data send. Dedicated handshake buffer avoids overwriting by data.
 */
static int ub_server_handshake(ub_mgmt_ctx_t *ctx)
{
    urma_sge_t sge = {0};
    urma_jfr_wr_t wr = {0};
    urma_jfr_wr_t *bad = NULL;
    urma_cr_t cr = {0};
    urma_rjetty_t rjetty = {0};

    LOG_INFO(PERFTEST_RESULT_LINE);
    LOG_INFO("                           Waiting for client to connect...\n");

    /* WQE[0]: handshake recv (1B). */
    sge.addr = (uint64_t)ctx->recv_buf_hs;
    sge.len = UB_MGMT_HANDSHAKE_SIZE;
    sge.tseg = ctx->tseg_recv_hs;
    wr.src.sge = &sge;
    wr.src.num_sge = 1;
    wr.user_ctx = 0;
    wr.next = NULL;
    if (urma_post_jetty_recv_wr(ctx->pair.jetty, &wr, &bad) != URMA_SUCCESS) {
        LOG_ERROR("Failed to post handshake recv.\n");
        return -1;
    }

    /* Pre-post RQ_DEPTH data recvs so RQ always has spare WQEs. */
    for (int i = 0; i < UB_MGMT_RQ_DEPTH; i++) {
        if (ub_post_one_recv(ctx, i) != 0) {
            LOG_ERROR("Failed to pre-post data recv slot %d.\n", i);
            return -1;
        }
    }

    if (poll_one_cqe(ctx->jfc, &cr, true) != 0) {
        return -1;
    }

    /* cr.remote_id (eid + id) is filled by HW on RECV. */
    fill_rjetty(cr.remote_id.eid, cr.remote_id.id, &rjetty);
    ctx->pair.tjetty = urma_import_jetty(ctx->urma_ctx, &rjetty, &g_ub_mgmt_token);
    if (ctx->pair.tjetty == NULL) {
        LOG_ERROR("Failed to import peer mgmt jetty (handshake).\n");
        return -1;
    }
    return 0;
}

/* Client handshake: parse server EID, import server jetty, post 1B send, poll CQE. */
static int ub_client_handshake(ub_mgmt_ctx_t *ctx, const char *peer_eid_str, uint32_t peer_jetty_id)
{
    urma_eid_t peer_eid = {0};
    urma_rjetty_t rjetty = {0};
    urma_sge_t sge = {0};
    urma_jfs_wr_t wr = {0};
    urma_jfs_wr_t *bad = NULL;
    urma_cr_t cr = {0};

    if (urma_str_to_eid(peer_eid_str, &peer_eid) != 0) {
        LOG_ERROR("Failed to parse peer eid: %s\n", peer_eid_str);
        return -1;
    }

    fill_rjetty(peer_eid, peer_jetty_id, &rjetty);
    ctx->pair.tjetty = urma_import_jetty(ctx->urma_ctx, &rjetty, &g_ub_mgmt_token);
    if (ctx->pair.tjetty == NULL) {
        LOG_ERROR("Failed to import peer mgmt jetty.\n");
        return -1;
    }

    ctx->send_buf[0] = 'H';
    sge.addr = (uint64_t)ctx->send_buf;
    sge.len = UB_MGMT_HANDSHAKE_SIZE;
    sge.tseg = ctx->tseg_send;
    wr.opcode = URMA_OPC_SEND;
    wr.flag.value = 0;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = ctx->pair.tjetty;
    wr.user_ctx = 0;
    wr.send.src.sge = &sge;
    wr.send.src.num_sge = 1;
    wr.send.imm_data = 0;
    wr.next = NULL;

    if (urma_post_jetty_send_wr(ctx->pair.jetty, &wr, &bad) != URMA_SUCCESS) {
        LOG_ERROR("Failed to post handshake send.\n");
        return -1;
    }

    if (poll_one_cqe(ctx->jfc, &cr, true) != 0) {
        return -1;
    }
    return 0;
}

int ub_establish_connection(const comm_ub_cfg_t *cfg)
{
    ub_mgmt_ctx_t *ctx = NULL;
    urma_init_attr_t init_attr = { .token = 0, .uasid = 0 };
    urma_status_t status;

    if (cfg == NULL) {
        return -EINVAL;
    }

    /* mgmt channel runs before init_device; must urma_init here. Tolerate EEXIST. */
    status = urma_init(&init_attr);
    if (status != URMA_SUCCESS && status != URMA_EEXIST) {
        LOG_ERROR("Failed to urma_init for mgmt channel, status: %d.\n", (int)status);
        return -1;
    }

    if (cfg->src_eid == NULL || cfg->src_eid[0] == '\0') {
        LOG_ERROR("Invalid mgmt ub cfg: src_eid missing.\n");
        return -EINVAL;
    }
    if (cfg->dst_eid != NULL && cfg->dst_eid[0] == '\0') {
        LOG_ERROR("Invalid mgmt ub cfg: empty dst_eid.\n");
        return -EINVAL;
    }
    if (g_ub_ctx != NULL) {
        LOG_ERROR("mgmt ub ctx already initialized.\n");
        return -EEXIST;
    }

    if (cfg->dst_eid == NULL && cfg->dst_jetty_id == 0) {
        LOG_ERROR("UB mgmt server requires -P for jetty id.\n");
        return -EINVAL;
    }

    if (ub_create_local_resources(cfg, &ctx) != 0) {
        return -1;
    }

    if (ctx->is_server) {
        if (ub_server_handshake(ctx) != 0) {
            goto rollback_handshake;
        }
    } else {
        if (ub_client_handshake(ctx, cfg->dst_eid, cfg->dst_jetty_id) != 0) {
            goto rollback_handshake;
        }
    }

    /* Pre-post RQ_DEPTH data recvs on client; server already has them in handshake. */
    if (!ctx->is_server) {
        for (int i = 0; i < UB_MGMT_RQ_DEPTH; i++) {
            if (ub_post_one_recv(ctx, i) != 0) {
                LOG_ERROR("Failed to pre-post mgmt recv slot %d.\n", i);
                goto rollback_handshake;
            }
        }
    }
    ctx->pair.have_pending_recv = !ctx->is_server;

    g_ub_ctx = ctx;
    return 0;

rollback_handshake:
    if (ctx->pair.tjetty != NULL) {
        (void)urma_unimport_jetty(ctx->pair.tjetty);
        ctx->pair.tjetty = NULL;
    }
    if (ctx->pair.jetty != NULL) {
        (void)urma_delete_jetty(ctx->pair.jetty);
    }
    (void)urma_delete_jfr(ctx->jfr);
    (void)urma_unregister_seg(ctx->tseg_recv_hs);
    (void)urma_unregister_seg(ctx->tseg_recvs);
    (void)urma_unregister_seg(ctx->tseg_probe);
    (void)urma_unregister_seg(ctx->tseg_send);
    free(ctx->send_buf);
    free(ctx->probe_buf);
    free(ctx->recv_bufs);
    free(ctx->recv_buf_hs);
    (void)urma_delete_jfc(ctx->jfc);
    (void)urma_delete_context(ctx->urma_ctx);
    free(ctx);
    return -1;
}

void ub_close_connection(void)
{
    if (g_ub_ctx == NULL) {
        return;
    }

    /* Caller (destroy_*_ctx) must invoke close_connection BEFORE uninit_device:
     * urma_uninit dlclose()'s provider .so, after which ctx->ops dangles. */
    if (g_ub_ctx->pair.tjetty != NULL) {
        (void)urma_unimport_jetty(g_ub_ctx->pair.tjetty);
        g_ub_ctx->pair.tjetty = NULL;
    }
    if (g_ub_ctx->pair.jetty != NULL) {
        (void)urma_delete_jetty(g_ub_ctx->pair.jetty);
        g_ub_ctx->pair.jetty = NULL;
    }
    if (g_ub_ctx->jfr != NULL) {
        (void)urma_delete_jfr(g_ub_ctx->jfr);
        g_ub_ctx->jfr = NULL;
    }
    if (g_ub_ctx->tseg_probe != NULL) {
        (void)urma_unregister_seg(g_ub_ctx->tseg_probe);
        g_ub_ctx->tseg_probe = NULL;
    }
    if (g_ub_ctx->tseg_recvs != NULL) {
        (void)urma_unregister_seg(g_ub_ctx->tseg_recvs);
        g_ub_ctx->tseg_recvs = NULL;
    }
    if (g_ub_ctx->tseg_recv_hs != NULL) {
        (void)urma_unregister_seg(g_ub_ctx->tseg_recv_hs);
        g_ub_ctx->tseg_recv_hs = NULL;
    }
    if (g_ub_ctx->tseg_send != NULL) {
        (void)urma_unregister_seg(g_ub_ctx->tseg_send);
        g_ub_ctx->tseg_send = NULL;
    }
    if (g_ub_ctx->jfc != NULL) {
        (void)urma_delete_jfc(g_ub_ctx->jfc);
        g_ub_ctx->jfc = NULL;
    }
    if (g_ub_ctx->urma_ctx != NULL) {
        (void)urma_delete_context(g_ub_ctx->urma_ctx);
        g_ub_ctx->urma_ctx = NULL;
    }
    free(g_ub_ctx->send_buf);
    g_ub_ctx->send_buf = NULL;
    free(g_ub_ctx->probe_buf);
    g_ub_ctx->probe_buf = NULL;
    free(g_ub_ctx->recv_bufs);
    g_ub_ctx->recv_bufs = NULL;
    free(g_ub_ctx->recv_buf_hs);
    g_ub_ctx->recv_buf_hs = NULL;
    free(g_ub_ctx);
    g_ub_ctx = NULL;
}

/* ========================================================================== */
/* sync_data / sync_time                                                       */
/* ========================================================================== */

int ub_sync_data(uint32_t index, int size, char *local_data, char *remote_data)
{
    urma_sge_t send_sge = {0};
    urma_jfs_wr_t send_wr = {0};
    urma_jfs_wr_t *send_bad = NULL;
    urma_cr_t cr = {0};

    (void)index; /* single pair; index ignored */

    if (g_ub_ctx == NULL || size <= 0 || size > UB_MGMT_MSG_MAX_SIZE ||
        local_data == NULL || remote_data == NULL) {
        LOG_ERROR("Invalid ub_sync_data args: ctx=%p, size=%d\n", (void *)g_ub_ctx, size);
        return -EINVAL;
    }

    /* RECV pre-posted in establish/handshake; refilled on each recv CQE below.
     * Don't post recv here —sync post races with peer send in UB+RM (no
     * kernel buffering, exhausts rnr_retry=7). 
     */

    /* copy local_data into registered send_buf */
    (void)memcpy(g_ub_ctx->send_buf, local_data, (size_t)size);

    /* post send (buffer=send_buf) */
    send_sge.addr = (uint64_t)g_ub_ctx->send_buf;
    send_sge.len = (uint32_t)size;
    send_sge.tseg = g_ub_ctx->tseg_send;
    send_wr.opcode = URMA_OPC_SEND;
    send_wr.flag.value = 0;
    send_wr.flag.bs.complete_enable = 1;
    send_wr.tjetty = g_ub_ctx->pair.tjetty;
    send_wr.user_ctx = 0;
    send_wr.send.src.sge = &send_sge;
    send_wr.send.src.num_sge = 1;
    send_wr.send.imm_data = 0;
    send_wr.next = NULL;
    if (urma_post_jetty_send_wr(g_ub_ctx->pair.jetty, &send_wr, &send_bad) != URMA_SUCCESS) {
        LOG_ERROR("Failed to post mgmt send wr.\n");
        return -1;
    }

    bool send_done = false;
    bool recv_done = g_ub_ctx->pair.have_deferred_recv;
    int consumed_buf_idx = recv_done ? (int)g_ub_ctx->pair.deferred_buf_idx : 0;
    g_ub_ctx->pair.have_deferred_recv = false;

    while (!send_done || !recv_done) {
        if (g_exit_flag) {
            return -EINTR;
        }
        int n = urma_poll_jfc(g_ub_ctx->jfc, 1, &cr);
        if (n < 0) {
            LOG_ERROR("Failed to poll jfc.\n");
            return -1;
        }
        if (n != 1) {
            continue;
        }
        if (cr.status != URMA_CR_SUCCESS) {
            LOG_ERROR("mgmt CR status %d (s_r=%u).\n", (int)cr.status, cr.flag.bs.s_r);
            return -1;
        }
        if (cr.flag.bs.s_r == 1) { /* recv CQE */
            if (!recv_done) {
                consumed_buf_idx = (int)cr.user_ctx;
                recv_done = true;
            } else {
                /* Next round's recv arrived before our send CQE — stash. */
                g_ub_ctx->pair.have_deferred_recv = true;
                g_ub_ctx->pair.deferred_buf_idx = (uint32_t)cr.user_ctx;
            }
        } else { /* send CQE */
            send_done = true;
        }
    }

    /* memcpy before refill: HW writes buf before CQE, but keep order clear. */
    char *consumed_buf = g_ub_ctx->recv_bufs + consumed_buf_idx * UB_MGMT_MSG_MAX_SIZE;
    (void)memcpy(remote_data, consumed_buf, (size_t)size);
    if (ub_post_one_recv(g_ub_ctx, consumed_buf_idx) != 0) {
        LOG_ERROR("Failed to refill mgmt recv (buf=%d).\n", consumed_buf_idx);
        return -1;
    }
    return 0;
}

int ub_sync_time(uint32_t index, const char *tag)
{
    int len;
    char *b = NULL;
    int ret;

    if (tag == NULL) {
        LOG_ERROR("Invalid parameter: tag is nullptr.\n");
        return -EINVAL;
    }
    len = (int)strlen(tag);
    if (len >= UB_MGMT_MSG_MAX_SIZE) {
        LOG_ERROR("sync_time tag too long: %d.\n", len);
        return -EINVAL;
    }
    b = (char *)calloc(1, (size_t)len + 1);
    if (b == NULL) {
        return -ENOMEM;
    }
    ret = ub_sync_data(index, len, (char *)tag, b);
    if (ret != 0) {
        LOG_ERROR("sync_time ub error, tag: %s, ret: %d.\n", tag, ret);
        free(b);
        return ret;
    }
    ret = (memcmp(tag, b, (size_t)len) == 0) ? 0 : -1;
    if (ret != 0) {
        b[len] = '\0';
        LOG_ERROR("sync_time ub mismatch: %s != %s.\n", tag, b);
    }
    free(b);
    return ret;
}

/* ========================================================================== */
/* comm_send / comm_recv / comm_poll (infinite BW mode control flow)          */
/* ========================================================================== */

ssize_t ub_comm_send(uint32_t index, const void *buf, size_t size)
{
    urma_sge_t sge = {0};
    urma_jfs_wr_t wr = {0};
    urma_jfs_wr_t *bad = NULL;
    urma_cr_t cr = {0};

    (void)index; /* single pair; index ignored */

    if (g_ub_ctx == NULL || buf == NULL || size == 0 || size > UB_MGMT_MSG_MAX_SIZE) {
        return -EINVAL;
    }
    (void)memcpy(g_ub_ctx->send_buf, buf, size);

    sge.addr = (uint64_t)g_ub_ctx->send_buf;
    sge.len = (uint32_t)size;
    sge.tseg = g_ub_ctx->tseg_send;
    wr.opcode = URMA_OPC_SEND;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = g_ub_ctx->pair.tjetty;
    wr.send.src.sge = &sge;
    wr.send.src.num_sge = 1;
    wr.next = NULL;

    if (urma_post_jetty_send_wr(g_ub_ctx->pair.jetty, &wr, &bad) != URMA_SUCCESS) {
        LOG_ERROR("Failed to post comm_send wr.\n");
        return -1;
    }

    if (poll_one_cqe(g_ub_ctx->jfc, &cr, false) != 0) {
        return -1;
    }
    return (ssize_t)size;
}

ssize_t ub_comm_recv(uint32_t index, void *buf, size_t size)
{
    urma_sge_t sge = {0};
    urma_jfr_wr_t wr = {0};
    urma_jfr_wr_t *bad = NULL;
    urma_cr_t cr = {0};

    (void)index; /* single pair; index ignored */

    if (g_ub_ctx == NULL || buf == NULL || size == 0 || size > UB_MGMT_MSG_MAX_SIZE) {
        return -EINVAL;
    }

    /* If comm_poll already captured probe data, return it directly.
     * perftest's comm_recv is only for 1B PERFTEST_EXIT_CMD. */
    if (g_ub_ctx->pair.have_pending_data) {
        if (size > 1) {
            LOG_ERROR("comm_recv: size=%zu but pending probe data is 1B only.\n", size);
            return -EINVAL;
        }
        (void)memcpy(buf, g_ub_ctx->probe_buf, 1);
        g_ub_ctx->pair.have_pending_data = false;
        g_ub_ctx->pair.pending_data_len = 0;
        return 1;
    }

    if (!g_ub_ctx->pair.have_pending_recv) {
        /* Fresh recv: post with caller's size. */
        sge.addr = (uint64_t)g_ub_ctx->probe_buf;
        sge.len = (uint32_t)size;
        sge.tseg = g_ub_ctx->tseg_probe;
        wr.src.sge = &sge;
        wr.src.num_sge = 1;
        wr.next = NULL;
        if (urma_post_jetty_recv_wr(g_ub_ctx->pair.jetty, &wr, &bad) != URMA_SUCCESS) {
            LOG_ERROR("Failed to post comm_recv wr.\n");
            return -1;
        }
    } else {
        /* Probe recv in flight; just wait for its CQE. */
        g_ub_ctx->pair.have_pending_recv = false;
    }

    if (poll_one_cqe(g_ub_ctx->jfc, &cr, true) != 0) {
        return -1;
    }
    uint32_t got = cr.completion_len;
    if (got > size) {
        got = (uint32_t)size;
    }
    (void)memcpy(buf, g_ub_ctx->probe_buf, got);
    return (ssize_t)got;
}

/*
 * UB equivalent of TCP poll(fd, POLLIN, timeout_ms). UB has no kernel
 * buffering, so poll posts a 1B probe recv and non-blocking polls jfc
 * until CQE arrives or timeout. Returns >0 if data ready, 0 on timeout.
 */
int ub_comm_poll(uint32_t index, int timeout_ms)
{
    urma_sge_t sge = {0};
    urma_jfr_wr_t wr = {0};
    urma_jfr_wr_t *bad = NULL;

    (void)index; /* single pair; index ignored */

    if (g_ub_ctx == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    /* If a previous poll already got data, return immediately. */
    if (g_ub_ctx->pair.have_pending_data) {
        return 1;
    }

    /* Post probe recv if not already in flight. */
    if (!g_ub_ctx->pair.have_pending_recv) {
        sge.addr = (uint64_t)g_ub_ctx->probe_buf;
        sge.len = 1;  /* probe: just 1B to detect peer exit signal */
        sge.tseg = g_ub_ctx->tseg_probe;
        wr.src.sge = &sge;
        wr.src.num_sge = 1;
        wr.next = NULL;
        if (urma_post_jetty_recv_wr(g_ub_ctx->pair.jetty, &wr, &bad) != URMA_SUCCESS) {
            LOG_ERROR("Failed to post comm_poll probe recv.\n");
            errno = EIO;
            return -1;
        }
        g_ub_ctx->pair.have_pending_recv = true;
    }

    /* Non-blocking poll loop with 1ms sleep, up to timeout_ms iterations. */
    struct timespec ts_start = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &ts_start);
    uint64_t start_ms = (uint64_t)ts_start.tv_sec * 1000 + (uint64_t)ts_start.tv_nsec / 1000000;

    while (true) {
        urma_cr_t cr = {0};
        int n = urma_poll_jfc(g_ub_ctx->jfc, 1, &cr);
        if (n < 0) {
            LOG_ERROR("Failed to poll jfc in comm_poll.\n");
            errno = EIO;
            return -1;
        }
        if (n == 1) {
            if (cr.status != URMA_CR_SUCCESS) {
                LOG_ERROR("comm_poll CR status %d.\n", (int)cr.status);
                errno = EIO;
                return -1;
            }
            /* Probe completed: data is in probe_buf. Keep it for comm_recv. */
            g_ub_ctx->pair.have_pending_recv = false;
            g_ub_ctx->pair.have_pending_data = true;
            g_ub_ctx->pair.pending_data_len = cr.completion_len;
            return 1;
        }

        struct timespec ts_now = {0};
        (void)clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ms = (uint64_t)ts_now.tv_sec * 1000 + (uint64_t)ts_now.tv_nsec / 1000000;
        if (now_ms - start_ms >= (uint64_t)timeout_ms) {
            return 0;  /* timeout, probe recv still pending */
        }
        (void)usleep(1000);  /* 1ms backoff to avoid burning CPU */
    }
}
