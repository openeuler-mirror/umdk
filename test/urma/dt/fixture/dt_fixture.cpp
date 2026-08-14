/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include "dt_fixture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

extern "C" __attribute__((weak)) void urma_sim_ipc_start(const uint8_t *eid);

#define DT_JFC_DEPTH 64
#define DT_JETTY_DEPTH 256

static void dt_log(int level, char *message)
{
    if (level <= 3) {
        fprintf(stderr, "[urma L%d] %s", level, message);
    }
}

dt_ctx_t::~dt_ctx_t()
{
    if (jetty) urma_delete_jetty(jetty);
    if (jfr) urma_delete_jfr(jfr);
    if (jfs) urma_delete_jfs(jfs);
    if (jfc) urma_delete_jfc(jfc);
    if (jfce) urma_delete_jfce(jfce);
    if (ctx) urma_delete_context(ctx);
    if (devs) urma_free_device_list(devs);
}

static int s_urma_inited = 0;

dt_ctx_t *dt_setup(int dev_idx, urma_transport_mode_t trans_mode, urma_tp_type_t tp_type)
{
    dt_ctx_t *c = new dt_ctx_t();
    c->trans_mode = trans_mode;
    c->tp_type = tp_type;

    if (!s_urma_inited) {
        urma_init_attr_t init_attr = {0};

        urma_register_log_func(dt_log);
        if (urma_init(&init_attr) != 0) {
            fprintf(stderr, "[dt_setup] init fail\n");
            delete c;
            return nullptr;
        }
        s_urma_inited = 1;
    }

    int num_devs = 0;
    c->devs = urma_get_device_list(&num_devs);
    fprintf(stderr, "[dt_setup] num_devs=%d\n", num_devs);
    if (dev_idx < 0 || dev_idx >= num_devs) {
        fprintf(stderr, "[dt_setup] dev idx\n");
        delete c;
        return nullptr;
    }

    c->ctx = urma_create_context(c->devs[dev_idx], 0);
    if (!c->ctx) {
        delete c;
        return nullptr;
    }
    if (urma_sim_ipc_start != nullptr) {
        urma_sim_ipc_start(c->ctx->eid.raw);
    }

    c->jfce = urma_create_jfce(c->ctx);
    if (!c->jfce) {
        delete c;
        return nullptr;
    }

    urma_jfc_cfg_t jfc_cfg = {0};
    jfc_cfg.depth = DT_JFC_DEPTH;
    jfc_cfg.jfce = c->jfce;
    c->jfc = urma_create_jfc(c->ctx, &jfc_cfg);
    if (!c->jfc) {
        delete c;
        return nullptr;
    }

    urma_jfr_cfg_t jfr_cfg = {0};
    jfr_cfg.depth = DT_JETTY_DEPTH;
    jfr_cfg.flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    jfr_cfg.flag.bs.order_type = 0;
    jfr_cfg.trans_mode = trans_mode;
    jfr_cfg.min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg.jfc = c->jfc;
    jfr_cfg.max_sge = 1;
    c->jfr = urma_create_jfr(c->ctx, &jfr_cfg);
    if (!c->jfr) {
        delete c;
        return nullptr;
    }

    urma_jfs_cfg_t jfs_cfg = {0};
    jfs_cfg.depth = DT_JETTY_DEPTH;
    jfs_cfg.flag.bs.order_type = 0;
    jfs_cfg.trans_mode = trans_mode;
    jfs_cfg.priority = URMA_MAX_PRIORITY;
    jfs_cfg.max_sge = 4;
    jfs_cfg.max_rsge = 4;
    jfs_cfg.max_inline_data = 64;
    jfs_cfg.rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg.err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    jfs_cfg.jfc = c->jfc;

    urma_jetty_cfg_t jetty_cfg = {0};
    jetty_cfg.flag.bs.share_jfr = 1;
    jetty_cfg.jfs_cfg = jfs_cfg;
    jetty_cfg.shared.jfr = c->jfr;
    c->jetty = urma_create_jetty(c->ctx, &jetty_cfg);
    if (!c->jetty) {
        delete c;
        return nullptr;
    }

    return c;
}

dt_ctx_t *dt_setup(int dev_idx, urma_transport_mode_t trans_mode)
{
    return dt_setup(dev_idx, trans_mode, URMA_UTP);
}

dt_ctx_t *dt_setup_default(int dev_idx)
{
    return dt_setup(dev_idx, URMA_TM_UM, URMA_UTP);
}

urma_target_seg_t *dt_register_seg(dt_ctx_t *c, void *buf, size_t len)
{
    if (!c || !c->ctx || !buf || !len) {
        return nullptr;
    }

    urma_seg_cfg_t cfg = {0};
    cfg.va = (uint64_t)(uintptr_t)buf;
    cfg.len = len;
    return urma_register_seg(c->ctx, &cfg);
}

urma_target_jetty_t *dt_import_self(dt_ctx_t *c)
{
    if (!c || !c->ctx || !c->jetty) {
        return nullptr;
    }

    urma_token_t tok = {0};
    urma_rjetty_t rjetty = {0};
    rjetty.jetty_id.eid = c->ctx->eid;
    rjetty.jetty_id.uasid = c->ctx->uasid;
    rjetty.jetty_id.id = c->jetty->jetty_id.id;
    rjetty.trans_mode = c->trans_mode;
    rjetty.type = URMA_JETTY;
    rjetty.tp_type = c->tp_type;
    return urma_import_jetty(c->ctx, &rjetty, &tok);
}

urma_target_jetty_t *dt_bind_remote(dt_ctx_t *c, urma_eid_t rmt_eid, uint32_t rmt_uasid, uint32_t rmt_jetty_id)
{
    if (!c || !c->ctx || !c->jetty) {
        return nullptr;
    }

    urma_token_t tok = {0};
    urma_rjetty_t rjetty = {0};
    rjetty.jetty_id.eid = rmt_eid;
    rjetty.jetty_id.uasid = rmt_uasid;
    rjetty.jetty_id.id = rmt_jetty_id;
    rjetty.trans_mode = c->trans_mode;
    rjetty.type = URMA_JETTY;
    rjetty.tp_type = c->tp_type;
    urma_target_jetty_t *tj = urma_import_jetty(c->ctx, &rjetty, &tok);
    if (!tj) {
        return nullptr;
    }
    if (urma_bind_jetty(c->jetty, tj) != URMA_SUCCESS) {
        (void)urma_unimport_jetty(tj);
        return nullptr;
    }
    return tj;
}

urma_target_jetty_t *dt_import_jetty_remote(dt_ctx_t *c, urma_eid_t rmt_eid,
                                         uint32_t rmt_uasid, uint32_t rmt_jetty_id)
{
    if (!c || !c->ctx) {
        return nullptr;
    }

    urma_token_t tok = {0};
    urma_rjetty_t rjetty = {0};
    rjetty.jetty_id.eid = rmt_eid;
    rjetty.jetty_id.uasid = rmt_uasid;
    rjetty.jetty_id.id = rmt_jetty_id;
    rjetty.trans_mode = c->trans_mode;
    rjetty.type = URMA_JETTY;
    rjetty.tp_type = c->tp_type;
    return urma_import_jetty(c->ctx, &rjetty, &tok);
}

urma_target_seg_t *dt_import_seg_remote(dt_ctx_t *c, urma_eid_t rmt_eid, uint32_t rmt_uasid,
                                     uint32_t rmt_token_id, uint64_t rmt_va, uint64_t rmt_len)
{
    if (!c || !c->ctx) {
        return nullptr;
    }

    urma_seg_t remote_seg = {0};
    remote_seg.ubva.eid = rmt_eid;
    remote_seg.ubva.uasid = rmt_uasid;
    remote_seg.ubva.va = rmt_va;
    remote_seg.len = rmt_len;
    remote_seg.token_id = rmt_token_id;
    urma_token_t tok = {0};
    urma_import_seg_flag_t flag = {0};
    flag.bs.access = (0x1 << 1) | (0x1 << 2);
    return urma_import_seg(c->ctx, &remote_seg, &tok, 0, flag);
}

int dt_post_rw(dt_ctx_t *c, urma_target_jetty_t *tj, urma_opcode_t opcode,
            void *local, urma_target_seg_t *local_tseg,
            void *remote_buf, urma_target_seg_t *remote_tseg,
            size_t len, uint64_t user_ctx, uint64_t extra1, uint64_t extra2)
{
    if (!c || !c->jetty || !tj || !local || !local_tseg ||
        !remote_buf || !remote_tseg) {
        return -1;
    }
    if (len > UINT32_MAX) {
        fprintf(stderr, "[dt_post_rw] len %zu exceeds UINT32_MAX\n", len);
        return -1;
    }

    urma_sge_t rsg = {0};
    rsg.addr = (uint64_t)(uintptr_t)remote_buf;
    rsg.len = len;
    rsg.tseg = remote_tseg;

    urma_sge_t lsg = {0};
    lsg.addr = (uint64_t)(uintptr_t)local;
    lsg.len = len;
    lsg.tseg = local_tseg;

    urma_jfs_wr_t wr = {};
    wr.opcode = opcode;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = tj;
    wr.user_ctx = user_ctx;

    if (opcode == URMA_OPC_CAS) {
        wr.cas.dst = &rsg;
        wr.cas.src = &lsg;
        wr.cas.cmp_data = extra1;
        wr.cas.swap_data = extra2;
    } else if (opcode == URMA_OPC_FADD) {
        wr.faa.dst = &rsg;
        wr.faa.src = &lsg;
        wr.faa.operand = extra1;
    } else {
        urma_sg_t rsg_wrap = {.sge = &rsg, .num_sge = 1};
        urma_sg_t lsg_wrap = {.sge = &lsg, .num_sge = 1};
        if (opcode == URMA_OPC_READ) {
            wr.rw.dst = lsg_wrap;
            wr.rw.src = rsg_wrap;
        } else {
            wr.rw.dst = rsg_wrap;
            wr.rw.src = lsg_wrap;
        }
    }

    urma_jfs_wr_t *bad = nullptr;
    return urma_post_jetty_send_wr(c->jetty, &wr, &bad);
}

int dt_post_read(dt_ctx_t *c, urma_target_jetty_t *tj,
              void *dst, urma_target_seg_t *dst_tseg,
              void *src_buf, urma_target_seg_t *src_tseg,
              size_t len, uint64_t user_ctx)
{
    return dt_post_rw(c, tj, URMA_OPC_READ, dst, dst_tseg, src_buf, src_tseg, len, user_ctx, 0, 0);
}

int dt_post_write(dt_ctx_t *c, urma_target_jetty_t *tj,
               void *src_buf, urma_target_seg_t *src_tseg,
               void *dst_buf, urma_target_seg_t *dst_tseg,
               size_t len, uint64_t user_ctx)
{
    return dt_post_rw(c, tj, URMA_OPC_WRITE, src_buf, src_tseg, dst_buf, dst_tseg, len, user_ctx, 0, 0);
}

int dt_post_cas(dt_ctx_t *c, urma_target_jetty_t *tj,
             void *atomic_buf, urma_target_seg_t *atomic_tseg,
             void *orig_buf, urma_target_seg_t *orig_tseg,
             uint64_t cmp, uint64_t swap, size_t len, uint64_t user_ctx)
{
    return dt_post_rw(c, tj, URMA_OPC_CAS, orig_buf, orig_tseg, atomic_buf, atomic_tseg,
                   len, user_ctx, cmp, swap);
}

int dt_post_faa(dt_ctx_t *c, urma_target_jetty_t *tj,
             void *atomic_buf, urma_target_seg_t *atomic_tseg,
             void *orig_buf, urma_target_seg_t *orig_tseg,
             uint64_t operand, size_t len, uint64_t user_ctx)
{
    return dt_post_rw(c, tj, URMA_OPC_FADD, orig_buf, orig_tseg, atomic_buf, atomic_tseg,
                   len, user_ctx, operand, 0);
}

int dt_post_recv(dt_ctx_t *c, void *recv_buf, urma_target_seg_t *recv_tseg,
              size_t len, uint64_t user_ctx)
{
    if (!c || !c->jetty || !recv_buf || !recv_tseg) {
        return -1;
    }
    if (len > UINT32_MAX) {
        fprintf(stderr, "[dt_post_recv] len %zu exceeds UINT32_MAX\n", len);
        return -1;
    }

    urma_sge_t sge = {0};
    sge.addr = (uint64_t)(uintptr_t)recv_buf;
    sge.len = len;
    sge.tseg = recv_tseg;
    urma_sg_t sg = {.sge = &sge, .num_sge = 1};
    urma_jfr_wr_t wr = {.src = sg, .user_ctx = user_ctx, .next = nullptr};
    urma_jfr_wr_t *bad = nullptr;
    return urma_post_jetty_recv_wr(c->jetty, &wr, &bad);
}

int dt_post_send(dt_ctx_t *c, urma_target_jetty_t *tj, void *data_buf, urma_target_seg_t *data_tseg,
              size_t len, uint64_t user_ctx)
{
    if (!c || !c->jetty || !tj || !data_buf || !data_tseg) {
        return -1;
    }
    if (len > UINT32_MAX) {
        fprintf(stderr, "[dt_post_send] len %zu exceeds UINT32_MAX\n", len);
        return -1;
    }

    urma_sge_t sge = {0};
    sge.addr = (uint64_t)(uintptr_t)data_buf;
    sge.len = len;
    sge.tseg = data_tseg;
    urma_sg_t sg = {.sge = &sge, .num_sge = 1};
    urma_send_wr_t send_wr = {.src = sg};
    urma_jfs_wr_t wr = {};
    wr.opcode = URMA_OPC_SEND;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = tj;
    wr.user_ctx = user_ctx;
    wr.send = send_wr;
    wr.next = nullptr;
    urma_jfs_wr_t *bad = nullptr;
    return urma_post_jetty_send_wr(c->jetty, &wr, &bad);
}

int dt_poll_cr(dt_ctx_t *c, urma_cr_t *cr)
{
    if (!c || !c->jfc || !cr) {
        return -1;
    }

    for (int i = 0; i < 100; i++) {
        int n = urma_poll_jfc(c->jfc, 1, cr);
        if (n > 0) {
            return n;
        }
        usleep(100000);
    }
    return 0;
}

uint32_t dt_get_jetty_id(dt_ctx_t *c)
{
    if (!c || !c->jetty) {
        return 0;
    }
    return c->jetty->jetty_id.id;
}

void dt_teardown(dt_ctx_t *c)
{
    delete c;
}
