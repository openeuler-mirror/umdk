/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// DT case fixture：封装 sim 建链、释放和常用数据面操作。

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "urma_api.h"
#include "urma_opcode.h"
#include "urma_types.h"

struct dt_ctx_t {
    urma_context_t *ctx = nullptr;
    urma_jfce_t *jfce = nullptr;
    urma_jfc_t *jfc = nullptr;
    urma_jfs_t *jfs = nullptr;
    urma_jfr_t *jfr = nullptr;
    urma_jetty_t *jetty = nullptr;
    urma_device_t **devs = nullptr;
    urma_transport_mode_t trans_mode = URMA_TM_UM;
    urma_tp_type_t tp_type = URMA_UTP;
    ~dt_ctx_t();
};

dt_ctx_t *dt_setup(int dev_idx, urma_transport_mode_t trans_mode);
dt_ctx_t *dt_setup(int dev_idx, urma_transport_mode_t trans_mode, urma_tp_type_t tp_type);
dt_ctx_t *dt_setup_default(int dev_idx);
urma_target_seg_t *dt_register_seg(dt_ctx_t *c, void *buf, size_t len);
urma_target_jetty_t *dt_import_self(dt_ctx_t *c);
urma_target_jetty_t *dt_bind_remote(dt_ctx_t *c, urma_eid_t rmt_eid, uint32_t rmt_uasid, uint32_t rmt_jetty_id);
urma_target_jetty_t *dt_import_jetty_remote(dt_ctx_t *c, urma_eid_t rmt_eid,
                                         uint32_t rmt_uasid, uint32_t rmt_jetty_id);
urma_target_seg_t *dt_import_seg_remote(dt_ctx_t *c, urma_eid_t rmt_eid, uint32_t rmt_uasid,
                                     uint32_t rmt_token_id, uint64_t rmt_va, uint64_t rmt_len);
int dt_post_rw(dt_ctx_t *c, urma_target_jetty_t *tj, urma_opcode_t opcode,
            void *local, urma_target_seg_t *local_tseg,
            void *remote_buf, urma_target_seg_t *remote_tseg,
            size_t len, uint64_t user_ctx, uint64_t extra1, uint64_t extra2);
int dt_post_read(dt_ctx_t *c, urma_target_jetty_t *tj,
              void *dst, urma_target_seg_t *dst_tseg,
              void *src_buf, urma_target_seg_t *src_tseg,
              size_t len, uint64_t user_ctx);
int dt_post_write(dt_ctx_t *c, urma_target_jetty_t *tj,
               void *src_buf, urma_target_seg_t *src_tseg,
               void *dst_buf, urma_target_seg_t *dst_tseg,
               size_t len, uint64_t user_ctx);
int dt_post_cas(dt_ctx_t *c, urma_target_jetty_t *tj,
             void *atomic_buf, urma_target_seg_t *atomic_tseg,
             void *orig_buf, urma_target_seg_t *orig_tseg,
             uint64_t cmp, uint64_t swap, size_t len, uint64_t user_ctx);
int dt_post_faa(dt_ctx_t *c, urma_target_jetty_t *tj,
             void *atomic_buf, urma_target_seg_t *atomic_tseg,
             void *orig_buf, urma_target_seg_t *orig_tseg,
             uint64_t operand, size_t len, uint64_t user_ctx);
int dt_post_recv(dt_ctx_t *c, void *recv_buf, urma_target_seg_t *recv_tseg,
              size_t len, uint64_t user_ctx);
int dt_post_send(dt_ctx_t *c, urma_target_jetty_t *tj, void *data_buf, urma_target_seg_t *data_tseg,
              size_t len, uint64_t user_ctx);
int dt_poll_cr(dt_ctx_t *c, urma_cr_t *cr);
uint32_t dt_get_jetty_id(dt_ctx_t *c);
void dt_teardown(dt_ctx_t *c);
