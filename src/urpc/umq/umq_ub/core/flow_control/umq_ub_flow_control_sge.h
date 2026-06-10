/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UMQ UB flow control SGE memory management
 * Create: 2026-5-28
 * Note:
 * History: 2026-5-28
 */

#ifndef UMQ_UB_FLOW_CONTROL_SGE_H
#define UMQ_UB_FLOW_CONTROL_SGE_H

#include "umq_ub_private.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE 32768 // max 64K jetties per host, each jetty uses one 64B slot
#define UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT 64  // bytes per slot, (4B req + 4B rsp) * 8

/* Flow control SGE memory management APIs */
int umq_ub_flow_control_sge_mgr_init(umq_ub_flow_control_sge_mgr_t *mgr);
void umq_ub_flow_control_sge_mgr_uninit(umq_ub_flow_control_sge_mgr_t *mgr);
int umq_ub_flow_control_sge_alloc(umq_ub_flow_control_sge_mgr_t *mgr, umq_ub_flow_control_sge_slot_t *slot);
void umq_ub_flow_control_sge_free(umq_ub_flow_control_sge_mgr_t *mgr, umq_ub_flow_control_sge_slot_t *slot);
int umq_ub_flow_control_share_rq_sge_init(umq_ub_flow_control_share_recv_t *recv, uint32_t qbuf_cnt);
void umq_ub_flow_control_share_rq_sge_uninit(umq_ub_flow_control_share_recv_t *recv);

#ifdef __cplusplus
}
#endif

#endif /* UMQ_UB_FLOW_CONTROL_SGE_H */
