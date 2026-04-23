/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check declarations
 */
#ifndef BONDP_HEALTH_CHECK_H
#define BONDP_HEALTH_CHECK_H

#include "bondp_types.h"

typedef enum bondp_health_event {
    BONDP_HEALTH_EVENT_TA_TIMEOUT  = 0,
    BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE,
    BONDP_HEALTH_EVENT_FALLBACK_TASK_KICK,
    BONDP_HEALTH_EVENT_MAX,
} bondp_health_event_t;

typedef int (*bondp_fallback_ctrl_send_cb_t)(bondp_context_t *bdp_ctx, uint32_t vjetty_id,
    int local_idx, int target_idx, uint8_t ctrl_type, uint8_t req_seq, uint32_t payload);

typedef struct bondp_health_event_info {
    int local_idx;
	int target_idx;
	uint64_t user_ctx;
	uint32_t cr_status;
	int new_active_idx;
	bondp_comp_t *bdp_jetty;
	bondp_target_jetty_t *bdp_tjetty;
} bondp_health_event_info_t;

void bondp_health_check_global_ctx_init(bondp_global_context_t *ctx);
void bondp_health_check_global_ctx_uninit(bondp_global_context_t *ctx);
void bondp_health_check_ctx_init(bondp_context_t *bond_ctx);
bool bondp_health_check_enabled(void);

int bondp_start_health_check_thread(void);
void bondp_stop_health_check_thread(void);

int bondp_create_health_check_ctx(bondp_context_t *bond_ctx);
void bondp_destroy_health_check_ctx(bondp_context_t *bond_ctx);
int bondp_register_health_check_seg_for_jetty(bondp_context_t *bond_ctx, bondp_comp_t *bdp_jetty);
void bondp_unregister_health_check_seg_for_jetty(bondp_comp_t *bdp_jetty);
int bondp_fill_vjetty_health_info(bondp_context_t *bond_ctx, bondp_comp_t *bdp_jetty,
	urma_bond_seg_info_out_t *health_check_seg, bool *is_health_check_enable);
int bondp_import_health_check_tseg(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
	urma_bond_id_info_out_t *rvjetty_info, urma_rjetty_t *rjetty);
int bondp_unimport_health_check_tseg(bondp_target_jetty_t *bdp_tjetty);
int bondp_register_health_check_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty, bondp_comp_t *cfg_jetty);
void bondp_unregister_health_check_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty);
void bondp_health_update_active_idx(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
	int new_active_idx);
bool bondp_try_handle_health_check_cr(bondp_context_t *bdp_ctx, int local_idx, urma_cr_t *cr);
void bondp_health_kick_fallback_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty);
void bondp_health_notify_fallback_ctrl_rx(bondp_context_t *bdp_ctx, uint32_t recv_local_id,
    uint8_t ctrl_type, uint8_t req_seq, uint32_t payload);
void bondp_notify_health_event(bondp_context_t *bdp_ctx, bondp_health_event_t event,
	const bondp_health_event_info_t *info);

#endif // BONDP_HEALTH_CHECK_H
