/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider datapath schedule implementation file
 * Author: Wang Hang
 * Create: 2026-04-06
 * Note:
 * History: 2026-04-06   Create File
 */

#include "bondp_types.h"
#include "urma_log.h"
#include "bondp_health_check.h"

#include "bondp_datapath_schedule.h"

static int schedule_send_standalone(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                    int *send_idx, int *target_idx)
{
    *send_idx = (int)bdp_comp->active_indices[0];
    *target_idx = (int)bdp_tjetty->active_indices[0];
    return 0;
}

static int schedule_send_active_backup(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                       int *send_idx, int *target_idx)
{
    uint32_t min_active_count = MIN(bdp_comp->active_count, bdp_tjetty->active_count);

    for (uint32_t i = 0; i < min_active_count; i++) {
        uint32_t active_idx = bdp_comp->active_indices[i];
        if (!bdp_comp->valid[active_idx]) {
            continue;
        }

        *send_idx = (int)active_idx;
        *target_idx = (int)bdp_tjetty->active_indices[i];
        return 0;
    }

    return -1;
}

static int schedule_send_balance(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                 int *send_idx, int *target_idx)
{
    uint32_t min_active_count = MIN(bdp_comp->active_count, bdp_tjetty->active_count);
    int least_load_pos = -1;
    uint32_t least_load = UINT32_MAX;

    for (uint32_t i = 0; i < min_active_count; i++) {
        uint32_t active_idx = bdp_comp->active_indices[i];
        if (!bdp_comp->valid[active_idx]) {
            continue;
        }

        uint32_t sqe_cnt = bdp_comp->sqe_cnt[active_idx];
        if (sqe_cnt < least_load) {
            least_load = sqe_cnt;
            least_load_pos = (int)i;
        }
    }

    if (least_load_pos < 0) {
        return -1;
    }

    *send_idx = (int)bdp_comp->active_indices[least_load_pos];
    *target_idx = (int)bdp_tjetty->active_indices[least_load_pos];
    return 0;
}

static int schedule_recv_standalone(const bondp_comp_t *bdp_comp, int *recv_idx)
{
    *recv_idx = (int)bdp_comp->active_indices[0];
    return 0;
}

static int schedule_recv_balance(const bondp_comp_t *bdp_comp, int *recv_idx)
{
    int least_load_idx = -1;
    uint32_t least_load = UINT32_MAX;

    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t active_idx = bdp_comp->active_indices[i];
        uint32_t rqe_cnt = bdp_comp->rqe_cnt[active_idx];
        if (rqe_cnt < least_load) {
            least_load = rqe_cnt;
            least_load_idx = (int)active_idx;
        }
    }

    if (least_load_idx < 0) {
        return -1;
    }

    *recv_idx = least_load_idx;
    return 0;
}

int schedule_send(urma_target_jetty_t *tjetty, bondp_comp_t *bdp_comp, int *send_idx, int *target_idx)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Invalid wr->tjetty: NULL\n");
        return URMA_EINVAL;
    }

    if (bdp_comp->active_count == 0 || bdp_tjetty->active_count == 0) {
        URMA_LOG_ERR("No active port\n");
        return -1;
    }

    switch (bdp_comp->bondp_ctx->bonding_mode) {
        case BONDP_BONDING_MODE_STANDALONE:
            return schedule_send_standalone(bdp_comp, bdp_tjetty, send_idx, target_idx);
        case BONDP_BONDING_MODE_ACTIVE_BACKUP:
            return schedule_send_active_backup(bdp_comp, bdp_tjetty, send_idx, target_idx);
        case BONDP_BONDING_MODE_BALANCE:
            return schedule_send_balance(bdp_comp, bdp_tjetty, send_idx, target_idx);
        default:
            return -1;
    }
}

int schedule_recv(bondp_comp_t *bdp_comp, int *recv_idx)
{
    if (bdp_comp->active_count == 0) {
        URMA_LOG_ERR("No active port\n");
        return -1;
    }

    switch (bdp_comp->bondp_ctx->bonding_mode) {
        case BONDP_BONDING_MODE_STANDALONE:
            return schedule_recv_standalone(bdp_comp, recv_idx);
        case BONDP_BONDING_MODE_ACTIVE_BACKUP:
        case BONDP_BONDING_MODE_BALANCE:
            return schedule_recv_balance(bdp_comp, recv_idx);
        default:
            return -1;
    }
}
