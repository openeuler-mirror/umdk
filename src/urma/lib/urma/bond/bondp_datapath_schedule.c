/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider datapath schedule implementation file
 * Author: Wang Hang
 * Create: 2026-04-06
 * Note:
 * History: 2026-04-06   Create File
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bondp_health_check.h"
#include "bondp_types.h"
#include "urma_log.h"

#include "bondp_datapath_schedule.h"

static void select_least_load_path(const bondp_comp_t *bdp_comp, uint32_t min_active_count,
                                   int min_idx, int max_idx, uint32_t *least_load_pos,
                                   uint32_t *least_load_cnt)
{
    uint32_t least_load = UINT32_MAX;

    *least_load_cnt = 0;
    for (uint32_t i = 0; i < min_active_count; i++) {
        uint32_t active_idx = bdp_comp->active_indices[i];
        if (!bdp_comp->valid[active_idx] || active_idx < (uint32_t)min_idx || active_idx > (uint32_t)max_idx) {
            continue;
        }

        uint32_t sqe_cnt = atomic_load(&bdp_comp->sqe_cnt[active_idx]);
        if (sqe_cnt < least_load) {
            least_load = sqe_cnt;
            least_load_pos[0] = i;
            *least_load_cnt = 1;
        } else if (sqe_cnt == least_load) {
            least_load_pos[(*least_load_cnt)++] = i;
        }
    }
}

static __thread struct random_data schedule_rand_data;
static __thread char schedule_rand_state[32] = {0};
static __thread bool schedule_rand_inited = false;

static uint32_t select_random_path(const uint32_t *candidate_pos, uint32_t candidate_cnt)
{
    uint32_t selected_pos;
    int32_t rand_val;

    if (!schedule_rand_inited) {
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid() ^
                            (unsigned int)(uintptr_t)pthread_self();
        (void)memset(&schedule_rand_data, 0, sizeof(schedule_rand_data));
        (void)initstate_r((unsigned int)seed, schedule_rand_state, sizeof(schedule_rand_state),
                          &schedule_rand_data);
        schedule_rand_inited = true;
    }

    (void)random_r(&schedule_rand_data, &rand_val);
    selected_pos = candidate_pos[(uint32_t)rand_val % candidate_cnt];
    return selected_pos;
}

static int schedule_send_standalone(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                    int *send_idx, int *target_idx)
{
    *send_idx = (int)bdp_tjetty->local_active_indices[0];
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
                                 int *send_idx, int *target_idx, bondp_chip_id_info_t *info)
{
    uint32_t min_active_count = MIN(bdp_comp->active_count, bdp_tjetty->active_count);
    uint32_t least_load_pos[URMA_UBAGG_DEV_MAX_NUM] = {0};
    uint32_t least_load_cnt = 0;
    bool enable_info_fallback = true;
    int min, max;

    if (min_active_count == 0) {
        URMA_LOG_ERR("Invalid min_active_count.\n");
        return URMA_EINVAL;
    }

    if (info != NULL && bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
        if (info->src_chip_id == BONDP_CHIP_ID_MIN) {
            min = BONDP_CHIP_ID_MIN_START_PORT;
            max = BONDP_CHIP_ID_MIN_END_PORT;
        } else {
            min = BONDP_CHIP_ID_MAX_START_PORT;
            max = BONDP_CHIP_ID_MAX_END_PORT;
        }
        select_least_load_path(bdp_comp, min_active_count, min, max, least_load_pos, &least_load_cnt);
        if (least_load_cnt == 0 && !enable_info_fallback) {
            return URMA_FAIL;
        }
    }

    if (least_load_cnt == 0) {
        if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_IODIE) {
            min = 0;
            max = IODIE_NUM - 1;
        } else if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
            min = IODIE_NUM;
            max = URMA_UBAGG_DEV_MAX_NUM - 1;
        } else {
            URMA_LOG_ERR("Unsupported bonding level=%d.\n", bdp_comp->bondp_ctx->bonding_level);
            return URMA_EINVAL;
        }
        select_least_load_path(bdp_comp, min_active_count, min, max, least_load_pos, &least_load_cnt);
    }

    if (least_load_cnt == 0) {
        return URMA_FAIL;
    }

    uint32_t selected_pos = select_random_path(least_load_pos, least_load_cnt);
    *send_idx = (int)bdp_comp->active_indices[selected_pos];
    *target_idx = (int)bdp_tjetty->active_indices[selected_pos];
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

int schedule_send(urma_target_jetty_t *tjetty, bondp_comp_t *bdp_comp, int *send_idx, int *target_idx,
                  bondp_chip_id_info_t *info)
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
            return schedule_send_balance(bdp_comp, bdp_tjetty, send_idx, target_idx, info);
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
