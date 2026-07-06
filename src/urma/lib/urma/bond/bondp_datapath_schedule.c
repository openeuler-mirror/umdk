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

static urma_transport_mode_t get_comp_urma_trans_mode(const bondp_comp_t *bdp_comp)
{
    switch (bdp_comp->comp_type) {
        case BONDP_COMP_JFS:
            return bdp_comp->v_jfs.jfs_cfg.trans_mode;
        case BONDP_COMP_JETTY:
            return bdp_comp->v_jetty.jetty_cfg.jfs_cfg.trans_mode;
        case BONDP_COMP_JFR:
            return bdp_comp->v_jfr.jfr_cfg.trans_mode;
        default:
            return URMA_TM_RM;
    }
}

static uint32_t select_path_by_priority(const bondp_comp_t *bdp_comp,
                                        const bondp_target_jetty_t *bdp_tjetty,
                                        const bondp_chip_id_info_t *chip_pri,
                                        bondp_path_t *path)
{
    uint32_t local_idx = 0;
    uint32_t target_idx = 0;
    for (int i = 0; i < CHIP_ROUTE_NUM; i++) {
        local_idx = chip_pri[i].src_chip_id - BONDP_CHIP_ID_MIN;
        if (!atomic_load(&bdp_comp->valid[local_idx])) {
            continue;
        }
        target_idx = chip_pri[i].dst_chip_id - BONDP_CHIP_ID_MIN;
        if (!atomic_load(&bdp_tjetty->valid[target_idx]) ||
            bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
            continue;
        }
        if (get_comp_urma_trans_mode(bdp_comp) == URMA_TM_RC && bdp_comp->comp_type == BONDP_COMP_JETTY &&
            bdp_comp->p_jetty[local_idx]->remote_jetty != bdp_tjetty->p_tjetty[local_idx][target_idx]) {
            continue;
        }
        path->local_idx = local_idx;
        path->target_idx = target_idx;
        path->least_load = atomic_load(&bdp_comp->sqe_cnt[local_idx][target_idx]);
        return URMA_SUCCESS;
    }
    return URMA_FAIL;
}

static uint32_t select_path_by_chip(const bondp_comp_t *bdp_comp,
                                    const bondp_target_jetty_t *bdp_tjetty,
                                    const bondp_chip_id_info_t *info,
                                    uint32_t route_id,
                                    bondp_path_t *path)
{
    uint32_t src_chip_id = info->src_chip_id - 1;
    uint32_t dst_chip_id = info->dst_chip_id - 1;
    uint32_t path_idx = 0;
    uint32_t local_idx = 0;
    uint32_t target_idx = 0;

    // printf("src_chip_id=%u, dst_chip_id=%u\n", info->src_chip_id, info->dst_chip_id);
    const uint32_t *failover_route =
        g_bondp_global_ctx->failover_route[src_chip_id][dst_chip_id][route_id];
    for (int i = 0 ; i < URMA_FAILOVER_LINK_NUM; i++) {
        path_idx = failover_route[i];
        if (path_idx > IODIE_NUM * IODIE_NUM * URMA_ACTIVE_PORT_PER_DIE + 1) {
            break;
        }
        local_idx = g_bondp_global_ctx->path[path_idx].local_idx;
        if (!atomic_load(&bdp_comp->valid[local_idx])) {
            continue;
        }
        target_idx = g_bondp_global_ctx->path[path_idx].target_idx;
        if (!atomic_load(&bdp_tjetty->valid[target_idx]) ||
            bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
            continue;
        }
        if (get_comp_urma_trans_mode(bdp_comp) == URMA_TM_RC && bdp_comp->comp_type == BONDP_COMP_JETTY &&
            bdp_comp->p_jetty[local_idx]->remote_jetty != bdp_tjetty->p_tjetty[local_idx][target_idx]) {
            continue;
        }
        path->local_idx = local_idx;
        path->target_idx = target_idx;
        path->least_load = atomic_load(&bdp_comp->sqe_cnt[local_idx][target_idx]);
        return URMA_SUCCESS;
    }
    return URMA_FAIL;
}

static uint32_t select_least_load_path(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                       uint32_t min_idx[], uint32_t max_idx[], bondp_path_t least_load_path[],
                                       uint32_t *least_load_cnt)
{
    uint32_t least_load = UINT32_MAX;
    uint32_t valid_route = 0;
    urma_transport_mode_t trans_mode = get_comp_urma_trans_mode(bdp_comp);

    if (*least_load_cnt != 0) {
        least_load = least_load_path[0].least_load;
    }

    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t local_idx = bdp_comp->active_indices[i];
        if (!atomic_load(&bdp_comp->valid[local_idx]) || local_idx < min_idx[0] || local_idx >= max_idx[0]) {
            continue;
        }
        for (uint32_t j = 0; j < bdp_tjetty->active_count; j++) {
            uint32_t target_idx = bdp_tjetty->active_indices[j];
            if (!atomic_load(&bdp_tjetty->valid[target_idx]) || target_idx < min_idx[1] || target_idx >= max_idx[1] ||
                bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
                continue;
            }
            if (trans_mode == URMA_TM_RC && bdp_comp->comp_type == BONDP_COMP_JETTY &&
                bdp_comp->p_jetty[local_idx]->remote_jetty != bdp_tjetty->p_tjetty[local_idx][target_idx]) {
                continue;
            }
            uint32_t sqe_cnt = atomic_load(&bdp_comp->sqe_cnt[local_idx][target_idx]);
            if (sqe_cnt < least_load) {
                least_load = sqe_cnt;
                least_load_path[0].least_load = least_load;
                least_load_path[0].local_idx = local_idx;
                least_load_path[0].target_idx = target_idx;
                *least_load_cnt = 1;
                valid_route++;
            } else if (sqe_cnt == least_load) {
                least_load_path[(*least_load_cnt)].least_load = least_load;
                least_load_path[(*least_load_cnt)].local_idx = local_idx;
                least_load_path[(*least_load_cnt)].target_idx = target_idx;
                (*least_load_cnt)++;
                valid_route++;
            }
        }
    }
    return valid_route;
}

static __thread struct random_data schedule_rand_data;
static __thread char schedule_rand_state[32] = {0};
static __thread bool schedule_rand_inited = false;

static uint32_t select_random_path(uint32_t candidate_cnt)
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
    selected_pos = (uint32_t)rand_val % candidate_cnt;
    return selected_pos;
}

static int schedule_send_standalone(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                    int *send_idx, int *target_idx)
{
    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t loc_idx = bdp_comp->active_indices[i];
        if (!atomic_load(&bdp_comp->valid[loc_idx])) {
            continue;
        }
        for (uint32_t j = 0; j < bdp_tjetty->active_count; j++) {
            uint32_t tar_idx = bdp_tjetty->active_indices[j];
            if (!atomic_load(&bdp_tjetty->valid[tar_idx]) || bdp_tjetty->p_tjetty[loc_idx][tar_idx] == NULL) {
                continue;
            }
            *send_idx = (int)loc_idx;
            *target_idx = (int)tar_idx;
            return 0;
        }
    }
    return -1;
}

static int schedule_send_active_backup(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                       int *send_idx, int *target_idx)
{
    bool target_used[URMA_UBAGG_DEV_MAX_NUM] = {0};

    // active_backup mode only use 4 paths
    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t loc_idx = bdp_comp->active_indices[i];
        for (uint32_t j = 0; j < bdp_tjetty->active_count; j++) {
            uint32_t tar_idx = bdp_tjetty->active_indices[j];
            if (!atomic_load(&bdp_tjetty->valid[tar_idx]) ||
                bdp_tjetty->p_tjetty[loc_idx][tar_idx] == NULL ||
                target_used[tar_idx]) {
                continue;
            }
            if (atomic_load(&bdp_comp->valid[loc_idx])) {
                *send_idx = (int)loc_idx;
                *target_idx = (int)tar_idx;
                return 0;
            }
            target_used[tar_idx] = true;
            break;
        }
    }

    return -1;
}

static inline uint32_t switch_iodie(uint32_t iodie_num)
{
    return iodie_num == BONDP_CHIP_ID_MIN ? BONDP_CHIP_ID_MAX : BONDP_CHIP_ID_MIN;
}

static void init_chip_priority(bondp_chip_id_info_t chip_priority[], const bondp_chip_id_info_t *info)
{
    uint32_t src_id = info->src_chip_id;
    uint32_t dst_id = info->dst_chip_id;

    chip_priority[0] = *info;

    chip_priority[1].src_chip_id = src_id;
    chip_priority[1].dst_chip_id = switch_iodie(dst_id);

    chip_priority[CHIP_ROUTE_NUM - 1].src_chip_id = switch_iodie(src_id);
    chip_priority[CHIP_ROUTE_NUM - 1].dst_chip_id = dst_id;
}

static uint32_t select_affinity_path(
    const bondp_comp_t *bdp_comp,
    const bondp_target_jetty_t *bdp_tjetty,
    const bondp_chip_id_info_t *info,
    bondp_path_t least_load_path[],
    int *send_idx)
{
    bondp_chip_id_info_t chip_priority[CHIP_ROUTE_NUM];
    uint32_t least_load_cnt = 0;

    if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_IODIE) {
        init_chip_priority(chip_priority, info);
        if (select_path_by_priority(bdp_comp, bdp_tjetty, chip_priority,
                                    &least_load_path[least_load_cnt]) == URMA_SUCCESS) {
            least_load_cnt++;
        }
    } else if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
        for (int i = 0; i < ACTIVE_PORT_PER_CHIP; i++) {
            if (*send_idx >= 0 && *send_idx != URMA_ACTIVE_PORT_MIN + i) {
                continue;
            }
            if (select_path_by_chip(bdp_comp, bdp_tjetty, info,
                                    i, &least_load_path[least_load_cnt]) == URMA_SUCCESS) {
                least_load_cnt++;
            }
        }
    }
    return least_load_cnt;
}

static int schedule_send_balance(const bondp_comp_t *bdp_comp, const bondp_target_jetty_t *bdp_tjetty,
                                 int *send_idx, int *target_idx, const bondp_chip_id_info_t *info)
{
    uint32_t min_active_count = MIN(bdp_comp->active_count, bdp_tjetty->active_count);
    bondp_path_t least_load_path[URMA_UBAGG_MAX_CONNECTION] = {{0, 0}};
    uint32_t least_load_cnt = 0;
    uint32_t min[2] = {0};
    uint32_t max[2] = {0};

    if (min_active_count == 0) {
        URMA_LOG_ERR("Invalid min_active_count.\n");
        return URMA_EINVAL;
    }

    if (info != NULL) {
        least_load_cnt = select_affinity_path(bdp_comp, bdp_tjetty, info,
                                              least_load_path, send_idx);
        if (least_load_cnt == 0 && !g_bondp_global_ctx->enable_failover) {
            return URMA_FAIL;
        }
    }

    if (least_load_cnt == 0) {
        if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_IODIE) {
            min[0] = min[1] = 0;
            max[0] = max[1] = IODIE_NUM;
        } else if (bdp_comp->bondp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
            min[0] = min[1] = IODIE_NUM;
            max[0] = max[1] = URMA_UBAGG_DEV_MAX_NUM;
        } else {
            URMA_LOG_ERR("Unsupported bonding level=%d.\n", bdp_comp->bondp_ctx->bonding_level);
            return URMA_EINVAL;
        }
        select_least_load_path(bdp_comp, bdp_tjetty, min, max, least_load_path, &least_load_cnt);
    }

    if (least_load_cnt == 0) {
        return URMA_FAIL;
    }

    uint32_t selected_pos = select_random_path(least_load_cnt);
    *send_idx = least_load_path[selected_pos].local_idx;
    *target_idx = least_load_path[selected_pos].target_idx;
    return 0;
}

static int schedule_recv_standalone(const bondp_comp_t *bdp_comp, int *recv_idx)
{
    if (bdp_comp->comp_type != BONDP_COMP_JETTY || bdp_comp->v_jetty.remote_jetty == NULL) {
        *recv_idx = (int)bdp_comp->active_indices[0];
        return 0;
    }

    const bondp_target_jetty_t *bdp_tjetty =
        CONTAINER_OF_FIELD(bdp_comp->v_jetty.remote_jetty, bondp_target_jetty_t, v_tjetty);

    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t loc_idx = bdp_comp->active_indices[i];
        if (!atomic_load(&bdp_comp->valid[loc_idx])) {
            continue;
        }
        for (uint32_t j = 0; j < bdp_tjetty->active_count; j++) {
            uint32_t tar_idx = bdp_tjetty->active_indices[j];
            if (!atomic_load(&bdp_tjetty->valid[tar_idx]) || bdp_tjetty->p_tjetty[loc_idx][tar_idx] == NULL) {
                continue;
            }
            *recv_idx = (int)loc_idx;
            return 0;
        }
    }
    return -1;
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

int schedule_recv_n(bondp_comp_t *bdp_comp, uint32_t wr_num, uint32_t recv_wr_cnt[URMA_UBAGG_DEV_MAX_NUM])
{
    uint32_t current_load[URMA_UBAGG_DEV_MAX_NUM] = {0};

    if (recv_wr_cnt == NULL) {
        URMA_LOG_ERR("Invalid recv_wr_cnt: NULL\n");
        return URMA_EINVAL;
    }

    if (bdp_comp->active_count == 0) {
        URMA_LOG_ERR("No active port\n");
        return -1;
    }
    uint32_t *rqe_cnt;
    if (bdp_comp->comp_type == BONDP_COMP_JETTY && bdp_comp->v_jetty.jetty_cfg.shared.jfr != NULL) {
        bondp_comp_t *jfr = CONTAINER_OF_FIELD(bdp_comp->v_jetty.jetty_cfg.shared.jfr, bondp_comp_t, v_jfr);
        rqe_cnt = jfr->rqe_cnt;
    } else {
        rqe_cnt = bdp_comp->rqe_cnt;
    }

    (void)memset(recv_wr_cnt, 0, sizeof(uint32_t) * URMA_UBAGG_DEV_MAX_NUM);
    if (wr_num == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t active_idx = bdp_comp->active_indices[i];
        current_load[active_idx] = rqe_cnt[active_idx];
    }

    for (uint32_t wr_idx = 0; wr_idx < wr_num; wr_idx++) {
        int least_load_idx = -1;
        uint32_t least_load = UINT32_MAX;

        for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
            uint32_t active_idx = bdp_comp->active_indices[i];
            if (current_load[active_idx] < least_load) {
                least_load = current_load[active_idx];
                least_load_idx = (int)active_idx;
            }
        }

        if (least_load_idx < 0) {
            return -1;
        }

        recv_wr_cnt[least_load_idx]++;
        current_load[least_load_idx]++;
    }

    return 0;
}
