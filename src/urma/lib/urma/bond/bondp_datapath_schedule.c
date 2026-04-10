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
#include "topo_info.h"
#include "urma_log.h"

#include "bondp_datapath_schedule.h"

/** Ignore idx_start, iterate the array from idx_start + 1.
 * This function returns idx_start if no other dev is valid.
 * This function returns -1 when all devs are invalid.
 */
int find_next_valid_jetty_idx(const bool *pjettys_valid, int dev_num, int idx_start)
{
    int ret = -1;
    for (int i = 0; i < dev_num; ++i) {
        if (pjettys_valid[(idx_start + i + 1) % dev_num]) {
            ret = (idx_start + i + 1) % dev_num;
            break;
        }
    }
    return ret;
}

static int __attribute__((unused)) get_send_idx_with_least_load(bjetty_ctx_t *bjetty_ctx)
{
    int least_load_idx = -1;
    uint32_t least_load = UINT32_MAX;
    uint32_t send_idx = 0;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        send_idx = (uint32_t)((i + bjetty_ctx->send_idx + 1) % URMA_UBAGG_DEV_MAX_NUM);
        if (bjetty_ctx->pjettys_valid[send_idx] == false) {
            continue;
        }
        uint32_t inflight_cnt = bjetty_ctx->inflight_cnt[send_idx];
        if (inflight_cnt < least_load) {
            least_load = inflight_cnt;
            least_load_idx = (int)send_idx;
        }
    }
    return least_load_idx;
}

/**
 * In matrix server, multipath mode has two different planes.
 * Each plane has one device which can connect to any other device identified by primary eid.
 * Choose target with RR and RQE requirement, then set send_idx = target_idx.
 * @param v_conn: can be NULL in single-die mode.
 */
static int schedule_next_route_in_matrix_server_multipath(const urma_jfs_wr_t *wr, bondp_target_jetty_t *bdp_tjetty,
                                                          bdp_v_conn_t *v_conn,
                                                          int *send_idx, int *target_idx)
{
    if (is_single_dev_mode(bdp_tjetty->v_tjetty.urma_ctx)) {
        *send_idx = 0;
        *target_idx = 0;
        return 0;
    }
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
            v_conn->rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid,
                                                        bdp_tjetty->target_dev_num, v_conn->rqe_idx);
            if (v_conn->rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->rqe_idx;
            break;
        default:
            v_conn->non_rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid,
                                                            bdp_tjetty->target_dev_num, v_conn->non_rqe_idx);
            if (v_conn->non_rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for non_rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->non_rqe_idx;
            break;
    }
    *send_idx = *target_idx;
    return 0;
}

static int schedule_next_route_in_matrix_server_singlepath(bjetty_ctx_t *bjetty_ctx, bondp_target_jetty_t *bdp_tjetty,
                                                           int *send_idx, int *target_idx)
{
    if (bjetty_ctx->direct_local_port == -1 || bjetty_ctx->direct_target_port == -1) {
        URMA_LOG_ERR("Invalid single path port. Single path mode only support RC and need to call bind_jetty\n");
        return -1;
    }
    *send_idx = bjetty_ctx->direct_local_port;
    *target_idx = bjetty_ctx->direct_target_port;
    return 0;
}

/**
 * @param v_conn: can be NULL in singledie mode
 * @param send_idx: output
 * @param target_idx: output
 */
int schedule_send(const urma_jfs_wr_t *wr, bjetty_ctx_t *bjetty_ctx, bdp_v_conn_t *v_conn,
                  int *send_idx, int *target_idx)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Invalid wr->tjetty: NULL\n");
        return URMA_EINVAL;
    }
    if (is_multipath_comp(bjetty_ctx->bdp_comp)) {
        return schedule_next_route_in_matrix_server_multipath(wr, bdp_tjetty, v_conn, send_idx, target_idx);
    }
    return schedule_next_route_in_matrix_server_singlepath(bjetty_ctx, bdp_tjetty, send_idx, target_idx);
}

/** Select recv pjetty in post_jetty_recv_wr */
static urma_status_t schedule_recv_idx_default(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    bjetty_ctx->post_recv_idx = find_next_valid_jetty_idx(bjetty_ctx->pjettys_valid, bjetty_ctx->bdp_comp->dev_num,
                                                          bjetty_ctx->post_recv_idx);
    if (bjetty_ctx->post_recv_idx < 0) {
        /* all pjetty fail */
        URMA_LOG_INFO("All pjetty fail in schedule_recv_idx_default.");
        return URMA_FAIL;
    }
    *recv_idx = bjetty_ctx->post_recv_idx;
    return URMA_SUCCESS;
}

static urma_status_t schedule_next_recv_port_matrix_multipath(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    if (is_single_dev_mode(&bjetty_ctx->bond_ctx->v_ctx)) {
        *recv_idx = 0;
        return URMA_SUCCESS;
    }
    return schedule_recv_idx_default(bjetty_ctx, recv_idx);
}

static urma_status_t schedule_next_recv_port_matrix_singlepath(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    if (bjetty_ctx->direct_local_port == -1 || bjetty_ctx->direct_target_port == -1) {
        URMA_LOG_ERR("Invalid single path port in recv."
                     "It is likely because `urma_post_jetty_recv` was called before `urma_bind_jetty`.\n");
        return URMA_EINVAL;
    }
    *recv_idx = bjetty_ctx->direct_local_port;
    return URMA_SUCCESS;
}

urma_status_t schedule_recv(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    /* JFR is set to multipath mode at default */
    /* Only JETTY can be single_path mode in schedule_recv */
    if (is_multipath_comp(bjetty_ctx->bdp_comp)) {
        return schedule_next_recv_port_matrix_multipath(bjetty_ctx, recv_idx);
    }
    return schedule_next_recv_port_matrix_singlepath(bjetty_ctx, recv_idx);
}
