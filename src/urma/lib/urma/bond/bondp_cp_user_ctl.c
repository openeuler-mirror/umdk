/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider control-plane user control implementation
 * Create: 2026-07-22
 * Note:
 * History: 2026-07-22  Create file
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "ub_util.h"
#include "urma_log.h"

#include "bondp_cp_tjetty.h"
#include "bondp_provider_ops.h"
#include "bondp_types.h"
#include "urma_ubagg.h"

#include "bondp_cp_user_ctl.h"

static int bondp_user_ctl_set_bonding_mode_legacy(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                                  urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(urma_context_aggr_mode_t)) {
        URMA_LOG_ERR("Invalid set bonding mode legacy param.\n");
        return -EINVAL;
    }

    urma_context_aggr_mode_t aggr_mode = *(urma_context_aggr_mode_t *)(uintptr_t)in->addr;
    if (aggr_mode < URMA_AGGR_MODE_STANDALONE || aggr_mode > URMA_AGGR_MODE_BALANCE) {
        URMA_LOG_ERR("Invalid aggr mode=%d.\n", aggr_mode);
        return -EINVAL;
    }
    return bondp_set_bonding_mode(ctx, (bondp_bonding_mode_t)aggr_mode, BONDP_BONDING_LEVEL_IODIE);
}

static int bondp_user_ctl_set_bonding_mode(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                           urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(bondp_set_bonding_mode_in_t)) {
        URMA_LOG_ERR("Invalid set bonding mode param.\n");
        return -EINVAL;
    }

    bondp_set_bonding_mode_in_t *mode_in = (bondp_set_bonding_mode_in_t *)(uintptr_t)in->addr;
    return bondp_set_bonding_mode(ctx, mode_in->bonding_mode, mode_in->bonding_level);
}

static int bondp_user_ctl_query_port(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                     urma_user_ctl_out_t *out)
{
    if (in->addr == 0 || out->addr == 0 || in->len != sizeof(bondp_query_port_in_t) ||
        out->len < sizeof(bondp_query_port_out_t)) {
        URMA_LOG_ERR("Invalid query port param.\n");
        return -EINVAL;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bondp_query_port_in_t *query_in = (bondp_query_port_in_t *)(uintptr_t)in->addr;
    bondp_query_port_out_t *query_out = (bondp_query_port_out_t *)(uintptr_t)out->addr;
    if (query_in->jfr == NULL) {
        URMA_LOG_ERR("Invalid jfr.\n");
        return -EINVAL;
    }
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(query_in->jfr, bondp_comp_t, v_jfr);
    if (bdp_comp->bondp_ctx != bdp_ctx) {
        URMA_LOG_ERR("The object does not belong to current context.\n");
        return -EINVAL;
    }

    query_out->enabled_count = bdp_comp->enabled_count;
    query_out->active_count = bdp_comp->active_count;
    (void)memcpy(query_out->enabled_indices, bdp_comp->enabled_indices, sizeof(query_out->enabled_indices));
    (void)memcpy(query_out->active_indices, bdp_comp->active_indices, sizeof(query_out->active_indices));
    return 0;
}

static int bondp_user_ctl_get_jfce_fd_list(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                           urma_user_ctl_out_t *out)
{
    if (in->addr == 0 || out->addr == 0 || in->len != sizeof(bondp_get_jfce_fd_list_in_t) ||
        out->len < sizeof(bondp_get_jfce_fd_list_out_t)) {
        URMA_LOG_ERR("Invalid get jfce fd list param.\n");
        return -EINVAL;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bondp_get_jfce_fd_list_in_t *get_in = (bondp_get_jfce_fd_list_in_t *)(uintptr_t)in->addr;
    bondp_get_jfce_fd_list_out_t *get_out = (bondp_get_jfce_fd_list_out_t *)(uintptr_t)out->addr;

    if (get_in->jfce == NULL) {
        URMA_LOG_ERR("Invalid jfce.\n");
        return -EINVAL;
    }

    bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(get_in->jfce, bondp_jfce_t, v_jfce);
    if (bdp_jfce->bondp_ctx != bdp_ctx) {
        URMA_LOG_ERR("The object does not belong to current context.\n");
        return -EINVAL;
    }

    get_out->count = 0;
    for (int i = 0; i < bdp_jfce->dev_num && i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bdp_jfce->p_jfce[i] != NULL) {
            get_out->fd_list[get_out->count] = bdp_jfce->p_jfce[i]->fd;
            get_out->count++;
        }
    }
    for (uint32_t i = get_out->count; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        get_out->fd_list[i] = -1;
    }
    return 0;
}

static int bondp_toggle_seg_cache(urma_context_t *ctx, bool enable)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Urma context is NULL\n");
        return -EINVAL;
    }

    uint64_t cnt = (uint64_t)atomic_load(&ctx->ref.atomic_cnt);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (cnt > 1) {
        URMA_LOG_WARN("Context already in use, atomic_cnt=%lu, dev_name=%s.\n", cnt, ctx->dev->name);
        return URMA_EAGAIN;
    }
    bdp_ctx->seg_cache_enable = enable;
    return 0;
}

static int bondp_toggle_msn(urma_context_t *ctx, bool enable)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Urma context is NULL\n");
        return -EINVAL;
    }

    uint64_t cnt = (uint64_t)atomic_load(&ctx->ref.atomic_cnt);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (cnt > 1) {
        URMA_LOG_WARN("Context already in use, atomic_cnt=%lu, dev_name=%s.\n", cnt, ctx->dev->name);
        return URMA_EAGAIN;
    }
    bdp_ctx->msn_enable = enable;
    return 0;
}

static int bondp_fill_seg_ext_from_tseg(const bondp_tseg_t *bdp_tseg, urma_bond_seg_ext_t *ext)
{
    if (bdp_tseg == NULL || bdp_tseg->bondp_ctx == NULL) {
        return -EINVAL;
    }

    ext->version = 0;
    ext->mask = 0;
    (void)memset(ext->peer_p_seg, 0, sizeof(ext->peer_p_seg));

    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        urma_target_seg_t *p_tseg = bdp_tseg->p_tseg[local_idx];
        if (p_tseg == NULL) {
            continue;
        }
        bondp_seg_to_base(&p_tseg->seg, &ext->peer_p_seg[local_idx]);
    }
    return 0;
}

static int bondp_user_ctl_get_seg_ctx(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                      urma_user_ctl_out_t *out)
{
    if (in == NULL || out == NULL || in->addr == 0 || in->len < sizeof(urma_target_seg_t) ||
        out->addr == 0 || out->len < sizeof(urma_seg_t *)) {
        URMA_LOG_ERR("Invalid parameter for get seg ctx.\n");
        return -EINVAL;
    }

    urma_target_seg_t *tseg = (urma_target_seg_t *)(uintptr_t)in->addr;
    if (tseg == NULL || tseg->urma_ctx != ctx) {
        URMA_LOG_ERR("Invalid target seg context for get seg ctx.\n");
        return -EINVAL;
    }

    bondp_tseg_t *bdp_tseg = CONTAINER_OF_FIELD(tseg, bondp_tseg_t, v_tseg);

    urma_seg_t *new_seg = (urma_seg_t *)calloc(1, sizeof(urma_seg_t) +
                                                      sizeof(bondp_seg_ext_priv_t) +
                                                      sizeof(urma_bond_seg_ext_t));
    if (new_seg == NULL) {
        URMA_LOG_ERR("Failed to alloc seg.\n");
        return -ENOMEM;
    }

    bondp_seg_set_user_info(new_seg, true);
    bondp_seg_ext_priv_t *seg_ext = bondp_seg_get_priv_ext(new_seg);
    seg_ext->len = sizeof(urma_bond_seg_ext_t);
    urma_bond_seg_ext_t *ext = (urma_bond_seg_ext_t *)seg_ext->data;
    int ret = bondp_fill_seg_ext_from_tseg(bdp_tseg, ext);
    if (ret != 0) {
        free(new_seg);
        return ret;
    }

    urma_seg_t **out_seg = (urma_seg_t **)(uintptr_t)out->addr;
    *out_seg = new_seg;
    return 0;
}

int bondp_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    if (in == NULL) {
        URMA_LOG_ERR("Input parameter is NULL\n");
        return -EINVAL;
    }

    switch (in->opcode) {
        case BONDP_USER_CTL_SET_BONDING_MODE_LEGACY:
            return bondp_user_ctl_set_bonding_mode_legacy(ctx, in, out);
        case BONDP_USER_CTL_ENABLE_SEG_CACHE:
            return bondp_toggle_seg_cache(ctx, true);
        case BONDP_USER_CTL_QUERY_PORT:
            return bondp_user_ctl_query_port(ctx, in, out);
        case BONDP_USER_CTL_SET_BONDING_MODE:
            return bondp_user_ctl_set_bonding_mode(ctx, in, out);
        case BONDP_USER_CTL_GET_JFCE_FD_LIST:
            return bondp_user_ctl_get_jfce_fd_list(ctx, in, out);
        case BONDP_USER_CTL_DISABLE_MSN:
            return bondp_toggle_msn(ctx, false);
        case BONDP_USER_CTL_OPCODE_GET_RJETTY:
            return bondp_get_rjetty(ctx, in, out);
        case BONDP_USER_CTL_OPCODE_GET_SEG_CTX:
            return bondp_user_ctl_get_seg_ctx(ctx, in, out);
        default: {
            URMA_LOG_ERR("Unsupported opcode, opcode=%d\n", in->opcode);
            return -EINVAL;
        }
    }
    return 0;
}
