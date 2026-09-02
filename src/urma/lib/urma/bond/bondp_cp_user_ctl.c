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
    if (ctx == NULL || ctx->dev == NULL) {
        URMA_LOG_ERR("Invalid context or device\n");
        return -EINVAL;
    }

    if (enable) {
        URMA_LOG_WARN("MSN feature is disabled and cannot be enabled.\n");
        return -EOPNOTSUPP;
    }

    uint64_t cnt = (uint64_t)atomic_load(&ctx->ref.atomic_cnt);
    if (cnt > 1) {
        URMA_LOG_WARN("Context already in use, atomic_cnt=%lu, dev_name=%s.\n", cnt, ctx->dev->name);
        return URMA_EAGAIN;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bdp_ctx->msn_enable = false;  // enable is false here
    return 0;
}

static inline size_t bondp_calc_seg_ext_len(uint32_t peer_cnt)
{
    return sizeof(urma_bond_seg_ext_v0_t) + sizeof(bondp_seg_peer_ctx_t) * peer_cnt;
}

static inline void bondp_set_seg_peer_ctx_entry(urma_bond_seg_ext_v0_t *ext, uint32_t idx,
                                                const bondp_seg_peer_ctx_t *entry)
{
    size_t off = sizeof(bondp_seg_peer_ctx_t) * idx;
    /* Use sizeof(*ext) instead of ext->data: GCC -Wstringop-overflow treats data[0] as size 0. */
    (void)memcpy((uint8_t *)ext + sizeof(*ext) + off, entry, sizeof(*entry));
}

static int bondp_fill_seg_ext_from_tseg(const bondp_tseg_t *bdp_tseg, urma_bond_seg_ext_v0_t *ext,
                                        size_t ext_len)
{
    if (bdp_tseg == NULL || bdp_tseg->bondp_ctx == NULL || ext == NULL) {
        return -EINVAL;
    }

    uint32_t peer_cnt = 0;
    uint32_t v_uasid = bdp_tseg->v_tseg.seg.ubva.uasid;
    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        urma_target_seg_t *p_tseg = bdp_tseg->p_tseg[local_idx];
        if (p_tseg == NULL) {
            continue;
        }
        if (p_tseg->seg.ubva.uasid != v_uasid) {
            URMA_LOG_ERR("pseg uasid mismatch, idx=%u, p_uasid=%u, v_uasid=%u.\n",
                         local_idx, p_tseg->seg.ubva.uasid, v_uasid);
            return -EINVAL;
        }
        ++peer_cnt;
    }
    if (ext_len < bondp_calc_seg_ext_len(peer_cnt)) {
        URMA_LOG_ERR("Invalid compact seg ext len=%zu, peer_cnt=%u.\n", ext_len, peer_cnt);
        return -EINVAL;
    }

    ext->version = 0;
    ext->mask = 0;
    ext->peer_cnt = peer_cnt;

    uint32_t n = 0;
    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        urma_target_seg_t *p_tseg = bdp_tseg->p_tseg[local_idx];
        if (p_tseg == NULL) {
            continue;
        }
        bondp_seg_peer_ctx_t entry = {0};
        entry.peer_idx = (uint8_t)local_idx;
        entry.eid = p_tseg->seg.ubva.eid;
        entry.token_id = p_tseg->seg.token_id;
        bondp_set_seg_peer_ctx_entry(ext, n, &entry);
        ++n;
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

    uint32_t peer_cnt = 0;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_tseg->p_tseg[i] != NULL) {
            ++peer_cnt;
        }
    }
    size_t ext_len = bondp_calc_seg_ext_len(peer_cnt);

    urma_seg_t *new_seg = (urma_seg_t *)calloc(1, sizeof(urma_seg_t) +
                                                      sizeof(bondp_seg_ext_priv_t) +
                                                      ext_len);
    if (new_seg == NULL) {
        URMA_LOG_ERR("Failed to alloc seg.\n");
        return -ENOMEM;
    }

    bondp_seg_set_user_info(new_seg, true);
    bondp_seg_ext_priv_t *seg_ext = bondp_seg_get_priv_ext(new_seg);
    seg_ext->len = (uint32_t)ext_len;
    urma_bond_seg_ext_v0_t *ext = (urma_bond_seg_ext_v0_t *)seg_ext->data;
    int ret = bondp_fill_seg_ext_from_tseg(bdp_tseg, ext, ext_len);
    if (ret != 0) {
        free(new_seg);
        return ret;
    }

    urma_seg_t **out_seg = (urma_seg_t **)(uintptr_t)out->addr;
    *out_seg = new_seg;
    return 0;
}

typedef urma_user_info_ext_hdr_t bondp_user_tseg_ext_priv_t;

static inline size_t bondp_calc_user_tseg_ext_len(uint32_t peer_cnt)
{
    return sizeof(urma_bond_user_tseg_ext_v0_t) + sizeof(bondp_user_tseg_peer_ctx_t) * peer_cnt;
}

static inline bondp_user_tseg_ext_priv_t *bondp_user_tseg_get_priv_ext(urma_user_tseg_t *user_tseg)
{
    return (bondp_user_tseg_ext_priv_t *)((uintptr_t)user_tseg + sizeof(*user_tseg));
}

static inline void bondp_set_user_tseg_peer_ctx_entry(urma_bond_user_tseg_ext_v0_t *ext, uint32_t idx,
                                                      const bondp_user_tseg_peer_ctx_t *entry)
{
    size_t off = sizeof(bondp_user_tseg_peer_ctx_t) * idx;
    /* Use sizeof(*ext) instead of ext->data: GCC -Wstringop-overflow treats data[0] as size 0. */
    (void)memcpy((uint8_t *)ext + sizeof(*ext) + off, entry, sizeof(*entry));
}

static int bondp_fill_user_tseg_ext_from_tseg(const bondp_tseg_t *bdp_tseg,
                                              urma_bond_user_tseg_ext_v0_t *ext, size_t ext_len)
{
    if (bdp_tseg == NULL || ext == NULL) {
        return -EINVAL;
    }

    uint32_t peer_cnt = 0;
    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        if (bdp_tseg->p_tseg[local_idx] != NULL) {
            ++peer_cnt;
        }
    }
    if (ext_len < bondp_calc_user_tseg_ext_len(peer_cnt)) {
        URMA_LOG_ERR("Invalid compact user tseg ext len=%zu, peer_cnt=%u.\n", ext_len, peer_cnt);
        return -EINVAL;
    }

    ext->version = 0;
    ext->mask = 0;
    ext->peer_cnt = peer_cnt;

    uint32_t n = 0;
    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        urma_target_seg_t *p_tseg = bdp_tseg->p_tseg[local_idx];
        if (p_tseg == NULL) {
            continue;
        }
        bondp_user_tseg_peer_ctx_t entry = {0};
        entry.peer_idx = (uint8_t)local_idx;
        entry.token_id = p_tseg->seg.token_id;
        bondp_set_user_tseg_peer_ctx_entry(ext, n, &entry);
        ++n;
    }
    return 0;
}

static int bondp_user_ctl_get_user_tseg(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                        urma_user_ctl_out_t *out)
{
    if (in == NULL || out == NULL || in->addr == 0 || in->len < sizeof(urma_target_seg_t) ||
        out->addr == 0 || out->len < sizeof(urma_user_tseg_t *)) {
        URMA_LOG_ERR("Invalid parameter for get user tseg.\n");
        return -EINVAL;
    }

    urma_target_seg_t *tseg = (urma_target_seg_t *)(uintptr_t)in->addr;
    if (tseg == NULL || tseg->urma_ctx != ctx) {
        URMA_LOG_ERR("Invalid target seg context for get user tseg.\n");
        return -EINVAL;
    }
    /* Only locally registered segs expose per-slave token ids. */
    if (tseg->token_id == NULL) {
        URMA_LOG_ERR("Imported seg does not support get user tseg.\n");
        return -EINVAL;
    }

    bondp_tseg_t *bdp_tseg = CONTAINER_OF_FIELD(tseg, bondp_tseg_t, v_tseg);

    uint32_t peer_cnt = 0;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_tseg->p_tseg[i] != NULL) {
            ++peer_cnt;
        }
    }
    size_t ext_len = bondp_calc_user_tseg_ext_len(peer_cnt);

    urma_user_tseg_t *new_ut = (urma_user_tseg_t *)calloc(1, sizeof(urma_user_tseg_t) +
                                                                sizeof(bondp_user_tseg_ext_priv_t) +
                                                                ext_len);
    if (new_ut == NULL) {
        URMA_LOG_ERR("Failed to alloc user tseg.\n");
        return -ENOMEM;
    }

    /* The core overwrites the outer attr/token_id/token_value fields afterwards;
     * only the has_user_info bit must survive that overwrite. */
    new_ut->attr.bs.has_user_info = 1;
    bondp_user_tseg_ext_priv_t *ut_ext = bondp_user_tseg_get_priv_ext(new_ut);
    ut_ext->len = (uint32_t)ext_len;
    urma_bond_user_tseg_ext_v0_t *ext = (urma_bond_user_tseg_ext_v0_t *)ut_ext->data;
    int ret = bondp_fill_user_tseg_ext_from_tseg(bdp_tseg, ext, ext_len);
    if (ret != 0) {
        free(new_ut);
        return ret;
    }

    urma_user_tseg_t **out_ut = (urma_user_tseg_t **)(uintptr_t)out->addr;
    *out_ut = new_ut;
    return 0;
}

static int bondp_user_ctl_set_bonding_port(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                           urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(bondp_set_bonding_port_in_t)) {
        URMA_LOG_ERR("Invalid set bonding port param.\n");
        return -EINVAL;
    }

    bondp_set_bonding_port_in_t *port_in = (bondp_set_bonding_port_in_t *)(uintptr_t)in->addr;
    if (port_in->port_ids == NULL || port_in->port_count == 0 ||
        port_in->port_count > URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid bonding port config, port_count=%u.\n", port_in->port_count);
        return -EINVAL;
    }

    /* this user_ctl opcode may config after urma_ctx used, so do not check ctx atomic_cnt */
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    uint32_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM] = {0};
    uint32_t enabled_count = 0;
    for (uint32_t i = 0; i < port_in->port_count; ++i) {
        uint8_t port_idx = port_in->port_ids[i].port_idx;
        if (port_idx != UINT8_MAX &&
            (port_idx < URMA_ACTIVE_PORT_MIN || port_idx > URMA_ACTIVE_PORT_MAX)) {
            URMA_LOG_ERR("Invalid bonding port_idx=%u at index=%u.\n", port_idx, i);
            return -EINVAL;
        }
        uint32_t active_index = 0;
        if (convert_bond_port_id_to_active_index(bdp_ctx, port_in->port_ids[i], &active_index) != 0) {
            URMA_LOG_ERR("Invalid bonding port_id at index=%u, value=0x%lx.\n",
                         i, port_in->port_ids[i].value);
            return -EINVAL;
        }
        bool is_duplicate = false;
        for (uint32_t j = 0; j < enabled_count; ++j) {
            if (enabled_indices[j] == active_index) {
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) {
            continue;
        }
        enabled_indices[enabled_count] = active_index;
        enabled_count++;
    }
    if (enabled_count == 0) {
        URMA_LOG_ERR("No valid bonding port after conversion.\n");
        return -EINVAL;
    }

    bdp_ctx->port_cfg.chip_id_count = port_in->port_count;
    for (uint32_t i = 0; i < port_in->port_count; ++i) {
        bdp_ctx->port_cfg.chip_id[i] = port_in->port_ids[i].chip_id;
    }

    bdp_ctx->port_cfg.enabled_count = enabled_count;
    (void)memcpy(bdp_ctx->port_cfg.enabled_indices, enabled_indices,
                 enabled_count * sizeof(uint32_t));
    bdp_ctx->port_cfg_enable = true;
    for (uint32_t i = 0; i < port_in->port_count; ++i) {
        URMA_LOG_INFO("Bonding port[%u]: chip_id=%u, port_id=%u.\n",
                      i, bdp_ctx->port_cfg.chip_id[i], port_in->port_ids[i].port_idx);
    }
    for (uint32_t i = 0; i < enabled_count; ++i) {
        URMA_LOG_INFO("Bonding enabled[%u]: enabled_index=%u.\n", i, enabled_indices[i]);
    }
    return 0;
}

static int bondp_user_ctl_set_ctx_cfg(urma_context_t *ctx, urma_user_ctl_in_t *in,
                                      urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(bondp_set_ctx_cfg_in_t)) {
        URMA_LOG_ERR("Invalid set context configuration parameter.\n");
        return -EINVAL;
    }

    const bondp_set_ctx_cfg_in_t *cfg_in =
        (const bondp_set_ctx_cfg_in_t *)(uintptr_t)in->addr;
    return bondp_set_ctx_cfg(ctx, cfg_in);
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
        case BONDP_USER_CTL_OPCODE_GET_USER_TSEG:
            return bondp_user_ctl_get_user_tseg(ctx, in, out);
        case BONDP_USER_CTL_SET_BONDING_PORT:
            return bondp_user_ctl_set_bonding_port(ctx, in, out);
        case BONDP_USER_CTL_SET_CTX_CFG:
            return bondp_user_ctl_set_ctx_cfg(ctx, in, out);
        default: {
            URMA_LOG_ERR("Unsupported opcode, opcode=%d\n", in->opcode);
            return -EINVAL;
        }
    }
    return 0;
}
