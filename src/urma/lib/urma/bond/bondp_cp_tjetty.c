/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider control-plane target jetty implementation
 * Create: 2026-07-21
 * Note:
 * History: 2026-07-21  Create file
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "ub_util.h"
#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_log.h"

#include "bondp_dp_health.h"
#include "bondp_topo_info.h"
#include "bondp_types.h"
#include "urma_ubagg.h"

#include "bondp_cp_tjetty.h"

typedef struct bondp_import_vobj_udata_in {
    uint32_t ue_idx;
} bondp_import_vobj_udata_in_t;

static inline size_t bondp_calc_rjetty_ext_len(uint32_t local_ctx_cnt, uint32_t target_ctx_cnt)
{
    return sizeof(urma_bond_jetty_ext_v0_t) +
           sizeof(uint8_t) * local_ctx_cnt +
           sizeof(bondp_rjetty_target_ctx_t) * target_ctx_cnt;
}

static inline uint8_t *bondp_rjetty_ext_v0_local_indices(urma_bond_jetty_ext_v0_t *ext)
{
    return (uint8_t *)ext->data;
}

static inline const uint8_t *bondp_rjetty_ext_v0_local_indices_const(const urma_bond_jetty_ext_v0_t *ext)
{
    return (const uint8_t *)ext->data;
}

static inline uint8_t *bondp_rjetty_ext_v0_target_ctx_bytes(urma_bond_jetty_ext_v0_t *ext)
{
    return bondp_rjetty_ext_v0_local_indices(ext) + ext->local_ctx_cnt;
}

static inline const uint8_t *bondp_rjetty_ext_v0_target_ctx_bytes_const(const urma_bond_jetty_ext_v0_t *ext)
{
    return bondp_rjetty_ext_v0_local_indices_const(ext) + ext->local_ctx_cnt;
}

static inline void bondp_set_rjetty_target_ctx_entry(urma_bond_jetty_ext_v0_t *ext, uint32_t idx,
                                                     const bondp_rjetty_target_ctx_t *entry)
{
    size_t off = sizeof(bondp_rjetty_target_ctx_t) * idx;
    (void)memcpy(bondp_rjetty_ext_v0_target_ctx_bytes(ext) + off, entry, sizeof(*entry));
}

static inline void bondp_get_rjetty_target_ctx_entry(const urma_bond_jetty_ext_v0_t *ext, uint32_t idx,
                                                     bondp_rjetty_target_ctx_t *entry)
{
    size_t off = sizeof(bondp_rjetty_target_ctx_t) * idx;
    (void)memcpy(entry, bondp_rjetty_ext_v0_target_ctx_bytes_const(ext) + off, sizeof(*entry));
}

static int bondp_fill_compact_rjetty_ext(const bondp_context_t *bdp_ctx, const bondp_comp_t *bdp_jetty,
                                         urma_bond_jetty_ext_v0_t *ext, size_t ext_len)
{
    if (bdp_ctx->enabled_count > URMA_UBAGG_DEV_MAX_NUM || bdp_jetty->enabled_count > URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid context count, local=%u, target=%u.\n",
                     bdp_ctx->enabled_count, bdp_jetty->enabled_count);
        return -EINVAL;
    }

    ext->version = BONDP_RJETTY_EXT_VERSION_V0;
    ext->mask = BONDP_RJETTY_EXT_MASK_MULTI_PATH | BONDP_RJETTY_EXT_MASK_LOCAL_CTX |
                BONDP_RJETTY_EXT_MASK_TARGET_CTX;
    ext->is_multipath = bdp_ctx->msn_enable;
    ext->is_health_check_enable = false;
    ext->local_ctx_cnt = bdp_ctx->enabled_count;
    ext->target_ctx_cnt = bdp_jetty->enabled_count;
    if (ext_len < bondp_calc_rjetty_ext_len(ext->local_ctx_cnt, ext->target_ctx_cnt)) {
        URMA_LOG_ERR("Invalid compact ext len=%zu.\n", ext_len);
        return -EINVAL;
    }

    uint8_t *local_indices = bondp_rjetty_ext_v0_local_indices(ext);
    for (uint32_t i = 0; i < ext->local_ctx_cnt; ++i) {
        local_indices[i] = (uint8_t)bdp_ctx->enabled_indices[i];
    }

    urma_bond_seg_info_out_t health_info = {0};
    bool health_enabled = false;
    if (bondp_hc_fill_seg_info(bdp_ctx, &health_info, &health_enabled) != 0) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ext->target_ctx_cnt; ++i) {
        uint32_t target_idx = bdp_jetty->enabled_indices[i];
        bondp_rjetty_target_ctx_t entry = {0};
        entry.target_idx = (uint8_t)target_idx;
        if (target_idx < URMA_UBAGG_DEV_MAX_NUM && bdp_jetty->p_jetty[target_idx] != NULL) {
            entry.slave_id = bdp_jetty->p_jetty[target_idx]->jetty_id;
        }
        if (health_enabled && target_idx < URMA_UBAGG_DEV_MAX_NUM &&
            health_info.slaves[target_idx].len != 0) {
            entry.health_check_seg = health_info.slaves[target_idx];
            ext->is_health_check_enable = true;
        }
        bondp_set_rjetty_target_ctx_entry(ext, i, &entry);
    }
    if (ext->is_health_check_enable) {
        ext->mask |= BONDP_RJETTY_EXT_MASK_HEALTH_CHECK;
    }

    return 0;
}

int bondp_get_rjetty(urma_context_t *ctx, urma_user_ctl_in_t *in,
                     urma_user_ctl_out_t *out)
{
    if (in == NULL || out == NULL || in->addr == 0 ||
        in->len < sizeof(urma_jetty_t) || out->addr == 0 ||
        out->len < sizeof(urma_rjetty_t *)) {
        URMA_LOG_ERR("Invalid parameter for get rjetty.\n");
        return -EINVAL;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    urma_jetty_t *jetty = (urma_jetty_t *)(uintptr_t)in->addr;
    if (jetty == NULL || jetty->urma_ctx != ctx) {
        URMA_LOG_ERR("Invalid jetty context for get rjetty.\n");
        return -EINVAL;
    }

    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    if (bdp_jetty->bondp_ctx != bdp_ctx) {
        URMA_LOG_ERR("Jetty does not belong to current context.\n");
        return -EINVAL;
    }

    uint32_t local_ctx_cnt = bdp_ctx->enabled_count;
    uint32_t target_ctx_cnt = bdp_jetty->enabled_count;
    size_t ext_len = bondp_calc_rjetty_ext_len(local_ctx_cnt, target_ctx_cnt);

    urma_rjetty_t *new_rjetty = (urma_rjetty_t *)calloc(1, sizeof(urma_rjetty_t) +
                                                               sizeof(bondp_rjetty_ext_priv_t) + ext_len);
    if (new_rjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc rjetty.\n");
        return -ENOMEM;
    }

    new_rjetty->flag.bs.has_user_info = 1;
    bondp_rjetty_ext_priv_t *ext_hdr = bondp_rjetty_get_priv_ext(new_rjetty);
    ext_hdr->len = (uint32_t)ext_len;
    urma_bond_jetty_ext_v0_t *ext = (urma_bond_jetty_ext_v0_t *)ext_hdr->data;
    int ret = bondp_fill_compact_rjetty_ext(bdp_ctx, bdp_jetty, ext, ext_len);
    if (ret != 0) {
        free(new_rjetty);
        return ret;
    }

    urma_rjetty_t **out_rjetty = (urma_rjetty_t **)(uintptr_t)out->addr;
    *out_rjetty = new_rjetty;
    return 0;
}

static int init_target_active_indices(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
                                      urma_bond_id_info_out_t *rvjetty_info)
{
    uint32_t active_count = 0;

    /* loop rvjetty first to make target idx ordered */
    for (uint32_t m = 0; m < rvjetty_info->enabled_count; ++m) {
        uint32_t target_indice = rvjetty_info->enabled_indices[m];
        for (uint32_t n = 0; n < bdp_ctx->enabled_count; ++n) {
            uint32_t local_indice = bdp_ctx->enabled_indices[n];
            if (rvjetty_info->connected[local_indice][target_indice]) {
                bdp_tjetty->active_indices[active_count] = target_indice;
                bdp_tjetty->local_active_indices[active_count] = local_indice;
                active_count += 1;
                break;
            }
        }
    }

    if (active_count == 0) {
        URMA_LOG_ERR("Failed to find connected port.\n");
        return -1;
    }
    bdp_tjetty->active_count = active_count;
    bdp_tjetty->local_dev_num = (int)active_count;
    bdp_tjetty->target_dev_num = (int)active_count;
    return 0;
}

static int bondp_fill_bond_id_info_from_compact_ext(const urma_bond_jetty_ext_v0_t *ext, uint32_t ext_len,
                                                    urma_bond_id_info_out_t *info)
{
    uint32_t known_mask = BONDP_RJETTY_EXT_MASK_MULTI_PATH |
                          BONDP_RJETTY_EXT_MASK_HEALTH_CHECK |
                          BONDP_RJETTY_EXT_MASK_LOCAL_CTX |
                          BONDP_RJETTY_EXT_MASK_TARGET_CTX;
    if ((ext->mask & (~(uint64_t)known_mask)) != 0) {
        URMA_LOG_DEBUG("Unknown rjetty ext mask bits=0x%lx, ignore them.\n",
                       ext->mask & (~(uint64_t)known_mask));
    }

    uint32_t local_ctx_cnt = (ext->mask & BONDP_RJETTY_EXT_MASK_LOCAL_CTX) ? ext->local_ctx_cnt : 0;
    uint32_t target_ctx_cnt = (ext->mask & BONDP_RJETTY_EXT_MASK_TARGET_CTX) ? ext->target_ctx_cnt : 0;
    (void)memset(info->connected, 0, sizeof(info->connected));

    if (local_ctx_cnt > URMA_UBAGG_DEV_MAX_NUM || target_ctx_cnt > URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid compact ext count, local=%u target=%u.\n", local_ctx_cnt, target_ctx_cnt);
        return -EINVAL;
    }

    size_t required = bondp_calc_rjetty_ext_len(local_ctx_cnt, target_ctx_cnt);
    if (ext_len < required) {
        URMA_LOG_ERR("Invalid compact ext len=%u, required=%zu.\n", ext_len, required);
        return -EINVAL;
    }

    info->is_msn_enabled = ((ext->mask & BONDP_RJETTY_EXT_MASK_MULTI_PATH) != 0) ? ext->is_multipath : false;
    info->is_health_check_enable =
        ((ext->mask & BONDP_RJETTY_EXT_MASK_HEALTH_CHECK) != 0) ? ext->is_health_check_enable : false;

    for (uint32_t i = 0; i < target_ctx_cnt; ++i) {
        bondp_rjetty_target_ctx_t entry = {0};
        bondp_get_rjetty_target_ctx_entry(ext, i, &entry);
        uint32_t target_idx = entry.target_idx;
        if (target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
            URMA_LOG_ERR("Invalid target idx=%u.\n", target_idx);
            return -EINVAL;
        }
        info->enabled_indices[info->enabled_count++] = (uint8_t)target_idx;
        info->slave_id[target_idx] = entry.slave_id;
        if (info->is_health_check_enable) {
            info->health_check_seg.slaves[target_idx] = entry.health_check_seg;
        }
    }

    return 0;
}

static int bondp_fill_bond_id_info_from_rjetty_ext(const urma_rjetty_t *rjetty, urma_bond_id_info_out_t *info)
{
    if (!bondp_rjetty_has_user_info(rjetty)) {
        URMA_LOG_ERR("rjetty user_info ext is not enabled.\n");
        return -EINVAL;
    }
    const bondp_rjetty_ext_priv_t *ext_hdr = bondp_rjetty_get_priv_ext_const(rjetty);
    if (ext_hdr->len < sizeof(urma_bond_jetty_ext_v0_t)) {
        URMA_LOG_ERR("Invalid rjetty ext length=%u.\n", ext_hdr->len);
        return -EINVAL;
    }
    const urma_bond_jetty_ext_v0_t *compact_ext = (const urma_bond_jetty_ext_v0_t *)ext_hdr->data;
    if (compact_ext->version != BONDP_RJETTY_EXT_VERSION_V0) {
        URMA_LOG_DEBUG("rjetty ext version=%u, parse by mask only.\n", compact_ext->version);
    }
    return bondp_fill_bond_id_info_from_compact_ext(compact_ext, ext_hdr->len, info);
}

static int bondp_import_vjetty(
    urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *rjetty_token,
    bondp_target_jetty_t *bdp_tjetty, urma_bond_id_info_out_t *udata_out)
{
    urma_tjetty_cfg_t cfg = {
        .jetty_id = rjetty->jetty_id,
        .flag = rjetty->flag,
        .token = rjetty_token,
        .trans_mode = rjetty->trans_mode,
        .policy = rjetty->policy,
        .type = rjetty->type,
    };
    int ret = -1;

    for (uint32_t ue_idx = 0; ue_idx < IODIE_NUM; ++ue_idx) {
        bondp_import_vobj_udata_in_t udata_in = {
            .ue_idx = ue_idx,
        };
        urma_cmd_udrv_priv_t udata = {
            .in_addr = (uint64_t)&udata_in,
            .in_len = sizeof(udata_in),
            .out_addr = (uint64_t)udata_out,
            .out_len = sizeof(*udata_out),
        };

        ret = urma_cmd_import_jetty(ctx, &bdp_tjetty->v_tjetty, &cfg, &udata);
        if (ret == 0) {
            URMA_LOG_DEBUG("Imported vjetty successfully, jetty_id=%u\n", rjetty->jetty_id.id);
            return 0;
        }
    }

    URMA_LOG_ERR("Failed to import vjetty, jetty_id=%u, ret=%d\n", rjetty->jetty_id.id, ret);
    return ret;
}

static int bondp_import_pjetty(
    bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjetty_t *rjetty, urma_token_t *rjetty_token,
    urma_bond_id_info_out_t *rvjetty_info)
{
    urma_rjetty_t p_rjetty = *rjetty;
    p_rjetty.flag.bs.has_user_info = 0;

    for (uint32_t m = 0; m < rvjetty_info->enabled_count; ++m) {
        uint32_t target_idx = rvjetty_info->enabled_indices[m];
        p_rjetty.jetty_id = rvjetty_info->slave_id[target_idx];
        for (uint32_t n = 0; n < bdp_ctx->enabled_count; ++n) {
            uint32_t local_idx = bdp_ctx->enabled_indices[n];

            if (!rvjetty_info->connected[local_idx][target_idx]) {
                continue;
            }

            if (bdp_tjetty->p_tjetty[local_idx][target_idx] != NULL) {
                continue;
            }

            bdp_tjetty->p_tjetty[local_idx][target_idx] =
                urma_import_jetty(bdp_ctx->p_ctxs[local_idx], &p_rjetty, rjetty_token);
            if (bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
                URMA_LOG_ERR("Failed to import tjetty local_idx=%u, target_idx=%u, jetty_id=%u\n",
                             local_idx, target_idx, rvjetty_info->slave_id[target_idx].id);
                return -1;
            }
            atomic_store(&bdp_tjetty->valid[local_idx][target_idx], true);
        }
    }
    return 0;
}

static int bondp_unimport_vjetty(bondp_target_jetty_t *bdp_tjetty)
{
    unsigned long ref_cnt;

    ref_cnt = atomic_load(&(bdp_tjetty->use_cnt.atomic_cnt));
    URMA_LOG_INFO("bondp vjetty id is %u, v_jetty use_cnt before import is %lu.\n",
                  bdp_tjetty->v_tjetty.id.id, ref_cnt);
    return urma_cmd_unimport_jetty(&bdp_tjetty->v_tjetty);
}

static int bondp_unimport_pjetty(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;

    if (bondp_hc_unimport_tseg(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }

    memset(bdp_tjetty->valid, 0, sizeof(bdp_tjetty->valid));
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_tjetty[i][j] == NULL) {
                continue;
            }
            URMA_LOG_INFO("bondp unimport pjetty is done, jetty id is %u.\n",
                          bdp_tjetty->p_tjetty[i][j]->id.id);
            /* NULL the slot before freeing so concurrent readers (datapath
             * scheduling, health probe) observe NULL instead of a dangling
             * pointer once urma_unimport_jetty releases the object. */
            urma_target_jetty_t *p_tjetty = bdp_tjetty->p_tjetty[i][j];
            bdp_tjetty->p_tjetty[i][j] = NULL;
            if (urma_unimport_jetty(p_tjetty) != URMA_SUCCESS) {
                ret = URMA_FAIL;
            }
        }
    }

    URMA_LOG_INFO("Finish to unimport pjetty.\n");
    return ret;
}

static int bondp_rebuild_connected_by_topo(const urma_eid_t *dst_eid, urma_bond_id_info_out_t *info)
{
    bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM] = {0};
    if (dst_eid == NULL || info == NULL) {
        return -1;
    }
    if (bondp_topo_query_linked_port(dst_eid, connected) != 0) {
        return -1;
    }

    (void)memset(info->connected, 0, sizeof(info->connected));
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (i < TOPO_CONNECTED_MAX_NUM && j < TOPO_CONNECTED_MAX_NUM) {
                info->connected[i][j] = connected[i][j];
            }
        }
    }
    return 0;
}

urma_target_jetty_t *bondp_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value)
{
    if (rjetty == NULL) {
        URMA_LOG_ERR("Input rjetty is NULL\n");
        errno = EINVAL;
        return NULL;
    }

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    // disable cfg jetty
    bondp_comp_t *cfg_jetty = NULL;
    bondp_target_jetty_t *bdp_tjetty = calloc(1, sizeof(bondp_target_jetty_t));
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc target jetty\n");
        errno = ENOMEM;
        return NULL;
    }
    if (token_value != NULL) {
        bdp_tjetty->import_token_value = *token_value;
        bdp_tjetty->import_token_valid = true;
    }
    atomic_init(&bdp_tjetty->use_cnt.atomic_cnt, 1);

    urma_bond_id_info_out_t rvjetty_info = {0};
    if (rjetty->flag.bs.has_drv_ext) {
        const bondp_rjetty_t *bdp_rjetty = (const bondp_rjetty_t *)rjetty;
        if (bdp_rjetty->jetty != NULL) {
            cfg_jetty = CONTAINER_OF_FIELD(bdp_rjetty->jetty, bondp_comp_t, v_jetty);
        }
    }
    if (bondp_rjetty_has_user_info(rjetty)) {
        bdp_tjetty->skip_import_vjetty = true;
        if (bondp_fill_bond_id_info_from_rjetty_ext(rjetty, &rvjetty_info) != 0) {
            const bondp_rjetty_ext_priv_t *ext_hdr = bondp_rjetty_get_priv_ext_const(rjetty);
            URMA_LOG_ERR("Invalid rjetty ext, length=%u.\n", ext_hdr->len);
            goto FREE_TJETTY;
        }
        bdp_tjetty->v_tjetty.urma_ctx = ctx;
        bdp_tjetty->v_tjetty.id = rjetty->jetty_id;
        bdp_tjetty->v_tjetty.trans_mode = rjetty->trans_mode;
        bdp_tjetty->v_tjetty.type = rjetty->type;
        bdp_tjetty->v_tjetty.flag = rjetty->flag;
        bdp_tjetty->v_tjetty.policy = rjetty->policy;
        bdp_tjetty->v_tjetty.tp_type = rjetty->tp_type;
    } else {
        if (bondp_import_vjetty(ctx, rjetty, token_value, bdp_tjetty, &rvjetty_info) != 0) {
            URMA_LOG_ERR("Failed to import vjetty, [" EID_FMT "]=%u\n",
                         EID_ARGS(rjetty->jetty_id.eid), rjetty->jetty_id.id);
            goto FREE_TJETTY;
        }
    }

    if (bondp_rebuild_connected_by_topo(&rjetty->jetty_id.eid, &rvjetty_info) != 0) {
        URMA_LOG_ERR("Failed to rebuild connected matrix by topo.\n");
        goto UNIMPORT_VJETTY;
    }

    bdp_tjetty->is_msn_enabled = rvjetty_info.is_msn_enabled;

    if (init_target_active_indices(bdp_ctx, bdp_tjetty, &rvjetty_info) != 0) {
        URMA_LOG_ERR("Failed to init target active indices\n");
        goto UNIMPORT_VJETTY;
    }

    if (bondp_import_pjetty(bdp_ctx, bdp_tjetty, rjetty, token_value, &rvjetty_info) != 0) {
        URMA_LOG_ERR("Failed to import pjetty\n");
        goto UNIMPORT_PJETTY;
    }

    if (bondp_hc_import_tseg(bdp_ctx, bdp_tjetty, &rvjetty_info) != 0) {
        URMA_LOG_ERR("Failed to import health check seg for jetty\n");
        goto UNIMPORT_TSEG;
    }

    if (rjetty->trans_mode == URMA_TM_RM && rjetty->flag.bs.has_drv_ext && cfg_jetty != NULL) {
        cfg_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
    }

    if (bondp_hc_register_tjetty(bdp_ctx, bdp_tjetty) != 0) {
        URMA_LOG_ERR("Failed to register health check tjetty\n");
        goto UNIMPORT_TSEG;
    }

    URMA_LOG_DEBUG("Successfully imported target jetty=" URMA_JETTY_ID_FMT "\n",
                   URMA_JETTY_ID_ARGS(&rjetty->jetty_id));

    return &bdp_tjetty->v_tjetty;

UNIMPORT_TSEG:
    (void)bondp_hc_unimport_tseg(bdp_tjetty);

UNIMPORT_PJETTY:
    bondp_unimport_pjetty(bdp_tjetty);
UNIMPORT_VJETTY:
    if (!bdp_tjetty->skip_import_vjetty) {
        bondp_unimport_vjetty(bdp_tjetty);
    }
FREE_TJETTY:
    free(bdp_tjetty);
    return NULL;
}

static urma_status_t bondp_unimport_jetty_inner(urma_target_jetty_t *target_jetty)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jetty, bondp_target_jetty_t, v_tjetty);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(target_jetty->urma_ctx, bondp_context_t, v_ctx);
    urma_status_t ret = URMA_SUCCESS;

    bondp_hc_unregister_tjetty(bdp_ctx, bdp_tjetty);

    if (bondp_unimport_pjetty(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    if (!bdp_tjetty->skip_import_vjetty) {
        if (bondp_unimport_vjetty(bdp_tjetty) != URMA_SUCCESS) {
            ret = URMA_FAIL;
        }
    }
    free(bdp_tjetty);
    return ret;
}

static void bondp_put_remote_jetty(urma_target_jetty_t *target_jetty)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jetty, bondp_target_jetty_t, v_tjetty);
    if (atomic_fetch_sub(&bdp_tjetty->use_cnt.atomic_cnt, 1) == 1) {
        bondp_unimport_jetty_inner(target_jetty);
    }
}

urma_status_t bondp_unimport_jetty(urma_target_jetty_t *target_jetty)
{
    bondp_put_remote_jetty(target_jetty);
    return URMA_SUCCESS;
}

urma_status_t bondp_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    bool target_used[URMA_UBAGG_DEV_MAX_NUM] = {0};
    bool bind_done = false;

    if (jetty->remote_jetty) {
        URMA_LOG_ERR("Jetty already has a binded target jetty\n");
        return URMA_EINVAL;
    }

    if (bdp_jetty->active_count == 0 || bdp_tjetty->active_count == 0) {
        URMA_LOG_ERR("No valid active slice to bind\n");
        return URMA_FAIL;
    }

    for (uint32_t n = 0; n < bdp_jetty->active_count; ++n) {
        uint32_t local_idx = bdp_jetty->active_indices[n];
        urma_jetty_t *pjetty = bdp_jetty->p_jetty[local_idx];
        for (uint32_t m = 0; m < bdp_tjetty->active_count; ++m) {
            uint32_t target_idx = bdp_tjetty->active_indices[m];
            urma_target_jetty_t *ptjetty = bdp_tjetty->p_tjetty[local_idx][target_idx];
            if (ptjetty == NULL || target_used[target_idx]) {
                continue;
            }
            target_used[target_idx] = true;
            if (pjetty == NULL) {
                break;
            }
            if (urma_bind_jetty(pjetty, ptjetty) != 0) {
                goto UNBIND;
            }
            bind_done = true;
            URMA_LOG_DEBUG("Binded pjetty successfully, local_idx=%u, target_idx=%u, jetty_id=%u, tjetty_id=%u\n",
                           local_idx, target_idx, pjetty->jetty_id.id, ptjetty->id.id);
            break;
        }
    }

    if (!bind_done) {
        return URMA_FAIL;
    }

    bdp_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
    bondp_tjetty_get(&bdp_tjetty->v_tjetty);
    return URMA_SUCCESS;

UNBIND:
    for (uint32_t p = 0; p < URMA_UBAGG_DEV_MAX_NUM; ++p) {
        uint32_t local_idx = bdp_jetty->active_indices[p];
        if (bdp_jetty->p_jetty[local_idx] != NULL &&
            bdp_jetty->p_jetty[local_idx]->remote_jetty != NULL) {
            urma_unbind_jetty(bdp_jetty->p_jetty[local_idx]);
            bdp_jetty->p_jetty[local_idx]->remote_jetty = NULL;
        }
    }
    return URMA_FAIL;
}

urma_status_t bondp_unbind_jetty(urma_jetty_t *jetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_target_jetty_t *tjetty = jetty->remote_jetty;
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    urma_status_t ret = URMA_SUCCESS;

    for (uint32_t p = 0; p < URMA_UBAGG_DEV_MAX_NUM; ++p) {
        uint32_t local_idx = bdp_jetty->active_indices[p];
        if (bdp_jetty->p_jetty[local_idx] != NULL &&
            bdp_jetty->p_jetty[local_idx]->remote_jetty != NULL) {
            if (urma_unbind_jetty(bdp_jetty->p_jetty[local_idx]) != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unbind tjetty [%u](%d, %d)\n",
                             bdp_tjetty->v_tjetty.id.id, local_idx, local_idx);
                ret = URMA_FAIL;
                continue;
            }
            URMA_LOG_INFO("Unbinded pjetty successfully, local_idx=%u, jetty_id=%u, tjetty_id=%u\n",
                          local_idx, bdp_jetty->p_jetty[local_idx]->jetty_id.id, bdp_tjetty->v_tjetty.id.id);
            bdp_jetty->p_jetty[local_idx]->remote_jetty = NULL;
        }
    }
    if (ret == URMA_SUCCESS) {
        bdp_jetty->v_jetty.remote_jetty = NULL;
        bondp_tjetty_put(tjetty);
    }
    return ret;
}

static int bondp_import_vjfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value,
                             bondp_target_jetty_t *bdp_tjetty, urma_bond_id_info_out_t *udata_out)
{
    urma_tjfr_cfg_t cfg = {
        .jfr_id = rjfr->jfr_id,
        .flag = rjfr->flag,
        .token = token_value,
        .trans_mode = rjfr->trans_mode,
    };

    int ret = -1;

    for (uint32_t ue_idx = 0; ue_idx < IODIE_NUM; ++ue_idx) {
        bondp_import_vobj_udata_in_t udata_in = {
            .ue_idx = ue_idx,
        };
        urma_cmd_udrv_priv_t udata = {
            .in_addr = (uint64_t)&udata_in,
            .in_len = sizeof(udata_in),
            .out_addr = (uint64_t)udata_out,
            .out_len = sizeof(*udata_out),
        };

        ret = urma_cmd_import_jfr(ctx, &bdp_tjetty->v_tjetty, &cfg, &udata);
        if (ret == 0) {
            return 0;
        }
    }

    return ret;
}

static int bondp_import_pjfr(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
                             urma_rjfr_t *rjfr, urma_token_t *token_value, urma_bond_id_info_out_t *udata_out)
{
    urma_rjfr_t p_rjfr = *rjfr;

    for (uint32_t m = 0; m < udata_out->enabled_count; ++m) {
        uint32_t target_idx = udata_out->enabled_indices[m];
        p_rjfr.jfr_id = udata_out->slave_id[target_idx];
        for (uint32_t n = 0; n < bdp_ctx->enabled_count; ++n) {
            uint32_t local_idx = bdp_ctx->enabled_indices[n];

            if (!udata_out->connected[local_idx][target_idx]) {
                continue;
            }

            if (bdp_tjetty->p_tjetty[local_idx][target_idx] != NULL) {
                continue;
            }

            bdp_tjetty->p_tjetty[local_idx][target_idx] =
                urma_import_jfr(bdp_ctx->p_ctxs[local_idx], &p_rjfr, token_value);
            if (bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
                URMA_LOG_ERR("Failed to import tjetty loc_idx=%u, tar_idx=%u, jfr_id=%u\n",
                             local_idx, target_idx, udata_out->slave_id[target_idx].id);
                return -1;
            }
            atomic_store(&bdp_tjetty->valid[local_idx][target_idx], true);
        }
    }
    return 0;
}

static int bondp_unimport_vjfr(bondp_target_jetty_t *bdp_tjetty)
{
    return urma_cmd_unimport_jfr(&bdp_tjetty->v_tjetty);
}

static int bondp_unimport_pjfr(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;
    uint32_t tjetty_id = bdp_tjetty->v_tjetty.id.id;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_tjetty[i][j] == NULL) {
                continue;
            }
            uint32_t jfr_id = bdp_tjetty->p_tjetty[i][j]->id.id;
            int p_ret = urma_unimport_jfr(bdp_tjetty->p_tjetty[i][j]);
            if (p_ret != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unimport pjfr, tjetty_id=%u, idx=%d/%d, jfr_id=%u, ret=%d\n",
                             tjetty_id, i, j, jfr_id, p_ret);
                ret = URMA_FAIL;
            } else {
                URMA_LOG_INFO_RL("Unimported pjfr successfully, tjetty_id=%u, idx=%d/%d, jfr_id=%u\n",
                                 tjetty_id, i, j, jfr_id);
            }
        }
    }

    URMA_LOG_INFO("Unimported pjfr, tjetty_id=%u, ret=%d\n", tjetty_id, ret);
    return ret;
}

urma_target_jetty_t *bondp_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    bondp_target_jetty_t *bdp_tjetty = calloc(1, sizeof(bondp_target_jetty_t));
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc target jetty\n");
        return NULL;
    }
    atomic_init(&bdp_tjetty->use_cnt.atomic_cnt, 1);

    urma_bond_id_info_out_t udata_out = {0};
    if (bondp_import_vjfr(ctx, rjfr, token_value, bdp_tjetty, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vjetty, [" EID_FMT "]=%u\n",
                     EID_ARGS(rjfr->jfr_id.eid), rjfr->jfr_id.id);
        goto FREE_TJFR;
    }
    bdp_tjetty->is_msn_enabled = udata_out.is_msn_enabled;
    if (init_target_active_indices(bdp_ctx, bdp_tjetty, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to init target active indices\n");
        goto UNIMPORT_VJFR;
    }

    if (bondp_import_pjfr(bdp_ctx, bdp_tjetty, rjfr, token_value, &udata_out) != 0) {
        goto UNIMPORT_PJFR;
    }

    URMA_LOG_DEBUG("Imported jfr successfully, jfr_id=%u, dev=%s, eid_idx=%u\n",
                   rjfr->jfr_id.id, ctx->dev->name, ctx->eid_index);
    return &bdp_tjetty->v_tjetty;

UNIMPORT_PJFR:
    bondp_unimport_pjfr(bdp_tjetty);
UNIMPORT_VJFR:
    bondp_unimport_vjfr(bdp_tjetty);
FREE_TJFR:
    free(bdp_tjetty);
    return NULL;
}

static urma_status_t bondp_unimport_jfr_inner(urma_target_jetty_t *target_jfr)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jfr, bondp_target_jetty_t, v_tjetty);
    urma_status_t ret = URMA_SUCCESS;
    uint32_t tjetty_id = target_jfr->id.id;

    if (bondp_unimport_pjfr(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    if (bondp_unimport_vjfr(bdp_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport vjfr, tjetty_id=%u\n", tjetty_id);
        ret = URMA_FAIL;
    }
    free(bdp_tjetty);
    return ret;
}

static void bondp_put_remote_jfr(urma_target_jetty_t *target_jfr)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jfr, bondp_target_jetty_t, v_tjetty);
    if (atomic_fetch_sub(&bdp_tjetty->use_cnt.atomic_cnt, 1) == 1) {
        bondp_unimport_jfr_inner(target_jfr);
    }
}

urma_status_t bondp_unimport_jfr(urma_target_jetty_t *target_jfr)
{
    bondp_put_remote_jfr(target_jfr);
    return URMA_SUCCESS;
}

void bondp_tjetty_get(urma_target_jetty_t *target_jetty)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jetty, bondp_target_jetty_t, v_tjetty);
    atomic_fetch_add(&bdp_tjetty->use_cnt.atomic_cnt, 1);
}

void bondp_tjetty_put(urma_target_jetty_t *target_jetty)
{
    if (target_jetty->type == URMA_JFR) {
        bondp_put_remote_jfr(target_jetty);
    } else {
        bondp_put_remote_jetty(target_jetty);
    }
}
