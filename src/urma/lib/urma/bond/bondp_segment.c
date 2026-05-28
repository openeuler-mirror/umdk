/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider segment implementation
 * Author: Ma Chuan
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18
 */

#include <stdlib.h>

#include "ub_hash.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_provider.h"

#include "bondp_context_table.h"
#include "bondp_hash_table.h"
#include "bondp_types.h"

#include "bondp_segment.h"

typedef struct bondp_udata_import_seg {
    urma_seg_t peer_p_seg[URMA_UBAGG_DEV_MAX_NUM];
    bool connected[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
} bondp_udata_import_seg_t;

typedef struct bondp_import_vobj_udata_in {
    uint32_t ue_idx;
} bondp_import_vobj_udata_in_t;

typedef enum bondp_result {
    BONDP_SKIP = -2,
    BONDP_ERROR = -1,
    BONDP_SUCCESS = 0,
} bondp_ret_t;

typedef struct bondp_seg_cfg {
    urma_token_t *token;
    uint64_t addr;
    urma_import_seg_flag_t flag;
    bondp_udata_import_seg_t *udata_out;
    bondp_import_tseg_t *bdp_imprt_tseg;
} bondp_seg_cfg_t;

/*
 * Since the actual token ID for bonding device is allocated by the kernel mode
 * during segment registration, the function only returns an empty token ID to
 * make api useable
 */
urma_token_id_t *bondp_alloc_token_id(urma_context_t *ctx)
{
    urma_token_id_t *token = calloc(1, sizeof(urma_token_id_t));
    if (token == NULL) {
        return NULL;
    }
    token->urma_ctx = ctx;
    return token;
}

urma_status_t bondp_free_token_id(urma_token_id_t *token_id)
{
    free(token_id);
    return URMA_SUCCESS;
}

static int bondp_delete_pseg(bondp_tseg_t *bdp_seg)
{
    int ret = URMA_SUCCESS;

    for (int i = 0; i < bdp_seg->dev_num; ++i) {
        if (bdp_seg->p_tseg[i] == NULL) {
            continue;
        }
        URMA_LOG_INFO("bondp delete_pseg token_id is %u.\n",
            bdp_seg->p_tseg[i]->seg.token_id);
        bdp_seg->p_tseg[i]->handle = bdp_seg->p_orig_handle[i];
        if (urma_unregister_seg(bdp_seg->p_tseg[i]) != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to unregister pseg %d\n", i);
            ret = URMA_FAIL;
        }
        bdp_seg->p_tseg[i] = NULL;
    }

    return ret;
}

static int bondp_create_pseg(bondp_context_t *bdp_ctx, bondp_tseg_t *bdp_seg, urma_seg_cfg_t *seg_cfg)
{
    if ((void *)seg_cfg->va == NULL) {
        URMA_LOG_ERR("Invalid segment address for bondp seg\n");
        return -1;
    }

    urma_seg_cfg_t p_cfg = *seg_cfg;
    p_cfg.token_id = NULL;
    p_cfg.flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        urma_target_seg_t *p_tseg = urma_register_seg(bdp_ctx->p_ctxs[i], &p_cfg);
        if (p_tseg == NULL) {
            URMA_LOG_ERR("Failed to register pseg %d\n", i);
            goto DELETE_PSEG;
        }

        if (p_tseg->token_id == NULL) {
            p_tseg->token_id = seg_cfg->token_id;
        }
        bdp_seg->p_orig_handle[i] = p_tseg->handle;
        p_tseg->handle = (uint64_t)&bdp_seg->v_tseg;
        bdp_seg->p_tseg[i] = p_tseg;
    }

    return 0;

DELETE_PSEG:
    bondp_delete_pseg(bdp_seg);
    return -1;
}

static int bondp_delete_vseg(bondp_tseg_t *bdp_seg)
{
    unsigned long ref_cnt;

    if (bdp_seg == NULL) {
        URMA_LOG_ERR("invalid param.\n");
        return URMA_FAIL;
    }
    ref_cnt = atomic_load(&(bdp_seg->use_cnt.atomic_cnt));
    urma_target_seg_t *target_seg = &bdp_seg->v_tseg;
    target_seg->handle = bdp_seg->v_orig_handle;
    URMA_LOG_INFO("bondp delete_vseg, token_id is %u, bdp_seg use_cnt is %lu.\n",
            bdp_seg->v_tseg.seg.token_id, ref_cnt);

    if (urma_cmd_unregister_seg(target_seg) != 0) {
        URMA_LOG_ERR("Failed to unregister segment, token_id=%u, handle=%lu.\n",
                     target_seg->seg.token_id, target_seg->handle);
        return URMA_FAIL;
    }

    URMA_LOG_INFO("Successfully unregistered seg, handle=%lu.\n", target_seg->handle);
    return URMA_SUCCESS;
}

static int bondp_create_vseg(bondp_context_t *bdp_ctx, bondp_tseg_t *bdp_seg, urma_seg_cfg_t *seg_cfg)
{
    urma_bond_seg_info_out_t in_seg_info = {0};
    urma_cmd_udrv_priv_t udata = {0};
    urma_target_seg_t t_seg = {0};

    bdp_seg->v_tseg.seg.ubva.eid = bdp_ctx->v_ctx.eid;
    bdp_seg->v_tseg.seg.ubva.uasid = bdp_ctx->v_ctx.uasid;
    bdp_seg->v_tseg.seg.ubva.va = seg_cfg->va;
    bdp_seg->v_tseg.seg.len = seg_cfg->len;
    bdp_seg->v_tseg.seg.attr.value = seg_cfg->flag.value;
    bdp_seg->v_tseg.mva = seg_cfg->va;
    bdp_seg->v_tseg.urma_ctx = &bdp_ctx->v_ctx;
    bdp_seg->v_tseg.user_ctx = seg_cfg->user_ctx;
    bdp_seg->v_tseg.token_id = seg_cfg->token_id;

    in_seg_info.base = bdp_seg->v_tseg.seg;
    in_seg_info.dev_num = bdp_seg->dev_num;
    for (int i = 0; i < bdp_seg->dev_num; ++i) {
        if (bdp_seg->p_tseg[i] == NULL) {
            continue;
        }
        in_seg_info.slaves[i] = bdp_seg->p_tseg[i]->seg;
    }

    udata.in_addr = (uint64_t)&in_seg_info;
    udata.in_len = sizeof(urma_bond_seg_info_out_t);

    int ret = urma_cmd_register_seg(&bdp_ctx->v_ctx, &t_seg, seg_cfg, &udata);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to register vseg, ret=%d.\n", ret);
        return ret;
    }

    bdp_seg->v_tseg.seg.token_id = t_seg.seg.token_id;
    bdp_seg->v_orig_handle = t_seg.handle;
    bdp_seg->v_tseg.handle = (uint64_t)&bdp_seg->v_tseg;
    URMA_LOG_INFO("Successfully registered seg, handle=%lu.\n", t_seg.handle);

    return 0;
}

urma_target_seg_t *bondp_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (seg_cfg->token_id == NULL || seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID) {
        URMA_LOG_ERR("Invalid token id for register bondp seg\n");
        return NULL;
    }

    bondp_tseg_t *bdp_seg = (bondp_tseg_t *)calloc(1, sizeof(bondp_tseg_t));
    if (bdp_seg == NULL) {
        URMA_LOG_ERR("Failed to alloc bondp segment comp\n");
        return NULL;
    }

    bdp_seg->bondp_ctx = bdp_ctx;
    bdp_seg->dev_num = bdp_ctx->dev_num;
    atomic_init(&bdp_seg->use_cnt.atomic_cnt, 1);

    if (bondp_create_pseg(bdp_ctx, bdp_seg, seg_cfg) != 0) {
        URMA_LOG_ERR("Failed to create pseg\n");
        goto FREE_BDP_SEG;
    }

    if (bondp_create_vseg(bdp_ctx, bdp_seg, seg_cfg) != 0) {
        URMA_LOG_ERR("Failed to create vseg\n");
        goto DELETE_PSEG;
    }

    return &bdp_seg->v_tseg;

DELETE_PSEG:
    (void)bondp_delete_pseg(bdp_seg);
FREE_BDP_SEG:
    free(bdp_seg);
    return NULL;
}

static urma_status_t bondp_unregister_seg_inner(urma_target_seg_t *target_seg)
{
    int ret = URMA_SUCCESS;
    bondp_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_tseg_t, v_tseg);

    if (bondp_delete_vseg(bdp_seg) != 0) {
        URMA_LOG_ERR("Failed to delete vseg, token_id=%u, handle=%lu.\n",
                     target_seg->seg.token_id, target_seg->handle);
        ret = URMA_FAIL;
    }

    if (bondp_delete_pseg(bdp_seg) != 0) {
        URMA_LOG_ERR("Failed to delete pseg for vseg, token_id=%u, handle=%lu.\n",
                     target_seg->seg.token_id, target_seg->handle);
        ret = URMA_FAIL;
    }

    free(bdp_seg);
    return ret;
}

static void bondp_get_local_seg(urma_target_seg_t *target_seg)
{
    bondp_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_tseg_t, v_tseg);
    atomic_fetch_add(&bdp_seg->use_cnt.atomic_cnt, 1);
}

static void bondp_put_local_seg(urma_target_seg_t *target_seg)
{
    bondp_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_tseg_t, v_tseg);
    if (atomic_fetch_sub(&bdp_seg->use_cnt.atomic_cnt, 1) == 1) {
        bondp_unregister_seg_inner(target_seg);
    }
}

urma_status_t bondp_unregister_seg(urma_target_seg_t *target_seg)
{
    bondp_put_local_seg(target_seg);
    return URMA_SUCCESS;
}

static bondp_ret_t import_pseg(bondp_context_t *bdp_ctx, bondp_seg_cfg_t *seg_cfg,
                               int local_idx, int target_idx)
{
    urma_seg_t *peer_p_seg = &seg_cfg->udata_out->peer_p_seg[target_idx];
    urma_eid_t eid = peer_p_seg->ubva.eid;
    if (is_empty_eid(&eid)) {
        URMA_LOG_DEBUG("BONDP import p_seg has empty EID=%d\n", target_idx);
        return BONDP_SKIP;
    }
    urma_target_seg_t *p_tseg = urma_import_seg(bdp_ctx->p_ctxs[local_idx], peer_p_seg, seg_cfg->token,
                                                seg_cfg->addr, seg_cfg->flag);
    if (p_tseg == NULL) {
        URMA_LOG_ERR("Failed to import seg (%d, %d)\n", local_idx, target_idx);
        return BONDP_ERROR;
    }
    seg_cfg->bdp_imprt_tseg->p_orig_handle[local_idx][target_idx] = p_tseg->handle;
    p_tseg->handle = (uint64_t)(seg_cfg->bdp_imprt_tseg);
    seg_cfg->bdp_imprt_tseg->p_tseg[local_idx][target_idx] = p_tseg;

    URMA_LOG_DEBUG("Import seg [%d](" EID_FMT ")<-[%d](" EID_FMT ")\n",
                  local_idx, EID_ARGS(bdp_ctx->p_ctxs[local_idx]->eid),
                  target_idx, EID_ARGS(p_tseg->seg.ubva.eid));

    return BONDP_SUCCESS;
}

static int bondp_add_v2p_token_id(bondp_context_t *bdp_ctx, bondp_v2p_token_id_t *v2p_token_id)
{
    unsigned long token_id_cnt = atomic_load(&bdp_ctx->token_id_cnt);
    uint32_t target_idx = (uint32_t)(token_id_cnt % BONDP_MAX_NUM_RSEGS);
    bondp_hash_table_t *tbl = &bdp_ctx->remote_v2p_token_id_table;
    int ret;

    (void)pthread_rwlock_wrlock(&tbl->lock);
    if (token_id_cnt >= BONDP_MAX_NUM_RSEGS) {
        /* remove the token_id with target_idx */
        ret = bdp_r_v2p_token_id_del_idx_lockless(tbl, target_idx);
        if (ret != 0) {
            (void)pthread_rwlock_unlock(&tbl->lock);
            return ret;
        }
    }
    /* add new v2p_token_id */
    v2p_token_id->index = target_idx;
    ret = bdp_r_v2p_token_id_table_add_lockless(tbl, v2p_token_id);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return ret;
    }
    (void)pthread_rwlock_unlock(&tbl->lock);

    atomic_fetch_add(&bdp_ctx->token_id_cnt, 1);
    return 0;
}

static void bondp_fill_v_tseg(urma_target_seg_t *tseg, urma_seg_t *seg, uint64_t addr,
                              uint64_t handle, urma_context_t *ctx)
{
    tseg->seg.attr = seg->attr;
    tseg->seg.ubva = seg->ubva;
    tseg->seg.len = seg->len;
    tseg->seg.token_id = seg->token_id;
    tseg->mva = addr;
    tseg->handle = handle;
    tseg->urma_ctx = ctx;
}

static int bondp_import_vseg(urma_context_t *ctx, urma_seg_t *seg,
                             urma_token_t *token, uint64_t addr, urma_import_seg_flag_t flag,
                             bondp_import_tseg_t *bdp_tseg, bondp_udata_import_seg_t *udata_out)
{
    urma_import_tseg_cfg_t cfg = {
        .ubva = seg->ubva,
        .len = seg->len,
        .attr = seg->attr,
        .token_id = seg->token_id,
        .token = token,
        .flag = flag,
        .mva = addr,
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

        ret = urma_cmd_import_seg(ctx, &bdp_tseg->v_tseg, &cfg, &udata);
        if (ret == 0) {
            // Hacky
            bdp_tseg->v_orig_handle = bdp_tseg->v_tseg.handle;
            bdp_tseg->v_tseg.handle = (uint64_t)&bdp_tseg->v_tseg;
            return 0;
        }
    }

    return ret;
}

static int bondp_import_pseg(bondp_context_t *bdp_ctx, urma_seg_t *seg,
                             bondp_seg_cfg_t *bondp_seg_cfg)
{
    bool has_valid_route = false;
    int p_ctxs_valid_cnt = 0;
    int connected_cnt = 0;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        p_ctxs_valid_cnt++;
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; j++) {
            if (!bondp_seg_cfg->udata_out->connected[i][j]) {
                continue;
            }
            connected_cnt++;
            bondp_ret_t ret = import_pseg(bdp_ctx, bondp_seg_cfg, i, j);
            if (ret == BONDP_SKIP) {
                URMA_LOG_DEBUG("BONDP import_pseg skip, local=%d, target=%d\n", i, j);
                continue;
            } else if (ret == BONDP_ERROR) {
                URMA_LOG_INFO("BONDP import_pseg error, local=%d, target=%d\n", i, j);
                return -1;
            }
            has_valid_route = true;
        }
    }
    if (!has_valid_route) {
        URMA_LOG_ERR("No valid direct route, p_ctxs_valid=%d, connected_cnt=%d, dev_num=%d\n",
                     p_ctxs_valid_cnt, connected_cnt, bdp_ctx->dev_num);
        return -1;
    }
    return 0;
}

static int bondp_unimport_vseg(bondp_import_tseg_t *bdp_tseg)
{
    bdp_tseg->v_tseg.handle = bdp_tseg->v_orig_handle;
    return urma_cmd_unimport_seg(&bdp_tseg->v_tseg);
}

static int bondp_unimport_pseg(bondp_import_tseg_t *bdp_tseg)
{
    int ret = URMA_SUCCESS;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; j++) {
            if (bdp_tseg->p_tseg[i][j] == NULL) {
                continue;
            }
            bdp_tseg->p_tseg[i][j]->handle = bdp_tseg->p_orig_handle[i][j];
            if (urma_unimport_seg(bdp_tseg->p_tseg[i][j]) != URMA_SUCCESS) {
                ret = URMA_FAIL;
            }
            bdp_tseg->p_tseg[i][j] = NULL;
        }
    }
    return ret;
}

urma_target_seg_t *bondp_import_seg(urma_context_t *ctx, urma_seg_t *seg,
                                    urma_token_t *token, uint64_t addr, urma_import_seg_flag_t flag)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    int ret = 0;

    bondp_import_tseg_t *bdp_tseg = calloc(1, sizeof(bondp_import_tseg_t));
    if (bdp_tseg == NULL) {
        URMA_LOG_ERR("Failed to alloc target seg\n");
        errno = ENOMEM;
        return NULL;
    }
    bdp_tseg->local_dev_num = bdp_ctx->dev_num;
    bdp_tseg->target_dev_num = URMA_UBAGG_DEV_MAX_NUM;
    bdp_tseg->is_reused = false;
    atomic_init(&bdp_tseg->use_cnt.atomic_cnt, 1);

    bondp_udata_import_seg_t udata_out = {0};
    bool seg_cache_enable = bdp_ctx->seg_cache_enable;
    URMA_LOG_DEBUG("seg_cache_enable is %d.\n", seg_cache_enable);
    if (seg_cache_enable) {
        bondp_v2p_token_id_t v2p_token_id = {0};
        ret = bdp_r_v2p_token_id_tabl_lookup(&bdp_ctx->remote_v2p_token_id_table, seg->token_id,
                                                 seg->ubva.eid, &v2p_token_id);
        if (ret == 0) {
            (void)memcpy(&udata_out.peer_p_seg, v2p_token_id.peer_p_seg, sizeof(udata_out.peer_p_seg));
            (void)memcpy(&udata_out.connected, v2p_token_id.connected, sizeof(udata_out.connected));
            bdp_tseg->is_reused = true;
            bondp_fill_v_tseg(&bdp_tseg->v_tseg, seg, addr, v2p_token_id.v_handle, ctx);
            // Hacky
            bdp_tseg->v_orig_handle = bdp_tseg->v_tseg.handle;
            bdp_tseg->v_tseg.handle = (uint64_t)&bdp_tseg->v_tseg;
        } else if (ret != BONDP_HASH_MAP_NOT_FOUND_ERROR) {
            URMA_LOG_ERR("Failed to lookup v2p_token_id, ret=%d.\n", ret);
            free(bdp_tseg);
            return NULL;
        }
    }

    if (!bdp_tseg->is_reused) {
        ret = bondp_import_vseg(ctx, seg, token, addr, flag, bdp_tseg, &udata_out);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to import vseg\n");
            goto free_bdp_tseg;
        }
    }

    bondp_seg_cfg_t bondp_seg_cfg = {
        .token = token,
        .addr = addr,
        .flag = flag,
        .udata_out = &udata_out,
        .bdp_imprt_tseg = bdp_tseg,
    };
    if (bondp_import_pseg(bdp_ctx, seg, &bondp_seg_cfg) != 0) {
        URMA_LOG_ERR("Failed to import pseg\n");
        goto unimport_pseg;
    }

    if (seg_cache_enable && !bdp_tseg->is_reused) {
        bondp_v2p_token_id_t v2p_token_id = {0};
        v2p_token_id.key.v_remote_eid = seg->ubva.eid;
        v2p_token_id.key.v_token_id = seg->token_id;
        (void)memcpy(v2p_token_id.peer_p_seg, udata_out.peer_p_seg, sizeof(udata_out.peer_p_seg));
        (void)memcpy(v2p_token_id.connected, udata_out.connected, sizeof(udata_out.connected));
        v2p_token_id.v_handle = bdp_tseg->v_tseg.handle;
        ret = bondp_add_v2p_token_id(bdp_ctx, &v2p_token_id);
        if (ret != 0) {
            goto unimport_pseg;
        }
    }

    return &bdp_tseg->v_tseg;
unimport_pseg:
    bondp_unimport_pseg(bdp_tseg);
    if (!bdp_tseg->is_reused) {
        bondp_unimport_vseg(bdp_tseg);
    }
free_bdp_tseg:
    free(bdp_tseg);
    return NULL;
}

static urma_status_t bondp_unimport_seg_inner(urma_target_seg_t *target_seg)
{
    bondp_import_tseg_t *bdp_tseg = CONTAINER_OF_FIELD(target_seg, bondp_import_tseg_t, v_tseg);
    urma_status_t ret = URMA_SUCCESS;

    if (bondp_unimport_pseg(bdp_tseg) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    if (!bdp_tseg->is_reused) {
        if (bondp_unimport_vseg(bdp_tseg) != URMA_SUCCESS) {
            ret = URMA_FAIL;
        }
    }
    free(bdp_tseg);
    return ret;
}

static void bondp_get_remote_seg(urma_target_seg_t *target_seg)
{
    bondp_import_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_import_tseg_t, v_tseg);
    atomic_fetch_add(&bdp_seg->use_cnt.atomic_cnt, 1);
}

static void bondp_put_remote_seg(urma_target_seg_t *target_seg)
{
    bondp_import_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_import_tseg_t, v_tseg);
    if (atomic_fetch_sub(&bdp_seg->use_cnt.atomic_cnt, 1) == 1) {
        bondp_unimport_seg_inner(target_seg);
    }
}

urma_status_t bondp_unimport_seg(urma_target_seg_t *target_seg)
{
    bondp_put_remote_seg(target_seg);
    return URMA_SUCCESS;
}

void bondp_tseg_get(urma_target_seg_t *target_seg)
{
    if (target_seg->token_id != NULL) {
        bondp_get_local_seg(target_seg);
    } else {
        bondp_get_remote_seg(target_seg);
    }
}

void bondp_tseg_put(urma_target_seg_t *target_seg)
{
    if (target_seg->token_id != NULL) {
        bondp_put_local_seg(target_seg);
    } else {
        bondp_put_remote_seg(target_seg);
    }
}
