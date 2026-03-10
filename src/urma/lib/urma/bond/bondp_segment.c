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
#include "urma_api.h"
#include "urma_log.h"
#include "urma_provider.h"
#include "ub_hash.h"

#include "bondp_types.h"
#include "bondp_comp.h"
#include "bondp_context_table.h"
#include "bondp_hash_table.h"
#include "bondp_segment.h"

#define  SIMPLE_SEG_INFO_DEV_NUM      (2)
#define  TOKEN_ID_BIT_NUM             (16)

#define BDP_VA_VTSEG_INFO_HASH_BASIS (0x52989218)
#define BDP_VA_VTSEG_HASH_INFO_TABLE_SIZE (1024)

static bondp_hash_table_t g_va_vtseg_tbl;
static bool g_seg_cache_enable = false;

// key is va
typedef struct bdp_va_vtseg_info {
    hmap_node_t hmap_node;
    uint64_t va;
    urma_target_seg_t *vtseg;
} bdp_va_vtseg_info_t;

typedef struct bondp_udata_import_seg {
    urma_seg_t peer_p_seg[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t ports[IODIE_NUM][PORT_NUM];
} bondp_udata_import_seg_t;

typedef enum bondp_result {
    BONDP_SKIP    = -2,
    BONDP_ERROR   = -1,
    BONDP_SUCCESS = 0,
} bondp_ret_t;

typedef struct bondp_seg_cfg {
    urma_token_t *token;
    uint64_t addr;
    urma_import_seg_flag_t flag;
    bondp_udata_import_seg_t *udata_out;
    bondp_import_tseg_t *bdp_imprt_tseg;
}bondp_seg_cfg_t;

static bool is_same_eid(urma_eid_t *eid1, urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

bool comp_func_va_vtseg_tbl(hmap_node_t *node, void *key)
{
    bdp_va_vtseg_info_t *va_vtseg_info = CONTAINER_OF_FIELD(node, bdp_va_vtseg_info_t, hmap_node);
    return va_vtseg_info->va == *(uint64_t *)key;
}

static void free_func_va_vtseg_tbl(hmap_node_t *node)
{
    bdp_va_vtseg_info_t *va_vtseg_info = CONTAINER_OF_FIELD(node, bdp_va_vtseg_info_t, hmap_node);
    free(va_vtseg_info);
}

static uint32_t hash_func_va_vtseg_tbl(void *key)
{
    return ub_hash_bytes(key, sizeof(uint64_t), BDP_VA_VTSEG_INFO_HASH_BASIS);
}

static void __attribute__((constructor)) bondp_create_va_vtseg_tbl(void)
{
    int ret = 0;
    ret = bondp_hash_table_create(&g_va_vtseg_tbl, BDP_VA_VTSEG_HASH_INFO_TABLE_SIZE,
        comp_func_va_vtseg_tbl, free_func_va_vtseg_tbl, hash_func_va_vtseg_tbl);
    if (ret != 0) {
        printf("bondp_create_va_tseg_tbl fail.\n");
    }
}

static void __attribute__((destructor)) bondp_delete_va_vtseg_tbl(void)
{
    bondp_hash_table_destroy(&g_va_vtseg_tbl);
}

urma_target_seg_t *bondp_find_vtseg_by_va(uint64_t va)
{
    hmap_node_t *node = bondp_hash_table_lookup(&g_va_vtseg_tbl, &va,
        ub_hash_bytes(&va, sizeof(uint64_t), BDP_VA_VTSEG_INFO_HASH_BASIS));
    if (node == NULL) {
        URMA_LOG_ERR("bondp_hash_table_lookup fail.\n");
        return NULL;
    }

    bdp_va_vtseg_info_t *va_vtseg_info = CONTAINER_OF_FIELD(node, bdp_va_vtseg_info_t, hmap_node);
    return va_vtseg_info->vtseg;
}

urma_token_id_t *bondp_alloc_token_id(urma_context_t *ctx)
{
    urma_token_id_t *token = NULL;
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid bdp_ctx");
        return NULL;
    }

    token = calloc(1, sizeof(urma_token_id_t));
    if (token == NULL) {
        return NULL;
    }
    if (bondp_bitmap_alloc_idx(&bdp_ctx->token_id_bitmap, &token->token_id)) {
        URMA_LOG_ERR("Failed to alloc token id.\n");
        free(token);
        return NULL;
    }
    token->urma_ctx = ctx;
    return token;
}

urma_status_t bondp_free_token_id(urma_token_id_t *token_id)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(token_id->urma_ctx, bondp_context_t, v_ctx);

    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid bdp_ctx");
        return URMA_FAIL;
    }
    if (bondp_bitmap_free_idx(&bdp_ctx->token_id_bitmap, token_id->token_id)) {
        URMA_LOG_ERR("Failed to free idx, tid: %u.\n", token_id->token_id);
        return URMA_FAIL;
    }
    free(token_id);
    return URMA_SUCCESS;
}

urma_target_seg_t *bondp_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg)
{
    if (seg_cfg->token_id == NULL || seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID) {
        URMA_LOG_ERR("Invalid token id for register bondp seg\n");
        return NULL;
    }

    bondp_comp_t *bdp_comp = bondp_create_comp(ctx, BONDP_COMP_SEGMENT, seg_cfg);
    if (bdp_comp == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }

    // va --> vtarget_seg hash table
    bdp_va_vtseg_info_t *va_vtseg = calloc(1, sizeof(bdp_va_vtseg_info_t));
    if (va_vtseg == NULL) {
        (void)bondp_delete_comp(bdp_comp, BONDP_COMP_SEGMENT);
        return NULL;
    }
    va_vtseg->va = bdp_comp->v_tseg.seg.token_id;
    va_vtseg->vtseg = &bdp_comp->v_tseg;
    bondp_hash_table_add_with_hash(&g_va_vtseg_tbl, &va_vtseg->hmap_node,
        ub_hash_bytes(&va_vtseg->va, sizeof(uint64_t), BDP_VA_VTSEG_INFO_HASH_BASIS));

    return &bdp_comp->v_tseg;
}

urma_status_t bondp_unregister_seg(urma_target_seg_t *target_seg)
{
    target_seg->handle = ((bondp_comp_t *)target_seg)->v_orig_handle;
    return bondp_delete_comp(target_seg, BONDP_COMP_SEGMENT);
}

static bondp_ret_t import_p_tseg(bondp_context_t *bdp_ctx, bondp_seg_cfg_t *seg_cfg,
    int local_idx, int target_idx)
{
    if (bdp_ctx->p_ctxs[local_idx] == NULL) {
        URMA_LOG_INFO("BONDP import seg p_ctxs is NULL: %d\n", local_idx);
        return BONDP_SKIP;
    }
    urma_seg_t *peer_p_seg = &seg_cfg->udata_out->peer_p_seg[target_idx];
    urma_eid_t eid = peer_p_seg->ubva.eid;
    if (is_empty_eid(&eid)) {
        URMA_LOG_INFO("BONDP import p_seg has empty EID: %d\n", target_idx);
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

    URMA_LOG_INFO("Import seg [%d]("EID_FMT")<-[%d]("EID_FMT")\n",
            local_idx, EID_ARGS(bdp_ctx->p_ctxs[local_idx]->eid),
            target_idx, EID_ARGS(p_tseg->seg.ubva.eid));

    return BONDP_SUCCESS;
}
/**
 * Import primary segment to primary eids.
 * Only import the segment corresponding to the primary EID on the iodie.
 * The function is not responsible for rollback in case of failure.
 */
static bondp_ret_t import_matrix_primary_seg(bondp_context_t *bdp_ctx, bondp_seg_cfg_t *seg_cfg)
{
    bool has_success = false;
    int iodie_num = is_single_dev_mode(&bdp_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : IODIE_NUM;
    for (int iodie_idx = 0; iodie_idx < iodie_num; ++iodie_idx) {
        bondp_ret_t ret = import_p_tseg(bdp_ctx, seg_cfg, iodie_idx, iodie_idx);
        if (ret == BONDP_SKIP) {
            continue;
        } else if (ret == BONDP_ERROR) {
            return BONDP_ERROR;
        }
        has_success = true;
    }
    return has_success ? BONDP_SUCCESS : BONDP_ERROR;
}
/**
 * Import port eid in matrix server on a certain iodie.
 * In the matrix server scenario, for each port EID,
 * we need to locate the directly connected context and then proceed with the import,
 * ignoring other ports.
 * The function is not responsible for rollback in case of failure.
 * This is a full-mesh import segment on each iodie.
 */
static bondp_ret_t import_matrix_port_seg_on_iodie(bondp_context_t *bdp_ctx, bondp_seg_cfg_t *bondp_seg_cfg,
    int iodie_idx)
{
    for (int local_port_idx = 0; local_port_idx < PORT_EID_MAX_NUM_PER_DEV; ++local_port_idx) {
        for (int target_port_idx = 0; target_port_idx < PORT_EID_MAX_NUM_PER_DEV; ++target_port_idx) {
            int local_idx = get_matrix_port_p_idx(iodie_idx, local_port_idx);
            int target_idx = get_matrix_port_p_idx(iodie_idx, target_port_idx);
            bondp_ret_t ret = import_p_tseg(bdp_ctx, bondp_seg_cfg, local_idx, target_idx);
            if (ret == BONDP_SKIP) {
                continue;
            } else if (ret == BONDP_ERROR) {
                return BONDP_ERROR;
            }
        }
    }
    return BONDP_SUCCESS;
}

/**
* Obtain topology information via eid Direct connection paths,
* between local and remote devices in direct_dev_info_t.
* Perform import_seg based on direct connection path information
 */
static bondp_ret_t import_matrix_port_seg_by_direct_route(bondp_context_t *bdp_ctx,
    bondp_seg_cfg_t *bondp_seg_cfg, urma_eid_t eid)
{
    bool has_valid_route = false;

    for (int i = 0; i < IODIE_NUM; i++) {
        for (int j = 0; j < PORT_NUM; j++) {
            int local_port = IODIE_NUM + PORT_NUM * i + j;
            int target_port = IODIE_NUM + PORT_NUM * i + bondp_seg_cfg->udata_out->ports[i][j];

            if (local_port >= bdp_ctx->dev_num ||
                bdp_ctx->p_ctxs[local_port] == NULL) {
                URMA_LOG_DEBUG("BONDP skip route (%d %d)\n", local_port, target_port);
                continue;
            }
            bondp_ret_t ret = import_p_tseg(bdp_ctx, bondp_seg_cfg, local_port, target_port);
            if (ret == BONDP_SKIP) {
                continue;
            } else if (ret == BONDP_ERROR) {
                return -1;
            }
            has_valid_route = true;
        }
    }
    if (!has_valid_route) {
        URMA_LOG_ERR("No valid direct route\n");
        return -1;
    }
    return 0;
}

static bondp_ret_t import_matrix_port_seg_loopback(bondp_context_t *bdp_ctx,
    bondp_seg_cfg_t *bondp_seg_cfg)
{
    int success_import_num = 0;
    for (int i = IODIE_NUM; i < bdp_ctx->dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        bondp_ret_t ret = import_p_tseg(bdp_ctx, bondp_seg_cfg, i, i);
        if (ret != BONDP_SUCCESS) {
            continue;
        } else {
            success_import_num += 1;
            break;
        }
    }
    return (success_import_num > 0) ? BONDP_SUCCESS : BONDP_ERROR;
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

void bondp_toggle_seg_cache(bool enable)
{
    g_seg_cache_enable = enable;
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
    urma_cmd_udrv_priv_t udata = {
        .in_addr = 0,
        .in_len = 0,
        .out_addr = (uint64_t)udata_out,
        .out_len = sizeof(*udata_out),
    };

    int ret = urma_cmd_import_seg(ctx, &bdp_tseg->v_tseg, &cfg, &udata);
    // Hacky
    if (ret == 0) {
        bdp_tseg->v_orig_handle = bdp_tseg->v_tseg.handle;
        bdp_tseg->v_tseg.handle = (uint64_t)&bdp_tseg->v_tseg;
    }
    return ret;
}

static int bondp_import_pseg(bondp_context_t *bdp_ctx, urma_seg_t *seg,
                             bondp_seg_cfg_t *bondp_seg_cfg)
{
    bondp_ret_t ret;
    ret = import_matrix_primary_seg(bdp_ctx, bondp_seg_cfg);
    if (ret != BONDP_SUCCESS) {
        return -1;
    }

    urma_eid_t eid = seg->ubva.eid;
    if (is_empty_eid(&eid)) {
        URMA_LOG_WARN("Can't get direct route by seg->ubva.eid, it is empty. Import segment to all port eid.\n");
        int iodie_num = is_single_dev_mode(&bdp_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : IODIE_NUM;
        for (int iodie_idx = 0; iodie_idx < iodie_num; ++iodie_idx) {
            ret = import_matrix_port_seg_on_iodie(bdp_ctx, bondp_seg_cfg, iodie_idx);
            if (ret != BONDP_SUCCESS) {
                return -1;
            }
        }
        return 0;
    } else if (is_same_eid(&bdp_ctx->v_ctx.eid, &eid)) {
        URMA_LOG_INFO("Import segment to loopback.\n");
        ret = import_matrix_port_seg_loopback(bdp_ctx, bondp_seg_cfg);
        return ret == BONDP_SUCCESS ? 0 : -1;
    } else {
        URMA_LOG_INFO("Import segment by direct route.\n");
        ret = import_matrix_port_seg_by_direct_route(bdp_ctx, bondp_seg_cfg, eid);
        return ret == BONDP_SUCCESS ? 0 : -1;
    }
    return -1;
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

    bondp_import_tseg_t *bdp_tseg = calloc(1, sizeof(bondp_import_tseg_t));
    if (bdp_tseg == NULL) {
        URMA_LOG_ERR("Failed to alloc target seg\n");
        errno = ENOMEM;
        return NULL;
    }
    bdp_tseg->local_dev_num = bdp_ctx->dev_num;
    bdp_tseg->target_dev_num = URMA_UBAGG_DEV_MAX_NUM;
    bdp_tseg->is_reused = false;

    bondp_udata_import_seg_t udata_out = {0};
    if (g_seg_cache_enable) {
        bondp_v2p_token_id_t v2p_token_id = {0};
        int ret = bdp_r_v2p_token_id_tabl_lookup(&bdp_ctx->remote_v2p_token_id_table, seg->token_id,
                                                 seg->ubva.eid, &v2p_token_id);
        if (ret == 0) {
            (void)memcpy(&udata_out, v2p_token_id.peer_p_seg, sizeof(udata_out.peer_p_seg));
            bdp_tseg->is_reused = true;
            bondp_fill_v_tseg(&bdp_tseg->v_tseg, seg, addr, v2p_token_id.v_handle, ctx);
            // Hacky
            bdp_tseg->v_orig_handle = bdp_tseg->v_tseg.handle;
            bdp_tseg->v_tseg.handle = (uint64_t)&bdp_tseg->v_tseg;
        } else if (ret == BONDP_HASH_MAP_NOT_FOUND_ERROR) {
            if (bondp_import_vseg(ctx, seg, token, addr, flag, bdp_tseg, &udata_out) != 0) {
                URMA_LOG_ERR("Failed to import vseg\n");
                goto free_bdp_tseg;
            }
        } else {
            URMA_LOG_ERR("Failed to lookup v2p_token_id, ret: %d.\n", ret);
            free(bdp_tseg);
            return NULL;
        }
    }

    if (bondp_import_vseg(ctx, seg, token, addr, flag, bdp_tseg, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vseg\n");
        goto free_bdp_tseg;
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

    if (g_seg_cache_enable && !bdp_tseg->is_reused) {
        bondp_v2p_token_id_t v2p_token_id = {0};
        v2p_token_id.key.v_remote_eid = seg->ubva.eid;
        v2p_token_id.key.v_token_id = seg->token_id;
        (void)memcpy(v2p_token_id.peer_p_seg, udata_out.peer_p_seg, sizeof(udata_out.peer_p_seg));
        v2p_token_id.v_handle = bdp_tseg->v_tseg.handle;
        int ret = bondp_add_v2p_token_id(bdp_ctx, &v2p_token_id);
        if (ret != 0) {
            goto unimport_pseg;
        }
    }

    return &bdp_tseg->v_tseg;
unimport_pseg:
    bondp_unimport_pseg(bdp_tseg);
    bondp_unimport_vseg(bdp_tseg);
free_bdp_tseg:
    free(bdp_tseg);
    return NULL;
}

urma_status_t bondp_unimport_seg(urma_target_seg_t *target_seg)
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
