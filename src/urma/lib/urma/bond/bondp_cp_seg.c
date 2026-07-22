/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider segment implementation
 * Author: Ma Chuan
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_log.h"
#include "urma_private.h"

#include "bondp_topo_info.h"
#include "bondp_types.h"

#include "bondp_cp_seg.h"

typedef struct bondp_udata_import_seg {
    urma_seg_base_t peer_p_seg[URMA_UBAGG_DEV_MAX_NUM];
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

typedef struct bondp_seg_cache_key {
    uint32_t token_id;
    urma_eid_t remote_eid;
} bondp_seg_cache_key_t;

typedef struct bondp_seg_cache_entry {
    struct ub_hmap_node hmap_node;
    bondp_seg_cache_key_t key;
    urma_seg_t peer_p_seg[URMA_UBAGG_DEV_MAX_NUM];
    bool connected[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_handle;
    uint32_t index;
} bondp_seg_cache_entry_t;

static bool seg_cache_key_equal(const bondp_seg_cache_entry_t *entry, const bondp_seg_cache_key_t *key)
{
    return entry->key.token_id == key->token_id &&
        memcmp(&entry->key.remote_eid, &key->remote_eid, sizeof(urma_eid_t)) == 0;
}

int bondp_seg_cache_init(struct bondp_context *bdp_ctx)
{
    (void)pthread_rwlock_init(&bdp_ctx->seg_cache_lock, NULL);
    if (ub_hmap_init(&bdp_ctx->seg_cache_map, BONDP_MAX_NUM_RSEGS) != 0) {
        URMA_LOG_ERR("Failed to initialize segment cache map.\n");
        (void)pthread_rwlock_destroy(&bdp_ctx->seg_cache_lock);
        return -1;
    }
    bdp_ctx->seg_cache_insert_cnt = 0;
    return 0;
}

void bondp_seg_cache_uninit(struct bondp_context *bdp_ctx)
{
    struct ub_hmap_node *node;

    (void)pthread_rwlock_wrlock(&bdp_ctx->seg_cache_lock);
    node = ub_hmap_first(&bdp_ctx->seg_cache_map);
    while (node != NULL) {
        struct ub_hmap_node *next = ub_hmap_next(&bdp_ctx->seg_cache_map, node);
        bondp_seg_cache_entry_t *entry = CONTAINER_OF_FIELD(node, bondp_seg_cache_entry_t, hmap_node);
        ub_hmap_remove(&bdp_ctx->seg_cache_map, node);
        free(entry);
        node = next;
    }
    ub_hmap_destroy(&bdp_ctx->seg_cache_map);
    (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
    (void)pthread_rwlock_destroy(&bdp_ctx->seg_cache_lock);
}

static int seg_cache_lookup(bondp_context_t *bdp_ctx, uint32_t token_id,
                            urma_eid_t remote_eid, bondp_seg_cache_entry_t *entry)
{
    bondp_seg_cache_key_t key = {
        .token_id = token_id,
        .remote_eid = remote_eid,
    };

    (void)pthread_rwlock_rdlock(&bdp_ctx->seg_cache_lock);
    struct ub_hmap_node *node = ub_hmap_first_with_hash(&bdp_ctx->seg_cache_map, token_id);
    while (node != NULL) {
        bondp_seg_cache_entry_t *cached = CONTAINER_OF_FIELD(node, bondp_seg_cache_entry_t, hmap_node);
        if (seg_cache_key_equal(cached, &key)) {
            (void)memcpy(entry, cached, sizeof(*entry));
            (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
            return 0;
        }
        node = ub_hmap_next_with_hash(node, token_id);
    }
    (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
    return -ENOENT;
}

static int seg_cache_remove_by_index_nolock(struct ub_hmap *map, uint32_t index)
{
    struct ub_hmap_node *node = ub_hmap_first(map);

    while (node != NULL) {
        bondp_seg_cache_entry_t *entry = CONTAINER_OF_FIELD(node, bondp_seg_cache_entry_t, hmap_node);
        if (entry->index == index) {
            ub_hmap_remove(map, node);
            free(entry);
            return 0;
        }
        node = ub_hmap_next(map, node);
    }

    URMA_LOG_ERR("Failed to find segment cache entry, index=%u.\n", index);
    return -1;
}

static int seg_cache_add(bondp_context_t *bdp_ctx, const bondp_seg_cache_entry_t *entry)
{
    bondp_seg_cache_entry_t *new_entry = calloc(1, sizeof(*new_entry));
    if (new_entry == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(new_entry->peer_p_seg, entry->peer_p_seg, sizeof(new_entry->peer_p_seg));
    (void)memcpy(new_entry->connected, entry->connected, sizeof(new_entry->connected));
    new_entry->v_handle = entry->v_handle;
    new_entry->key = entry->key;

    (void)pthread_rwlock_wrlock(&bdp_ctx->seg_cache_lock);
    uint32_t hash = entry->key.token_id;
    struct ub_hmap_node *node = ub_hmap_first_with_hash(&bdp_ctx->seg_cache_map, hash);
    while (node != NULL) {
        bondp_seg_cache_entry_t *cached = CONTAINER_OF_FIELD(node, bondp_seg_cache_entry_t, hmap_node);
        if (seg_cache_key_equal(cached, &entry->key)) {
            (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
            free(new_entry);
            return 0;
        }
        node = ub_hmap_next_with_hash(node, hash);
    }

    uint32_t target_idx = (uint32_t)(bdp_ctx->seg_cache_insert_cnt % BONDP_MAX_NUM_RSEGS);
    if (bdp_ctx->seg_cache_insert_cnt >= BONDP_MAX_NUM_RSEGS) {
        int ret = seg_cache_remove_by_index_nolock(&bdp_ctx->seg_cache_map, target_idx);
        if (ret != 0) {
            (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
            free(new_entry);
            return ret;
        }
    }
    new_entry->index = target_idx;
    ub_hmap_insert(&bdp_ctx->seg_cache_map, &new_entry->hmap_node, hash);
    bdp_ctx->seg_cache_insert_cnt++;
    (void)pthread_rwlock_unlock(&bdp_ctx->seg_cache_lock);
    return 0;
}

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
        URMA_LOG_INFO("Registered pseg successfully, idx=%d, token_id=%u\n", i, p_tseg->seg.token_id);

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

    for (int i = 0; i < bdp_seg->dev_num; ++i) {
        if (bdp_seg->p_tseg[i] == NULL) {
            continue;
        }
        bondp_seg_to_base(&bdp_seg->p_tseg[i]->seg, &in_seg_info.slaves[i]);
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
    atomic_init(&bdp_seg->deleting, false);

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
    int ret = URMA_SUCCESS;
    bondp_tseg_t *bdp_seg = CONTAINER_OF_FIELD(target_seg, bondp_tseg_t, v_tseg);

    atomic_store(&bdp_seg->deleting, true);
    unsigned long use_cnt = atomic_load(&bdp_seg->use_cnt.atomic_cnt);
    if (use_cnt > 1) {
        /* In-flight WRs still reference this seg; caller must stop posting and retry. */
        atomic_store(&bdp_seg->deleting, false);
        URMA_LOG_ERR("Failed to unregister seg, still in use. token_id=%u, use_cnt=%lu\n",
                     target_seg->seg.token_id, use_cnt);
        return URMA_EAGAIN;
    }
    if (bondp_delete_pseg(bdp_seg) != 0) {
        URMA_LOG_ERR("Failed to delete pseg for vseg, token_id=%u, handle=%lu.\n",
                     target_seg->seg.token_id, target_seg->handle);
        ret = URMA_FAIL;
    }

    bondp_put_local_seg(target_seg);
    return ret;
}

static bondp_ret_t import_pseg(bondp_context_t *bdp_ctx, bondp_seg_cfg_t *seg_cfg,
                               int local_idx, int target_idx)
{
    urma_seg_t peer_p_seg = {0};
    bondp_seg_base_to_seg(&seg_cfg->udata_out->peer_p_seg[target_idx], &peer_p_seg);
    urma_eid_t eid = peer_p_seg.ubva.eid;
    if (is_empty_eid(&eid)) {
        URMA_LOG_DEBUG("BONDP import p_seg has empty EID=%d\n", target_idx);
        return BONDP_SKIP;
    }
    urma_target_seg_t *p_tseg = urma_import_seg(bdp_ctx->p_ctxs[local_idx], &peer_p_seg, seg_cfg->token,
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

static void bondp_fill_v_tseg(urma_target_seg_t *tseg, urma_seg_t *seg, uint64_t addr,
                              uint64_t handle, urma_context_t *ctx)
{
    tseg->seg.attr = seg->attr;
    bondp_seg_set_user_info(&tseg->seg, false);
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
            URMA_LOG_DEBUG("Imported vseg successfully, token_id=%u\n", seg->token_id);
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
    int ret;

    bdp_tseg->v_tseg.handle = bdp_tseg->v_orig_handle;
    ret = urma_cmd_unimport_seg(&bdp_tseg->v_tseg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR_RL("Failed to unimport vseg, token_id=%u, ret=%d\n",
                        bdp_tseg->v_tseg.seg.token_id, ret);
        return ret;
    }

    URMA_LOG_INFO("Unimported vseg successfully, token_id=%u\n", bdp_tseg->v_tseg.seg.token_id);
    return URMA_SUCCESS;
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
            } else {
                URMA_LOG_INFO("Unimported pseg successfully, idx=%d/%d\n", i, j);
            }
            bdp_tseg->p_tseg[i][j] = NULL;
        }
    }
    return ret;
}

static int bondp_fill_udata_connected_from_topo(urma_eid_t dst_eid, bondp_udata_import_seg_t *udata_out)
{
    bool topo_connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM] = {0};

    if (bondp_topo_query_linked_port(&dst_eid, topo_connected) != 0) {
        return -1;
    }

    for (uint32_t local_idx = 0; local_idx < URMA_UBAGG_DEV_MAX_NUM; ++local_idx) {
        for (uint32_t target_idx = 0; target_idx < URMA_UBAGG_DEV_MAX_NUM; ++target_idx) {
            if (local_idx < TOPO_CONNECTED_MAX_NUM && target_idx < TOPO_CONNECTED_MAX_NUM &&
                topo_connected[local_idx][target_idx]) {
                udata_out->connected[local_idx][target_idx] = true;
            }
        }
    }
    return 0;
}

static int bondp_try_reuse_seg_cache(bondp_context_t *bdp_ctx, urma_seg_t *seg, uint64_t addr,
                                     urma_context_t *ctx, bondp_import_tseg_t *bdp_tseg,
                                     bondp_udata_import_seg_t *udata_out)
{
    bondp_seg_cache_entry_t cache_entry = {0};
    int ret = seg_cache_lookup(bdp_ctx, seg->token_id, seg->ubva.eid, &cache_entry);
    if (ret == -ENOENT) {
        return 0;
    }
    if (ret != 0) {
        URMA_LOG_ERR("Failed to look up segment cache, ret=%d.\n", ret);
        return -1;
    }

    (void)memcpy(&udata_out->peer_p_seg, cache_entry.peer_p_seg, sizeof(udata_out->peer_p_seg));
    (void)memcpy(&udata_out->connected, cache_entry.connected, sizeof(udata_out->connected));
    bdp_tseg->is_reused = true;
    bondp_fill_v_tseg(&bdp_tseg->v_tseg, seg, addr, cache_entry.v_handle, ctx);
    bdp_tseg->v_orig_handle = bdp_tseg->v_tseg.handle;
    bdp_tseg->v_tseg.handle = (uint64_t)&bdp_tseg->v_tseg;
    return 0;
}

static int bondp_import_seg_from_user_ext(bondp_context_t *bdp_ctx, urma_context_t *ctx, urma_seg_t *seg,
                                          uint64_t addr, bondp_import_tseg_t *bdp_tseg,
                                          bondp_udata_import_seg_t *udata_out)
{
    const bondp_seg_ext_priv_t *seg_ext = bondp_seg_get_priv_ext_const(seg);

    bdp_tseg->skip_import_vseg = true;
    if (seg_ext->len < sizeof(urma_bond_seg_ext_t)) {
        URMA_LOG_ERR("Invalid seg ext length=%u.\n", seg_ext->len);
        return -1;
    }

    const urma_bond_seg_ext_t *bond_ext = (const urma_bond_seg_ext_t *)seg_ext->data;
    (void)memcpy(&udata_out->peer_p_seg, bond_ext->peer_p_seg, sizeof(udata_out->peer_p_seg));
    bondp_fill_v_tseg(&bdp_tseg->v_tseg, seg, addr, 0, ctx);

    urma_eid_t dst_eid = seg->ubva.eid;
    if (bondp_fill_udata_connected_from_topo(dst_eid, udata_out) != 0) {
        URMA_LOG_ERR("Failed to rebuild connected matrix by topo.\n");
        return -1;
    }
    return 0;
}

static int bondp_prepare_import_udata(bondp_context_t *bdp_ctx, urma_context_t *ctx, urma_seg_t *seg,
                                      urma_token_t *token, uint64_t addr, urma_import_seg_flag_t flag,
                                      bondp_import_tseg_t *bdp_tseg, bondp_udata_import_seg_t *udata_out)
{
    if (bondp_seg_has_user_info(seg)) {
        return bondp_import_seg_from_user_ext(bdp_ctx, ctx, seg, addr, bdp_tseg, udata_out);
    }

    if (bondp_import_vseg(ctx, seg, token, addr, flag, bdp_tseg, udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vseg\n");
        return -1;
    }
    return 0;
}

static int bondp_cache_imported_seg(bondp_context_t *bdp_ctx, urma_seg_t *seg,
                                    bondp_import_tseg_t *bdp_tseg, bondp_udata_import_seg_t *udata_out)
{
    bondp_seg_cache_entry_t cache_entry = {0};

    cache_entry.key.remote_eid = seg->ubva.eid;
    cache_entry.key.token_id = seg->token_id;
    (void)memcpy(cache_entry.peer_p_seg, udata_out->peer_p_seg, sizeof(cache_entry.peer_p_seg));
    (void)memcpy(cache_entry.connected, udata_out->connected, sizeof(cache_entry.connected));
    cache_entry.v_handle = bdp_tseg->v_tseg.handle;
    return seg_cache_add(bdp_ctx, &cache_entry);
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
    bdp_tseg->skip_import_vseg = false;
    atomic_init(&bdp_tseg->use_cnt.atomic_cnt, 1);

    bondp_udata_import_seg_t udata_out = {0};
    URMA_LOG_DEBUG("seg_cache_enable is %d.\n", bdp_ctx->seg_cache_enable);
    if (bdp_ctx->seg_cache_enable &&
        bondp_try_reuse_seg_cache(bdp_ctx, seg, addr, ctx, bdp_tseg, &udata_out) != 0) {
        goto free_bdp_tseg;
    }

    if (!bdp_tseg->is_reused &&
        bondp_prepare_import_udata(bdp_ctx, ctx, seg, token, addr, flag, bdp_tseg, &udata_out) != 0) {
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

    if (bdp_ctx->seg_cache_enable && !bdp_tseg->is_reused &&
        bondp_cache_imported_seg(bdp_ctx, seg, bdp_tseg, &udata_out) != 0) {
        goto unimport_pseg;
    }

    return &bdp_tseg->v_tseg;
unimport_pseg:
    bondp_unimport_pseg(bdp_tseg);
    if (!bdp_tseg->is_reused && !bondp_seg_has_user_info(seg)) {
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
    if (!bdp_tseg->is_reused && !(bdp_tseg->skip_import_vseg)) {
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
    if (target_seg == NULL) {
        URMA_LOG_WARN_RL("bondp_tseg_get called with NULL target_seg; in-flight WR holds a NULL tseg\n");
        return;
    }
    if (target_seg->token_id != NULL) {
        bondp_get_local_seg(target_seg);
    } else {
        bondp_get_remote_seg(target_seg);
    }
}

void bondp_tseg_put(urma_target_seg_t *target_seg)
{
    if (target_seg == NULL) {
        URMA_LOG_WARN_RL("bondp_tseg_put called with NULL target_seg; in-flight WR holds a NULL tseg\n");
        return;
    }
    if (target_seg->token_id != NULL) {
        bondp_put_local_seg(target_seg);
    } else {
        bondp_put_remote_seg(target_seg);
    }
}
