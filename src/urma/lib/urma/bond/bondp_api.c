/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of Bonding API
 * Author: Ma Chuan
 * Create: 2025-02-06
 * Note:
 * History: 2025-02-06
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>
#include "ub_util.h"
#include "urma_log.h"
#include "urma_api.h"
#include "bondp_types.h"
#include "bondp_comp.h"
#include "urma_ubagg.h"
#include "bondp_jetty_ctx.h"
#include "bondp_context_table.h"
#include "bondp_provider_ops.h"
#include "ubagg_ioctl.h"
#include "urma_provider.h"
#include "bondp_api.h"

urma_jfce_t *bondp_create_jfce(urma_context_t *ctx)
{
    bondp_comp_t *bdp_jfce = bondp_create_comp(ctx, BONDP_COMP_JFCE, NULL);

    if (bdp_jfce == NULL) {
        URMA_LOG_ERR("Failed to create bonding jfce\n");
        return NULL;
    }

    return &bdp_jfce->v_jfce;
}

urma_status_t bondp_delete_jfce(urma_jfce_t *jfce)
{
    bondp_comp_t *bdp_jfce = CONTAINER_OF_FIELD(jfce, bondp_comp_t, v_jfce);
    unsigned long use_cnt = atomic_load(&bdp_jfce->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        URMA_LOG_ERR("Failed to delete jfce[%d], still in use. use_cnt: %lu\n", jfce->fd, use_cnt);
        return URMA_EAGAIN;
    }
    return bondp_delete_comp(jfce, BONDP_COMP_JFCE);
}

static int bondp_create_vjfc(urma_context_t *ctx, bondp_comp_t *bdp_jfc, urma_jfc_cfg_t *jfc_cfg)
{
    urma_cmd_udrv_priv_t udata = {0};
    urma_jfc_cfg_t tmp_cfg = *jfc_cfg;
    /* We need to set jfce to NULL because the kernel-mode uobj is not created when the vjfce is created. */
    /* If a pointer to vjfce is passed here, */
    /* it will cause ubcore to report an error when creating jfc because it cannot find jfce. */
    /* If the corresponding kernel-space structure for vjfce is created, */
    /* then it is needed to set the fd of vjfce to the fd allocated in the kernel space. */
    /* Currently, the fd in vjfce is a brand new epoll_fd, so we need to change it to the kernel-allocated one. */
    tmp_cfg.jfce = NULL;
    int ret = urma_cmd_create_jfc(ctx, &bdp_jfc->v_jfc, &tmp_cfg, &udata);
    if (ret != 0) {
        return ret;
    }
    /* It is necessary to backfill jfc_cfg->jfce because rearm_jfc will use this pointer, and it must point to vjfce. */
    bdp_jfc->v_jfc.jfc_cfg.jfce = jfc_cfg->jfce;
    return 0;
}

static int bondp_delete_vjfc(bondp_comp_t *bdp_jfc)
{
    return urma_cmd_delete_jfc(&bdp_jfc->v_jfc);
}

urma_jfc_t *bondp_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
    bondp_comp_t *bdp_jfc = bondp_create_comp(ctx, BONDP_COMP_JFC, cfg);
    if (bdp_jfc == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }
    /* JFC use comp_ctx as uintptr_t to store the latest polled jfc idx */
    bdp_jfc->comp_ctx = (void *)(uintptr_t)0;

    for (int i = 0; i < bdp_jfc->dev_num; ++i) {
        if (!bdp_jfc->p_jfc[i]) {
            continue;
        }
        bdp_jfc->p_jfc[i]->jfc_cfg.user_ctx = (uint64_t)&bdp_jfc->v_jfc;
    }

    if (bondp_create_vjfc(ctx, bdp_jfc, cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjfc.\n");
        goto free_bondp_jfc;
    }
    URMA_LOG_INFO("Successfully created vjfc, ["EID_FMT"]:%u\n",
        EID_ARGS(bdp_jfc->v_jfc.jfc_id.eid), bdp_jfc->v_jfc.jfc_id.id);

    if (cfg->jfce != NULL) {
        bondp_comp_t *bdp_jfce = CONTAINER_OF_FIELD(cfg->jfce, bondp_comp_t, v_jfce);
        atomic_fetch_add(&bdp_jfce->use_cnt.atomic_cnt, 1);
    }

    return &bdp_jfc->v_jfc;

free_bondp_jfc:
    bondp_delete_comp(bdp_jfc, BONDP_COMP_JFC);
    return NULL;
}

urma_status_t bondp_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_comp_t, v_jfc);

    for (int i = 0; i < bdp_jfc->dev_num; i++) {
        if (bdp_jfc->p_jfc[i] == NULL) {
            continue;
        }
        ret = urma_modify_jfc(bdp_jfc->p_jfc[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjfc fail, index:%d, ret:%d\n", i, final_ret);
        }
    }
    return final_ret;
}

urma_status_t bondp_delete_jfc(urma_jfc_t *jfc)
{
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_comp_t, v_jfc);
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfce = NULL;

    if (jfc->jfc_cfg.jfce != NULL) {
        bdp_jfce = CONTAINER_OF_FIELD(jfc->jfc_cfg.jfce, bondp_comp_t, v_jfce);
    }

    unsigned long use_cnt = atomic_load(&bdp_jfc->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        URMA_LOG_ERR("Failed to delete jfc[%d], still in use. use_cnt: %lu\n", jfc->jfc_id.id, use_cnt);
        return URMA_EAGAIN;
    }

    if (bondp_delete_vjfc(bdp_jfc) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete vjfc\n");
        ret = URMA_FAIL;
    }
    if (bondp_delete_comp(jfc, BONDP_COMP_JFC) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete bdp_jfc");
        ret = URMA_FAIL;
    }
    if (bdp_jfce != NULL) {
        atomic_fetch_sub(&bdp_jfce->use_cnt.atomic_cnt, 1);
    }
    return ret;
}

static int bondp_create_vjfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg, bondp_comp_t *bdp_jfs)
{
    urma_cmd_udrv_priv_t udata = {0};
    if (urma_cmd_create_jfs(ctx, &bdp_jfs->v_jfs, cfg, &udata) != 0) {
        URMA_LOG_ERR("ubcore create jfs failed.\n");
        return -1;
    }
    return 0;
}

static int bondp_delete_vjfs(bondp_comp_t *bdp_jfs)
{
    return urma_cmd_delete_jfs(&bdp_jfs->v_jfs);
}

static int bondp_add_jfs_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfs, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    int i = 0;
    for (i = 0; i < bdp_jfs->dev_num; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jfs->p_jfs[i]->jfs_id.id, JFS, jetty_id, bdp_jfs);
        if (ret) {
            URMA_LOG_ERR("Failed to add p_vjfs_id[%d]: ret: %d, p_jfs_id: %u, v_jfs_id: %u\n",
                i, ret, bdp_jfs->p_jfs[i]->jfs_id.id, jetty_id);
            goto DEL_P_VJFS_ID;
        }
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return 0;
DEL_P_VJFS_ID:
    for (int j = 0; j < i; ++j) {
        if (bdp_jfs->p_jfs[j] == NULL) {
            continue;
        }
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, bdp_jfs->p_jfs[j]->jfs_id.id, JFS);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jfs_p_vjetty_info_without_lock(bondp_comp_t *bdp_jfs)
{
    bondp_context_t *bdp_ctx = bdp_jfs->bondp_ctx;
    for (int i = 0; i < bdp_jfs->dev_num; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jfs->p_jfs[i]->jfs_id.id, JFS);
        if (ret) {
            URMA_LOG_ERR("Failed to delete p_vjfs_id node[%d]: ret: %d pjfs_id: %u\n",
                i, ret, bdp_jfs->p_jfs[i]->jfs_id.id);
        }
    }
}

static void bondp_del_jfs_p_vjetty_info(bondp_comp_t *bdp_jfs)
{
    bondp_context_t *bdp_ctx = bdp_jfs->bondp_ctx;
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_del_jfs_p_vjetty_info_without_lock(bdp_jfs);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
}

urma_jfs_t *bondp_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (is_in_matrix_server(bdp_ctx)) {
        if (cfg->flag.bs.multi_path == false) {
            URMA_LOG_ERR("In matrix server, JFS don't support single-path mode.\n");
            return NULL;
        }
    }

    bondp_comp_t *bdp_jfs = bondp_create_comp(ctx, BONDP_COMP_JFS, cfg);
    if (bdp_jfs == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }
    if (bondp_create_vjfs(ctx, cfg, bdp_jfs)) {
        URMA_LOG_ERR("Failed to create vjfs\n");
        goto DELETE_COMP;
    }
    if (bondp_add_jfs_p_vjetty_id_info(bdp_ctx, bdp_jfs, bdp_jfs->v_jfs.jfs_id.id)) {
        URMA_LOG_ERR("Failed to add jfs p_vjetty_id info\n");
        goto DELETE_VJFS;
    }
    for (int i = 0; i < bdp_jfs->dev_num; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        bdp_jfs->p_jfs[i]->jfs_cfg.user_ctx = (uint64_t)bdp_jfs;
    }
    bjetty_ctx_t *jfs_datapath_ctx = create_bjetty_ctx(ctx, bdp_jfs, URMA_UBAGG_WR_BUF_SIZE, URMA_UBAGG_HDR_BUF_SIZE);
    if (jfs_datapath_ctx == NULL) {
        URMA_LOG_ERR("Failed to create jfs datapath ctx");
        goto DEL_P_VJFS_ID;
    }
    bdp_jfs->comp_ctx = jfs_datapath_ctx;
    bdp_jfs->is_multipath = cfg->flag.bs.multi_path;

    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_comp_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    return &bdp_jfs->v_jfs;
DEL_P_VJFS_ID:
    bondp_del_jfs_p_vjetty_info(bdp_jfs);
DELETE_VJFS:
    (void)bondp_delete_vjfs(bdp_jfs);
DELETE_COMP:
    bondp_delete_comp(bdp_jfs, BONDP_COMP_JFS);
    return NULL;
}

urma_status_t bondp_delete_jfs(urma_jfs_t *jfs)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfs->jfs_cfg.jfc, bondp_comp_t, v_jfc);
    bondp_context_t *bdp_ctx = bdp_jfs->bondp_ctx;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing bjetty_ctx through this table.
    ! Currently, the only way to access bjetty_ctx in a multi-threaded senario is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
     */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    unsigned long use_cnt = atomic_load(&bdp_jfs->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jfs[%u], still in use. use_cnt: %lu\n", jfs->jfs_id.id, use_cnt);
        return URMA_EAGAIN;
    }
    bondp_del_jfs_p_vjetty_info_without_lock(bdp_jfs);
    /*
    ! The unlocking here is possible because after we remove this item,
    ! we can ensure that no other part of the system can access this pointer,
    ! thus allowing us to directly execute the deletion process.
    */
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    int del_ret = bondp_delete_vjfs(bdp_jfs);
    if (del_ret) {
        URMA_LOG_ERR("ubcore delete jfs failed, ret: %d.\n", del_ret);
        ret = URMA_FAIL;
    }
    destroy_bjetty_ctx(bdp_jfs->comp_ctx);
    del_ret = bondp_delete_comp(bdp_jfs, BONDP_COMP_JFS);
    if (del_ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete_comp: %d", del_ret);
        ret = URMA_FAIL;
    }
    atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    return ret;
}

urma_status_t bondp_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);

    for (int i = 0; i < bdp_jfs->dev_num; i++) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        ret = urma_modify_jfs(bdp_jfs->p_jfs[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjfs fail, index:%d, ret:%d\n", i, final_ret);
        }
    }
    return final_ret;
}

static int bondp_create_vjfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg, bondp_comp_t *bdp_jfr)
{
    urma_cmd_udrv_priv_t udata = {0};
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    urma_bond_add_rjfr_id_info_in_t jfr_info = {
        .base_id = {
            .eid = bdp_ctx->v_ctx.eid,
            .uasid = 0, /* Default set to 0, this field is currently not in use. */
            .id = 0,    /* Handled by ubagg.ko */
        },
        .dev_num = bdp_jfr->dev_num,
        .is_in_matrix_server = is_in_matrix_server(bdp_ctx),
        .is_multipath = bdp_jfr->is_multipath
    };

    for (int i = 0; i < bdp_jfr->dev_num; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        jfr_info.slave_id[i] = bdp_jfr->p_jfr[i]->jfr_id;
    }
    udata.in_addr = (uint64_t)&jfr_info;
    udata.in_len = sizeof(urma_bond_add_rjfr_id_info_in_t);

    int ret = urma_cmd_create_jfr(&bdp_ctx->v_ctx, &bdp_jfr->v_jfr, cfg, &udata);
    if (ret) {
        URMA_LOG_ERR("bondp init jfr fail: %d.\n", ret);
        return -1;
    }
    return 0;
}

static int bondp_delete_vjfr(bondp_comp_t *bdp_jfr)
{
    return urma_cmd_delete_jfr(&bdp_jfr->v_jfr);
}

static int bondp_add_jfr_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfr, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    int i = 0;
    for (i = 0; i < bdp_jfr->dev_num; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jfr->p_jfr[i]->jfr_id.id, JFR, jetty_id, bdp_jfr);
        if (ret) {
            URMA_LOG_ERR("Failed to add p_vjfr_id[%d]: ret: %d, p_jfr_id: %u, v_jfr_id: %u\n",
                i, ret, bdp_jfr->p_jfr[i]->jfr_id.id, jetty_id);
            goto DEL_P_VJFR_ID;
        }
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return 0;
DEL_P_VJFR_ID:
    for (int j = 0; j < i; ++j) {
        if (bdp_jfr->p_jfr[j] == NULL) {
            continue;
        }
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, bdp_jfr->p_jfr[j]->jfr_id.id, JFR);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jfr_p_vjetty_info_without_lock(bondp_comp_t *bdp_jfr)
{
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    for (int i = 0; i < bdp_jfr->dev_num; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jfr->p_jfr[i]->jfr_id.id, JFR);
        if (ret) {
            URMA_LOG_ERR("Failed to delete p_vjfr_id node[%d]: ret %d pjfr_id: %u\n",
                i, ret, bdp_jfr->p_jfr[i]->jfr_id.id);
        }
    }
}

static void bondp_del_jfr_p_vjetty_info(bondp_comp_t *bdp_jfr)
{
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_del_jfr_p_vjetty_info_without_lock(bdp_jfr);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
}

urma_jfr_t *bondp_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    if (is_in_matrix_server(bdp_ctx)) {
        URMA_LOG_INFO("CONSTRAINT: JFR only support multi_path mode in matrix server."
            "Set to multi_path mode forcely.\n");
    }
    bondp_comp_t *bdp_jfr = bondp_create_comp(ctx, BONDP_COMP_JFR, cfg);
    if (bdp_jfr == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }
    if (bondp_create_vjfr(ctx, cfg, bdp_jfr)) {
        URMA_LOG_ERR("Failed to create vjfr\n");
        goto DELETE_COMP;
    }
    if (bondp_add_jfr_p_vjetty_id_info(bdp_ctx, bdp_jfr, bdp_jfr->v_jfr.jfr_id.id)) {
        goto DELETE_VJFR;
    }
    for (int i = 0; i < bdp_jfr->dev_num; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        bdp_jfr->p_jfr[i]->jfr_cfg.user_ctx = (uint64_t)bdp_jfr;
    }
    bjetty_ctx_t *jfr_datapath_ctx = create_bjetty_ctx(ctx, bdp_jfr, URMA_UBAGG_WR_BUF_SIZE, URMA_UBAGG_HDR_BUF_SIZE);
    if (jfr_datapath_ctx == NULL) {
        URMA_LOG_ERR("Failed to create jfr datapath ctx");
        goto DEL_P_VJFR_ID;
    }
    bdp_jfr->comp_ctx = jfr_datapath_ctx;

    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_comp_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    return &bdp_jfr->v_jfr;
DEL_P_VJFR_ID:
    bondp_del_jfr_p_vjetty_info(bdp_jfr);
DELETE_VJFR:
    (void)bondp_delete_vjfr(bdp_jfr);
DELETE_COMP:
    bondp_delete_comp(bdp_jfr, BONDP_COMP_JFR);
    return NULL;
}

urma_status_t bondp_delete_jfr(urma_jfr_t *jfr)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    /* Ensure non-null during creation. */
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfr->jfr_cfg.jfc, bondp_comp_t, v_jfc);
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing bjetty_ctx through this table.
    ! Currently, the only way to access bjetty_ctx in a multi-threaded senario is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
    */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    unsigned long use_cnt = atomic_load(&bdp_jfr->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jfr[%d], still in use. use_cnt: %lu\n", jfr->jfr_id.id, use_cnt);
        return URMA_EAGAIN;
    }
    bondp_del_jfr_p_vjetty_info_without_lock(bdp_jfr);
    /*
    ! The unlocking here is possible because after we remove this item,
    ! we can ensure that no other part of the system can access this pointer,
    ! thus allowing us to directly execute the deletion process.
    */
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    destroy_bjetty_ctx(bdp_jfr->comp_ctx);
    int del_ret = bondp_delete_vjfr(bdp_jfr);
    if (del_ret) {
        URMA_LOG_ERR("Failed to delete_vjfr: %d\n", del_ret);
        ret = URMA_FAIL;
    }
    del_ret = bondp_delete_comp(bdp_jfr, BONDP_COMP_JFR);
    if (del_ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete_comp: %d", del_ret);
        ret = URMA_FAIL;
    }
    atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    return ret;
}

urma_status_t bondp_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);

    for (int i = 0; i < bdp_jfr->dev_num; i++) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        ret = urma_modify_jfr(bdp_jfr->p_jfr[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjfr fail, index:%d, ret:%d\n", i, final_ret);
        }
    }
    return final_ret;
}

/*
    @param[out]attr->state:When both values returned by urma_query_jfr are identical, they are returned directly.
    If the two values differ and a single ready event exists, the ready event is returned.
    The scenario involving one reset and one error event is not considered at this stage.

    @param[out]attr->rx_threshold:urma_query_jfr returns the smaller value if two are returned; returns the value
    directly if only one is returned; returns zero if neither is returned.

    @param[out]attr->mask:Use bits to indicate whether the aforementioned two values are valid. The state remains
    valid at all times, whereas rx_threshold requires processing based on the return value of urma_query_jfr.

    @param[out]cfg:Directly assign jfr_cfg to v_jfr
*/
urma_status_t bondp_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    int cmp_threshold = UINT32_MAX;
    bool isready = false;
    /*
    The sequential traversal from 0 to 2 is because JFR currently only supports multi-path configuration,
    hence it is only necessary to traverse the JFR corresponding to the primary EID.
    */
    for (int i = 0; i < IODIE_NUM; i++) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        ret = urma_query_jfr(bdp_jfr->p_jfr[i], cfg, attr);
        if (ret == URMA_SUCCESS) {
            /*
            Consider only three scenarios:
            1. Both return values are identical and neither is ready, in which case the last state is returned.
            2. Both return values are different and one is ready.
            3. Both return values are different and neither is ready.
            */
            if ((attr->mask & JFR_STATE) && attr->state == URMA_JFR_STATE_READY) {
                isready = true;
            }
            if ((attr->mask & JFR_RX_THRESHOLD) && attr->rx_threshold != 0) {
                cmp_threshold = cmp_threshold > attr->rx_threshold ? attr->rx_threshold : cmp_threshold;
            }
        } else {
            // Query failure indicates an internal error, preventing normal response from upper layers.
            // tags: Failover scenarios require additional consideration.
            URMA_LOG_ERR("query pjfr fail, index:%d, ret:%d\n", i, ret);
            return ret;
        }
    }
    if (isready) {
        attr->state = URMA_JFR_STATE_READY;
    }
    if (cmp_threshold != UINT32_MAX) {
        attr->rx_threshold = cmp_threshold;
        attr->mask = JFR_STATE | JFR_RX_THRESHOLD;
    } else {
        attr->rx_threshold = 0;
        attr->mask = JFR_STATE;
    }
    *cfg = bdp_jfr->v_jfr.jfr_cfg;
    return URMA_SUCCESS;
}

static int bondp_create_vjetty(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, urma_jetty_cfg_t *jetty_cfg)
{
    urma_bond_id_info_out_t jetty_info = {
        .base_id = {
            .eid = bdp_ctx->v_ctx.eid,
            .uasid = 0, /* Default set to 0, this field is currently not in use. */
            .id = 0,    /* Handled by ubagg.ko */
        },
        .dev_num = bdp_jetty->dev_num,
        .is_in_matrix_server = is_in_matrix_server(bdp_ctx),
        .is_multipath = jetty_cfg->jfs_cfg.flag.bs.multi_path,
    };
    for (int i = 0; i < bdp_ctx->dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        jetty_info.slave_id[i] = bdp_jetty->p_jetty[i]->jetty_id;
    }
    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jetty_info,
        .in_len = sizeof(urma_bond_id_info_out_t),
    };

    bdp_jetty->v_jetty.jetty_cfg = *jetty_cfg;
    int ret = urma_cmd_create_jetty(&bdp_ctx->v_ctx, &bdp_jetty->v_jetty, jetty_cfg, &udata);
    if (ret == 0) {
        bdp_jetty->v_jetty.jetty_cfg.shared.jfr->jfr_cfg = jetty_cfg->shared.jfr->jfr_cfg;
    }
    return ret;
}

static int bondp_delete_vjetty(bondp_comp_t *bdp_jetty)
{
    return urma_cmd_delete_jetty(&bdp_jetty->v_jetty);
}

static int bondp_add_jetty_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    for (int i = 0; i < bdp_jetty->dev_num; ++i) {
        if (!bdp_jetty->p_jetty[i]) {
            continue;
        }
        uint32_t pjetty_id = bdp_jetty->p_jetty[i]->jetty_id.id;
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table, pjetty_id, JETTY,
            jetty_id, bdp_jetty);
        if (ret == BONDP_HASH_MAP_COLLIDE_ERROR &&
            jetty_id > 0 && jetty_id < BONDP_MAX_WELL_KNOWN_JETTY_ID) {
            URMA_LOG_INFO("Add repeated wk-jetty id[%d]: ret: %d, p_jetty_id: %u, v_jetty_id: %u\n",
                i, ret, pjetty_id, jetty_id);
        } else if (ret != 0) {
            URMA_LOG_ERR("Failed to add p_vjetty_id[%d]: ret: %d, p_jetty_id: %u, v_jetty_id: %u\n",
                i, ret, pjetty_id, jetty_id);
            goto DEL_P_VJETTY_ID;
        }
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return 0;
DEL_P_VJETTY_ID:
    for (int i = 0; i < bdp_jetty->dev_num; ++i) {
        if (!bdp_jetty->p_jetty[i]) {
            continue;
        }
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jetty->p_jetty[i]->jetty_id.id, JETTY);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jetty_p_vjetty_info_without_lock(bondp_comp_t *bdp_jetty)
{
    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;
    for (int i = 0; i < bdp_jetty->dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table,
            bdp_jetty->p_jetty[i]->jetty_id.id, JETTY);
        if (ret) {
            URMA_LOG_ERR("Failed to delete p_vjetty_id node: ret: %d pjetty_id: %u\n",
                ret, bdp_jetty->p_jetty[i]->jetty_id.id);
        }
    }
}

static void bondp_del_jetty_p_vjetty_info(bondp_comp_t *bdp_jetty)
{
    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_del_jetty_p_vjetty_info_without_lock(bdp_jetty);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
}

urma_jetty_t *bondp_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    if (jetty_cfg->flag.bs.share_jfr != true || jetty_cfg->shared.jfr == NULL) {
        URMA_LOG_ERR("UB device must use shared jfr when create jetty.\n");
        errno = EINVAL;
        return NULL;
    }
    if (jetty_cfg->id >= BONDP_MAX_WELL_KNOWN_JETTY_ID) {
        URMA_LOG_ERR("Invalid well known jetty id: %d, should be in (0, 1024)\n", jetty_cfg->id);
        return NULL;
    }
    if (is_in_matrix_server(bdp_ctx)) {
        if (jetty_cfg->jfs_cfg.flag.bs.multi_path == false) {
            if (jetty_cfg->jfs_cfg.trans_mode != URMA_TM_RC) {
                URMA_LOG_ERR("In matrix server, jetty only supports single-path mode with RC.\n");
                errno = EINVAL;
                return NULL;
            }
            if (!is_single_dev_mode(ctx)) {
                URMA_LOG_ERR("In matrix server, multi-device mode don't support single path currently.\n");
                errno = EINVAL;
                return NULL;
            }
            if (jetty_cfg->id != 0) {
                URMA_LOG_WARN("In matrix server, wellknown jetty must use multi-path mode, "
                    "set to multi-path mode forcely\n");
                jetty_cfg->jfs_cfg.flag.bs.multi_path = true;
            }
        }
    }

    bondp_comp_t *bdp_jetty = bondp_create_comp(ctx, BONDP_COMP_JETTY, jetty_cfg);
    if (bdp_jetty == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }

    if (bondp_create_vjetty(bdp_ctx, bdp_jetty, jetty_cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjetty, %u\n", jetty_cfg->id);
        goto free_bondp_jetty;
    }
    URMA_LOG_INFO("Successfully created vjetty, ["EID_FMT"]:%u\n",
        EID_ARGS(bdp_jetty->v_jetty.jetty_id.eid), bdp_jetty->v_jetty.jetty_id.id);

    if (bondp_add_jetty_p_vjetty_id_info(bdp_ctx, bdp_jetty, bdp_jetty->v_jetty.jetty_id.id) != 0) {
        URMA_LOG_ERR("Failed to add jetty id to p_vjetty_id table\n");
        goto DELETE_VJETTY;
    }
    for (int i = 0; i < bdp_jetty->dev_num; ++i) {
        if (!bdp_jetty->p_jetty[i]) {
            continue;
        }
        bdp_jetty->p_jetty[i]->jetty_cfg.user_ctx = (uint64_t)bdp_jetty;
    }

    bjetty_ctx_t *bjetty_ctx = create_bjetty_ctx(ctx, bdp_jetty, URMA_UBAGG_WR_BUF_SIZE, URMA_UBAGG_HDR_BUF_SIZE);
    if (bjetty_ctx == NULL) {
        URMA_LOG_ERR("Failed to create jetty ctx");
        goto DEL_P_VJETTY_ID;
    }
    bdp_jetty->comp_ctx = bjetty_ctx;
    bdp_jetty->is_multipath = jetty_cfg->jfs_cfg.flag.bs.multi_path;
    /* Validate bdp_jfr below at the function entry point to ensure they are not empty. */
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr, bondp_comp_t, v_jfr);
    atomic_fetch_add(&bdp_jfr->use_cnt.atomic_cnt, 1);
    if (jetty_cfg->shared.jfc != NULL) {
        bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jetty_cfg->shared.jfc, bondp_comp_t, v_jfc);
        atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);
    }

    return &bdp_jetty->v_jetty;

DEL_P_VJETTY_ID:
    bondp_del_jetty_p_vjetty_info(bdp_jetty);
DELETE_VJETTY:
    bondp_delete_vjetty(bdp_jetty);
free_bondp_jetty:
    bondp_delete_comp(bdp_jetty, BONDP_COMP_JETTY);
    return NULL;
}

urma_status_t bondp_delete_jetty(urma_jetty_t *jetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, base);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jetty->urma_ctx, bondp_context_t, v_ctx);
    urma_status_t ret = URMA_SUCCESS;
    /* When creating bondp_jetty, jetty_cfg.shared.jfr has been validated and is non-null. */
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty->jetty_cfg.shared.jfr, bondp_comp_t, v_jfr);
    bondp_comp_t *bdp_jfc = NULL;
    if (jetty->jetty_cfg.shared.jfc != NULL) {
        bdp_jfc = CONTAINER_OF_FIELD(jetty->jetty_cfg.shared.jfc, bondp_comp_t, v_jfc);
    }
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing bjetty_ctx through this table.
    ! Currently, the only way to access bjetty_ctx in a multi-threaded senario is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
    */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    unsigned long use_cnt = atomic_load(&bdp_jetty->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jetty[%d], still in use. use_cnt: %lu\n", jetty->jetty_id.id, use_cnt);
        return URMA_EAGAIN;
    }
    bondp_del_jetty_p_vjetty_info_without_lock(bdp_jetty);
    /*
    ! The unlocking here is possible because after we remove this item,
    ! we can ensure that no other part of the system can access this pointer,
    ! thus allowing us to directly execute the deletion process.
    */
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    destroy_bjetty_ctx(bdp_jetty->comp_ctx);
    if (bondp_delete_vjetty(bdp_jetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete vjetty\n");
        ret = URMA_FAIL;
    }
    if (bondp_delete_comp(jetty, BONDP_COMP_JETTY) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete bdp_jetty\n");
        ret = URMA_FAIL;
    }

    atomic_fetch_sub(&bdp_jfr->use_cnt.atomic_cnt, 1);
    if (bdp_jfc != NULL) {
        atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    }

    return ret;
}

urma_status_t bondp_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    int i = 0;
    int j = 0;
    if (!is_valid_bondp_comp(bdp_jetty)) {
        URMA_LOG_ERR("Invalid param jetty\n");
        return URMA_EINVAL;
    }
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid param tjetty\n");
        return URMA_EINVAL;
    }
    for (i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        for (j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (urma_advise_jetty(bdp_jetty->p_jetty[i], bdp_tjetty->p_tjetty[i][j])) {
                goto UNADVISE;
            }
        }
    }
    return URMA_SUCCESS;
UNADVISE:
    /*
    This branch is only entered in error cases,
    and both i and j are less than their respective maximum values,
    so there is no out-of-bounds situation.
    */
    for (int p = 0; p < i + 1; ++p) {
        for (int q = 0; q < j + 1; ++q) {
            if (bdp_tjetty->p_tjetty[p][q] != NULL) {
                urma_unadvise_jetty(bdp_jetty->p_jetty[i], bdp_tjetty->p_tjetty[p][q]);
            }
        }
    }
    return URMA_FAIL;
}

urma_status_t bondp_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    bool has_error = false;
    if (!is_valid_bondp_comp(bdp_jetty)) {
        URMA_LOG_ERR("Invalid param jetty\n");
        return URMA_EINVAL;
    }
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid param tjetty\n");
        return URMA_EINVAL;
    }
    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (urma_unadvise_jetty(bdp_jetty->p_jetty[i], bdp_tjetty->p_tjetty[i][j])) {
                has_error = true;
            }
        }
    }
    if (has_error) {
        goto LOG_ERR_UNADVISE;
    } else {
        return URMA_SUCCESS;
    }
LOG_ERR_UNADVISE:
    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (bdp_tjetty->p_tjetty[i][j]) {
                URMA_LOG_ERR("Failed to unadvise tjetty (%d, %d)\n", i, j);
            }
        }
    }
    return URMA_FAIL;
}

urma_status_t bondp_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);

    for (int i = 0; i < bdp_jetty->dev_num; i++) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        ret = urma_modify_jetty(bdp_jetty->p_jetty[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjetty fail, index:%d, ret:%d\n", i, final_ret);
        }
    }
    return final_ret;
}

int bondp_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    switch (in->opcode) {
        case URMA_USER_CTL_BOND_GET_ID_INFO:
        case URMA_USER_CTL_BOND_ADD_RJFR_ID_INFO:
        case URMA_USER_CTL_BOND_ADD_RJETTY_ID_INFO:
        case URMA_USER_CTL_BOND_GET_SEG_INFO:
        case URMA_USER_CTL_BOND_ADD_REMOTE_SEG_INFO:
            break;
        case URMA_USER_CTL_BOND_SET_AGGR_MODE:
            if (in->len != sizeof(urma_context_aggr_mode_t)) {
                URMA_LOG_ERR("Invalid len");
                return -EINVAL;
            }
            return bondp_set_aggr_mode(ctx, *(urma_context_aggr_mode_t *)in->addr);
        default: {
            URMA_LOG_ERR("Unsupported opcode, opcode:%d\n", in->opcode);
            return -EINVAL;
        }
    }
    return 0;
}
/**
 * Try to import jetty for full-mesh, allow unimported jetty.
 */
static int import_jetty_default(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *ex_info, urma_rjetty_t *rjetty, urma_token_t *rjetty_token)
{
    bool has_import = false;
    urma_rjetty_t p_rjetty = *rjetty;

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        bdp_tjetty->local_valid[i] = true;
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (is_empty_eid(&ex_info->slave_id[j].eid)) {
                continue;
            }
            bdp_tjetty->target_valid[i] = true;
            p_rjetty.jetty_id = ex_info->slave_id[j];
            bdp_tjetty->p_tjetty[i][j] = urma_import_jetty(bdp_ctx->p_ctxs[i], &p_rjetty, rjetty_token);
            if (bdp_tjetty->p_tjetty[i][j] == NULL) {
                /* Allow unimported p_tjetty */
                continue;
            }
            has_import = true;
        }
    }
    if (!has_import) {
        URMA_LOG_ERR("Failed to import jetty, no valid route to rjetty\n");
        return -1;
    }
    return 0;
}
/**
 * Import primary ports for each plane in matrix server
 */
static int import_primary_ports(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *ex_info, urma_rjetty_t *rjetty, urma_token_t *rjetty_token)

{
    urma_rjetty_t p_rjetty = *rjetty;
    p_rjetty.tp_type = URMA_CTP; /* only support multi-path mode and use CTP */

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            URMA_LOG_ERR("Primary dev has NULL ctx\n");
            return -1;
        }
        bdp_tjetty->local_valid[i] = true;
        if (is_empty_eid(&ex_info->slave_id[i].eid)) {
            URMA_LOG_ERR("Primary dev has NULL rjetty eid\n");
            return -1;
        }
        bdp_tjetty->target_valid[i] = true;
        p_rjetty.jetty_id = ex_info->slave_id[i];
        /* To be implemented: import jetty in CTP mode */
        bdp_tjetty->p_tjetty[i][i] = urma_import_jetty(bdp_ctx->p_ctxs[i], &p_rjetty, rjetty_token);
        if (bdp_tjetty->p_tjetty[i][i] == NULL) {
            URMA_LOG_ERR("Failed to import primary tjetty %d %d\n", i, i);
            return -1;
        }
    }
    return 0;
}

static int import_direct_route(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *ex_info, urma_rjetty_t *rjetty, urma_token_t *rjetty_token)
{
    if (!has_direct_route(bdp_ctx->topo_map, &rjetty->jetty_id.eid)) {
        URMA_LOG_ERR("No direct route to target jetty in single-path mode\n");
        return -1;
    }

    urma_rjetty_t p_rjetty = *rjetty;
    if (p_rjetty.trans_mode == URMA_TM_UM) {
        p_rjetty.tp_type = URMA_UTP;
    } else {
        p_rjetty.tp_type = URMA_RTP;
    }
    bdp_tjetty->direct_route_num = 0;
    /* This function won't return NULL ptr because check function has_direct_route has been called before */
    direct_dev_info_t *direct_dev_info = get_direct_dev_info_by_bonding_eid(bdp_ctx->topo_map, &rjetty->jetty_id.eid);
    for (int i = 0; i < direct_dev_info->direct_num; ++i) {
        int local_port = get_matrix_port_p_idx(direct_dev_info->local_map_idx[i].plane_idx,
            direct_dev_info->local_map_idx[i].port_idx);
        int target_port = get_matrix_port_p_idx(direct_dev_info->target_map_idx[i].plane_idx,
            direct_dev_info->target_map_idx[i].port_idx);
        if (local_port >= bdp_ctx->dev_num ||
            bdp_ctx->p_ctxs[local_port] == NULL ||
            target_port >= ex_info->dev_num ||
            is_empty_eid(&ex_info->slave_id[target_port].eid)) {
            URMA_LOG_DEBUG("BONDP skip route (%d %d)\n", local_port, target_port);
            continue;
        }
        p_rjetty.jetty_id = ex_info->slave_id[target_port];
        bdp_tjetty->p_tjetty[local_port][target_port] =
            urma_import_jetty(bdp_ctx->p_ctxs[local_port], &p_rjetty, rjetty_token);
        if (bdp_tjetty->p_tjetty[local_port][target_port] == NULL) {
            URMA_LOG_ERR("Failed to import direct tjetty %d %d\n", local_port, target_port);
            return -1;
        }
        bdp_tjetty->local_valid[local_port] = true;
        bdp_tjetty->target_valid[target_port] = true;
        bdp_tjetty->direct_tjetty_port[i] = target_port;
        bdp_tjetty->direct_local_port[i] = local_port;
        bdp_tjetty->direct_route_num++;
    }
    if (bdp_tjetty->direct_route_num == 0) {
        /* Because direct_route_num == 0, so we didn't import any route by now */
        /* We can directly return */
        URMA_LOG_ERR("No valid route when importing direct route\n");
        return -1;
    }
    return 0;
}

static inline bool is_well_known_jetty_id(int jetty_id)
{
    return jetty_id > 0 && jetty_id < BONDP_MAX_WELL_KNOWN_JETTY_ID;
}
/**
 * Use topo info to find target primary eid and then import well known jetty.
 * To be implemented: After implementing message channel in bondp, we can exchange ex_id for well known jetty.
 * Then the import process for the well-known jetty and regular jetty can be unified
 */
static int import_well_known_jetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjetty_t *rjetty, urma_token_t *rjetty_token)
{
    urma_rjetty_t p_rjetty = *rjetty;
    p_rjetty.tp_type = URMA_CTP; /* only support multi-path mode and use CTP */

    topo_info_t *topo_info = get_topo_info_by_bonding_eid(bdp_ctx->topo_map, &rjetty->jetty_id.eid);
    if (topo_info == NULL) {
        URMA_LOG_ERR("Failed to get topo info in import jetty\n");
        return -1;
    }

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            URMA_LOG_ERR("Primary dev has NULL ctx\n");
            return -1;
        }
        bdp_tjetty->local_valid[i] = true;
        p_rjetty.jetty_id.eid = *(urma_eid_t *)topo_info->io_die_info[i].primary_eid;
        if (is_empty_eid(&p_rjetty.jetty_id.eid)) {
            URMA_LOG_WARN("Primary dev has NULL rjetty eid\n");
            return -1;
        }
        bdp_tjetty->target_valid[i] = true;
        p_rjetty.jetty_id.id = p_rjetty.jetty_id.id; /* Well known jetty has same jetty_id.id */
        bdp_tjetty->p_tjetty[i][i] = urma_import_jetty(bdp_ctx->p_ctxs[i], &p_rjetty, rjetty_token);
        if (bdp_tjetty->p_tjetty[i][i] == NULL) {
            URMA_LOG_ERR("Failed to import primary tjetty %d %d\n", i, i);
            return -1;
        }
        URMA_LOG_ERR("BONDP import target wk pjetty: (" EID_FMT ", %u)", EID_ARGS(p_rjetty.jetty_id.eid),
            p_rjetty.jetty_id.id);
    }
    return 0;
}

static bool is_same_eid(urma_eid_t *eid1, urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

static int import_loopback_matrix_jetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *rjetty_id_info,
    urma_rjetty_t *rjetty, urma_token_t *rjetty_token)
{
    urma_rjetty_t p_rjetty = *rjetty;
    if (p_rjetty.trans_mode == URMA_TM_UM) {
        p_rjetty.tp_type = URMA_UTP;
    } else {
        p_rjetty.tp_type = URMA_RTP;
    }
    /* Select the first available port EID for import, so start traversing from index 2. */
    for (int i = IODIE_NUM; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        p_rjetty.jetty_id = rjetty_id_info->slave_id[i];
        bdp_tjetty->p_tjetty[i][i] = urma_import_jetty(bdp_ctx->p_ctxs[i], &p_rjetty, rjetty_token);
        if (bdp_tjetty->p_tjetty[i][i] == NULL) {
            URMA_LOG_ERR("Failed to import jetty.\n");
            return -1;
        }
        bdp_tjetty->direct_local_port[0] = i;
        bdp_tjetty->direct_tjetty_port[0] = i;
        bdp_tjetty->direct_route_num = 1;
        break;
    }
    return 0;
}

static int bondp_import_vjetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *rjetty_token,
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
    urma_cmd_udrv_priv_t udata = {
        .in_addr = 0,
        .in_len = 0,
        .out_addr = (uint64_t)udata_out,
        .out_len = sizeof(*udata_out),
    };

    return urma_cmd_import_jetty(ctx, &bdp_tjetty->v_tjetty, &cfg, &udata);
}

static int bondp_import_pjetty(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjetty_t *rjetty, urma_token_t *rjetty_token, urma_bond_id_info_out_t *udata_out)
{
    int ret = 0;
    if (bdp_tjetty->is_in_matrix_server) {
        if (is_same_eid(&bdp_ctx->v_ctx.eid, &rjetty->jetty_id.eid)) {
            if (udata_out->is_multipath) {
                URMA_LOG_ERR("Target jetty is multipath mode, which does not support Loopback.\n");
                return -1;
            }
            bdp_tjetty->local_dev_num = bdp_ctx->dev_num;
            bdp_tjetty->target_dev_num = bdp_ctx->dev_num;
            bdp_tjetty->is_multipath = false; /* only support single-path mode */
            ret = import_loopback_matrix_jetty(bdp_ctx, bdp_tjetty, udata_out, rjetty, rjetty_token);
        } else {
            if (is_well_known_jetty_id(rjetty->jetty_id.id)) {
                int iodie_num = is_single_dev_mode(&bdp_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : IODIE_NUM;
                bdp_tjetty->local_dev_num = iodie_num;
                bdp_tjetty->target_dev_num = iodie_num;
                bdp_tjetty->is_multipath = true;
                ret = import_well_known_jetty(bdp_ctx, bdp_tjetty, rjetty, rjetty_token);
            } else {
                bdp_tjetty->is_multipath = udata_out->is_multipath;
                if (bdp_tjetty->is_multipath) {
                    int iodie_num = is_single_dev_mode(&bdp_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : IODIE_NUM;
                    bdp_tjetty->local_dev_num = iodie_num;
                    bdp_tjetty->target_dev_num = iodie_num;
                    ret = import_primary_ports(bdp_ctx, bdp_tjetty, udata_out, rjetty, rjetty_token);
                } else {
                    bdp_tjetty->local_dev_num = bdp_ctx->dev_num;
                    bdp_tjetty->target_dev_num = udata_out->dev_num;
                    ret = import_direct_route(bdp_ctx, bdp_tjetty, udata_out, rjetty, rjetty_token);
                }
            }
        }
    } else {
        bdp_tjetty->local_dev_num = bdp_ctx->dev_num;
        bdp_tjetty->target_dev_num = udata_out->dev_num;
        ret = import_jetty_default(bdp_ctx, bdp_tjetty, udata_out, rjetty, rjetty_token);
    }
    return ret;
}

static int bondp_unimport_vjetty(bondp_target_jetty_t *bdp_tjetty)
{
    return urma_cmd_unimport_jetty(&bdp_tjetty->v_tjetty);
}

static int bondp_unimport_pjetty(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;

    memset(bdp_tjetty->local_valid, 0, sizeof(bdp_tjetty->local_valid));
    memset(bdp_tjetty->target_valid, 0, sizeof(bdp_tjetty->target_valid));

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (!bdp_tjetty->p_tjetty[i][j]) {
                continue;
            }
            if (urma_unimport_jetty(bdp_tjetty->p_tjetty[i][j]) != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unimport jetty [%u](%d, %d)\n", bdp_tjetty->v_tjetty.id.id, i, j);
                ret = URMA_FAIL;
            }
            bdp_tjetty->p_tjetty[i][j] = NULL;
        }
    }
    return ret;
}

static int add_remote_jetty_id_info(bondp_context_t *bdp_ctx, urma_bond_id_info_out_t *udata_out)
{
    pthread_rwlock_wrlock(&bdp_ctx->remote_p2v_jetty_id_table.lock);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (is_empty_eid(&udata_out->slave_id[i].eid)) {
            continue;
        }
        int ret = bdp_r_p2v_jetty_id_table_add_without_lock(&bdp_ctx->remote_p2v_jetty_id_table,
            &udata_out->slave_id[i], REMOTE_JETTY, &udata_out->base_id);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to add bdp_r_p2v_vjetty_id[%d]: ret: %d, jetty_id: " URMA_JETTY_ID_FMT "\n", i, ret,
                URMA_JETTY_ID_ARGS(&udata_out->slave_id[i]));
            for (int j = 0; j < i; ++j) {
                (void)bdp_r_p2v_jetty_id_table_del_without_lock(&bdp_ctx->remote_p2v_jetty_id_table,
                    &udata_out->slave_id[j], REMOTE_JETTY);
            }
            pthread_rwlock_unlock(&bdp_ctx->remote_p2v_jetty_id_table.lock);
            return -1;
        }
        URMA_LOG_INFO("Succeed to add bdp_r_p2v_vjetty_id[%d]: ret: %d, jetty_id: " URMA_JETTY_ID_FMT "\n", i, 0,
            URMA_JETTY_ID_ARGS(&udata_out->slave_id[i]));
    }
    pthread_rwlock_unlock(&bdp_ctx->remote_p2v_jetty_id_table.lock);
    return 0;
}

static bool bondp_import_jetty_is_valid(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjetty_t *rjetty, urma_bond_id_info_out_t *udata_out)
{
    if (is_in_matrix_server(bdp_ctx)) {
        /* Only allow the following combinations: */
        /* RC + single_path */
        /* RM + multi_path  */
        /* RC + multi_path  */
        /* Ignore rjetty.flag.bs.ctp, and set it according to jetty multipath mode. */
        if (!((rjetty->trans_mode == URMA_TM_RC && !udata_out->is_multipath) ||
              (rjetty->trans_mode == URMA_TM_RM && udata_out->is_multipath) ||
              (rjetty->trans_mode == URMA_TM_RC && udata_out->is_multipath))) {
            URMA_LOG_ERR("Invalid import! Only support RC + single_path, RM + multi_path, RC + multi_path."
                "rjetty->trans_mode = %d, is_multipath = %d, rjetty->tp_type = %d.\n",
                rjetty->trans_mode, udata_out->is_multipath, rjetty->tp_type);
            return false;
        }
    }
    if (!is_valid_dev_num(udata_out->dev_num)) {
        URMA_LOG_ERR("Invalid rjetty dev num: %d\n", udata_out->dev_num);
        return false;
    }
    if (bdp_tjetty->is_in_matrix_server != udata_out->is_in_matrix_server) {
        URMA_LOG_ERR("The in_matrix_server attribute of jetty is different\n");
        return false;
    }
    if (udata_out->is_in_matrix_server && !udata_out->is_multipath && rjetty->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Loopback in single-path mode only supports RC mode. Rjetty is %d\n", rjetty->trans_mode);
        return false;
    }
    return true;
}

urma_target_jetty_t *bondp_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid param ctx\n");
        return NULL;
    }

    bondp_target_jetty_t *bdp_tjetty = calloc(1, sizeof(bondp_target_jetty_t));
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc target jetty\n");
        return NULL;
    }
    bdp_tjetty->is_in_matrix_server = is_in_matrix_server(bdp_ctx);

    urma_bond_id_info_out_t udata_out = {0};
    if (bondp_import_vjetty(ctx, rjetty, token_value, bdp_tjetty, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vjetty, ["EID_FMT"]:%u\n",
            EID_ARGS(rjetty->jetty_id.eid), rjetty->jetty_id.id);
        goto free_bondp_tjetty;
    }

    if (!bondp_import_jetty_is_valid(bdp_ctx, bdp_tjetty, rjetty, &udata_out)) {
        errno = EINVAL;
        goto unimport_vjetty;
    }

    if (bondp_import_pjetty(bdp_ctx, bdp_tjetty, rjetty, token_value, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import pjetty\n");
        goto unimport_pjetty;
    }

    bdp_tjetty->rvjetty_id_info = udata_out;

    if (add_remote_jetty_id_info(bdp_ctx, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to add remote jetty id info\n");
        goto unimport_pjetty;
    }

    URMA_LOG_INFO("Successfully imported target jetty: " URMA_JETTY_ID_FMT, URMA_JETTY_ID_ARGS(&rjetty->jetty_id));

    return &bdp_tjetty->v_tjetty;

unimport_pjetty:
    bondp_unimport_pjetty(bdp_tjetty);
unimport_vjetty:
    bondp_unimport_vjetty(bdp_tjetty);
free_bondp_tjetty:
    free(bdp_tjetty);
    return NULL;
}

urma_status_t bondp_unimport_jetty(urma_target_jetty_t *target_jetty)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jetty, bondp_target_jetty_t, v_tjetty);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(target_jetty->urma_ctx, bondp_context_t, v_ctx);
    urma_status_t ret = URMA_SUCCESS;

    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid bdp tjetty\n");
        return URMA_EINVAL;
    }

    pthread_rwlock_wrlock(&bdp_ctx->remote_p2v_jetty_id_table.lock);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (is_empty_eid(&bdp_tjetty->rvjetty_id_info.slave_id[i].eid)) {
            continue;
        }
        int del_ret = bdp_r_p2v_jetty_id_table_del_without_lock(&bdp_ctx->remote_p2v_jetty_id_table,
            &bdp_tjetty->rvjetty_id_info.slave_id[i], REMOTE_JETTY);
        if (del_ret != 0) {
            URMA_LOG_ERR("Failed to del bdp_r_p2v_vjetty_id[%d]: ret: %d, jetty_id: " URMA_JETTY_ID_FMT "\n",
            i, del_ret, URMA_JETTY_ID_ARGS(&bdp_tjetty->rvjetty_id_info.slave_id[i]));
            ret = URMA_FAIL;
        }
    }
    pthread_rwlock_unlock(&bdp_ctx->remote_p2v_jetty_id_table.lock);

    if (bondp_unimport_pjetty(bdp_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport pjetty\n");
        ret = URMA_FAIL;
    }
    if (bondp_unimport_vjetty(bdp_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport vjetty\n");
        ret = URMA_FAIL;
    }
    free(bdp_tjetty);
    return ret;
}

/**
 * Only bind jetty p_jetty[i], p_tjetty[i][i].
 * Set vjetty and tjetty's remote_jetty.
 */
static urma_status_t bind_jetty_default(bondp_comp_t *bdp_jetty, bondp_target_jetty_t *bdp_tjetty)
{
    int i = 0;
    int ret = 0;
    for (i = 0; i < bdp_tjetty->local_dev_num && i < bdp_tjetty->target_dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL || bdp_tjetty->p_tjetty[i][i] == NULL) {
            continue;
        }
        ret = urma_bind_jetty(bdp_jetty->p_jetty[i], bdp_tjetty->p_tjetty[i][i]);
        if (ret) {
            URMA_LOG_ERR("bondp bind jetty failed (%d, %d)\n", i, i);
            goto UNBIND;
        }
        bdp_jetty->p_jetty[i]->remote_jetty = bdp_tjetty->p_tjetty[i][i];
    }
    bdp_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
    return URMA_SUCCESS;
UNBIND:
    for (int p = 0; p < i; ++p) {
        if (bdp_tjetty->p_tjetty[p][p] != NULL) {
            urma_unbind_jetty(bdp_jetty->p_jetty[p]);
        }
    }
    return URMA_FAIL;
}

static urma_status_t bind_jetty_single_path(bondp_comp_t *bdp_jetty, bondp_target_jetty_t *bdp_tjetty)
{
    int i = 0;
    int ret = 0;
    int local_port = 0;
    int target_port = 0;
    bool has_valid_route = false;
    if (!is_same_eid(&bdp_jetty->v_jetty.jetty_id.eid, &bdp_tjetty->v_tjetty.id.eid) &&
        !has_direct_route(bdp_jetty->bondp_ctx->topo_map, &bdp_tjetty->v_tjetty.id.eid)) {
        URMA_LOG_ERR("No direct route to target jetty\n");
        return URMA_EINVAL;
    }
    for (i = 0; i < bdp_tjetty->direct_route_num; ++i) {
        //! Need to check device valid to handle device failure
        local_port = bdp_tjetty->direct_local_port[i];
        target_port = bdp_tjetty->direct_tjetty_port[i];
        if (bdp_jetty->p_jetty[local_port] == NULL || bdp_tjetty->p_tjetty[local_port][target_port] == NULL) {
            URMA_LOG_WARN("Invalid local jetty or target jetty in binding single path (%d, %d)\n",
                local_port, target_port);
            continue;
        }
        ret = urma_bind_jetty(bdp_jetty->p_jetty[local_port], bdp_tjetty->p_tjetty[local_port][target_port]);
        if (ret) {
            URMA_LOG_ERR("bondp bind jetty failed (%d, %d)\n", local_port, target_port);
            return URMA_FAIL;
        }
        has_valid_route = true;
        bdp_jetty->p_jetty[local_port]->remote_jetty = bdp_tjetty->p_tjetty[local_port][target_port];
        break;
    }
    if (!has_valid_route) {
        URMA_LOG_ERR("No valid direct route\n");
        return URMA_FAIL;
    }
    bdp_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
    bjetty_ctx_t *bjetty_ctx = (bjetty_ctx_t *)(bdp_jetty->comp_ctx); /* Not NULL guaranteed by bondp_create_jetty */
    bjetty_ctx->direct_local_port = local_port;
    bjetty_ctx->direct_target_port = target_port;
    return URMA_SUCCESS;
}

urma_status_t bondp_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);

    if (!is_valid_bondp_comp(bdp_jetty)) {
        URMA_LOG_ERR("Invalid param jetty\n");
        return URMA_EINVAL;
    }
    if (bdp_jetty->is_multipath && memcmp(&jetty->jetty_id.eid, &tjetty->id.eid, sizeof(urma_eid_t)) == 0) {
        URMA_LOG_ERR("Loopback not supported in multipath.\n");
        return URMA_EINVAL;
    }
    if (jetty->remote_jetty) {
        URMA_LOG_ERR("Jetty already has a binded target jetty\n");
        return URMA_EINVAL;
    }
    if (is_in_matrix_server(bdp_jetty->bondp_ctx) != bdp_tjetty->is_in_matrix_server) {
        URMA_LOG_ERR("The in_matrix_server attributes of jetty and tjetty are different\n");
        return URMA_EINVAL;
    }
    if (is_in_matrix_server(bdp_jetty->bondp_ctx) && bdp_jetty->is_multipath != bdp_tjetty->is_multipath) {
        URMA_LOG_ERR("The is_multipath attributes of jetty and tjetty are different\n");
        return URMA_EINVAL;
    }
    if (!is_in_matrix_server(bdp_jetty->bondp_ctx) || is_multipath_comp(bdp_jetty)) {
        return bind_jetty_default(bdp_jetty, bdp_tjetty);
    }
    return bind_jetty_single_path(bdp_jetty, bdp_tjetty);
}

urma_status_t bondp_unbind_jetty(urma_jetty_t *jetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_target_jetty_t *tjetty = jetty->remote_jetty;
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);
    urma_status_t ret = URMA_SUCCESS;

    if (!is_valid_bondp_comp(bdp_jetty)) {
        URMA_LOG_ERR("Invalid param jetty\n");
        return URMA_EINVAL;
    }
    for (int i = 0; i < bdp_tjetty->local_dev_num && bdp_tjetty->target_dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        if (bdp_jetty->p_jetty[i]->remote_jetty == NULL) {
            URMA_LOG_INFO("BONDP no remote jetty for pjetty[%d]\n", i);
            continue;
        }
        if (urma_unbind_jetty(bdp_jetty->p_jetty[i]) != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to unbind tjetty [%u](%d, %d)\n", bdp_tjetty->v_tjetty.id.id, i, i);
            ret = URMA_FAIL;
        }
        bdp_jetty->p_jetty[i]->remote_jetty = NULL;
    }
    bdp_jetty->v_jetty.remote_jetty = NULL;
    ((bjetty_ctx_t *)bdp_jetty->comp_ctx)->direct_local_port = -1;
    ((bjetty_ctx_t *)bdp_jetty->comp_ctx)->direct_target_port = -1;
    return ret;
}

static int import_jfr_default(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *ex_info, urma_rjfr_t *rjfr, urma_token_t *rjfr_token)
{
    bool has_import = false;
    urma_rjfr_t p_rjfr = *rjfr;
    p_rjfr.tp_type = URMA_CTP;

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        bdp_tjetty->local_valid[i] = true;
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (is_empty_eid(&ex_info->slave_id[j].eid)) {
                continue;
            }
            bdp_tjetty->target_valid[i] = true;
            p_rjfr.jfr_id = ex_info->slave_id[j];
            bdp_tjetty->p_tjetty[i][j] = urma_import_jfr(bdp_ctx->p_ctxs[i], &p_rjfr, rjfr_token);
            if (bdp_tjetty->p_tjetty[i][j] == NULL) {
                /* Allow unimported p_tjetty */
                continue;
            }
            has_import = true;
        }
    }
    if (!has_import) {
        URMA_LOG_ERR("Failed to import jfr, no valid route to rjfr\n");
        return -1;
    }
    return 0;
}

static int import_primary_ports_jfr(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *ex_info, urma_rjfr_t *rjfr, urma_token_t *rjfr_token)
{
    urma_rjfr_t p_rjfr = *rjfr;
    p_rjfr.tp_type = URMA_CTP;

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            URMA_LOG_WARN("Primary dev has NULL ctx\n");
            continue;
        }
        if (is_empty_eid(&ex_info->slave_id[i].eid)) {
            URMA_LOG_WARN("Primary dev has NULL rjetty eid\n");
            continue;
        }
        bdp_tjetty->target_valid[i] = true;
        p_rjfr.jfr_id = ex_info->slave_id[i];
        bdp_tjetty->p_tjetty[i][i] = urma_import_jfr(bdp_ctx->p_ctxs[i], &p_rjfr, rjfr_token);
        if (bdp_tjetty->p_tjetty[i][i] == NULL) {
            URMA_LOG_ERR("Failed to import primary tjfr %d %d\n", i, i);
            return -1;
        }
    }
    return 0;
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
    urma_cmd_udrv_priv_t udata = {
        .in_addr = 0,
        .in_len = 0,
        .out_addr = (uint64_t)udata_out,
        .out_len = sizeof(*udata_out),
    };

    return urma_cmd_import_jfr(ctx, &bdp_tjetty->v_tjetty, &cfg, &udata);
}

static int bondp_import_pjfr(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjfr_t *rjfr, urma_token_t *token_value, urma_bond_id_info_out_t *udata_out)
{
    int ret = 0;

    if (is_in_matrix_server(bdp_ctx)) {
        bdp_tjetty->is_in_matrix_server = true;
        bdp_tjetty->is_multipath = true; /* JFR currently only support multipath mode */

        if (bdp_tjetty->is_multipath) {
            int iodie_num = is_single_dev_mode(&bdp_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : IODIE_NUM;
            bdp_tjetty->local_dev_num = iodie_num;
            bdp_tjetty->target_dev_num = iodie_num;
            ret = import_primary_ports_jfr(bdp_ctx, bdp_tjetty, udata_out, rjfr, token_value);
        } else {
            URMA_LOG_ERR("Currently, jfr does not support single-path mode.\n");
            return -1;
        }
    } else {
        bdp_tjetty->local_dev_num = bdp_ctx->dev_num;
        bdp_tjetty->target_dev_num = udata_out->dev_num;
        ret = import_jfr_default(bdp_ctx, bdp_tjetty, udata_out, rjfr, token_value);
    }
    return ret;
}

static int bondp_unimport_vjfr(bondp_target_jetty_t *bdp_tjetty)
{
    return urma_cmd_unimport_jfr(&bdp_tjetty->v_tjetty);
}

static int bondp_unimport_pjfr(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;

    for (int i = 0; i < bdp_tjetty->local_dev_num; ++i) {
        for (int j = 0; j < bdp_tjetty->target_dev_num; ++j) {
            if (!bdp_tjetty->p_tjetty[i][j]) {
                continue;
            }
            if (urma_unimport_jfr(bdp_tjetty->p_tjetty[i][j]) != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unimport jfr [%u](%d, %d)\n", bdp_tjetty->v_tjetty.id.id, i, j);
                ret = URMA_FAIL;
            }
            bdp_tjetty->p_tjetty[i][j] = NULL;
        }
    }
    return ret;
}

urma_target_jetty_t *bondp_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid param ctx\n");
        return NULL;
    }

    bondp_target_jetty_t *bdp_tjetty = calloc(1, sizeof(bondp_target_jetty_t));
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc target jetty\n");
        return NULL;
    }
    bdp_tjetty->is_in_matrix_server = is_in_matrix_server(bdp_ctx);

    urma_bond_id_info_out_t udata_out = {0};
    if (bondp_import_vjfr(ctx, rjfr, token_value, bdp_tjetty, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vjetty, ["EID_FMT"]:%u\n",
            EID_ARGS(rjfr->jfr_id.eid), rjfr->jfr_id.id);
        goto free_bondp_tjetty;
    }

    if (bdp_tjetty->is_in_matrix_server != udata_out.is_in_matrix_server) {
        URMA_LOG_ERR("The in_matrix_server attribute of jfr is different\n");
        goto unimport_vjfr;
    }

    if (bondp_import_pjfr(bdp_ctx, bdp_tjetty, rjfr, token_value, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import pjetty\n");
        goto unimport_pjfr;
    }

    return &bdp_tjetty->v_tjetty;

unimport_pjfr:
    bondp_unimport_pjfr(bdp_tjetty);
unimport_vjfr:
    bondp_unimport_vjfr(bdp_tjetty);
free_bondp_tjetty:
    free(bdp_tjetty);
    return NULL;
}

urma_status_t bondp_unimport_jfr(urma_target_jetty_t *target_jfr)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(target_jfr, bondp_target_jetty_t, v_tjetty);
    urma_status_t ret = URMA_SUCCESS;

    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid bdp tjetty\n");
        return URMA_EINVAL;
    }
    if (bondp_unimport_pjfr(bdp_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport pjfr\n");
        ret = URMA_FAIL;
    }
    if (bondp_unimport_vjfr(bdp_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport vjfr\n");
        ret = URMA_FAIL;
    }
    free(bdp_tjetty);
    return ret;
}

urma_status_t bondp_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_comp_t, v_jfc);
    bool success_once = false;

    if (!is_valid_bondp_comp(bdp_jfc)) {
        URMA_LOG_ERR("Invalid param");
        return URMA_EINVAL;
    }

    if (bdp_jfc->v_jfc.jfc_cfg.jfce == NULL) {
        URMA_LOG_ERR("Failed to rearm jfc: JFCE is NULL\n");
        return URMA_EINVAL;
    }

    for (int i = 0; i < bdp_jfc->dev_num; ++i) {
        if (!bdp_jfc->p_jfc[i]) {
            continue;
        }
        urma_status_t ret = urma_rearm_jfc(bdp_jfc->p_jfc[i], solicited_only);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_WARN("Failed to rearm jfc %d, ret:%d\n", i, ret);
            continue;
        }
        success_once = true;
    }

    return success_once ? URMA_SUCCESS : URMA_FAIL;
}

int bondp_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[])
{
    bondp_comp_t *bdp_jfce = CONTAINER_OF_FIELD(jfce, bondp_comp_t, v_jfce);
    bondp_hash_table_t *v_jfce_table = bdp_jfce->comp_ctx;
    bdp_vjfce_info_t *node = NULL;

    if (!is_valid_bondp_comp(bdp_jfce)) {
        URMA_LOG_ERR("Invalid param");
        return URMA_EINVAL;
    }

    if (v_jfce_table == NULL) {
        URMA_LOG_ERR("v_jfce_table is NULL.\n");
        return -1;
    }
    struct epoll_event events[BOND_EPOLL_NUM] = {0};
    int epoll_event_limit = jfc_cnt < BOND_EPOLL_NUM ? jfc_cnt : BOND_EPOLL_NUM;
    int num = epoll_wait(bdp_jfce->v_jfce.fd, events, epoll_event_limit, time_out);
    if (num < 0 || num > epoll_event_limit) {
        URMA_LOG_ERR("Epoll wait err, ret:%d.\n", num);
        return -1;
    } else if (num == 0) {
        return 0;
    }

    int actual_num = 0;
    (void)pthread_rwlock_rdlock(&v_jfce_table->lock);
    for (int i = 0; i < num; i++) {
        int fd = events[i].data.fd;
        node = bdp_vjfce_info_table_lookup(v_jfce_table, fd);
        if (node == NULL) {
            URMA_LOG_WARN("Fail to find fd:%d from table.\n", fd);
            continue;
        }

        urma_jfc_t *p_jfc = NULL;
        int p_num = urma_wait_jfc(node->p_jfce, 1, 0, &p_jfc);
        if (p_num <= 0) {
            URMA_LOG_WARN("Cannot wait p_jfc, skip\n");
            continue;
        }

        uint32_t nevents = 1;
        urma_ack_jfc(&p_jfc, &nevents, 1);

        urma_jfc_t *v_jfc = (urma_jfc_t *)p_jfc->jfc_cfg.user_ctx;
        if (v_jfc == NULL) {
            URMA_LOG_WARN("v_jfc is NULL, pjfc_id:%u.\n", p_jfc->jfc_id.id);
            continue;
        }
        jfc[actual_num++] = v_jfc;
        URMA_LOG_DEBUG("p_jfc:%p, add v_jfc:%p", p_jfc, v_jfc);
    }
    (void)pthread_rwlock_unlock(&v_jfce_table->lock);
    return actual_num;
}

void bondp_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt)
{
    // for now we do not need to call bondp_ack_multiple_die_jfc
    return;
}

static void *get_jetty_and_ret(uint64_t addr, int *ret)
{
    if (addr == 0) {
        *ret = -1;
        return NULL;
    }

    *ret = 0;
    return (void *)addr;
}

static int init_elment_vjetty(urma_async_event_t *v_event, urma_async_event_t *p_event)
{
    int ret = 0;

    switch (p_event->event_type) {
        case URMA_EVENT_JFC_ERR:
            v_event->element.jfc = (urma_jfc_t *)get_jetty_and_ret(
                p_event->element.jfc->jfc_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JFS_ERR:
            v_event->element.jfs = (urma_jfs_t *)get_jetty_and_ret(
                p_event->element.jfs->jfs_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JFR_ERR:
        case URMA_EVENT_JFR_LIMIT:
            v_event->element.jfr = (urma_jfr_t *)get_jetty_and_ret(
                p_event->element.jfr->jfr_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JETTY_ERR:
        case URMA_EVENT_JETTY_LIMIT:
            v_event->element.jetty = (urma_jetty_t *)get_jetty_and_ret(
                p_event->element.jetty->jetty_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JETTY_GRP_ERR:
        case URMA_EVENT_PORT_ACTIVE:
        case URMA_EVENT_PORT_DOWN:
        case URMA_EVENT_DEV_FATAL:
            break;
        case URMA_EVENT_EID_CHANGE:
            v_event->element.eid_idx = 0;
            break;
        default:
            break;
    }
    return ret;
}

urma_status_t bondp_get_async_event(urma_context_t *ctx, urma_async_event_t *v_event)
{
    if (ctx == NULL || ctx->async_fd < 0 || v_event == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }
    struct epoll_event event;
    urma_async_event_t *p_event;
    urma_status_t status;

    int nfds = epoll_wait(ctx->async_fd, &event, 1, 0);
    if (nfds == -1) {
        URMA_LOG_ERR("epoll_wait no event or err.\n");
        return URMA_EVENT_ELR_ERR;
    }

    if ((event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        URMA_LOG_ERR("bondp get error epoll_event: 0x%x.\n", event.events);
        return URMA_EVENT_ELR_ERR;
    }
    if (event.events & EPOLLIN) {
        urma_context_t *p_contex = (urma_context_t *)event.data.ptr;
        p_event = calloc(1, sizeof(urma_async_event_t));
        if (p_event == NULL) {
            return URMA_ENOMEM;
        }
        status = urma_get_async_event(p_contex, p_event);
        if (status != URMA_SUCCESS) {
            free(p_event);
            URMA_LOG_ERR("bondp failed to get async event, ret = %u\n", status);
            return status;
        }
        v_event->urma_ctx = ctx;
        if (init_elment_vjetty(v_event, p_event) != 0) {
            free(p_event);
            URMA_LOG_ERR("failed to get invalid jetty.\n");
            return URMA_EINVAL;
        }
        v_event->event_type = p_event->event_type;
        v_event->priv = p_event;
        return URMA_SUCCESS;
    }
    return URMA_FAIL;
}

void bondp_ack_async_event(urma_async_event_t *event)
{
    if (event->priv == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return;
    }
    urma_async_event_t *p_event = (urma_async_event_t *)event->priv;
    urma_ack_async_event(p_event);
    URMA_LOG_INFO("ack v_event: %p, p_event: %p\n", event, p_event);
    event->priv = NULL;
    free(p_event);
}
