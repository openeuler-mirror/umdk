/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of Bonding API
 * Author: Ma Chuan
 * Create: 2025-02-06
 * Note:
 * History: 2025-02-06
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "ub_util.h"
#include "ubagg_ioctl.h"
#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_log.h"
#include "urma_provider.h"

#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_hash_table.h"
#include "bondp_provider_ops.h"
#include "bondp_segment.h"
#include "bondp_types.h"
#include "urma_ubagg.h"

#include "bondp_api.h"
#include "bondp_health_check.h"
#include "ub_get_clock.h"
#include "urma_perf.h"

typedef struct bondp_create_vjetty_udata {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    bool is_multipath; // deprecated
    uint8_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
} bondp_create_vjetty_udata_t;

static int bondp_init_connection_table(bondp_comp_t *bdp_comp)
{
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_comp->members[i] == NULL) {
            bdp_comp->pjettys_error_done[i] = PJETTY_SUSPEND_DONE | PJETTY_FLUSH_ERROR_DONE;
        }
    }

    if (bdp_v_conn_table_create(&bdp_comp->v_conn_table, BONDP_MAX_NUM_JETTYS)) {
        return -1;
    }
    return 0;
}

static void bondp_uninit_connection_table(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return;
    }
    bondp_hash_table_destroy(&bdp_comp->v_conn_table);
}

typedef bondp_create_vjetty_udata_t bondp_create_vjfr_udata_t;

#define BOND_EPOLL_NUM (32)

static int bondp_create_pjfce(bondp_context_t *bdp_ctx, bondp_jfce_t *bdp_jfce)
{
    for (int i = 0; i < bdp_jfce->dev_num; i++) {
        if (!bdp_ctx->p_ctxs[i]) {
            continue;
        }

        urma_jfce_t *jfce = urma_create_jfce(bdp_ctx->p_ctxs[i]);
        if (jfce == NULL) {
            URMA_LOG_ERR("Failed to create pjfce %d.\n", i);
            return -1;
        }
        bdp_jfce->p_jfce[i] = jfce;

        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = jfce->fd;
        if (epoll_ctl(bdp_jfce->v_jfce.fd, EPOLL_CTL_ADD, jfce->fd, &ev) != 0) {
            URMA_LOG_ERR("Fail to add fd:%d to epoll fd:%d.\n", jfce->fd, bdp_jfce->v_jfce.fd);
            return -1;
        }
    }

    return 0;
}

static int bondp_delete_pjfce(bondp_jfce_t *bdp_jfce)
{
    int ret = 0;

    for (int i = 0; i < bdp_jfce->dev_num; i++) {
        if (bdp_jfce->p_jfce[i] == NULL) {
            continue;
        }

        struct epoll_event ev = {0};
        if (epoll_ctl(bdp_jfce->v_jfce.fd, EPOLL_CTL_DEL, bdp_jfce->p_jfce[i]->fd, &ev) != 0) {
            URMA_LOG_WARN("non-zero return value of EPOLL_CTL_DEL, ret = %d.\n", errno);
        }

        int p_ret = urma_delete_jfce(bdp_jfce->p_jfce[i]);
        if (p_ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to delete pjfce %d, ret: %d.\n", i, p_ret);
            ret = p_ret;
        }
        bdp_jfce->p_jfce[i] = NULL;
    }

    return ret;
}

static int bondp_create_vjfce(bondp_context_t *bdp_ctx, bondp_jfce_t *bdp_jfce)
{
    int epoll_fd = -1;

    bdp_jfce->v_jfce.urma_ctx = &bdp_ctx->v_ctx;
    epoll_fd = epoll_create(BOND_EPOLL_NUM);
    if (epoll_fd < 0) {
        URMA_LOG_ERR("Fail to create epoll_fd for vjfce.\n");
        return -1;
    }
    bdp_jfce->v_jfce.fd = epoll_fd;

    bdp_jfce->v_jfce.ref.atomic_cnt = 0;
    return 0;
}

static int bondp_delete_vjfce(bondp_jfce_t *bdp_jfce)
{
    close(bdp_jfce->v_jfce.fd);
    return 0;
}

urma_jfce_t *bondp_create_jfce(urma_context_t *ctx)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid bond ctx.\n");
        return NULL;
    }

    bondp_jfce_t *bdp_jfce = (bondp_jfce_t *)calloc(1, sizeof(bondp_jfce_t));
    if (bdp_jfce == NULL) {
        return NULL;
    }
    bdp_jfce->dev_num = bdp_ctx->dev_num;
    bdp_jfce->bondp_ctx = bdp_ctx;
    atomic_init(&bdp_jfce->use_cnt.atomic_cnt, 0);

    if (bondp_create_vjfce(bdp_ctx, bdp_jfce)) {
        URMA_LOG_ERR("Failed to create vjfce.\n");
        goto FREE_JFCE;
    }

    if (bondp_create_pjfce(bdp_ctx, bdp_jfce)) {
        URMA_LOG_ERR("Failed to create pjfce.\n");
        goto DELETE_PJFCE;
    }
    URMA_LOG_INFO("Finish to create jfce, dev_name: %s, eid_idx: %u.\n",
                  ctx->dev->name, ctx->eid_index);

    return &bdp_jfce->v_jfce;

DELETE_PJFCE:
    (void)bondp_delete_pjfce(bdp_jfce);
    (void)bondp_delete_vjfce(bdp_jfce);
FREE_JFCE:
    free(bdp_jfce);
    return NULL;
}

urma_status_t bondp_delete_jfce(urma_jfce_t *jfce)
{
    bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(jfce, bondp_jfce_t, v_jfce);
    urma_status_t ret = URMA_SUCCESS;

    unsigned long use_cnt = atomic_load(&bdp_jfce->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        URMA_LOG_ERR("Failed to delete jfce[%d], still in use. use_cnt: %lu\n", jfce->fd, use_cnt);
        return URMA_EAGAIN;
    }

    if (bondp_delete_pjfce(bdp_jfce) != 0) {
        URMA_LOG_ERR("Failed to delete pjfce.\n");
        ret = URMA_FAIL;
    }

    if (bondp_delete_vjfce(bdp_jfce) != 0) {
        URMA_LOG_ERR("Failed to delete vjfce.\n");
        ret = URMA_FAIL;
    }

    free(bdp_jfce);
    return ret;
}

static int bondp_create_vjfc(urma_context_t *ctx, bondp_jfc_t *bdp_jfc, urma_jfc_cfg_t *jfc_cfg)
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

static int bondp_create_pjfc(bondp_context_t *bdp_ctx, bondp_jfc_t *bdp_jfc, urma_jfc_cfg_t *cfg)
{
    urma_jfc_cfg_t p_cfg = *cfg;

    for (int i = 0; i < bdp_jfc->dev_num; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        if (cfg->jfce != NULL) {
            bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(cfg->jfce, bondp_jfce_t, v_jfce);
            p_cfg.jfce = bdp_jfce->p_jfce[i];
        }
        p_cfg.user_ctx = (uint64_t)&bdp_jfc->v_jfc;
        urma_jfc_t *jfc = urma_create_jfc(bdp_ctx->p_ctxs[i], &p_cfg);
        if (jfc == NULL) {
            URMA_LOG_ERR("Failed to create pjfc %d.\n", i);
            return -1;
        }
        bdp_jfc->p_jfc[i] = jfc;
    }
    return 0;
}

static int bondp_delete_vjfc(bondp_jfc_t *bdp_jfc)
{
    return urma_cmd_delete_jfc(&bdp_jfc->v_jfc);
}

static int bondp_delete_pjfc(bondp_jfc_t *bdp_jfc)
{
    int ret = 0;

    for (int i = 0; i < bdp_jfc->dev_num; ++i) {
        if (bdp_jfc->p_jfc[i] == NULL) {
            continue;
        }

        int p_ret = urma_delete_jfc(bdp_jfc->p_jfc[i]);
        if (p_ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to delete pjfc %d, ret: %d.\n", i, ret);
            ret = p_ret;
        }
        bdp_jfc->p_jfc[i] = NULL;
    }

    return ret;
}

urma_jfc_t *bondp_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    bondp_jfc_t *bdp_jfc = (bondp_jfc_t *)calloc(1, sizeof(bondp_jfc_t));
    if (bdp_jfc == NULL) {
        return NULL;
    }
    bdp_jfc->dev_num = bdp_ctx->dev_num;
    bdp_jfc->lasted_polled_jfc_idx = 0;
    atomic_init(&bdp_jfc->use_cnt.atomic_cnt, 0);

    if (bondp_create_pjfc(bdp_ctx, bdp_jfc, cfg) != 0) {
        URMA_LOG_ERR("Failed to create pjfc\n");
        goto DELETE_PJFC;
    }

    if (bondp_create_vjfc(ctx, bdp_jfc, cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjfc, dev_name: %s, eid_idx: %u.\n",
                     ctx->dev->name, ctx->eid_index);
        goto DELETE_PJFC;
    }

    if (bdp_ctx->bonding_mode != BONDP_BONDING_MODE_STANDALONE) {
        uint32_t wr_buf_multiple = 1;
        if (bdp_ctx->bonding_level == BONDP_BONDING_LEVEL_IODIE) {
            wr_buf_multiple = IODIE_NUM;
        } else if (bdp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
            wr_buf_multiple = PORT_NUM * 2;
        }
        if (wr_buf_init(&bdp_jfc->wr_buf, cfg->depth * wr_buf_multiple) != 0) {
            URMA_LOG_ERR("Failed to init jfc wr buf, dev_name: %s, eid_idx: %u.\n",
                         ctx->dev->name, ctx->eid_index);
            goto DELETE_VJFC;
        }
    }

    if (cfg->jfce != NULL) {
        bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(cfg->jfce, bondp_jfce_t, v_jfce);
        atomic_fetch_add(&bdp_jfce->use_cnt.atomic_cnt, 1);
    }

    return &bdp_jfc->v_jfc;

DELETE_VJFC:
    bondp_delete_vjfc(bdp_jfc);
DELETE_PJFC:
    bondp_delete_pjfc(bdp_jfc);
    free(bdp_jfc);
    return NULL;
}

urma_status_t bondp_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);

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
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);
    urma_status_t ret = URMA_SUCCESS;
    bondp_jfce_t *bdp_jfce = NULL;

    if (jfc->jfc_cfg.jfce != NULL) {
        bdp_jfce = CONTAINER_OF_FIELD(jfc->jfc_cfg.jfce, bondp_jfce_t, v_jfce);
    }

    unsigned long use_cnt = atomic_load(&bdp_jfc->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        URMA_LOG_ERR("Failed to delete jfc[%d], still in use. use_cnt: %lu\n", jfc->jfc_id.id, use_cnt);
        return URMA_EAGAIN;
    }

    wr_buf_uninit(&bdp_jfc->wr_buf);

    if (bondp_delete_vjfc(bdp_jfc) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete vjfc\n");
        ret = URMA_FAIL;
    }

    if (bondp_delete_pjfc(bdp_jfc) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete pjfc\n");
        ret = URMA_FAIL;
    }

    free(bdp_jfc);

    if (bdp_jfce != NULL) {
        atomic_fetch_sub(&bdp_jfce->use_cnt.atomic_cnt, 1);
    }
    return ret;
}

static int convert_bond_port_id_to_active_index(const bondp_context_t *bdp_ctx, bondp_port_id_t port_id,
                                                uint32_t *active_index)
{
    if (port_id.port_idx == UINT8_MAX) {
        if (port_id.chip_id > PRIMARY_EID_NUM) {
            URMA_LOG_ERR("Invalid primary chip_id: %u.\n", port_id.chip_id);
            return -1;
        }
        *active_index = port_id.chip_id - 1;
        return 0;
    }

    if (port_id.port_idx > PORT_NUM || port_id.chip_id > PRIMARY_EID_NUM) {
        URMA_LOG_ERR("Invalid port id, chip_id: %u, port_idx: %u.\n", port_id.chip_id, port_id.port_idx);
        return -1;
    }

    *active_index = (uint32_t)get_matrix_port_p_idx(port_id.chip_id - 1, port_id.port_idx);
    if (*active_index >= (uint32_t)bdp_ctx->dev_num) {
        URMA_LOG_ERR("Invalid converted active index: %u.\n", *active_index);
        return -1;
    }
    return 0;
}

static int init_active_indices(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_comp,
                               const bondp_port_id_t *port_ids, uint32_t port_count)
{
    if (port_ids == NULL || port_count == 0) {
        int start, end;
        if (bdp_ctx->bonding_level == BONDP_BONDING_LEVEL_IODIE) {
            start = 0;
            end = IODIE_NUM;
        } else {
            start = IODIE_NUM;
            end = URMA_UBAGG_DEV_MAX_NUM;
        }
        for (int i = start; i < end; i++) {
            if (bdp_ctx->p_ctxs[i] != NULL) {
                bdp_comp->enabled_indices[bdp_comp->enabled_count] = i;
                bdp_comp->enabled_count += 1;
                bdp_comp->active_indices[bdp_comp->active_count] = i;
                bdp_comp->active_count += 1;
            }
        }
        return 0;
    }

    if (port_count > URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid port_count: %u.\n", port_count);
        return -1;
    }

    bdp_comp->enabled_count = 0;
    for (uint32_t n = 0; n < port_count; ++n) {
        uint32_t active_index = 0;
        if (convert_bond_port_id_to_active_index(bdp_ctx, port_ids[n], &active_index) != 0) {
            URMA_LOG_ERR("Invalid active port id, value: 0x%lx.\n", port_ids[n].value);
            return -1;
        }

        bool is_duplicate = false;
        for (uint32_t i = 0; i < bdp_comp->enabled_count; ++i) {
            if (bdp_comp->enabled_indices[i] == active_index) {
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) {
            continue;
        }
        bdp_comp->enabled_indices[bdp_comp->enabled_count] = active_index;
        bdp_comp->enabled_count += 1;
        bdp_comp->active_indices[bdp_comp->active_count] = active_index;
        bdp_comp->active_count += 1;
    }
    return 0;
}

static int init_target_active_indices(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
                                      urma_bond_id_info_out_t *rvjetty_info, bondp_comp_t *jetty)
{
    uint32_t active_count = 0;

    for (uint32_t n = 0; n < jetty->enabled_count; ++n) {
        uint32_t local_indice = jetty->enabled_indices[n];
        for (uint32_t m = 0; m < rvjetty_info->enabled_count; ++m) {
            uint32_t target_indice = rvjetty_info->enabled_indices[m];
            if (rvjetty_info->connected[local_indice][target_indice]) {
                jetty->active_indices[active_count] = local_indice;
                bdp_tjetty->active_indices[active_count] = target_indice;
                bdp_tjetty->local_active_indices[active_count] = local_indice;
                active_count += 1;
                if (bdp_ctx->bonding_mode == BONDP_BONDING_MODE_STANDALONE) {
                    goto FIND_FINISH;
                }
            }
        }
    }

FIND_FINISH:
    if (active_count == 0) {
        URMA_LOG_ERR("Failed to find connected port\n")
        return -1;
    }
    jetty->active_count = active_count;
    bdp_tjetty->active_count = active_count;
    bdp_tjetty->local_dev_num = active_count;
    bdp_tjetty->target_dev_num = active_count;
    return 0;
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

static int bondp_create_pjfs(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfs, urma_jfs_cfg_t *cfg)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    urma_jfs_cfg_t p_cfg = *cfg;

    for (uint32_t n = 0; n < bdp_jfs->enabled_count; ++n) {
        uint32_t i = bdp_jfs->enabled_indices[n];
        p_cfg.jfc = bdp_jfc->p_jfc[i];
        urma_jfs_t *jfs = urma_create_jfs(bdp_ctx->p_ctxs[i], &p_cfg);
        if (jfs == NULL) {
            URMA_LOG_ERR("Failed to create pjfs %d.\n", i);
            return -1;
        }
        bdp_jfs->p_jfs[i] = jfs;
        bdp_jfs->p_jfs[i]->jfs_cfg.user_ctx = (uint64_t)bdp_jfs;
        bdp_jfs->valid[i] = true;
    }

    return 0;
}

static int bondp_delete_vjfs(bondp_comp_t *bdp_jfs)
{
    return urma_cmd_delete_jfs(&bdp_jfs->v_jfs);
}

static int bondp_delete_pjfs(bondp_comp_t *bdp_jfs)
{
    int ret = 0;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }

        int p_ret = urma_delete_jfs(bdp_jfs->p_jfs[i]);
        if (p_ret != 0) {
            URMA_LOG_ERR("Failed to delete pjfs %d, ret: %d.\n", i, p_ret);
            ret = p_ret;
        }
        bdp_jfs->p_jfs[i] = NULL;
    }

    return ret;
}

static int bondp_add_jfs_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfs, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    int i = 0;
    for (i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        urma_jfr_id_t pjfs_id = bdp_jfs->p_jfs[i]->jfs_id;
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table, pjfs_id, JFS, jetty_id, bdp_jfs);
        if (ret) {
            URMA_LOG_ERR("Failed to add p_vjfs_id[%d]: ret: %d, p_jfs_id: %u, v_jfs_id: %u\n", i, ret, pjfs_id.id,
                         jetty_id);
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
        urma_jfr_id_t pjfs_id = bdp_jfs->p_jfs[j]->jfs_id;
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjfs_id, JFS);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jfs_p_vjetty_info_without_lock(bondp_comp_t *bdp_jfs)
{
    bondp_context_t *bdp_ctx = bdp_jfs->bondp_ctx;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        urma_jfr_id_t pjfs_id = bdp_jfs->p_jfs[i]->jfs_id;
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjfs_id, JFS);
        if (ret) {
            URMA_LOG_ERR("Failed to delete p_vjfs_id node[%d]: ret: %d pjfs_id: %u\n", i, ret, pjfs_id.id);
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

    bondp_comp_t *bdp_jfs = (bondp_comp_t *)calloc(1, sizeof(bondp_comp_t));
    if (bdp_jfs == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }

    bdp_jfs->bondp_ctx = bdp_ctx;
    bdp_jfs->comp_type = BONDP_COMP_JFS;
    atomic_init(&bdp_jfs->use_cnt.atomic_cnt, 0);
    bdp_jfs->send_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    bdp_jfs->recv_jfc = NULL;
    (void)pthread_spin_init(&bdp_jfs->send_lock, PTHREAD_PROCESS_PRIVATE);

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (cfg->flag.bs.has_drv_ext) {
        const bondp_jfs_cfg_t *bdp_cfg = (const bondp_jfs_cfg_t *)cfg;
        cfg_active_port_count = bdp_cfg->port_count;
        cfg_active_port_ids = bdp_cfg->port_ids;
    }

    if (init_active_indices(bdp_ctx, bdp_jfs, cfg_active_port_ids, cfg_active_port_count) != 0) {
        URMA_LOG_ERR("Failed to init active indices\n");
        goto FREE_JFS;
    }

    if (bondp_create_pjfs(bdp_ctx, bdp_jfs, cfg) != 0) {
        URMA_LOG_ERR("Failed to create pjfs\n");
        goto DELETE_PJFS;
    }

    if (bondp_create_vjfs(ctx, cfg, bdp_jfs)) {
        URMA_LOG_ERR("Failed to create vjfs\n");
        goto DELETE_PJFS;
    }
    if (bondp_add_jfs_p_vjetty_id_info(bdp_ctx, bdp_jfs, bdp_jfs->v_jfs.jfs_id.id)) {
        URMA_LOG_ERR("Failed to add jfs p_vjetty_id info\n");
        goto DELETE_VJFS;
    }

    if (bondp_init_connection_table(bdp_jfs) != 0) {
        URMA_LOG_ERR("Failed to create jfs datapath ctx\n");
        goto DEL_P_VJFS_ID;
    }

    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    return &bdp_jfs->v_jfs;

DEL_P_VJFS_ID:
    bondp_del_jfs_p_vjetty_info(bdp_jfs);
DELETE_VJFS:
    (void)bondp_delete_vjfs(bdp_jfs);
DELETE_PJFS:
    bondp_delete_pjfs(bdp_jfs);
FREE_JFS:
    (void)pthread_spin_destroy(&bdp_jfs->send_lock);
    free(bdp_jfs);
    return NULL;
}

urma_status_t bondp_delete_jfs(urma_jfs_t *jfs)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfs->jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_context_t *bdp_ctx = bdp_jfs->bondp_ctx;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
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

    bondp_uninit_connection_table(bdp_jfs);

    if (bondp_delete_vjfs(bdp_jfs) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete vjfs\n");
        ret = URMA_FAIL;
    }

    if (bondp_delete_pjfs(bdp_jfs) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete pjfs\n");
        ret = URMA_FAIL;
    }

    (void)pthread_spin_destroy(&bdp_jfs->send_lock);
    free(bdp_jfs);

    atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    return ret;
}

urma_status_t bondp_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
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

static int bondp_create_vjfr(bondp_context_t *bdp_ctx, urma_jfr_cfg_t *cfg, bondp_comp_t *bdp_jfr)
{
    bondp_create_vjfr_udata_t jfr_info = {0};

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfr->p_jfr[i] != NULL) {
            jfr_info.slave_id[i] = bdp_jfr->p_jfr[i]->jfr_id;
        }
        jfr_info.enabled_indices[i] = bdp_jfr->enabled_indices[i];
    }
    jfr_info.enabled_count = bdp_jfr->enabled_count;

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jfr_info,
        .in_len = sizeof(bondp_create_vjfr_udata_t),
    };

    int ret = urma_cmd_create_jfr(&bdp_ctx->v_ctx, &bdp_jfr->v_jfr, cfg, &udata);
    if (ret) {
        URMA_LOG_ERR("bondp init jfr fail: %d.\n", ret);
        return -1;
    }
    return 0;
}

static int bondp_create_pjfr(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfr, urma_jfr_cfg_t *cfg)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    urma_jfr_cfg_t p_cfg = *cfg;

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        p_cfg.jfc = bdp_jfc->p_jfc[i];
        urma_jfr_t *jfr = urma_create_jfr(bdp_ctx->p_ctxs[i], &p_cfg);
        if (jfr == NULL) {
            URMA_LOG_ERR("Failed to create pjfr %d.\n", i);
            return -1;
        }
        jfr->jfr_cfg.user_ctx = (uint64_t)bdp_jfr;
        bdp_jfr->p_jfr[i] = jfr;
        bdp_jfr->valid[i] = true;
    }
    return 0;
}

static int bondp_delete_vjfr(bondp_comp_t *bdp_jfr)
{
    return urma_cmd_delete_jfr(&bdp_jfr->v_jfr);
}

static int bondp_delete_pjfr(bondp_comp_t *bdp_jfr)
{
    int ret = 0;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        int p_ret = urma_delete_jfr(bdp_jfr->p_jfr[i]);
        if (p_ret) {
            URMA_LOG_ERR("Failed to delete pjfr %d, ret: %d.\n", i, ret);
            ret = p_ret;
        }
        bdp_jfr->p_jfr[i] = NULL;
    }
    return ret;
}

static int bondp_add_jfr_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfr, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    int i = 0;
    for (i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        urma_jfr_id_t pjfr_id = bdp_jfr->p_jfr[i]->jfr_id;
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table, pjfr_id, JFR, jetty_id, bdp_jfr);
        if (ret) {
            URMA_LOG_ERR("Failed to add p_vjfr_id[%d]: ret: %d, p_jfr_id: %u, v_jfr_id: %u\n", i, ret, pjfr_id.id,
                         jetty_id);
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
        urma_jfr_id_t pjfr_id = bdp_jfr->p_jfr[i]->jfr_id;
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjfr_id, JFR);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jfr_p_vjetty_info_without_lock(bondp_comp_t *bdp_jfr)
{
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfr->p_jfr[i] == NULL) {
            continue;
        }
        urma_jfr_id_t pjfr_id = bdp_jfr->p_jfr[i]->jfr_id;
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjfr_id, JFR);
        if (ret) {
            URMA_LOG_ERR("Failed to delete p_vjfr_id node[%d]: ret %d pjfr_id: %u\n", i, ret, pjfr_id.id);
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

    bondp_comp_t *bdp_jfr = (bondp_comp_t *)calloc(1, sizeof(bondp_comp_t));
    if (bdp_jfr == NULL) {
        return NULL;
    }
    bdp_jfr->bondp_ctx = bdp_ctx;
    bdp_jfr->comp_type = BONDP_COMP_JFR;
    atomic_init(&bdp_jfr->use_cnt.atomic_cnt, 0);
    bdp_jfr->send_jfc = NULL;
    bdp_jfr->recv_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;

    if (init_active_indices(bdp_ctx, bdp_jfr, cfg_active_port_ids, cfg_active_port_count) != 0) {
        URMA_LOG_ERR("Failed to init active indices\n");
        goto FREE_JFR;
    }

    if (bondp_create_pjfr(bdp_ctx, bdp_jfr, cfg)) {
        URMA_LOG_ERR("Failed to create pjfr\n");
        goto DELETE_PJFR;
    }

    if (bondp_create_vjfr(bdp_ctx, cfg, bdp_jfr)) {
        URMA_LOG_ERR("Failed to create vjfr\n");
        goto DELETE_PJFR;
    }

    if (bondp_add_jfr_p_vjetty_id_info(bdp_ctx, bdp_jfr, bdp_jfr->v_jfr.jfr_id.id)) {
        goto DELETE_VJFR;
    }

    if (bondp_init_connection_table(bdp_jfr) != 0) {
        URMA_LOG_ERR("Failed to create jfr datapath ctx\n");
        goto DEL_P_VJFR_ID;
    }

    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    return &bdp_jfr->v_jfr;

DEL_P_VJFR_ID:
    bondp_del_jfr_p_vjetty_info(bdp_jfr);
DELETE_VJFR:
    (void)bondp_delete_vjfr(bdp_jfr);
DELETE_PJFR:
    bondp_delete_pjfr(bdp_jfr);
FREE_JFR:
    free(bdp_jfr);
    return NULL;
}

urma_status_t bondp_delete_jfr(urma_jfr_t *jfr)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfr->jfr_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
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
    bondp_uninit_connection_table(bdp_jfr);

    if (bondp_delete_vjfr(bdp_jfr) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete_vjfr\n");
        ret = URMA_FAIL;
    }
    if (bondp_delete_pjfr(bdp_jfr) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete pjfr\n");
        ret = URMA_FAIL;
    }
    free(bdp_jfr);

    atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    return ret;
}

urma_status_t bondp_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
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
    bondp_create_vjetty_udata_t jetty_info = {0};

    if (bondp_fill_vjetty_health_info(bdp_ctx, bdp_jetty,
                                      &jetty_info.health_check_seg,
                                      &jetty_info.is_health_check_enable) != 0) {
        URMA_LOG_ERR("Failed to fill health check seg info for vjetty\n");
        return -1;
    }

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->p_jetty[i] != NULL) {
            jetty_info.slave_id[i] = bdp_jetty->p_jetty[i]->jetty_id;
        }
        jetty_info.enabled_indices[i] = bdp_jetty->enabled_indices[i];
    }
    jetty_info.enabled_count = bdp_jetty->enabled_count;

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jetty_info,
        .in_len = sizeof(bondp_create_vjetty_udata_t),
    };

    bdp_jetty->v_jetty.jetty_cfg = *jetty_cfg;
    int ret = urma_cmd_create_jetty(&bdp_ctx->v_ctx, &bdp_jetty->v_jetty, jetty_cfg, &udata);
    if (ret == 0) {
        bdp_jetty->v_jetty.jetty_cfg.shared.jfr->jfr_cfg = jetty_cfg->shared.jfr->jfr_cfg;
    }
    return ret;
}

static int bondp_create_pjetty(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, urma_jetty_cfg_t *jetty_cfg)
{
    bondp_jfc_t *bdp_jfs_jfc = CONTAINER_OF_FIELD(jetty_cfg->jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr, bondp_comp_t, base);
    bondp_jfc_t *bdp_rplc_jfc = CONTAINER_OF_FIELD(jetty_cfg->shared.jfc, bondp_jfc_t, v_jfc);
    urma_jetty_cfg_t p_cfg = *jetty_cfg;

    for (uint32_t n = 0; n < bdp_jetty->enabled_count; ++n) {
        uint32_t i = bdp_jetty->enabled_indices[n];
        p_cfg.jfs_cfg.jfc = bdp_jfs_jfc->p_jfc[i];
        p_cfg.shared.jfr = bdp_jfr->p_jfr[i];
        if (bdp_rplc_jfc) {
            p_cfg.shared.jfc = bdp_rplc_jfc->p_jfc[i];
        }
        urma_jetty_t *jetty = urma_create_jetty(bdp_ctx->p_ctxs[i], &p_cfg);
        if (jetty == NULL) {
            URMA_LOG_ERR("Failed to create pjetty %d.\n", i);
            return -1;
        }
        jetty->jetty_cfg.user_ctx = (uint64_t)bdp_jetty;
        bdp_jetty->p_jetty[i] = jetty;
        bdp_jetty->valid[i] = true;
    }
    return 0;
}

static int bondp_delete_vjetty(bondp_comp_t *bdp_jetty)
{
    return urma_cmd_delete_jetty(&bdp_jetty->v_jetty);
}

static int bondp_delete_pjetty(bondp_comp_t *bdp_jetty)
{
    int ret = 0;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        int p_ret = urma_delete_jetty(bdp_jetty->p_jetty[i]);
        if (p_ret) {
            URMA_LOG_ERR("Failed to delete pjetty %d, ret: %d.\n", i, ret);
            ret = p_ret;
        }
        bdp_jetty->p_jetty[i] = NULL;
    }
    return ret;
}

static int bondp_add_jetty_p_vjetty_id_info(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, uint32_t jetty_id)
{
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (!bdp_jetty->p_jetty[i]) {
            continue;
        }
        urma_jetty_id_t pjetty_id = bdp_jetty->p_jetty[i]->jetty_id;
        int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table, pjetty_id, JETTY,
                                                         jetty_id, bdp_jetty);
        if (ret == BONDP_HASH_MAP_COLLIDE_ERROR &&
            jetty_id > 0 && jetty_id < BONDP_MAX_WELL_KNOWN_JETTY_ID) {
            URMA_LOG_INFO("Add repeated wk-jetty id[%d]: ret: %d, p_jetty_id: %u, v_jetty_id: %u\n",
                          i, ret, pjetty_id.id, jetty_id);
        } else if (ret != 0) {
            URMA_LOG_ERR("Failed to add p_vjetty_id[%d]: ret: %d, p_jetty_id: %u, v_jetty_id: %u\n",
                         i, ret, pjetty_id.id, jetty_id);
            goto DEL_P_VJETTY_ID;
        }
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return 0;
DEL_P_VJETTY_ID:
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (!bdp_jetty->p_jetty[i]) {
            continue;
        }
        urma_jetty_id_t pjetty_id = bdp_jetty->p_jetty[i]->jetty_id;
        (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjetty_id, JETTY);
    }
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return -1;
}

static void bondp_del_jetty_p_vjetty_info_without_lock(bondp_comp_t *bdp_jetty)
{
    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        urma_jetty_id_t pjetty_id = bdp_jetty->p_jetty[i]->jetty_id;
        int ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, pjetty_id, JETTY);
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

    bondp_comp_t *bdp_jetty = (bondp_comp_t *)calloc(1, sizeof(bondp_comp_t));
    if (bdp_jetty == NULL) {
        URMA_LOG_ERR("Failed to create bondp comp\n");
        return NULL;
    }
    bdp_jetty->bondp_ctx = bdp_ctx;
    bdp_jetty->comp_type = BONDP_COMP_JETTY;
    atomic_init(&bdp_jetty->use_cnt.atomic_cnt, 0);
    bdp_jetty->send_jfc = CONTAINER_OF_FIELD(jetty_cfg->jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bdp_jetty->recv_jfc = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr->jfr_cfg.jfc, bondp_jfc_t, v_jfc);
    (void)pthread_spin_init(&bdp_jetty->send_lock, PTHREAD_PROCESS_PRIVATE);

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (jetty_cfg->flag.bs.has_drv_ext) {
        const bondp_jetty_cfg_t *bdp_cfg = (const bondp_jetty_cfg_t *)jetty_cfg;
        cfg_active_port_count = bdp_cfg->port_count;
        cfg_active_port_ids = bdp_cfg->port_ids;
    }

    if (init_active_indices(bdp_ctx, bdp_jetty, cfg_active_port_ids, cfg_active_port_count) != 0) {
        URMA_LOG_ERR("Failed to init active indices\n");
        goto FREE_JETTY;
    }

    if (bondp_create_pjetty(bdp_ctx, bdp_jetty, jetty_cfg) != 0) {
        URMA_LOG_ERR("Failed to create pjetty\n");
        goto DELETE_PJETTY;
    }

    if (bondp_register_health_check_seg_for_jetty(bdp_ctx, bdp_jetty) != 0) {
        URMA_LOG_ERR("Failed to register health check seg for jetty creation\n");
        goto DELETE_PJETTY;
    }

    if (bondp_create_vjetty(bdp_ctx, bdp_jetty, jetty_cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjetty, %u\n", jetty_cfg->id);
        goto UNREGISTER_HEALTH_SEG;
    }

    if (bondp_add_jetty_p_vjetty_id_info(bdp_ctx, bdp_jetty, bdp_jetty->v_jetty.jetty_id.id) != 0) {
        URMA_LOG_ERR("Failed to add jetty id to p_vjetty_id table\n");
        goto DELETE_VJETTY;
    }

    if (bondp_init_connection_table(bdp_jetty) != 0) {
        URMA_LOG_ERR("Failed to create jetty ctx\n");
        goto DEL_P_VJETTY_ID;
    }

    /* Validate bdp_jfr below at the function entry point to ensure they are not empty. */
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr, bondp_comp_t, v_jfr);
    atomic_fetch_add(&bdp_jfr->use_cnt.atomic_cnt, 1);
    if (jetty_cfg->shared.jfc != NULL) {
        bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jetty_cfg->shared.jfc, bondp_jfc_t, v_jfc);
        atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);
    }

    return &bdp_jetty->v_jetty;

DEL_P_VJETTY_ID:
    bondp_del_jetty_p_vjetty_info(bdp_jetty);
DELETE_VJETTY:
    bondp_delete_vjetty(bdp_jetty);
UNREGISTER_HEALTH_SEG:
    bondp_unregister_health_check_seg_for_jetty(bdp_jetty);
DELETE_PJETTY:
    bondp_delete_pjetty(bdp_jetty);
FREE_JETTY:
    (void)pthread_spin_destroy(&bdp_jetty->send_lock);
    free(bdp_jetty);
    return NULL;
}

urma_status_t bondp_delete_jetty(urma_jetty_t *jetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, base);
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jetty->urma_ctx, bondp_context_t, v_ctx);
    urma_status_t ret = URMA_SUCCESS;
    /* When creating bondp_jetty, jetty_cfg.shared.jfr has been validated and is non-null. */
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty->jetty_cfg.shared.jfr, bondp_comp_t, v_jfr);
    bondp_jfc_t *bdp_jfc = NULL;
    if (jetty->jetty_cfg.shared.jfc != NULL) {
        bdp_jfc = CONTAINER_OF_FIELD(jetty->jetty_cfg.shared.jfc, bondp_jfc_t, v_jfc);
    }
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
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
    bondp_unregister_health_check_seg_for_jetty(bdp_jetty);
    bondp_uninit_connection_table(bdp_jetty);
    if (bondp_delete_vjetty(bdp_jetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete vjetty\n");
        ret = URMA_FAIL;
    }
    if (bondp_delete_pjetty(bdp_jetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete pjetty\n");
        ret = URMA_FAIL;
    }
    (void)pthread_spin_destroy(&bdp_jetty->send_lock);
    free(bdp_jetty);

    atomic_fetch_sub(&bdp_jfr->use_cnt.atomic_cnt, 1);
    if (bdp_jfc != NULL) {
        atomic_fetch_sub(&bdp_jfc->use_cnt.atomic_cnt, 1);
    }

    return ret;
}

urma_status_t bondp_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
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

static int bondp_user_ctl_set_bonding_mode_legacy(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(urma_context_aggr_mode_t)) {
        URMA_LOG_ERR("Invalid set bonding mode legacy param.\n");
        return -EINVAL;
    }

    urma_context_aggr_mode_t aggr_mode = *(urma_context_aggr_mode_t *)(uintptr_t)in->addr;
    if (aggr_mode < URMA_AGGR_MODE_STANDALONE ||
        aggr_mode > URMA_AGGR_MODE_BALANCE) {
        URMA_LOG_ERR("Invalid aggr mode: %d.\n", aggr_mode);
        return -EINVAL;
    }
    return bondp_set_bonding_mode(ctx, (bondp_bonding_mode_t)aggr_mode, BONDP_BONDING_LEVEL_IODIE);
}

static int bondp_user_ctl_set_bonding_mode(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    (void)out;

    if (in->addr == 0 || in->len != sizeof(bondp_set_bonding_mode_in_t)) {
        URMA_LOG_ERR("Invalid set bonding mode param.\n");
        return -EINVAL;
    }

    bondp_set_bonding_mode_in_t *mode_in = (bondp_set_bonding_mode_in_t *)(uintptr_t)in->addr;
    return bondp_set_bonding_mode(ctx, mode_in->bonding_mode, mode_in->bonding_level);
}

static int bondp_user_ctl_query_port(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    if (in->addr == 0 || out->addr == 0 ||
        in->len != sizeof(bondp_query_port_in_t) ||
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

int bondp_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    switch (in->opcode) {
        case BONDP_USER_CTL_SET_BONDING_MODE_LEGACY:
            return bondp_user_ctl_set_bonding_mode_legacy(ctx, in, out);
        case BONDP_USER_CTL_ENABLE_SEG_CACHE:
            bondp_toggle_seg_cache(true);
            return 0;
        case BONDP_USER_CTL_QUERY_PORT:
            return bondp_user_ctl_query_port(ctx, in, out);
        case BONDP_USER_CTL_SET_BONDING_MODE:
            return bondp_user_ctl_set_bonding_mode(ctx, in, out);
        default: {
            URMA_LOG_ERR("Unsupported opcode, opcode:%d\n", in->opcode);
            return -EINVAL;
        }
    }
    return 0;
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
    urma_cmd_udrv_priv_t udata = {
        .in_addr = 0,
        .in_len = 0,
        .out_addr = (uint64_t)udata_out,
        .out_len = sizeof(*udata_out),
    };

    return urma_cmd_import_jetty(ctx, &bdp_tjetty->v_tjetty, &cfg, &udata);
}

static int bondp_import_pjetty(
    bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_rjetty_t *rjetty, urma_token_t *rjetty_token,
    urma_bond_id_info_out_t *rvjetty_info, bondp_comp_t *bdp_jetty)
{
    urma_rjetty_t p_rjetty = *rjetty;

    for (uint32_t n = 0; n < bdp_tjetty->active_count; ++n) {
        uint32_t local_idx = bdp_jetty->active_indices[n];
        uint32_t target_idx = bdp_tjetty->active_indices[n];
        p_rjetty.jetty_id = rvjetty_info->slave_id[target_idx];
        urma_target_jetty_t *tjetty = urma_import_jetty(bdp_ctx->p_ctxs[local_idx], &p_rjetty, rjetty_token);
        if (tjetty == NULL) {
            URMA_LOG_ERR("Failed to import tjetty %u %u\n", local_idx, target_idx);
            return -1;
        }
        bdp_tjetty->p_tjetty[local_idx][target_idx] = tjetty;
        bdp_tjetty->valid[target_idx] = true;
    }
    return 0;
}

static int bondp_unimport_vjetty(bondp_target_jetty_t *bdp_tjetty)
{
    return urma_cmd_unimport_jetty(&bdp_tjetty->v_tjetty);
}

static int bondp_unimport_pjetty(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;

    if (bondp_unimport_health_check_tseg(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }

    memset(bdp_tjetty->valid, 0, sizeof(bdp_tjetty->valid));

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (!bdp_tjetty->p_tjetty[i][j]) {
                continue;
            }
            if (urma_unimport_jetty(bdp_tjetty->p_tjetty[i][j]) != URMA_SUCCESS) {
                ret = URMA_FAIL;
            }
            bdp_tjetty->p_tjetty[i][j] = NULL;
        }
    }
    return ret;
}

urma_target_jetty_t *bondp_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    bondp_comp_t *cfg_jetty = NULL;
    if (rjetty->flag.bs.has_drv_ext) {
        const bondp_rjetty_t *bdp_rjetty = (const bondp_rjetty_t *)rjetty;
        cfg_jetty = CONTAINER_OF_FIELD(bdp_rjetty->jetty, bondp_comp_t, v_jetty);
    }

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

    urma_bond_id_info_out_t rvjetty_info = {0};
    if (bondp_import_vjetty(ctx, rjetty, token_value, bdp_tjetty, &rvjetty_info) != 0) {
        URMA_LOG_ERR("Failed to import vjetty, [" EID_FMT "]:%u\n",
                     EID_ARGS(rjetty->jetty_id.eid), rjetty->jetty_id.id);
        goto FREE_TJETTY;
    }

    bondp_comp_t fake_jetty = {0};
    bool is_fake_jetty = false;
    if (cfg_jetty == NULL) {
        if (rjetty->trans_mode == URMA_TM_RM && bdp_ctx->bonding_mode == BONDP_BONDING_MODE_ACTIVE_BACKUP) {
            URMA_LOG_ERR("RM jetty import requires drv_ext.vjetty.\n");
            return NULL;
        }
        is_fake_jetty = true;
        cfg_jetty = &fake_jetty;
        if (init_active_indices(bdp_ctx, &fake_jetty, NULL, 0) != 0) {
            URMA_LOG_ERR("Failed to init active indices\n");
            return NULL;
        }
    }
    if (init_target_active_indices(bdp_ctx, bdp_tjetty, &rvjetty_info, cfg_jetty) != 0) {
        URMA_LOG_ERR("Failed to init target active indices\n");
        goto UNIMPORT_VJETTY;
    }

    if (bondp_import_pjetty(bdp_ctx, bdp_tjetty, rjetty, token_value, &rvjetty_info, cfg_jetty) != 0) {
        URMA_LOG_ERR("Failed to import pjetty\n");
        goto UNIMPORT_PJETTY;
    }

    if (bondp_import_health_check_tseg(bdp_ctx, bdp_tjetty, &rvjetty_info, rjetty) != 0) {
        URMA_LOG_ERR("Failed to import health check seg for jetty\n");
        goto UNIMPORT_TSEG;
    }

    if (rjetty->trans_mode == URMA_TM_RM && rjetty->flag.bs.has_drv_ext && !is_fake_jetty) {
        cfg_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
    }

    if (bondp_register_health_check_task(bdp_ctx, bdp_tjetty, cfg_jetty) != 0) {
        URMA_LOG_ERR("Failed to register health check task\n");
        goto UNIMPORT_TSEG;
    }

    URMA_LOG_INFO("Successfully imported target jetty: " URMA_JETTY_ID_FMT "\n",
                  URMA_JETTY_ID_ARGS(&rjetty->jetty_id));

    return &bdp_tjetty->v_tjetty;

UNIMPORT_TSEG:
    bondp_unimport_health_check_tseg(bdp_tjetty);
UNIMPORT_PJETTY:
    bondp_unimport_pjetty(bdp_tjetty);
UNIMPORT_VJETTY:
    bondp_unimport_vjetty(bdp_tjetty);
FREE_TJETTY:
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

    bondp_unregister_health_check_task(bdp_ctx, bdp_tjetty);

    if (bondp_unimport_pjetty(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    if (bondp_unimport_vjetty(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    free(bdp_tjetty);
    return ret;
}

urma_status_t bondp_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty);

    if (jetty->remote_jetty) {
        URMA_LOG_ERR("Jetty already has a binded target jetty\n");
        return URMA_EINVAL;
    }

    memcpy(bdp_jetty->active_indices, bdp_tjetty->local_active_indices,
           sizeof(bdp_jetty->active_indices));
    bdp_jetty->active_count = bdp_tjetty->active_count;

    uint32_t min_active_count = MIN(bdp_jetty->active_count, bdp_tjetty->active_count);
    if (min_active_count == 0) {
        URMA_LOG_ERR("No valid active slice to bind\n");
        return URMA_FAIL;
    }

    for (uint32_t n = 0; n < min_active_count; ++n) {
        uint32_t local_idx = bdp_jetty->active_indices[n];
        uint32_t target_idx = bdp_tjetty->active_indices[n];

        urma_jetty_t *pjetty = bdp_jetty->p_jetty[local_idx];
        urma_target_jetty_t *ptjetty = bdp_tjetty->p_tjetty[local_idx][target_idx];

        if (urma_bind_jetty(pjetty, ptjetty) != 0) {
            goto UNBIND;
        }
    }

    bdp_jetty->v_jetty.remote_jetty = &bdp_tjetty->v_tjetty;
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
                URMA_LOG_ERR("Failed to unbind tjetty [%u](%d, %d)\n", bdp_tjetty->v_tjetty.id.id, local_idx, local_idx);
                ret = URMA_FAIL;
            }
            bdp_jetty->p_jetty[local_idx]->remote_jetty = NULL;
        }
    }
    bdp_jetty->v_jetty.remote_jetty = NULL;
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
    urma_rjfr_t p_rjfr = *rjfr;

    for (uint32_t n = 0; n < bdp_tjetty->active_count; ++n) {
        uint32_t i = bdp_tjetty->active_indices[n];
        p_rjfr.jfr_id = udata_out->slave_id[i];
        urma_target_jetty_t *tjetty = urma_import_jfr(bdp_ctx->p_ctxs[i], &p_rjfr, token_value);
        if (tjetty == NULL) {
            URMA_LOG_ERR("Failed to import tjfr %u %u\n", i, i);
            return -1;
        }
        bdp_tjetty->p_tjetty[i][i] = tjetty;
        bdp_tjetty->valid[i] = true;
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

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (!bdp_tjetty->p_tjetty[i][j]) {
                continue;
            }
            if (urma_unimport_jfr(bdp_tjetty->p_tjetty[i][j]) != URMA_SUCCESS) {
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

    bondp_comp_t *cfg_jfs = NULL;
    if (rjfr->flag.bs.has_drv_ext) {
        const bondp_rjfr_t *bdp_rjfr = (const bondp_rjfr_t *)rjfr;
        cfg_jfs = CONTAINER_OF_FIELD(bdp_rjfr->jfs, bondp_comp_t, v_jfs);
    }

    bondp_target_jetty_t *bdp_tjetty = calloc(1, sizeof(bondp_target_jetty_t));
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc target jetty\n");
        return NULL;
    }

    urma_bond_id_info_out_t udata_out = {0};
    if (bondp_import_vjfr(ctx, rjfr, token_value, bdp_tjetty, &udata_out) != 0) {
        URMA_LOG_ERR("Failed to import vjetty, [" EID_FMT "]:%u\n",
                     EID_ARGS(rjfr->jfr_id.eid), rjfr->jfr_id.id);
        goto FREE_TJFR;
    }

    bondp_comp_t fake_jfs = {0};
    if (cfg_jfs == NULL) {
        if (rjfr->trans_mode == URMA_TM_RM && bdp_ctx->bonding_mode == BONDP_BONDING_MODE_ACTIVE_BACKUP) {
            URMA_LOG_ERR("RM jfr import requires drv_ext.vjfs\n");
            return NULL;
        }
        cfg_jfs = &fake_jfs;
        if (init_active_indices(bdp_ctx, &fake_jfs, NULL, 0) != 0) {
            URMA_LOG_ERR("Failed to init active indices\n");
            return NULL;
        }
    }
    if (init_target_active_indices(bdp_ctx, bdp_tjetty, &udata_out, cfg_jfs) != 0) {
        URMA_LOG_ERR("Failed to init target active indices\n");
        goto UNIMPORT_VJFR;
    }

    if (bondp_import_pjfr(bdp_ctx, bdp_tjetty, rjfr, token_value, &udata_out) != 0) {
        goto UNIMPORT_PJFR;
    }

    return &bdp_tjetty->v_tjetty;

UNIMPORT_PJFR:
    bondp_unimport_pjfr(bdp_tjetty);
UNIMPORT_VJFR:
    bondp_unimport_vjfr(bdp_tjetty);
FREE_TJFR:
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
        ret = URMA_FAIL;
    }
    if (bondp_unimport_vjfr(bdp_tjetty) != URMA_SUCCESS) {
        ret = URMA_FAIL;
    }
    free(bdp_tjetty);
    return ret;
}

urma_status_t bondp_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);
    bool success_once = false;

    PERF_PROFILING_START(BOND_REARM_JFC);
    if (bdp_jfc->v_jfc.jfc_cfg.jfce == NULL) {
        URMA_LOG_ERR("Failed to rearm jfc: JFCE is NULL\n");
        PERF_PROFILING_END(BOND_REARM_JFC);
        return URMA_EINVAL;
    }

    for (int i = 0; i < bdp_jfc->dev_num; ++i) {
        if (!bdp_jfc->p_jfc[i]) {
            continue;
        }
        urma_status_t ret = urma_rearm_jfc(bdp_jfc->p_jfc[i], solicited_only);
        if (ret != URMA_SUCCESS) {
            continue;
        }
        success_once = true;
    }

    PERF_PROFILING_END(BOND_REARM_JFC);
    return success_once ? URMA_SUCCESS : URMA_FAIL;
}

int bondp_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[])
{
    bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(jfce, bondp_jfce_t, v_jfce);

    PERF_PROFILING_START(BOND_WAIT_JFC);
    struct epoll_event events[BOND_EPOLL_NUM] = {0};
    int epoll_event_limit = jfc_cnt < BOND_EPOLL_NUM ? jfc_cnt : BOND_EPOLL_NUM;
    int num = epoll_wait(bdp_jfce->v_jfce.fd, events, epoll_event_limit, time_out);
    if (num < 0 || num > epoll_event_limit) {
        URMA_LOG_ERR("Epoll wait err, ret:%d.\n", num);
        PERF_PROFILING_END(BOND_WAIT_JFC);
        return -1;
    } else if (num == 0) {
        PERF_PROFILING_END(BOND_WAIT_JFC);
        return 0;
    }

    int actual_num = 0;
    for (int i = 0; i < num; i++) {
        int fd = events[i].data.fd;
        urma_jfce_t *p_jfce = NULL;
        for (int j = 0; j < bdp_jfce->dev_num; j++) {
            if (bdp_jfce->p_jfce[j] != NULL && bdp_jfce->p_jfce[j]->fd == fd) {
                p_jfce = bdp_jfce->p_jfce[j];
                break;
            }
        }
        if (p_jfce == NULL) {
            URMA_LOG_WARN("Fail to find fd:%d from p_jfce array.\n", fd);
            continue;
        }

        urma_jfc_t *p_jfc = NULL;
        int p_num = urma_wait_jfc(p_jfce, 1, 0, &p_jfc);
        if (p_num <= 0) {
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
        URMA_LOG_DEBUG("p_jfc:%p, add v_jfc:%p\n", p_jfc, v_jfc);
    }
    PERF_PROFILING_END(BOND_WAIT_JFC);
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
        URMA_LOG_ERR("Invalid parameter\n");
        return URMA_EINVAL;
    }
    struct epoll_event event;
    urma_async_event_t *p_event;
    urma_status_t status;

    int nfds = epoll_wait(ctx->async_fd, &event, 1, 0);
    if (nfds == -1) {
        URMA_LOG_ERR("epoll_wait no event or err.\n");
        return URMA_FAIL;
    }

    if ((event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        URMA_LOG_ERR("bondp get error epoll_event: 0x%x.\n", event.events);
        return URMA_FAIL;
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
        URMA_LOG_ERR("Invalid parameter\n");
        return;
    }
    urma_async_event_t *p_event = (urma_async_event_t *)event->priv;
    urma_ack_async_event(p_event);
    event->priv = NULL;
    free(p_event);
}
