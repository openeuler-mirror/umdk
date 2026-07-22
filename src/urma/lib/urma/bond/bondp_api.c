/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of Bonding API
 * Author: Ma Chuan
 * Create: 2025-02-06
 * Note:
 * History: 2025-02-06
 */
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "ub_util.h"
#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_log.h"
#include "urma_private.h"

#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_dp_failback.h"
#include "bondp_dp_health.h"
#include "bondp_hash_table.h"
#include "bondp_types.h"
#include "urma_ubagg.h"

#include "bondp_api.h"

typedef struct bondp_create_vjetty_udata {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    bool is_msn_enabled; // deprecated
    uint8_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
} bondp_create_vjetty_udata_t;

typedef struct bondp_create_vjfc_udata {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
} bondp_create_vjfc_udata_t;

typedef struct bondp_create_vjfs_udata {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
} bondp_create_vjfs_udata_t;

static int bondp_init_connection_table(bondp_comp_t *bdp_comp)
{
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_comp->members[i] == NULL) {
            bdp_comp->pjettys_error_done[i] = PJETTY_SUSPEND_DONE | PJETTY_FLUSH_ERROR_DONE;
        }
    }

    if (!bdp_comp->bondp_ctx->msn_enable) {
        URMA_LOG_INFO("MSN is not enabled, skip creating connection table\n");
        return 0;
    }

    if (bondp_conn_table_create(&bdp_comp->v_conn_table, BONDP_MAX_NUM_JETTYS) != 0) {
        return -1;
    }
    return 0;
}

static void bondp_uninit_connection_table(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return;
    }
    if (!bdp_comp->bondp_ctx->msn_enable) {
        return;
    }
    bondp_hash_table_destroy(&bdp_comp->v_conn_table);
}

static int bondp_init_wr_buf(const bondp_comp_t *bdp_comp, wr_buf_t *wr_buf, uint32_t depth,
                             uint32_t max_sge, bool is_send)
{
    if (bdp_comp->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_STANDALONE) {
        return 0;
    }

    // Send: 1 wr_buf entry per WR regardless of port count; recv: all ports need entries for failover
    uint32_t port_cnt = is_send
                            ? 1
                            : bdp_comp->enabled_count;
    return wr_buf_init(wr_buf, depth * port_cnt, max_sge);
}

static void bondp_uninit_wr_buf(wr_buf_t *wr_buf)
{
    wr_buf_uninit(wr_buf);
}

static urma_jfc_t *bondp_get_effective_shared_jfc(const urma_jetty_cfg_t *jetty_cfg)
{
    if (jetty_cfg->shared.jfc != NULL) {
        return jetty_cfg->shared.jfc;
    }
    if (jetty_cfg->shared.jfr == NULL) {
        return NULL;
    }
    return jetty_cfg->shared.jfr->jfr_cfg.jfc;
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
            URMA_LOG_ERR("Failed to add fd=%d to epoll fd=%d.\n", jfce->fd, bdp_jfce->v_jfce.fd);
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
            URMA_LOG_ERR("Failed to delete pjfce %d, ret=%d.\n", i, p_ret);
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
        URMA_LOG_ERR("Failed to create epoll_fd for vjfce.\n");
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

    bondp_jfce_t *bdp_jfce = (bondp_jfce_t *)calloc(1, sizeof(bondp_jfce_t));
    if (bdp_jfce == NULL) {
        return NULL;
    }
    bdp_jfce->dev_num = bdp_ctx->dev_num;
    bdp_jfce->bondp_ctx = bdp_ctx;
    atomic_init(&bdp_jfce->use_cnt.atomic_cnt, 0);

    if (bondp_create_vjfce(bdp_ctx, bdp_jfce) != 0) {
        URMA_LOG_ERR("Failed to create vjfce.\n");
        goto FREE_JFCE;
    }

    if (bondp_create_pjfce(bdp_ctx, bdp_jfce) != 0) {
        URMA_LOG_ERR("Failed to create pjfce.\n");
        goto DELETE_PJFCE;
    }
    URMA_LOG_DEBUG("Finish to create jfce, dev_name=%s, eid_idx=%u.\n",
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
        URMA_LOG_ERR("Failed to delete jfce[%d], still in use. use_cnt=%lu.\n", jfce->fd, use_cnt);
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

    URMA_LOG_INFO("Deleting jfce, fd=%d, ret=%d\n", jfce->fd, ret);
    free(bdp_jfce);
    return ret;
}

static int bondp_create_vjfc(urma_context_t *ctx, bondp_jfc_t *bdp_jfc, urma_jfc_cfg_t *jfc_cfg)
{
    bondp_create_vjfc_udata_t jfc_info = {0};
    urma_jfc_cfg_t tmp_cfg = *jfc_cfg;
    /* We need to set jfce to NULL because the kernel-mode uobj is not created when the vjfce is created. */
    /* If a pointer to vjfce is passed here, */
    /* it will cause ubcore to report an error when creating jfc because it cannot find jfce. */
    /* If the corresponding kernel-space structure for vjfce is created, */
    /* then it is needed to set the fd of vjfce to the fd allocated in the kernel space. */
    /* Currently, the fd in vjfce is a brand new epoll_fd, so we need to change it to the kernel-allocated one. */
    tmp_cfg.jfce = NULL;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfc->p_jfc[i] != NULL) {
            jfc_info.slave_id[i] = bdp_jfc->p_jfc[i]->jfc_id;
            URMA_LOG_INFO_RL("PJFC ID is %u.\n", bdp_jfc->p_jfc[i]->jfc_id.id);
        }
    }

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jfc_info,
        .in_len = sizeof(bondp_create_vjfc_udata_t),
    };

    int ret = urma_cmd_create_jfc(ctx, &bdp_jfc->v_jfc, &tmp_cfg, &udata);
    if (ret != 0) {
        return ret;
    }
    /* It is necessary to backfill jfc_cfg->jfce because rearm_jfc will use this pointer, and it must point to vjfce. */
    bdp_jfc->v_jfc.jfc_cfg.jfce = jfc_cfg->jfce;
    URMA_LOG_DEBUG("Created vjfc successfully, jfc_id=%u, dev=%s, eid_idx=%u\n",
                   bdp_jfc->v_jfc.jfc_id.id, ctx->dev->name, ctx->eid_index);
    return 0;
}

static int bondp_create_pjfc(bondp_context_t *bdp_ctx, bondp_jfc_t *bdp_jfc, urma_jfc_cfg_t *cfg)
{
    urma_jfc_cfg_t p_cfg = *cfg;

    for (uint32_t n = 0; n < bdp_jfc->enabled_count; ++n) {
        uint32_t i = bdp_jfc->enabled_indices[n];
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
        URMA_LOG_DEBUG("Created pjfc successfully, idx=%u, jfc_id=%u, dev=%s, eid_idx=%u\n",
                       i, jfc->jfc_id.id, bdp_ctx->p_ctxs[i]->dev->name, bdp_ctx->p_ctxs[i]->eid_index);
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

        uint32_t jfc_id = bdp_jfc->p_jfc[i]->jfc_id.id;
        int p_ret = urma_delete_jfc(bdp_jfc->p_jfc[i]);
        if (p_ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to delete pjfc, idx=%d, jfc_id=%u, ret=%d\n",
                         i, jfc_id, p_ret);
            ret = p_ret;
        } else {
            URMA_LOG_INFO("Deleted pjfc, idx=%d, jfc_id=%u\n", i, jfc_id);
        }
        bdp_jfc->p_jfc[i] = NULL;
    }

    return ret;
}

static int init_active_indices_ex(bondp_context_t *bdp_ctx,
                                  uint32_t enabled_indices[], uint32_t *enabled_count,
                                  uint32_t active_indices[], uint32_t *active_count,
                                  const bondp_port_id_t *port_ids, uint32_t port_count);

urma_jfc_t *bondp_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);

    bondp_jfc_t *bdp_jfc = (bondp_jfc_t *)calloc(1, sizeof(bondp_jfc_t));
    if (bdp_jfc == NULL) {
        return NULL;
    }
    bdp_jfc->dev_num = bdp_ctx->dev_num;
    atomic_init(&bdp_jfc->lasted_polled_jfc_idx, 0);
    atomic_init(&bdp_jfc->fast_return_count, 0);
    atomic_init(&bdp_jfc->use_cnt.atomic_cnt, 0);

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (cfg->flag.bs.has_drv_ext != 0) {
        const bondp_jfc_cfg_t *bdp_cfg = (const bondp_jfc_cfg_t *)cfg;
        if (bdp_cfg->port_ids == NULL || bdp_cfg->port_count == 0) {
            URMA_LOG_ERR("Invalid active port config, port_ids is NULL or port_count is 0.\n");
            goto FREE_JFC;
        }
        cfg_active_port_count = bdp_cfg->port_count;
        cfg_active_port_ids = bdp_cfg->port_ids;
    }

    if (init_active_indices_ex(bdp_ctx, bdp_jfc->enabled_indices, &bdp_jfc->enabled_count,
                               bdp_jfc->active_indices, &bdp_jfc->active_count,
                               cfg_active_port_ids, cfg_active_port_count) != 0) {
        URMA_LOG_ERR("Failed to init active indices\n");
        goto FREE_JFC;
    }

    if (bondp_create_pjfc(bdp_ctx, bdp_jfc, cfg) != 0) {
        URMA_LOG_ERR("Failed to create pjfc\n");
        goto DELETE_PJFC;
    }

    if (bondp_create_vjfc(ctx, bdp_jfc, cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjfc, dev_name=%s, eid_idx=%u.\n",
                     ctx->dev->name, ctx->eid_index);
        goto DELETE_PJFC;
    }

    if (cfg->jfce != NULL) {
        bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(cfg->jfce, bondp_jfce_t, v_jfce);
        atomic_fetch_add(&bdp_jfce->use_cnt.atomic_cnt, 1);
    }

    URMA_LOG_DEBUG("Created jfc successfully, jfc_id=%u, dev=%s, eid_idx=%u\n",
                   bdp_jfc->v_jfc.jfc_id.id, ctx->dev->name, ctx->eid_index);
    return &bdp_jfc->v_jfc;

DELETE_PJFC:
    bondp_delete_pjfc(bdp_jfc);
FREE_JFC:
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
            URMA_LOG_ERR("modify pjfc fail, index=%d, jfc_id=%u, ret=%d\n",
                         i, bdp_jfc->p_jfc[i]->jfc_id.id, final_ret);
        }
    }
    return final_ret;
}

urma_status_t bondp_delete_jfc(urma_jfc_t *jfc)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);
    urma_status_t ret = URMA_SUCCESS;
    bondp_jfce_t *bdp_jfce = NULL;
    uint32_t jfc_id = jfc->jfc_id.id;

    if (jfc->jfc_cfg.jfce != NULL) {
        bdp_jfce = CONTAINER_OF_FIELD(jfc->jfc_cfg.jfce, bondp_jfce_t, v_jfce);
    }

    unsigned long use_cnt = atomic_load(&bdp_jfc->use_cnt.atomic_cnt);
    if (use_cnt > 0) {
        URMA_LOG_ERR("Failed to delete jfc[%d], still in use. use_cnt=%lu.\n", jfc_id, use_cnt);
        return URMA_EAGAIN;
    }

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
    URMA_LOG_INFO("Deleted jfc, jfc_id=%u, ret=%d\n", jfc_id, ret);
    return ret;
}

static inline int get_matrix_port_p_idx(int primary_idx, int port_idx)
{
    return primary_idx * PORT_EID_MAX_NUM_PER_DEV + port_idx + PRIMARY_EID_NUM;
}

static int convert_bond_port_id_to_active_index(const bondp_context_t *bdp_ctx, bondp_port_id_t port_id,
                                                uint32_t *active_index)
{
    if (port_id.chip_id == 0 || port_id.chip_id > CHIP_NUM) {
        URMA_LOG_ERR("Invalid primary chip_id=%u.\n", port_id.chip_id);
        return -1;
    }

    if (port_id.die_id != 1) {
        URMA_LOG_ERR("Invalid port_id.die_id=%u.\n", port_id.die_id);
        return -1;
    }

    if (port_id.port_idx == UINT8_MAX) {
        *active_index = port_id.chip_id - 1;
        return 0;
    }

    if (port_id.port_idx > PORT_NUM) {
        URMA_LOG_ERR("Invalid port_id.port_idx=%u.\n", port_id.port_idx);
        return -1;
    }

    *active_index = (uint32_t)get_matrix_port_p_idx(port_id.chip_id - 1, port_id.port_idx);
    if (*active_index >= (uint32_t)bdp_ctx->dev_num) {
        URMA_LOG_ERR("Invalid converted active index=%u.\n", *active_index);
        return -1;
    }
    return 0;
}

static int init_active_indices_ex(bondp_context_t *bdp_ctx,
                                  uint32_t enabled_indices[], uint32_t *enabled_count,
                                  uint32_t active_indices[], uint32_t *active_count,
                                  const bondp_port_id_t *port_ids, uint32_t port_count)
{
    if (port_ids == NULL || port_count == 0) {
        *enabled_count = bdp_ctx->enabled_count;
        *active_count = bdp_ctx->enabled_count;
        for (uint32_t i = 0; i < bdp_ctx->enabled_count; i++) {
            enabled_indices[i] = bdp_ctx->enabled_indices[i];
            active_indices[i] = bdp_ctx->enabled_indices[i];
        }
        return 0;
    }

    if (port_count > URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid port_count=%u.\n", port_count);
        return -1;
    }

    *enabled_count = 0;
    for (uint32_t n = 0; n < port_count; ++n) {
        uint32_t active_index = 0;
        if (convert_bond_port_id_to_active_index(bdp_ctx, port_ids[n], &active_index) != 0) {
            URMA_LOG_ERR("Invalid active port id, value=0x%lx.\n", port_ids[n].value);
            return -1;
        }

        bool is_duplicate = false;
        for (uint32_t i = 0; i < *enabled_count; ++i) {
            if (enabled_indices[i] == active_index) {
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) {
            continue;
        }
        enabled_indices[*enabled_count] = active_index;
        *enabled_count += 1;
        active_indices[*active_count] = active_index;
        *active_count += 1;
    }
    return 0;
}

static int init_active_indices(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_comp,
                               const bondp_port_id_t *port_ids, uint32_t port_count)
{
    return init_active_indices_ex(bdp_ctx, bdp_comp->enabled_indices, &bdp_comp->enabled_count,
                                  bdp_comp->active_indices, &bdp_comp->active_count,
                                  port_ids, port_count);
}

static int bondp_create_vjfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg, bondp_comp_t *bdp_jfs)
{
    bondp_create_vjfs_udata_t jfs_info = {0};

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jfs->p_jfs[i] != NULL) {
            jfs_info.slave_id[i] = bdp_jfs->p_jfs[i]->jfs_id;
        }
    }

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jfs_info,
        .in_len = sizeof(bondp_create_vjfs_udata_t),
    };
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
        atomic_store(&bdp_jfs->valid[i], true);
        URMA_LOG_DEBUG("Created pjfs successfully, idx=%u, jfs_id=%u, dev=%s, eid_idx=%u\n",
                       i, jfs->jfs_id.id, bdp_ctx->p_ctxs[i]->dev->name, bdp_ctx->p_ctxs[i]->eid_index);
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

        uint32_t jfs_id = bdp_jfs->p_jfs[i]->jfs_id.id;
        int p_ret = urma_delete_jfs(bdp_jfs->p_jfs[i]);
        if (p_ret != 0) {
            URMA_LOG_ERR("Failed to delete pjfs, idx=%d, jfs_id=%u, ret=%d\n",
                         i, jfs_id, p_ret);
            ret = p_ret;
        } else {
            URMA_LOG_INFO("Deleted pjfs, idx=%d, jfs_id=%u\n", i, jfs_id);
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
            URMA_LOG_ERR("Failed to add p_vjfs_id[%d]: ret=%d, p_jfs_id=%u, v_jfs_id=%u\n", i, ret, pjfs_id.id,
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
            URMA_LOG_ERR("Failed to delete p_vjfs_id node[%d], ret=%d, pjfs_id=%u.\n", i, ret, pjfs_id.id);
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
    atomic_init(&bdp_jfs->deleting, false);
    (void)pthread_spin_init(&bdp_jfs->send_lock, PTHREAD_PROCESS_PRIVATE);
    bdp_jfs->modify_to_error = false;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        for (uint32_t j = 0; j < URMA_UBAGG_DEV_MAX_NUM; j++) {
            atomic_init(&bdp_jfs->sqe_cnt[i][j], 0);
        }
    }

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (cfg->flag.bs.has_drv_ext != 0) {
        const bondp_jfs_cfg_t *bdp_cfg = (const bondp_jfs_cfg_t *)cfg;
        if (bdp_cfg->port_ids == NULL || bdp_cfg->port_count == 0) {
            URMA_LOG_ERR("Invalid active port config for jfs, port_ids is NULL or port_count is 0.\n");
            goto FREE_JFS;
        }
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

    uint32_t cfg_max_sge = (cfg->max_sge == 0 || cfg->max_sge > BONDP_MAX_SGE_NUM)
                               ? BONDP_MAX_SGE_NUM
                               : cfg->max_sge;
    if (bondp_init_wr_buf(bdp_jfs, &bdp_jfs->send_wr_buf, cfg->depth, cfg_max_sge, true) != 0) {
        URMA_LOG_ERR("Failed to init jfs wr buf\n");
        goto UNINIT_CONNECTION_TABLE;
    }

    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    URMA_LOG_DEBUG("Created jfs successfully, jfs_id=%u, dev=%s, eid_idx=%u\n",
                   bdp_jfs->v_jfs.jfs_id.id, ctx->dev->name, ctx->eid_index);
    return &bdp_jfs->v_jfs;

UNINIT_CONNECTION_TABLE:
    bondp_uninit_connection_table(bdp_jfs);
DEL_P_VJFS_ID:
    bondp_del_jfs_p_vjetty_info(bdp_jfs);
DELETE_VJFS:
    (void)bondp_delete_vjfs(bdp_jfs);
DELETE_PJFS:
    bondp_delete_pjfs(bdp_jfs);
FREE_JFS:
    bondp_uninit_wr_buf(&bdp_jfs->send_wr_buf);
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
    uint32_t jfs_id = jfs->jfs_id.id;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
     */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    atomic_store(&bdp_jfs->deleting, true);
    unsigned long use_cnt = atomic_load(&bdp_jfs->use_cnt.atomic_cnt);
    if (use_cnt == 0) {
        /* Invalidate fast-path cache */
        bondp_hash_table_inc_gen(&bdp_ctx->p_vjetty_id_table);
        /* Re-check */
        use_cnt = atomic_load(&bdp_jfs->use_cnt.atomic_cnt);
    }
    if (use_cnt > 0) {
        atomic_store(&bdp_jfs->deleting, false);
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jfs[%u], still in use. use_cnt=%lu\n", jfs_id, use_cnt);
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
    bondp_uninit_wr_buf(&bdp_jfs->send_wr_buf);

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
    URMA_LOG_INFO("Deleted jfs, jfs_id=%u, ret=%d\n", jfs_id, ret);
    return ret;
}

urma_status_t bondp_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr)
{
    urma_status_t ret = URMA_SUCCESS, final_ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);

    if (((attr->mask & JFS_STATE) != 0) && attr->state == URMA_JETTY_STATE_ERROR) {
        bdp_jfs->modify_to_error = true;
    }
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bdp_jfs->p_jfs[i] == NULL) {
            continue;
        }
        ret = urma_modify_jfs(bdp_jfs->p_jfs[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjfs fail, index=%d, jfs_id=%u, ret=%d\n",
                         i, bdp_jfs->p_jfs[i]->jfs_id.id, final_ret);
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
        jfr_info.enabled_indices[i] = (uint8_t)bdp_jfr->enabled_indices[i];
    }
    jfr_info.enabled_count = bdp_jfr->enabled_count;
    jfr_info.is_msn_enabled = bdp_ctx->msn_enable;

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jfr_info,
        .in_len = sizeof(bondp_create_vjfr_udata_t),
    };

    int ret = urma_cmd_create_jfr(&bdp_ctx->v_ctx, &bdp_jfr->v_jfr, cfg, &udata);
    if (ret) {
        URMA_LOG_ERR("bondp init jfr fail=%d.\n", ret);
        return -1;
    }
    return 0;
}

static int bondp_create_pjfr(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfr, urma_jfr_cfg_t *cfg)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    urma_jfr_cfg_t p_cfg = *cfg;

    for (uint32_t n = 0; n < bdp_jfr->enabled_count; ++n) {
        uint32_t i = bdp_jfr->enabled_indices[n];
        p_cfg.jfc = bdp_jfc->p_jfc[i];
        urma_jfr_t *jfr = urma_create_jfr(bdp_ctx->p_ctxs[i], &p_cfg);
        if (jfr == NULL) {
            URMA_LOG_ERR("Failed to create pjfr %d.\n", i);
            return -1;
        }
        jfr->jfr_cfg.user_ctx = (uint64_t)bdp_jfr;
        bdp_jfr->p_jfr[i] = jfr;
        atomic_store(&bdp_jfr->valid[i], true);
        URMA_LOG_DEBUG("Created pjfr successfully, idx=%u, jfr_id=%u, dev=%s, eid_idx=%u\n",
                       i, jfr->jfr_id.id, bdp_ctx->p_ctxs[i]->dev->name, bdp_ctx->p_ctxs[i]->eid_index);
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
        uint32_t jfr_id = bdp_jfr->p_jfr[i]->jfr_id.id;
        int p_ret = urma_delete_jfr(bdp_jfr->p_jfr[i]);
        if (p_ret != 0) {
            URMA_LOG_ERR("Failed to delete pjfr, idx=%d, jfr_id=%u, ret=%d\n",
                         i, jfr_id, p_ret);
            ret = p_ret;
        } else {
            URMA_LOG_INFO("Deleted pjfr, idx=%d, jfr_id=%u\n", i, jfr_id);
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
            URMA_LOG_ERR("Failed to add p_vjfr_id[%d]: ret=%d, p_jfr_id=%u, v_jfr_id=%u\n", i, ret, pjfr_id.id,
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
        urma_jfr_id_t pjfr_id = bdp_jfr->p_jfr[j]->jfr_id;
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
            URMA_LOG_ERR("Failed to delete p_vjfr_id node[%d]: ret=%d pjfr_id=%u\n", i, ret, pjfr_id.id);
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
        URMA_LOG_ERR("Failed to alloc bondp jfr, dev=%s, eid_idx=%u\n",
                     ctx->dev->name, ctx->eid_index);
        return NULL;
    }
    bdp_jfr->bondp_ctx = bdp_ctx;
    bdp_jfr->comp_type = BONDP_COMP_JFR;
    atomic_init(&bdp_jfr->use_cnt.atomic_cnt, 0);
    atomic_init(&bdp_jfr->deleting, false);

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (cfg->flag.bs.has_drv_ext != 0) {
        const bondp_jfr_cfg_t *bdp_cfg = (const bondp_jfr_cfg_t *)cfg;
        if (bdp_cfg->port_ids == NULL || bdp_cfg->port_count == 0) {
            URMA_LOG_ERR("Invalid active port config, port_ids is NULL or port_count is 0.\n");
            goto FREE_JFR;
        }
        cfg_active_port_count = bdp_cfg->port_count;
        cfg_active_port_ids = bdp_cfg->port_ids;
    }

    if (init_active_indices(bdp_ctx, bdp_jfr, cfg_active_port_ids, cfg_active_port_count) != 0) {
        URMA_LOG_ERR("Failed to init active indices\n");
        goto FREE_JFR;
    }

    if (bondp_create_pjfr(bdp_ctx, bdp_jfr, cfg) != 0) {
        URMA_LOG_ERR("Failed to create pjfr\n");
        goto DELETE_PJFR;
    }

    if (bondp_create_vjfr(bdp_ctx, cfg, bdp_jfr) != 0) {
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

    uint32_t cfg_max_sge = (cfg->max_sge == 0 || cfg->max_sge > BONDP_MAX_SGE_NUM)
                               ? BONDP_MAX_SGE_NUM
                               : cfg->max_sge;
    if (bdp_ctx->msn_enable && bondp_init_wr_buf(bdp_jfr, &bdp_jfr->recv_wr_buf, cfg->depth, cfg_max_sge, false) != 0) {
        URMA_LOG_ERR("Failed to init jfr wr buf\n");
        goto UNINIT_JFR_CONNECTION_TABLE;
    }

    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_jfc_t, v_jfc);
    atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);

    URMA_LOG_DEBUG("Created jfr successfully, jfr_id=%u, dev=%s, eid_idx=%u\n",
                   bdp_jfr->v_jfr.jfr_id.id, ctx->dev->name, ctx->eid_index);
    return &bdp_jfr->v_jfr;

UNINIT_JFR_CONNECTION_TABLE:
    bondp_uninit_connection_table(bdp_jfr);
DEL_P_VJFR_ID:
    bondp_del_jfr_p_vjetty_info(bdp_jfr);
DELETE_VJFR:
    (void)bondp_delete_vjfr(bdp_jfr);
DELETE_PJFR:
    bondp_delete_pjfr(bdp_jfr);
FREE_JFR:
    if (bdp_ctx->msn_enable) {
        bondp_uninit_wr_buf(&bdp_jfr->recv_wr_buf);
    }
    free(bdp_jfr);
    return NULL;
}

urma_status_t bondp_delete_jfr(urma_jfr_t *jfr)
{
    urma_status_t ret = URMA_SUCCESS;
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfr->jfr_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_context_t *bdp_ctx = bdp_jfr->bondp_ctx;
    uint32_t jfr_id = jfr->jfr_id.id;
    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
    */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    atomic_store(&bdp_jfr->deleting, true);
    unsigned long use_cnt = atomic_load(&bdp_jfr->use_cnt.atomic_cnt);
    if (use_cnt == 0) {
        /* Invalidate fast-path cache */
        bondp_hash_table_inc_gen(&bdp_ctx->p_vjetty_id_table);
        /* Re-check */
        use_cnt = atomic_load(&bdp_jfr->use_cnt.atomic_cnt);
    }
    if (use_cnt > 0) {
        atomic_store(&bdp_jfr->deleting, false);
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jfr[%u], still in use. use_cnt=%lu\n", jfr_id, use_cnt);
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
    if (bdp_ctx->msn_enable) {
        bondp_uninit_wr_buf(&bdp_jfr->recv_wr_buf);
    }

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
    URMA_LOG_INFO("Deleted jfr, jfr_id=%u, ret=%d\n", jfr_id, ret);
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
            URMA_LOG_ERR("modify pjfr fail, index=%d, jfr_id=%u, ret=%d\n",
                         i, bdp_jfr->p_jfr[i]->jfr_id.id, final_ret);
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
            URMA_LOG_ERR("query pjfr fail, index=%d, jfr_id=%u, ret=%d\n",
                         i, bdp_jfr->p_jfr[i]->jfr_id.id, ret);
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

    if (bondp_hc_fill_seg_info(bdp_ctx, &jetty_info.health_check_seg,
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
    jetty_info.is_msn_enabled = bdp_ctx->msn_enable;

    urma_cmd_udrv_priv_t udata = {
        .in_addr = (uint64_t)&jetty_info,
        .in_len = sizeof(bondp_create_vjetty_udata_t),
    };

    bdp_jetty->v_jetty.jetty_cfg = *jetty_cfg;
    int ret = urma_cmd_create_jetty(&bdp_ctx->v_ctx, &bdp_jetty->v_jetty, jetty_cfg, &udata);
    if (ret == 0) {
        bdp_jetty->v_jetty.jetty_cfg.shared.jfr->jfr_cfg = jetty_cfg->shared.jfr->jfr_cfg;
        bdp_jetty->v_jetty.jetty_cfg.shared.jfc = bondp_get_effective_shared_jfc(jetty_cfg);
        URMA_LOG_DEBUG("Created vjetty successfully, jetty_id=%u, dev=%s, eid_idx=%u\n",
                       bdp_jetty->v_jetty.jetty_id.id, bdp_ctx->v_ctx.dev->name, bdp_ctx->v_ctx.eid_index);
    } else {
        URMA_LOG_ERR("Failed to create vjetty, dev=%s, eid_idx=%u, ret=%d\n",
                     bdp_ctx->v_ctx.dev->name, bdp_ctx->v_ctx.eid_index, ret);
    }
    return ret;
}

static int bondp_create_pjetty(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, urma_jetty_cfg_t *jetty_cfg)
{
    bondp_jfc_t *bdp_jfs_jfc = CONTAINER_OF_FIELD(jetty_cfg->jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr, bondp_comp_t, base);
    bondp_jfc_t *bdp_rplc_jfc = NULL;
    urma_jetty_cfg_t p_cfg = *jetty_cfg;

    if (jetty_cfg->shared.jfc != NULL) {
        bdp_rplc_jfc = CONTAINER_OF_FIELD(jetty_cfg->shared.jfc, bondp_jfc_t, v_jfc);
    }
    for (uint32_t n = 0; n < bdp_jetty->enabled_count; ++n) {
        uint32_t i = bdp_jetty->enabled_indices[n];
        p_cfg.jfs_cfg.jfc = bdp_jfs_jfc->p_jfc[i];
        p_cfg.shared.jfr = bdp_jfr->p_jfr[i];
        if (bdp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
            p_cfg.id = 0;
        }
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
        atomic_store(&bdp_jetty->valid[i], true);
        URMA_LOG_DEBUG("Created pjetty successfully, idx=%u, jetty_id=%u, dev=%s, eid_idx=%u\n",
                       i, jetty->jetty_id.id, bdp_ctx->p_ctxs[i]->dev->name, bdp_ctx->p_ctxs[i]->eid_index);
    }
    return 0;
}

static int bondp_delete_vjetty(bondp_comp_t *bdp_jetty)
{
    unsigned long ref_cnt;

    ref_cnt = atomic_load(&(bdp_jetty->use_cnt.atomic_cnt));

    URMA_LOG_INFO("bondp delete, v_jetty id is %u, modify_to err is %d, vjetty_use_cnt is %lu.\n",
                  bdp_jetty->v_jetty.jetty_id.id, bdp_jetty->modify_to_error, ref_cnt);
    return urma_cmd_delete_jetty(&bdp_jetty->v_jetty);
}

static int bondp_delete_pjetty(bondp_comp_t *bdp_jetty)
{
    int ret = 0;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }

        URMA_LOG_INFO("bondp delete, p_jetty id is %u.\n",
                      bdp_jetty->p_jetty[i]->jetty_id.id);
        int p_ret = urma_delete_jetty(bdp_jetty->p_jetty[i]);
        if (p_ret != 0) {
            URMA_LOG_ERR("Failed to delete pjetty %d, ret=%d.\n", i, ret);
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
            URMA_LOG_INFO("Add repeated wk-jetty id[%d]: ret=%d, p_jetty_id=%u, v_jetty_id=%u\n",
                          i, ret, pjetty_id.id, jetty_id);
        } else if (ret != 0) {
            URMA_LOG_ERR("Failed to add p_vjetty_id[%d]: ret=%d, p_jetty_id=%u, v_jetty_id=%u\n",
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
            URMA_LOG_ERR("Failed to delete p_vjetty_id node: ret=%d pjetty_id=%u\n",
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
        URMA_LOG_ERR("Invalid well known jetty id=%d, should be in (0, 1024)\n", jetty_cfg->id);
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
    atomic_init(&bdp_jetty->deleting, false);
    (void)pthread_spin_init(&bdp_jetty->send_lock, PTHREAD_PROCESS_PRIVATE);
    bdp_jetty->modify_to_error = false;

    const bondp_port_id_t *cfg_active_port_ids = NULL;
    uint32_t cfg_active_port_count = 0;
    if (jetty_cfg->flag.bs.has_drv_ext != 0) {
        const bondp_jetty_cfg_t *bdp_cfg = (const bondp_jetty_cfg_t *)jetty_cfg;
        if (bdp_cfg->port_ids == NULL || bdp_cfg->port_count == 0) {
            URMA_LOG_ERR("Invalid active port config for jetty, port_ids is NULL or port_count is 0\n");
            goto FREE_JETTY;
        }
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

    if (bondp_create_vjetty(bdp_ctx, bdp_jetty, jetty_cfg) != 0) {
        URMA_LOG_ERR("Failed to create vjetty, %u\n", jetty_cfg->id);
        goto DELETE_PJETTY;
    }

    if (bondp_add_jetty_p_vjetty_id_info(bdp_ctx, bdp_jetty, bdp_jetty->v_jetty.jetty_id.id) != 0) {
        URMA_LOG_ERR("Failed to add jetty id to p_vjetty_id table\n");
        goto DELETE_VJETTY;
    }

    if (bondp_init_connection_table(bdp_jetty) != 0) {
        URMA_LOG_ERR("Failed to create jetty ctx\n");
        goto DEL_P_VJETTY_ID;
    }

    uint32_t cfg_max_sge = (jetty_cfg->jfs_cfg.max_sge == 0 || jetty_cfg->jfs_cfg.max_sge > BONDP_MAX_SGE_NUM)
                               ? BONDP_MAX_SGE_NUM
                               : jetty_cfg->jfs_cfg.max_sge;
    if (bondp_init_wr_buf(bdp_jetty, &bdp_jetty->send_wr_buf, jetty_cfg->jfs_cfg.depth, cfg_max_sge, true) != 0) {
        URMA_LOG_ERR("Failed to init jetty send wr buf\n");
        goto UNINIT_JETTY_CONNECTION_TABLE;
    }

    /* Validate bdp_jfr below at the function entry point to ensure they are not empty. */
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jetty_cfg->shared.jfr, bondp_comp_t, v_jfr);
    atomic_fetch_add(&bdp_jfr->use_cnt.atomic_cnt, 1);
    urma_jfc_t *shared_jfc = bondp_get_effective_shared_jfc(&bdp_jetty->v_jetty.jetty_cfg);
    bdp_jetty->v_jetty.jetty_cfg.shared.jfc = shared_jfc;
    if (shared_jfc != NULL) {
        bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(shared_jfc, bondp_jfc_t, v_jfc);
        atomic_fetch_add(&bdp_jfc->use_cnt.atomic_cnt, 1);
    }

    return &bdp_jetty->v_jetty;

UNINIT_JETTY_CONNECTION_TABLE:
    bondp_uninit_connection_table(bdp_jetty);
DEL_P_VJETTY_ID:
    bondp_del_jetty_p_vjetty_info(bdp_jetty);
DELETE_VJETTY:
    bondp_delete_vjetty(bdp_jetty);
DELETE_PJETTY:
    bondp_delete_pjetty(bdp_jetty);
FREE_JETTY:
    bondp_uninit_wr_buf(&bdp_jetty->send_wr_buf);
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
    urma_jfc_t *shared_jfc = bondp_get_effective_shared_jfc(&jetty->jetty_cfg);
    if (shared_jfc != NULL) {
        bdp_jfc = CONTAINER_OF_FIELD(shared_jfc, bondp_jfc_t, v_jfc);
    }

    /*
    ! This locking mechanism is implemented to prevent other threads from accessing this bondp_comp through this table.
    ! Currently, the only multi-threaded access path to this bondp_comp is through this table.
    ! Therefore, by locking it, we can avoid the scenario where the reference count is incremented again after
    ! the check use_cnt > 0 but before the lock is acquired.
    */
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    atomic_store(&bdp_jetty->deleting, true);
    unsigned long use_cnt = atomic_load(&bdp_jetty->use_cnt.atomic_cnt);
    if (use_cnt == 0) {
        /* Invalidate fast-path cache */
        bondp_hash_table_inc_gen(&bdp_ctx->p_vjetty_id_table);
        /* Re-check */
        use_cnt = atomic_load(&bdp_jetty->use_cnt.atomic_cnt);
    }
    if (use_cnt > 0) {
        atomic_store(&bdp_jetty->deleting, false);
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete jetty[%d], still in use. use_cnt=%lu\n", jetty->jetty_id.id, use_cnt);
        return URMA_EAGAIN;
    }
    bondp_del_jetty_p_vjetty_info_without_lock(bdp_jetty);
    /*
    ! The unlocking here is possible because after we remove this item,
    ! we can ensure that no other part of the system can access this pointer,
    ! thus allowing us to directly execute the deletion process.
    */
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_fb_cancel_tasks(bdp_ctx, jetty->jetty_id.id);
    bondp_uninit_connection_table(bdp_jetty);
    bondp_uninit_wr_buf(&bdp_jetty->send_wr_buf);
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

    if (((attr->mask & JETTY_STATE) != 0) && attr->state == URMA_JETTY_STATE_ERROR) {
        bdp_jetty->modify_to_error = true;
    }
    URMA_LOG_DEBUG("bondp modify_jetty v_jetty id is %u, old_state is %d.\n",
                   bdp_jetty->v_jetty.jetty_id.id, attr->state);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        ret = urma_modify_jetty(bdp_jetty->p_jetty[i], attr);
        if (ret != URMA_SUCCESS) {
            final_ret = ret;
            URMA_LOG_ERR("modify pjetty fail, index=%d, ret=%d\n", i, final_ret);
        }
        URMA_LOG_DEBUG("bondp modify_jetty p_jetty id is %u, new_state is %d.\n",
                       bdp_jetty->p_jetty[i]->jetty_id.id, attr->state);
    }
    return final_ret;
}
