/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond device ops file
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "bondp_api.h"
#include "bondp_context_table.h"
#include "bondp_datapath.h"
#include "bondp_health_check.h"
#include "bondp_segment.h"
#include "bondp_types.h"
#include "ubagg_ioctl.h"
#include "urma_device.h"
#include "urma_log.h"
#include "urma_provider.h"
#include "urma_types.h"

#include "bondp_provider_ops.h"

#define UBAGG_MAX_EVENT       1
#define UBAGG_ENABLE_RECOVERY "UBAGG_ENABLE_RECOVERY"

/* manager of global table in bonding device */
bondp_global_context_t *g_bondp_global_ctx = NULL;

static urma_ops_t g_bond_ops = {
    /* OPs name */
    .name = "BOND_OPS",

    /* Jetty OPs */
    .create_jfc = bondp_create_jfc,
    .modify_jfc = bondp_modify_jfc,
    .delete_jfc = bondp_delete_jfc,
    .create_jfs = bondp_create_jfs,
    .modify_jfs = bondp_modify_jfs,
    .query_jfs = NULL,
    .flush_jfs = NULL,
    .delete_jfs = bondp_delete_jfs,
    .create_jfr = bondp_create_jfr,
    .modify_jfr = bondp_modify_jfr,
    .query_jfr = bondp_query_jfr,
    .delete_jfr = bondp_delete_jfr,
    .import_jfr = bondp_import_jfr,
    .unimport_jfr = bondp_unimport_jfr,
    .advise_jfr = NULL,       /* UB doesn't have this ops */
    .unadvise_jfr = NULL,     /* UB doesn't have this ops */
    .advise_jfr_async = NULL, /* UB doesn't have this ops */
    .create_jetty = bondp_create_jetty,
    .modify_jetty = bondp_modify_jetty,
    .query_jetty = NULL,
    .flush_jetty = bondp_flush_jetty,
    .delete_jetty = bondp_delete_jetty,
    .import_jetty = bondp_import_jetty,
    .unimport_jetty = bondp_unimport_jetty,
    .advise_jetty = NULL,
    .unadvise_jetty = NULL,
    .advise_jetty_async = NULL,
    .bind_jetty = bondp_bind_jetty,
    .unbind_jetty = bondp_unbind_jetty,
    .create_jetty_grp = NULL,
    .delete_jetty_grp = NULL,
    .create_jfce = bondp_create_jfce,
    .delete_jfce = bondp_delete_jfce,
    .get_tpn = NULL,
    .modify_tp = NULL,

    /* Segment OPs */
    .alloc_token_id = bondp_alloc_token_id,
    .free_token_id = bondp_free_token_id,
    .register_seg = bondp_register_seg,
    .unregister_seg = bondp_unregister_seg,
    .import_seg = bondp_import_seg,
    .unimport_seg = bondp_unimport_seg,

    /* Events OPs */
    .get_async_event = bondp_get_async_event,
    .ack_async_event = bondp_ack_async_event,

    /* Other OPs */
    .user_ctl = bondp_user_ctl,

    /* Dataplane OPs */
    .post_jfs_wr = bondp_post_jfs_wr,
    .post_jfr_wr = bondp_post_jfr_wr,
    .post_jetty_send_wr = bondp_post_jetty_send_wr,
    .post_jetty_recv_wr = bondp_post_jetty_recv_wr,
    .poll_jfc = bondp_poll_jfc,
    .rearm_jfc = bondp_rearm_jfc,
    .wait_jfc = bondp_wait_jfc,
    .ack_jfc = bondp_ack_jfc,
};

static int bondp_global_ctx_init(bondp_global_context_t **bondp_global_ctx)
{
    bondp_global_context_t *ctx = (bondp_global_context_t *)calloc(1, sizeof(bondp_global_context_t));
    if (ctx == NULL) {
        URMA_LOG_ERR("Failed to alloc global context\n");
        return -1;
    }

    ctx->pid = (uint32_t)getpid();
    bondp_health_check_global_ctx_init(ctx);
    *bondp_global_ctx = ctx;
    return 0;
}

static int bondp_global_ctx_uninit(bondp_global_context_t *bondp_global_ctx)
{
    bondp_stop_health_check_thread();
    if (bondp_global_ctx->topo_map) {
        delete_topo_map(bondp_global_ctx->topo_map);
    }
    free(bondp_global_ctx);
    return 0;
}

urma_status_t bondp_init(urma_init_attr_t *conf)
{
    if (g_bondp_global_ctx != NULL) {
        URMA_LOG_ERR("Initialized already\n");
        return URMA_FAIL;
    }
    int ret = bondp_global_ctx_init(&g_bondp_global_ctx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to create global context.\n");
        return URMA_FAIL;
    }

    if (bondp_start_health_check_thread() != 0) {
        URMA_LOG_ERR("Failed to start health check thread.\n");
        (void)bondp_global_ctx_uninit(g_bondp_global_ctx);
        g_bondp_global_ctx = NULL;
        return URMA_FAIL;
    }
    return URMA_SUCCESS;
}

urma_status_t bondp_uninit(void)
{
    if (g_bondp_global_ctx == NULL) {
        URMA_LOG_WARN("Deinitialized already.\n");
        return URMA_SUCCESS; /* Keep the same logic as urma_uninit */
    }

    int ret = bondp_global_ctx_uninit(g_bondp_global_ctx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to delete global context.\n");
        return URMA_FAIL;
    }
    g_bondp_global_ctx = NULL;

    return URMA_SUCCESS;
}

static int get_topo_info_from_ko(bondp_context_t *bond_ctx)
{
    if (g_bondp_global_ctx->topo_map) {
        return 0;
    }
    struct ubagg_topo_info_out info_out;
    urma_user_ctl_in_t in = {
        .opcode = GET_TOPO_INFO,
    };
    urma_user_ctl_out_t out = {
        .addr = (uint64_t)&info_out,
        .len = sizeof(info_out),
    };
    urma_udrv_t data = {0};
    if (urma_cmd_user_ctl(&bond_ctx->v_ctx, &in, &out, &data)) {
        URMA_LOG_ERR("Failed to get topo info, change to general mode\n");
        g_bondp_global_ctx->skip_load_topo = true;
        return -1;
    }
    g_bondp_global_ctx->topo_map = create_topo_map(info_out.topo_info, info_out.node_num);
    if (g_bondp_global_ctx->topo_map == NULL) {
        URMA_LOG_ERR("Failed to create topo map\n");
        return -1;
    }

    bond_ctx->topo_map = g_bondp_global_ctx->topo_map;
    return 0;
}

static int bondp_init_v_ctx(bondp_context_t *bond_ctx, urma_device_t *dev, uint32_t eid_index, int dev_fd)
{
    urma_context_t *v_ctx = &bond_ctx->v_ctx;

    if (urma_read_eid_with_index(dev->sysfs_dev, eid_index, &v_ctx->eid)) {
        URMA_LOG_ERR("Failed to query eid\n");
        return -1;
    }

    v_ctx->dev = dev;
    v_ctx->ops = &g_bond_ops;
    v_ctx->dev_fd = dev_fd;
    v_ctx->eid_index = eid_index;
    atomic_init(&v_ctx->ref.atomic_cnt, 1UL);
    (void)pthread_mutex_init(&v_ctx->mutex, NULL);
    return 0;
}

static void bondp_uninit_v_ctx(bondp_context_t *bond_ctx)
{
    (void)pthread_mutex_destroy(&bond_ctx->v_ctx.mutex);
}

static void bondp_delete_p_ctx(bondp_context_t *bond_ctx)
{
    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bond_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        (void)urma_delete_context(bond_ctx->p_ctxs[i]);
        bond_ctx->p_ctxs[i] = NULL;
    }
}

static void bondp_restore_async_fd(bondp_context_t *bond_ctx)
{
    if (bond_ctx->v_ctx.async_fd >= 0) {
        (void)close(bond_ctx->v_ctx.async_fd);
    }
    bond_ctx->v_ctx.async_fd = bond_ctx->real_async_fd;
    bond_ctx->real_async_fd = -1;
}

static int bondp_init_ctx_table(bondp_context_t *bond_ctx)
{
    if (bdp_p_vjetty_id_table_create(&bond_ctx->p_vjetty_id_table, BONDP_MAX_NUM_JETTYS)) {
        URMA_LOG_ERR("Failed to create p_vjetty_id_table\n");
        return -1;
    }
    if (bdp_r_p2v_jetty_id_table_create(&bond_ctx->remote_p2v_jetty_id_table, BONDP_MAX_NUM_JETTYS)) {
        URMA_LOG_ERR("Failed to create remote_p2v_jetty_id_table\n");
        goto FREE_P_VJETTY_ID_TABLE;
    }
    if (bdp_r_v2p_token_id_table_create(&bond_ctx->remote_v2p_token_id_table, BONDP_MAX_NUM_RSEGS)) {
        URMA_LOG_ERR("Failed to create remote_v2p_token_id_table\n");
        goto FREE_V_PTOKEN_ID_TABLE;
    }
    atomic_init(&bond_ctx->token_id_cnt, 0);
    return 0;
FREE_V_PTOKEN_ID_TABLE:
    (void)bdp_r_p2v_jetty_id_table_destroy(&bond_ctx->remote_p2v_jetty_id_table);
FREE_P_VJETTY_ID_TABLE:
    bdp_p_vjetty_id_table_destroy(&bond_ctx->p_vjetty_id_table);
    return -1;
}

static void bondp_uninit_ctx_table(bondp_context_t *bond_ctx)
{
    bdp_r_v2p_token_id_table_destroy(&bond_ctx->remote_v2p_token_id_table);
    bdp_r_p2v_jetty_id_table_destroy(&bond_ctx->remote_p2v_jetty_id_table);
    bdp_p_vjetty_id_table_destroy(&bond_ctx->p_vjetty_id_table);
}

static bondp_context_t *bondp_create_ctx(void)
{
    bondp_context_t *bond_ctx = NULL;

    bond_ctx = calloc(1, sizeof(bondp_context_t));
    if (bond_ctx == NULL) {
        return NULL;
    }
    bond_ctx->real_async_fd = -1;
    bond_ctx->v_ctx.async_fd = -1;
    bondp_health_check_ctx_init(bond_ctx);
    if (bondp_init_ctx_table(bond_ctx)) {
        free(bond_ctx);
        return NULL;
    }
    return bond_ctx;
}

static void bondp_delete_ctx(bondp_context_t *bond_ctx)
{
    bondp_uninit_ctx_table(bond_ctx);
    free(bond_ctx);
}

static int set_fd_noblock(int fd)
{
    int ret, flags;
    flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        URMA_LOG_ERR("flags: %d\n", flags);
        return -1;
    }
    ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (ret != 0) {
        URMA_LOG_ERR("ret: %d\n", ret);
        return ret;
    }
    return 0;
}

static int init_slave_context_fd(bondp_context_t *bond_ctx)
{
    int ret = -1, i, j;
    struct epoll_event ev;

    for (i = 0; i < bond_ctx->dev_num; ++i) {
        if (bond_ctx->p_ctxs[i] != NULL) {
            int fd = bond_ctx->p_ctxs[i]->async_fd;
            if (set_fd_noblock(fd) != 0) {
                goto roll_back;
            }
            ev.events = EPOLLIN;
            ev.data.fd = fd;
            ev.data.ptr = (void *)bond_ctx->p_ctxs[i];
            if (epoll_ctl(bond_ctx->v_ctx.async_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
                URMA_LOG_ERR("failed to add fd: %u, errno: %d.\n", fd, errno);
                goto roll_back;
            }
        }
    }
    return 0;

roll_back:
    for (j = 0; j < i; j++) {
        (void)epoll_ctl(bond_ctx->v_ctx.async_fd, EPOLL_CTL_DEL,
                        bond_ctx->p_ctxs[j]->async_fd, NULL);
    }
    return ret;
}

static int bondp_create_pctx(bondp_context_t *bond_ctx, bondp_bonding_mode_t bonding_mode,
                             bondp_bonding_level_t bonding_level)
{
    bondp_userctl_physical_device_out_t dev_info = {0};
    urma_user_ctl_in_t in = {
        .opcode = GET_SLAVE_DEVICE,
    };
    urma_user_ctl_out_t out = {
        .addr = (uint64_t)&dev_info,
        .len = sizeof(bondp_userctl_physical_device_out_t),
    };
    urma_udrv_t data = {0};
    if (urma_cmd_user_ctl(&bond_ctx->v_ctx, &in, &out, &data)) {
        URMA_LOG_ERR("Failed to get slave device info\n");
        return -1;
    }

    if (dev_info.physical_dev_num <= 0 || dev_info.physical_dev_num > IODIE_NUM) {
        URMA_LOG_ERR("Invalid slave device number %d of device %s\n",
                     dev_info.physical_dev_num, bond_ctx->v_ctx.dev->name);
        return -1;
    }

    const uint32_t INVALID_EID_INDEX = UINT32_MAX;

    if (bonding_level == BONDP_BONDING_LEVEL_IODIE) {
        for (int i = 0; i < IODIE_NUM; i++) {
            bondp_physical_device_t *pdev = &dev_info.physical_devs[i];

            urma_device_t *dev = urma_get_device_by_name(pdev->dev_name);
            if (dev == NULL) {
                URMA_LOG_ERR("Failed to get device by name %s\n", pdev->dev_name);
                return -1;
            }

            int primary_eid_idx = pdev->primary_eid_idx;
            if (primary_eid_idx != INVALID_EID_INDEX) {
                bond_ctx->p_devs[i] = dev;
                bond_ctx->p_ctxs[i] = urma_create_context(dev, primary_eid_idx);
                if (bond_ctx->p_ctxs[i] == NULL) {
                    URMA_LOG_ERR("Failed to create context for primary eid, dev:%s, eid_idx:%d\n",
                                 pdev->dev_name, primary_eid_idx);
                    return -1;
                }
            }

            if (bonding_mode == BONDP_BONDING_MODE_STANDALONE) {
                break;
            }
        }
    } else {
        for (int i = 0; i < IODIE_NUM; i++) {

            bondp_physical_device_t *pdev = &dev_info.physical_devs[i];

            urma_device_t *dev = urma_get_device_by_name(pdev->dev_name);
            if (dev == NULL) {
                URMA_LOG_ERR("Failed to get device by name %s\n", pdev->dev_name);
                return -1;
            }

            for (int j = 0; j < PORT_EID_MAX_NUM_PER_DEV; ++j) {
                int port_eid_idx = pdev->port_eid_idx[j];
                int ctx_idx = IODIE_NUM + PORT_EID_MAX_NUM_PER_DEV * i + j;
                if (port_eid_idx != INVALID_EID_INDEX) {
                    bond_ctx->p_devs[ctx_idx] = dev;
                    bond_ctx->p_ctxs[ctx_idx] = urma_create_context(dev, port_eid_idx);
                    if (bond_ctx->p_ctxs[ctx_idx] == NULL) {
                        URMA_LOG_ERR("Failed to create context for port eid, dev:%s, eid_idx:%d, port_idx:%d\n",
                                     pdev->dev_name, port_eid_idx, j);
                        return -1;
                    }
                }
            }

            if (bonding_mode == BONDP_BONDING_MODE_STANDALONE) {
                break;
            }
        }
    }

    bond_ctx->dev_num = bonding_mode == BONDP_BONDING_MODE_STANDALONE
                            ? SINGLE_DIE_DEVNUM
                            : PRIMARY_EID_NUM + PORT_EID_MAX_NUM;
    return init_slave_context_fd(bond_ctx);
}

static int bondp_delete_pctx(bondp_context_t *bond_ctx)
{
    int ret = 0, sub_ret = 0;
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bond_ctx->p_ctxs[i] != NULL) {
            sub_ret = urma_delete_context(bond_ctx->p_ctxs[i]);
            if (sub_ret != 0) {
                URMA_LOG_ERR("Failed to delete pctx, idx:%d, ret:%d", i, sub_ret);
                ret = URMA_FAIL;
            }
            bond_ctx->p_ctxs[i] = NULL;
        }
    }
    return ret;
}

urma_context_t *bondp_create_context(urma_device_t *dev, uint32_t eid_index, int dev_fd)
{
    if (!g_bondp_global_ctx) {
        URMA_LOG_ERR("Uninitialized variables");
        return NULL;
    }

    bondp_context_t *bond_ctx = bondp_create_ctx();
    if (bond_ctx == NULL) {
        URMA_LOG_ERR("Failed to create ctx");
        return NULL;
    }

    int ret = 0;
    ret = bondp_init_v_ctx(bond_ctx, dev, eid_index, dev_fd);
    if (ret) {
        URMA_LOG_ERR("Failed to init v_ctx\n");
        goto DELETE_CTX;
    }
    /* params of urma_cmd_user_ctl */
    urma_context_cfg_t cfg = {
        .dev = dev,
        .dev_fd = dev_fd,
        .eid_index = eid_index,
        .uasid = 0,
        .ops = &g_bond_ops,
    };
    urma_cmd_udrv_priv_t udata = {0};
    ret = urma_cmd_create_context(&bond_ctx->v_ctx, &cfg, &udata);
    if (ret) {
        URMA_LOG_ERR("Failed to create context\n");
        goto UNINIT_V_CTX;
    }
    bond_ctx->real_async_fd = bond_ctx->v_ctx.async_fd;
    bond_ctx->v_ctx.async_fd = epoll_create(UBAGG_MAX_EVENT);
    if (bond_ctx->v_ctx.async_fd == -1) {
        URMA_LOG_ERR("Failed to create epoll %s\n", ub_strerror(errno));
        goto CMD_DELETE_CONTEXT;
    }
    bond_ctx->v_ctx.aggr_mode = URMA_AGGR_MODE_STANDALONE;
    bond_ctx->bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    bond_ctx->bonding_level = BONDP_BONDING_LEVEL_IODIE;

    if (get_topo_info_from_ko(bond_ctx) != 0) {
        URMA_LOG_ERR("Failed to get topo info, change to general mode\n");
        goto CMD_DELETE_CONTEXT;
    }

    ret = bondp_create_pctx(bond_ctx, bond_ctx->bonding_mode, bond_ctx->bonding_level);
    if (ret) {
        URMA_LOG_ERR("Failed to create pctx\n");
        goto DELETE_PCTX;
    }

    if (bondp_create_health_check_ctx(bond_ctx) != 0) {
        URMA_LOG_ERR("Failed to create health check scene\n");
        goto CMD_DELETE_CONTEXT;
    }

    URMA_LOG_INFO("Finish to create ctx, dev_name: %s, eid_idx: %u.\n",
                  dev->name, eid_index);

    return &bond_ctx->v_ctx;

DELETE_PCTX:
    bondp_delete_pctx(bond_ctx);
CMD_DELETE_CONTEXT:
    bondp_destroy_health_check_ctx(bond_ctx);
    bondp_delete_p_ctx(bond_ctx);
    bondp_restore_async_fd(bond_ctx);
    (void)urma_cmd_delete_context(&bond_ctx->v_ctx);
UNINIT_V_CTX:
    bondp_uninit_v_ctx(bond_ctx);
DELETE_CTX:
    bondp_delete_ctx(bond_ctx);
    return NULL;
}

urma_status_t bondp_delete_context(urma_context_t *ctx)
{
    bondp_context_t *bond_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    urma_status_t ret = URMA_SUCCESS;
    char dev_name[URMA_MAX_NAME] = {0};
    uint32_t eid_index = ctx->eid_index;

    (void)strcpy(dev_name, ctx->dev->name);
    bondp_destroy_health_check_ctx(bond_ctx);
    if (bondp_delete_pctx(bond_ctx) != 0) {
        URMA_LOG_ERR("Failed to delete pctx\n");
        ret = URMA_FAIL;
    }
    bondp_restore_async_fd(bond_ctx);
    if (urma_cmd_delete_context(&bond_ctx->v_ctx)) {
        URMA_LOG_ERR("Failed to urma_cmd_delete_context");
        ret = URMA_FAIL;
    }
    bondp_uninit_v_ctx(bond_ctx);
    bondp_delete_ctx(bond_ctx);

    URMA_LOG_INFO("Finish to delete ctx, dev_name: %s, eid_idx: %u.\n",
                  dev_name, eid_index);

    return ret;
}

int bondp_set_bonding_mode(urma_context_t *ctx, bondp_bonding_mode_t bonding_mode,
                           bondp_bonding_level_t bonding_level)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid context.\n");
        return -EINVAL;
    }

    if (bonding_mode < 0 || bonding_mode >= BONDP_BONDING_MODE_MAX) {
        URMA_LOG_ERR("Invalid bonding mode: %d\n", bonding_mode);
        return -EINVAL;
    }

    if (bonding_level < 0 || bonding_level >= BONDP_BONDING_LEVEL_MAX) {
        URMA_LOG_ERR("Unsupported bonding level: %d\n", bonding_level);
        return -EINVAL;
    }

    bondp_context_t *bond_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    int ret = 0;

    (void)pthread_mutex_lock(&ctx->mutex);
    if (bond_ctx->bonding_mode == bonding_mode &&
        bond_ctx->bonding_level == bonding_level) {
        goto EXIT;
    }

    ret = bondp_delete_pctx(bond_ctx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to delete pctx when set bonding mode, ret:%d\n", ret);
        goto EXIT;
    }

    ret = bondp_create_pctx(bond_ctx, bonding_mode, bonding_level);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to create pctx when set aggr mode, ret:%d\n", ret);
        goto EXIT;
    }

EXIT:
    (void)pthread_mutex_unlock(&ctx->mutex);
    return ret;
}
