/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond device ops file
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05
 */

#include <endian.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include "urma_log.h"
#include "urma_types.h"
#include "urma_device.h"
#include "urma_provider.h"
#include "ubagg_ioctl.h"
#include "bondp_types.h"
#include "bondp_api.h"
#include "ubagg_ioctl.h"
#include "bondp_segment.h"
#include "bondp_datapath.h"
#include "bondp_context_table.h"
#include "bondp_provider_ops.h"

#define UBAGG_DISABLE_SINGLE_DIE "UBAGG_DISABLE_SINGLE_DIE"
#define UBAGG_MAX_EVENT 1
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
    .advise_jfr = NULL,                         /* UB doesn't have this ops */
    .unadvise_jfr = NULL,                       /* UB doesn't have this ops */
    .advise_jfr_async = NULL,                   /* UB doesn't have this ops */
    .create_jetty = bondp_create_jetty,
    .modify_jetty = bondp_modify_jetty,
    .query_jetty = NULL,
    .flush_jetty = NULL,
    .delete_jetty = bondp_delete_jetty,
    .import_jetty = bondp_import_jetty,
    .unimport_jetty = bondp_unimport_jetty,
    .advise_jetty = bondp_advise_jetty,         /* In case we need to bind two non-UB devices */
    .unadvise_jetty = bondp_unadvise_jetty,     /* In case we need to bind two non-UB devices */
    .advise_jetty_async = NULL,                 /* UB doesn't have this ops */
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

    const char *env_value = getenv(UBAGG_DISABLE_SINGLE_DIE);
    if (env_value == NULL || *env_value == '\0') {
        URMA_LOG_INFO("There is no env_value about UBAGG_DISABLE_SINGLE_DIE");
    }
    ctx->use_single_die = !(env_value != NULL && *env_value);
    env_value = getenv(UBAGG_ENABLE_RECOVERY);
    ctx->disable_recovery = !(env_value != NULL && *env_value);

    *bondp_global_ctx = ctx;
    return 0;
}

static int bondp_global_ctx_uninit(bondp_global_context_t *bondp_global_ctx)
{
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

static inline bool is_urma_eid_equal(urma_eid_t *eid1, urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

static int get_eid_index(urma_device_t *dev, urma_eid_t *eid)
{
    urma_eid_info_t *eid_list;
    uint32_t eid_cnt;
    int eid_index = -1;

    eid_list = urma_get_eid_list(dev, &eid_cnt);
    if (eid_list == NULL) {
        return -1;
    }
    if (eid != NULL) {
        for (int i = 0; i < eid_cnt; ++i) {
            if (is_urma_eid_equal(&eid_list[i].eid, eid)) {
                eid_index = eid_list[i].eid_index;
                break;
            }
        }
    } else {
        if (eid_cnt > 0) {
            eid_index = eid_list[0].eid_index;
        }
    }
    urma_free_eid_list(eid_list);
    return eid_index;
}

static int get_dev_and_ctx_by_name(char *dev_name, urma_device_t **dev, urma_context_t **ctx)
{
    *dev = urma_get_device_by_name(dev_name);
    if (*dev == NULL) {
        URMA_LOG_ERR("Failed to get device\n");
        return -1;
    }
    int eid_index = get_eid_index(*dev, NULL);
    if (eid_index < 0) {
        URMA_LOG_ERR("Failed to get eid_idx\n");
        return -1;
    }
    *ctx = urma_create_context(*dev, eid_index);
    if (*ctx == NULL) {
        URMA_LOG_ERR("Failed to create context\n");
        return -1;
    }
    return 0;
}
/**
 * This function will only be called in matrix server mode
 * so all devices are UB devices
 */
static int get_dev_and_ctx_by_eid(urma_eid_t *eid, urma_device_t **dev, urma_context_t **ctx)
{
    *dev = urma_get_device_by_eid(*eid, URMA_TRANSPORT_UB);
    if (*dev == NULL) {
        URMA_LOG_ERR("Failed to get device\n");
        return -1;
    }
    int eid_index = get_eid_index(*dev, eid);
    if (eid_index < 0) {
        URMA_LOG_ERR("Failed to get eid_idx\n");
        return -1;
    }
    *ctx = urma_create_context(*dev, eid_index);
    if (*ctx == NULL) {
        URMA_LOG_ERR("Failed to create context\n");
        return -1;
    }
    return 0;
}

static int get_topo_info_from_ko(bondp_context_t *bond_ctx)
{
    if (g_bondp_global_ctx->topo_map) {
        return 0;
    }
    struct ubagg_topo_info_out info_out;
    urma_user_ctl_in_t in = {
        .opcode = GET_TOPO_INFO
    };
    urma_user_ctl_out_t out = {
        .addr = (uint64_t)&info_out,
        .len = sizeof(info_out)
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

static int bondp_init_ctx_table(bondp_context_t *bond_ctx)
{
    if (bdp_tjetty_id_table_create(&bond_ctx->tjetty_id_table, BONDP_MAX_NUM_JETTYS * URMA_UBAGG_DEV_MAX_NUM)) {
        URMA_LOG_ERR("Failed to create hash table tjetty_id_table\n");
        return -1;
    }
    if (bondp_bitmap_init(&bond_ctx->token_id_bitmap, BONDP_MAX_NUM_SEGS + 1)) {
        URMA_LOG_ERR("Failed to create token_id_bitmap\n");
        goto FREE_TJETTY_TABLE;
    }
    if (bondp_id_store_init(&bond_ctx->ljetty_id_store, BONDP_MAX_NUM_JETTYS)) {
        URMA_LOG_ERR("Failed to create ljetty_id_store");
        goto FREE_TOKEN_ID_BITMAP;
    }
    if (bdp_p_vjetty_id_table_create(&bond_ctx->p_vjetty_id_table, BONDP_MAX_NUM_JETTYS)) {
        URMA_LOG_ERR("Failed to create p_vjetty_id_table\n");
        goto ID_STORE_UNINIT;
    }
    if (bdp_r_p2v_jetty_id_table_create(&bond_ctx->remote_p2v_jetty_id_table, BONDP_MAX_NUM_JETTYS)) {
        URMA_LOG_ERR("Failed to create remote_p2v_jetty_id_table\n");
        goto FREE_P_VJETTY_ID_TABLE;
    }
    if (bdp_r_p2v_jetty_id_table_create(&bond_ctx->remote_v2p_token_id_table, BONDP_MAX_NUM_RSEGS)) {
        URMA_LOG_ERR("Failed to create remote_v2p_jetty_id_table\n");
        goto FREE_V_PTOKEN_ID_TABLE;
    }
    atomic_init(&bond_ctx->token_id_cnt, 0);
    return 0;
FREE_V_PTOKEN_ID_TABLE:
    (void)bdp_r_p2v_jetty_id_table_destroy(&bond_ctx->remote_v2p_token_id_table);
FREE_P_VJETTY_ID_TABLE:
    bdp_p_vjetty_id_table_destroy(&bond_ctx->p_vjetty_id_table);
ID_STORE_UNINIT:
    bondp_id_store_uninit(&bond_ctx->ljetty_id_store);
FREE_TOKEN_ID_BITMAP:
    bondp_bitmap_uninit(&bond_ctx->token_id_bitmap);
FREE_TJETTY_TABLE:
    bdp_tjetty_id_table_destroy(&bond_ctx->tjetty_id_table);
    return -1;
}

static void bondp_uninit_ctx_table(bondp_context_t *bond_ctx)
{
    bdp_r_p2v_jetty_id_table_destroy(&bond_ctx->remote_p2v_jetty_id_table);
    bdp_p_vjetty_id_table_destroy(&bond_ctx->p_vjetty_id_table);
    bondp_id_store_uninit(&bond_ctx->ljetty_id_store);
    bondp_bitmap_uninit(&bond_ctx->token_id_bitmap);
    bdp_tjetty_id_table_destroy(&bond_ctx->tjetty_id_table);
}

static bondp_context_t* bondp_create_ctx()
{
    bondp_context_t *bond_ctx = NULL;

    bond_ctx = calloc(1, sizeof(bondp_context_t));
    if (bond_ctx == NULL) {
        URMA_LOG_ERR("Failed to alloc bondp_context_t\n");
        return NULL;
    }
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

static int init_general_slave_devices(bondp_context_t *bond_ctx)
{
    /* user ioctl input and output */
    struct ubagg_slave_device dev_info = {0};
    urma_user_ctl_in_t in = {
        .opcode = GET_SLAVE_DEVICE
    };
    urma_user_ctl_out_t out = {
        .addr = (uint64_t)&dev_info,
        .len = sizeof(struct ubagg_slave_device)
    };
    urma_udrv_t data = {0};
    /* error handling param of urma_create_context */
    int i = 0;

    if (urma_cmd_user_ctl(&bond_ctx->v_ctx, &in, &out, &data)) {
        URMA_LOG_ERR("Failed to get slave device info\n");
        return -1;
    }

    if (!is_valid_dev_num(dev_info.slave_dev_num)) {
        URMA_LOG_ERR("Invalid slave device number %d of device %s\n", dev_info.slave_dev_num,
            bond_ctx->v_ctx.dev->name);
        return -1;
    }

    if (is_single_dev_mode(&bond_ctx->v_ctx)) {
        bond_ctx->dev_num = SINGLE_DIE_IODIE_NUM;
    } else {
        bond_ctx->dev_num = dev_info.slave_dev_num;
    }

    for (i = 0; i < bond_ctx->dev_num; ++i) {
        if (get_dev_and_ctx_by_name(dev_info.slave_dev_name[i], &bond_ctx->p_devs[i], &bond_ctx->p_ctxs[i])) {
            URMA_LOG_ERR("Failed to create dev ctx %d in bonding\n", i);
            goto DELETE_SLAVE_CTX;
        }
    }
    return init_slave_context_fd(bond_ctx);

DELETE_SLAVE_CTX:
    for (int j = 0; j < i; ++j) {
        urma_delete_context(bond_ctx->p_ctxs[j]);
    }
    return -1;
}

static int init_matrix_slave_devices(bondp_context_t *bond_ctx)
{
    bond_ctx->topo_map = g_bondp_global_ctx->topo_map;
    topo_info_t *topo_info = get_topo_info_by_bonding_eid(bond_ctx->topo_map, &bond_ctx->v_ctx.eid);
    if (topo_info == NULL) {
        URMA_LOG_ERR("Failed to get topo info by bonding eid\n");
        return -1;
    }
    int ret = 0;
    int i = 0;
    int j = 0;
    int iodie_num = is_single_dev_mode(&bond_ctx->v_ctx) ? SINGLE_DIE_IODIE_NUM : PRIMARY_EID_NUM;
    /* The second iodie is empty and is set to valid in single-die mode */
    bool iodie_valid[IODIE_NUM] = {false, is_single_dev_mode(&bond_ctx->v_ctx)};
    for (i = 0; i < iodie_num; ++i) {
        /* Primary EID must be valid */
        if (is_empty_eid((urma_eid_t *)(topo_info->io_die_info[i].primary_eid))) {
            URMA_LOG_ERR("Primary eid %d is NULL\n", i);
            goto DELETE_CTX;
        }
        ret = get_dev_and_ctx_by_eid((urma_eid_t *)topo_info->io_die_info[i].primary_eid,
            &bond_ctx->primary_devs[i], &bond_ctx->primary_ctxs[i]);
        if (ret) {
            URMA_LOG_ERR("Failed to create ctx for primary eid[%d]\n", i);
            goto DELETE_CTX;
        }
        /* There should be at least one valid port eid */
        bool port_eid_valid = false;
        for (j = 0; j < PORT_EID_MAX_NUM_PER_DEV; ++j) {
            if (is_empty_eid((urma_eid_t *)(topo_info->io_die_info[i].port_eid[j]))) {
                URMA_LOG_INFO("Skip port ctx [%d, %d], eid is empty", i, j);
                continue;
            }
            int port_idx = get_matrix_port_ctx_idx(i, j);
            ret = get_dev_and_ctx_by_eid((urma_eid_t *)(topo_info->io_die_info[i].port_eid[j]),
                &bond_ctx->port_devs[port_idx], &bond_ctx->port_ctxs[port_idx]);
            if (ret) {
                URMA_LOG_ERR("Failed to create port ctx[%d, %d]\n", i, j);
                goto DELETE_CTX;
            }
            port_eid_valid = true;
        }
        iodie_valid[i] = port_eid_valid;
    }
    if (!iodie_valid[0] || !iodie_valid[1]) {
        i = iodie_num - 1;
        URMA_LOG_ERR("Either iodie is invalid: %d %d\n", iodie_valid[0], iodie_valid[1]);
        goto DELETE_CTX;
    }
    bond_ctx->dev_num = is_single_dev_mode(&bond_ctx->v_ctx) ? SINGLE_DIE_DEVNUM : PRIMARY_EID_NUM + PORT_EID_MAX_NUM;
    return init_slave_context_fd(bond_ctx);
DELETE_CTX:
    /*
    This branch is only entered in error cases,
    and at this time, the value of i is at most PRIMARY_EID_NUM - 1,
    so there is no array out of bounds situation.
    */
    for (int p = 0; p <= i; ++p) {
        for (int q = 0; q < PORT_EID_MAX_NUM_PER_DEV; ++q) {
            int port_idx = get_matrix_port_ctx_idx(p, q);
            if (bond_ctx->port_ctxs[port_idx]) {
                urma_delete_context(bond_ctx->port_ctxs[port_idx]);
            }
        }
        if (bond_ctx->primary_ctxs[p]) {
            urma_delete_context(bond_ctx->primary_ctxs[p]);
        }
    }
    return -1;
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
        goto UNINIT_V_CTX;
    }
    bond_ctx->v_ctx.aggr_mode = g_bondp_global_ctx->use_single_die
        ? URMA_AGGR_MODE_STANDALONE
        : URMA_AGGR_MODE_BALANCE;

    if (!g_bondp_global_ctx->skip_load_topo && get_topo_info_from_ko(bond_ctx) == 0) {
        ret = init_matrix_slave_devices(bond_ctx);
    } else {
        ret = init_general_slave_devices(bond_ctx);
    }
    if (ret) {
        goto CMD_DELETE_CONTEXT;
    }

    return &bond_ctx->v_ctx;

CMD_DELETE_CONTEXT:
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

    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bond_ctx->p_ctxs[i] && urma_delete_context(bond_ctx->p_ctxs[i])) {
            URMA_LOG_ERR("Failed to delete context %d", i);
            ret = URMA_FAIL;
        }
    }
    (void)close(bond_ctx->v_ctx.async_fd);
    bond_ctx->v_ctx.async_fd = bond_ctx->real_async_fd;
    if (urma_cmd_delete_context(&bond_ctx->v_ctx)) {
        URMA_LOG_ERR("Failed to urma_cmd_delete_context");
        ret = URMA_FAIL;
    }
    bondp_uninit_v_ctx(bond_ctx);
    bondp_delete_ctx(bond_ctx);
    return ret;
}
