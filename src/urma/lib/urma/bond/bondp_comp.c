/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of Bonding Component
 * Author: Ma Chuan
 * Create: 2025-02-12
 * Note:
 * History: 2025-02-12  Create file
 */
#include "urma_log.h"
#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_provider.h"
#include "bondp_comp.h"

/* bondp component common function types */
typedef void *(*bondp_comp_get_args_list_t)(bondp_context_t *bdp_ctx, void *cfg, int *args_num);
typedef void *(*bondp_comp_create_t)(urma_context_t *p_ctx, void *arg);
typedef urma_status_t (*bondp_comp_init_comp_attr_t)(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, void *cfg);
typedef urma_status_t (*bondp_comp_delete_t)(void *);
typedef urma_status_t (*bondp_comp_uninit_comp_attr_t)(bondp_comp_t *bdp_comp);

struct bondp_comp_ops {
    /* sizeof the component structure */
    uint32_t size;
    /* sizeof the component cfg */
    uint32_t cfg_size;
    /* return args list to create components */
    /* this list will be freed after creating components */
    bondp_comp_get_args_list_t get_args_list;
    /* create one component according to arg and returns ptr */
    bondp_comp_create_t create;
    /* init the attr in bdp_comp->base */
    bondp_comp_init_comp_attr_t init_comp_attr;
    /* delete the component created by *create* */
    bondp_comp_delete_t delete;
    /* uninit the attr in bdp_comp->base */
    bondp_comp_uninit_comp_attr_t uninit_comp_attr;
};

// table ops no lock, caller needs to ensure concurrency safety
bdp_vjfce_info_t *bdp_vjfce_info_table_lookup(bondp_hash_table_t *tbl, int key)
{
    bdp_vjfce_info_t *target = NULL;
    HMAP_FIND_INNER(&tbl->hmap, &key, sizeof(key), target);
    return target;
}

int bdp_vjfce_info_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, NULL, NULL, NULL);
}

int bdp_vjfce_info_table_add(bondp_hash_table_t *tbl, bdp_vjfce_info_t *node)
{
    if (bdp_vjfce_info_table_lookup(tbl, node->key) != NULL) {
        URMA_LOG_ERR("exist node in map.\n");
        return -EEXIST;
    }

    bdp_vjfce_info_t *tmp = calloc(1, sizeof(bdp_vjfce_info_t));
    if (tmp == NULL) {
        return -ENOMEM;
    }
    tmp->key = node->key;
    tmp->p_jfce = node->p_jfce;

    HMAP_INSERT_INNER(&tbl->hmap, tmp, &tmp->key, sizeof(tmp->key));
    URMA_LOG_DEBUG("Success add entry, fd:%d.\n", node->key);

    return 0;
}

void bdp_vjfce_info_table_del(bondp_hash_table_t *tbl, int key)
{
    bdp_vjfce_info_t *target = bdp_vjfce_info_table_lookup(tbl, key);
    if (target == NULL) {
        return;
    }

    ub_hmap_remove(&tbl->hmap, &target->node);
    URMA_LOG_DEBUG("Success del entry, fd:%d.\n", key);
    free(target);
}

void bdp_vjfce_info_table_close_fd(bondp_comp_t *bdp_comp)
{
    bondp_hash_table_t *tbl = (bondp_hash_table_t *)bdp_comp->comp_ctx;
    if (!tbl) {
        return;
    }
    bdp_vjfce_info_t *next = NULL;
    bdp_vjfce_info_t *cur = NULL;
    struct epoll_event ev = {0};
    HMAP_FOR_EACH_SAFE(cur, next, node, &tbl->hmap) {
        epoll_ctl(bdp_comp->v_jfce.fd, EPOLL_CTL_DEL, cur->key, &ev);
    }

    close(bdp_comp->v_jfce.fd);
}

void bdp_vjfce_info_table_destroy(bondp_hash_table_t *tbl)
{
    bdp_vjfce_info_t *cur = NULL;
    bdp_vjfce_info_t *next = NULL;
    (void)pthread_rwlock_wrlock(&tbl->lock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &tbl->hmap) {
        ub_hmap_remove(&tbl->hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&tbl->hmap);
    (void)pthread_rwlock_unlock(&tbl->lock);
    (void)pthread_rwlock_destroy(&tbl->lock);
}

static int bondp_insert_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce)
{
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = p_jfce->fd;
    if (epoll_ctl(v_jfce->fd, EPOLL_CTL_ADD, p_jfce->fd, &ev) != 0) {
        URMA_LOG_ERR("Fail to add fd:%d to epoll fd:%d.\n", p_jfce->fd, v_jfce->fd);
        return URMA_FAIL;
    }
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(v_jfce, bondp_comp_t, base);
    bdp_vjfce_info_t info = {
        .key = p_jfce->fd,
        .p_jfce = p_jfce,
    };
    bondp_hash_table_t *v_jfce_table = (bondp_hash_table_t *)bdp_comp->comp_ctx;
    (void)pthread_rwlock_wrlock(&v_jfce_table->lock);
    int ret = bdp_vjfce_info_table_add((bondp_hash_table_t *)bdp_comp->comp_ctx, &info);
    (void)pthread_rwlock_unlock(&v_jfce_table->lock);
    return ret;
}

static void bondp_remove_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce)
{
    struct epoll_event ev = {0};
    if (epoll_ctl(v_jfce->fd, EPOLL_CTL_DEL, p_jfce->fd, &ev) != 0) {
        URMA_LOG_ERR("Fail to del fd:%d to epoll fd:%d.\n", p_jfce->fd, v_jfce->fd);
    }
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(v_jfce, bondp_comp_t, base);
    bondp_hash_table_t *v_jfce_table = (bondp_hash_table_t *)bdp_comp->comp_ctx;

    (void)pthread_rwlock_wrlock(&v_jfce_table->lock);
    bdp_vjfce_info_table_del((bondp_hash_table_t *)bdp_comp->comp_ctx, p_jfce->fd);
    (void)pthread_rwlock_unlock(&v_jfce_table->lock);
}

/* JFCE related ops */
static urma_jfce_cfg_t *bondp_jfce_get_args_list(bondp_context_t *bdp_ctx, urma_jfce_cfg_t *cfg, int *args_num)
{
    /* JFCE doesn't require cfg, so the input *cfg is NULL */
    /* Entry entry of args is NULL pointer */
    urma_jfce_cfg_t *args = calloc(bdp_ctx->dev_num, sizeof(urma_jfce_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc jfce args");
        return NULL;
    }
    *args_num = bdp_ctx->dev_num;
    return args;
}

static urma_jfce_t *bondp_create_jfce_comp(urma_context_t *p_ctx, void *arg)
{
    return urma_create_jfce(p_ctx);
}

static urma_status_t bondp_jfce_init_comp_attr_not_single_die(bondp_comp_t *bdp_comp,
    bondp_context_t *bdp_ctx, urma_jfce_cfg_t *cfg)
{
    int i = 0;
    bdp_comp->v_jfce.urma_ctx = &bdp_ctx->v_ctx;
    bdp_comp->v_jfce.fd = epoll_create(BOND_EPOLL_NUM);
    if (bdp_comp->v_jfce.fd < 0) {
        URMA_LOG_ERR("Fail to create epoll_fd.\n");
        return URMA_FAIL;
    }

    bdp_comp->comp_ctx = (void *)calloc(1, sizeof(bondp_hash_table_t));
    if (bdp_comp->comp_ctx == NULL) {
        goto close_fd;
    }

    if (bdp_vjfce_info_table_create((bondp_hash_table_t *)bdp_comp->comp_ctx, BOND_EPOLL_NUM) != 0) {
        URMA_LOG_ERR("Fail to create hash table.\n");
        goto close_fd;
    }

    for (i = 0; i < bdp_comp->dev_num; ++i) {
        if (bdp_comp->p_jfce[i] == NULL) {
            continue;
        }
        if (bondp_insert_p_jfce(&bdp_comp->v_jfce, bdp_comp->p_jfce[i]) != 0) {
            goto remove_jfce;
        }
    }

    bdp_comp->v_jfce.ref.atomic_cnt = 0;
    return URMA_SUCCESS;

remove_jfce:
    for (int j = 0; j < i; ++j) {
        if (bdp_comp->p_jfce[j] != NULL) {
            bondp_remove_p_jfce(&bdp_comp->v_jfce, bdp_comp->p_jfce[j]);
        }
    }
    bdp_vjfce_info_table_destroy((bondp_hash_table_t *)bdp_comp->comp_ctx);
close_fd:
    free(bdp_comp->comp_ctx);
    close(bdp_comp->v_jfce.fd);
    return URMA_FAIL;
}

static urma_status_t bondp_jfce_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_jfce_cfg_t *cfg)
{
    return bondp_jfce_init_comp_attr_not_single_die(bdp_comp, bdp_ctx, cfg);
}

static urma_status_t bondp_jfce_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    bdp_vjfce_info_table_close_fd(bdp_comp);
    bdp_vjfce_info_table_destroy((bondp_hash_table_t *)bdp_comp->comp_ctx);
    free(bdp_comp->comp_ctx);
    bdp_comp->comp_ctx = NULL;
    return URMA_SUCCESS;
}

/* JFC related ops */
static urma_jfc_cfg_t *bondp_jfc_get_args_list(bondp_context_t *bdp_ctx, urma_jfc_cfg_t *cfg, int *args_num)
{
    urma_jfc_cfg_t *args = NULL;
    int i = 0;

    args = calloc(bdp_ctx->dev_num, sizeof(urma_jfc_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc args");
        return NULL;
    }

    for (i = 0; i < bdp_ctx->dev_num; ++i) {
        args[i] = *cfg;
        if (cfg->jfce == NULL || bdp_ctx->p_ctxs[i] == NULL) {
            args[i].jfce = NULL;
            continue;
        }
        args[i].jfce = CONTAINER_OF_FIELD(cfg->jfce, bondp_comp_t, v_jfce)->p_jfce[i];
    }

    *args_num = bdp_ctx->dev_num;
    return args;
}

static urma_status_t bondp_jfc_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_jfc_cfg_t *cfg)
{
    return URMA_SUCCESS;
}

static urma_status_t bondp_jfc_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    return URMA_SUCCESS;
}

/* JFS related ops */
static urma_jfs_cfg_t *bondp_jfs_get_args_list(bondp_context_t *bdp_ctx, urma_jfs_cfg_t *cfg, int *args_num)
{
    bondp_comp_t *bdp_jfc = NULL;
    urma_jfs_cfg_t *args = NULL;
    int dev_num = 0;

    bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_comp_t, base);
    if (!is_valid_bondp_comp(bdp_jfc)) {
        URMA_LOG_ERR("Invalid param jfc\n");
        return NULL;
    }

    if (cfg->flag.bs.multi_path) {
        if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
            dev_num = SINGLE_DIE_IODIE_NUM;
        } else {
            dev_num = PRIMARY_EID_NUM;
        }
    } else {
        dev_num = bdp_ctx->dev_num;
    }

    args = calloc(dev_num, sizeof(urma_jfs_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc args");
        return NULL;
    }

    for (int i = 0; i < dev_num; ++i) {
        args[i] = *cfg;
        args[i].jfc = bdp_jfc->p_jfc[i];
    }
    *args_num = dev_num;
    return args;
}

static urma_status_t bondp_jfs_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_jfs_cfg_t *cfg)
{
    return URMA_SUCCESS;
}

static urma_status_t bondp_jfs_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    return URMA_SUCCESS;
}

/* JFR related ops */
static urma_jfr_cfg_t *bondp_jfr_get_args_list(bondp_context_t *bdp_ctx, urma_jfr_cfg_t *cfg, int *args_num)
{
    bondp_comp_t *bdp_jfc = NULL;
    urma_jfr_cfg_t *args = NULL;

    bdp_jfc = CONTAINER_OF_FIELD(cfg->jfc, bondp_comp_t, base);
    if (!is_valid_bondp_comp(bdp_jfc)) {
        URMA_LOG_ERR("Invalid param jfc\n");
        return NULL;
    }

    args = calloc(bdp_ctx->dev_num, sizeof(urma_jfr_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc args");
        return NULL;
    }

    for (int i = 0; i < bdp_ctx->dev_num; ++i) {
        args[i] = *cfg;
        args[i].jfc = bdp_jfc->p_jfc[i];
        args[i].id = 0;
    }

    *args_num = bdp_ctx->dev_num;
    return args;
}

static urma_status_t bondp_jfr_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_jfr_cfg_t *cfg)
{
    return URMA_SUCCESS;
}

static urma_status_t bondp_jfr_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    return URMA_SUCCESS;
}

/* JETTY related ops */
static urma_jetty_cfg_t *bondp_jetty_get_args_list(bondp_context_t *bdp_ctx, urma_jetty_cfg_t *cfg, int *args_num)
{
    urma_jetty_cfg_t *args = NULL;
    bondp_comp_t *bdp_jfs_jfc = CONTAINER_OF_FIELD(cfg->jfs_cfg.jfc, bondp_comp_t, base);
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(cfg->shared.jfr, bondp_comp_t, base);
    bondp_comp_t *bdp_rplc_jfc = CONTAINER_OF_FIELD(cfg->shared.jfc, bondp_comp_t, base);
    int dev_num = 0;

    if (!is_valid_bondp_comp(bdp_jfs_jfc) || !is_valid_bondp_comp(bdp_jfr) ||
        (bdp_rplc_jfc && !is_valid_bondp_comp(bdp_rplc_jfc))) {
        URMA_LOG_ERR("Invalid param jetty cfg\n");
        return NULL;
    }

    if (cfg->jfs_cfg.flag.bs.multi_path) {
        if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
            dev_num = SINGLE_DIE_IODIE_NUM;
        } else {
            dev_num = PRIMARY_EID_NUM;
        }
    } else {
        dev_num = bdp_ctx->dev_num;
    }

    args = calloc(dev_num, sizeof(urma_jetty_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc args");
        return NULL;
    }

    for (int i = 0; i < dev_num; ++i) {
        args[i] = *cfg;
        args[i].jfs_cfg.jfc = bdp_jfs_jfc->p_jfc[i];
        args[i].shared.jfr = bdp_jfr->p_jfr[i];
        if (bdp_rplc_jfc) {
            args[i].shared.jfc = bdp_rplc_jfc->p_jfc[i];
        }
    }

    *args_num = dev_num;
    return args;
}

static urma_status_t bondp_jetty_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_jetty_cfg_t *cfg)
{
    return URMA_SUCCESS;
}

static urma_status_t bondp_jetty_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    return URMA_SUCCESS;
}

/* SEGMENT related ops */
static urma_seg_cfg_t *bondp_segment_get_args_list(bondp_context_t *bdp_ctx, urma_seg_cfg_t *cfg, int *args_num)
{
    urma_seg_cfg_t *args = NULL;

    if ((void*)cfg->va == NULL) {
        URMA_LOG_ERR("Invalid param va\n");
        return NULL;
    }

    args = calloc(bdp_ctx->dev_num, sizeof(urma_seg_cfg_t));
    if (args == NULL) {
        URMA_LOG_ERR("Failed to alloc args");
        return NULL;
    }

    for (int i = 0; i < bdp_ctx->dev_num; ++i) {
        args[i] = *cfg;
        /*
        We can't assign our token_id to UB dev
        So we set flag to invalid to let UB dev allocate it
        */
        args[i].token_id = NULL;
        args[i].flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;
    }
    *args_num = bdp_ctx->dev_num;
    return args;
}

int bondp_v_segment_register(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_seg_cfg_t *cfg)
{
    urma_bond_seg_info_out_t in_seg_info = {0};
    urma_cmd_udrv_priv_t udata = {0};
    urma_target_seg_t t_seg = {0};
    int i = 0;

    in_seg_info.base = bdp_comp->v_tseg.seg;
    in_seg_info.dev_num = bdp_comp->dev_num;
    for (i = 0; i < bdp_comp->dev_num; ++i) {
        if (!bdp_comp->p_tseg[i]) {
            continue;
        }
        in_seg_info.slaves[i] = bdp_comp->p_tseg[i]->seg;
    }

    udata.in_addr = (uint64_t)&in_seg_info;
    udata.in_len = sizeof(urma_bond_seg_info_out_t);

    int ret = urma_cmd_register_seg(&bdp_ctx->v_ctx, &t_seg, cfg, &udata);
    if (ret != 0) {
        URMA_LOG_ERR("Fail to register seg, ret:%d.\n", ret);
        return ret;
    }
    bdp_comp->v_tseg.seg.token_id = t_seg.seg.token_id;
    bdp_comp->v_tseg.handle = t_seg.handle;
    bdp_comp->v_orig_handle = t_seg.handle;
    bdp_comp->v_tseg.handle = (uint64_t)&bdp_comp->v_tseg;
    URMA_LOG_INFO("Success register seg, handle:%lu.\n", t_seg.handle);
    return 0;
}

static urma_status_t bondp_segment_init_comp_attr(bondp_comp_t *bdp_comp, bondp_context_t *bdp_ctx, urma_seg_cfg_t *cfg)
{
    bdp_comp->v_tseg.seg.ubva.eid = bdp_ctx->v_ctx.eid;
    bdp_comp->v_tseg.seg.ubva.uasid = bdp_ctx->v_ctx.uasid;
    bdp_comp->v_tseg.seg.ubva.va = cfg->va;
    bdp_comp->v_tseg.seg.len = cfg->len;
    bdp_comp->v_tseg.seg.attr.value = cfg->flag.value;
    bdp_comp->v_tseg.user_ctx = cfg->user_ctx;
    bdp_comp->v_tseg.mva = cfg->va;
    bdp_comp->v_tseg.urma_ctx = &bdp_ctx->v_ctx;
    bdp_comp->v_tseg.user_ctx = (uint64_t)&bdp_comp->v_tseg;
    bdp_comp->v_tseg.token_id = cfg->token_id;
    for (int i = 0; i < bdp_comp->dev_num; ++i) {
        if (!bdp_comp->p_tseg[i]) {
            continue;
        }
        if (bdp_comp->p_tseg[i]->token_id == NULL) {
            bdp_comp->p_tseg[i]->token_id = cfg->token_id;
        }
        bdp_comp->p_orig_handle[i] = bdp_comp->p_tseg[i]->handle;
        bdp_comp->p_tseg[i]->handle = (uint64_t)&bdp_comp->v_tseg;
    }

    return bondp_v_segment_register(bdp_comp, bdp_ctx, cfg);
}

static urma_status_t bondp_segment_uninit_comp_attr(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        URMA_LOG_ERR("invalid param.\n");
        return URMA_FAIL;
    }
    urma_target_seg_t *target_seg = &bdp_comp->v_tseg;

    if (urma_cmd_unregister_seg(target_seg) != 0) {
        URMA_LOG_ERR("Failed to unregister segment, token_id:%u, handle:%lu.\n",
            target_seg->seg.token_id, target_seg->handle);
        return URMA_FAIL;
    }

    URMA_LOG_INFO("Success unregister seg, handle:%lu.\n", target_seg->handle);
    return URMA_SUCCESS;
}

static struct bondp_comp_ops g_bondp_comp_table[BONDP_COMP_TYPE_MAX] = {
    {   /* JFCE */
        sizeof(urma_jfce_t),
        sizeof(urma_jfce_cfg_t),
        (bondp_comp_get_args_list_t)bondp_jfce_get_args_list,
        (bondp_comp_create_t)bondp_create_jfce_comp,
        (bondp_comp_init_comp_attr_t)bondp_jfce_init_comp_attr,
        (bondp_comp_delete_t)urma_delete_jfce,
        (bondp_comp_uninit_comp_attr_t)bondp_jfce_uninit_comp_attr
    },
    {   /* JFC */
        sizeof(urma_jfc_t),
        sizeof(urma_jfc_cfg_t),
        (bondp_comp_get_args_list_t)bondp_jfc_get_args_list,
        (bondp_comp_create_t)urma_create_jfc,
        (bondp_comp_init_comp_attr_t)bondp_jfc_init_comp_attr,
        (bondp_comp_delete_t)urma_delete_jfc,
        (bondp_comp_uninit_comp_attr_t)bondp_jfc_uninit_comp_attr
    },
    {   /* JFS */
        sizeof(urma_jfs_t),
        sizeof(urma_jfs_cfg_t),
        (bondp_comp_get_args_list_t)bondp_jfs_get_args_list,
        (bondp_comp_create_t)urma_create_jfs,
        (bondp_comp_init_comp_attr_t)bondp_jfs_init_comp_attr,
        (bondp_comp_delete_t)urma_delete_jfs,
        (bondp_comp_uninit_comp_attr_t)bondp_jfs_uninit_comp_attr
    },
    {   /* JFR */
        sizeof(urma_jfr_t),
        sizeof(urma_jfr_cfg_t),
        (bondp_comp_get_args_list_t)bondp_jfr_get_args_list,
        (bondp_comp_create_t)urma_create_jfr,
        (bondp_comp_init_comp_attr_t)bondp_jfr_init_comp_attr,
        (bondp_comp_delete_t)urma_delete_jfr,
        (bondp_comp_uninit_comp_attr_t)bondp_jfr_uninit_comp_attr
    },
    {   /* JETTY */
        sizeof(urma_jetty_t),
        sizeof(urma_jetty_cfg_t),
        (bondp_comp_get_args_list_t)bondp_jetty_get_args_list,
        (bondp_comp_create_t)urma_create_jetty,
        (bondp_comp_init_comp_attr_t)bondp_jetty_init_comp_attr,
        (bondp_comp_delete_t)urma_delete_jetty,
        (bondp_comp_uninit_comp_attr_t)bondp_jetty_uninit_comp_attr
    },
    {
        /* SEGMENT */
        sizeof(urma_target_seg_t),
        sizeof(urma_seg_cfg_t),
        (bondp_comp_get_args_list_t)bondp_segment_get_args_list,
        (bondp_comp_create_t)urma_register_seg,
        (bondp_comp_init_comp_attr_t)bondp_segment_init_comp_attr,
        (bondp_comp_delete_t)urma_unregister_seg,
        (bondp_comp_uninit_comp_attr_t)bondp_segment_uninit_comp_attr
    }
};

bondp_comp_t *bondp_create_comp(urma_context_t *ctx, bondp_comp_type_t type, void *cfg)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bondp_comp_t *bdp_comp = NULL;
    void *args = NULL;
    int i = 0;

    if (!is_valid_ctx(bdp_ctx)) {
        URMA_LOG_ERR("Invalid param ctx\n");
        return NULL;
    }
    bdp_comp = (bondp_comp_t *)calloc(1, sizeof(bondp_comp_t));
    if (bdp_comp == NULL) {
        URMA_LOG_ERR("Failed to alloc bdp_comp\n");
        return NULL;
    }
    args = g_bondp_comp_table[type].get_args_list(bdp_ctx, cfg, &bdp_comp->dev_num);
    if (args == NULL) {
        URMA_LOG_ERR("Failed to get args list\n");
        goto FREE_COMP;
    }
    for (i = 0; i < bdp_comp->dev_num; ++i) {
        if (!bdp_ctx->p_ctxs[i]) {
            continue;
        }
        bdp_comp->members[i] = g_bondp_comp_table[type].create(
            bdp_ctx->p_ctxs[i],
            args + i * g_bondp_comp_table[type].cfg_size);
        if (bdp_comp->members[i] == NULL) {
            URMA_LOG_ERR("Failed to create comp %d\n", i);
            goto DELETE_MEMBER;
        }
    }

    if (g_bondp_comp_table[type].init_comp_attr(bdp_comp, bdp_ctx, cfg) != 0) {
        goto DELETE_MEMBER;
    }
    bdp_comp->bondp_ctx = bdp_ctx;
    bdp_comp->comp_type = type;
    atomic_init(&bdp_comp->use_cnt.atomic_cnt, 0);
    free(args);
    return bdp_comp;
DELETE_MEMBER:
    free(args);
    for (int j = 0; j < i; ++j) {
        (void)g_bondp_comp_table[type].delete(bdp_comp->members[j]);
    }
FREE_COMP:
    free(bdp_comp);
    return NULL;
}

urma_status_t bondp_delete_comp(void *comp, bondp_comp_type_t type)
{
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(comp, bondp_comp_t, base);
    urma_status_t ret = URMA_SUCCESS;
    if (!is_valid_bondp_comp(bdp_comp)) {
        URMA_LOG_ERR("Invalid param\n");
        return URMA_EINVAL;
    }
    for (int i = 0; i < bdp_comp->dev_num; ++i) {
        if (type == BONDP_COMP_SEGMENT && bdp_comp->p_tseg[i]) {
            bdp_comp->p_tseg[i]->handle = bdp_comp->p_orig_handle[i];
        }
        if (bdp_comp->members[i] &&
            g_bondp_comp_table[type].delete(bdp_comp->members[i]) != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to delete comp %d type %d\n", i, type);
            ret = URMA_FAIL;
        }
    }

    ret = g_bondp_comp_table[type].uninit_comp_attr(comp);
    if (ret != 0) {
        URMA_LOG_ERR("Fail to uninit comp attr, ret%d.\n", ret);
    }

    free(bdp_comp);
    return ret;
}
