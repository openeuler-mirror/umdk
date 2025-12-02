/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: urma cmd implementation
 * Author: Ouyang Changchun, Qian Guoxin, Yan Fangfang
 * Create: 2021-11-12
 * Note:
 * History: 2021-11-12
 * History: 2022-07-25: Yan Fangfang Change the prefix ubp_ioctl_ to urma_cmd_
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "urma_cmd_tlv.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_provider.h"
#include "urma_types.h"

#include "urma_cmd.h"

static inline void urma_cmd_set_udrv_priv(urma_cmd_udrv_priv_t *arg, urma_cmd_udrv_priv_t *udata)
{
    if (arg != NULL && udata != NULL) {
        *arg = *udata;
    }
}

static void init_urma_ctx(urma_context_t *ctx, urma_context_cfg_t *cfg, urma_eid_t *eid)
{
    atomic_init(&ctx->ref.atomic_cnt, 1);
    ctx->ops = cfg->ops;
    ctx->dev_fd = cfg->dev_fd;
    ctx->dev = cfg->dev;
    ctx->eid = *eid;
    ctx->eid_index = cfg->eid_index;
    ctx->uasid = cfg->uasid;
    (void)pthread_mutex_init(&ctx->mutex, NULL);
}

static inline void uninit_urma_ctx(urma_context_t *ctx)
{
    (void)pthread_mutex_destroy(&ctx->mutex);
}

static inline void uburma_is_destroy_err(int *ret)
{
    /* Reset removes the kernel mode device and returns EIO to the user mode.
     * Only when the user mode returns successfully can the resource be deleted.
     */
    if (*ret == EIO) {
        *ret = 0;
    }
}

int urma_cmd_create_context(urma_context_t *ctx, urma_context_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || cfg == NULL || cfg->dev_fd < 0 || cfg->dev == NULL || cfg->ops == NULL) {
        errno = EINVAL;
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_eid_t eid;
    if (urma_query_eid(cfg->dev, cfg->eid_index, &eid) != 0) {
        URMA_LOG_ERR("Failed to query eid.\n");
        errno = EIO;
        return -1;
    }
    init_urma_ctx(ctx, cfg, &eid);

    int ret;
    urma_cmd_create_ctx_t arg = {0};
    arg.in.eid_index = cfg->eid_index;
    (void)memcpy(arg.in.eid, eid.raw, URMA_EID_SIZE);
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_create_ctx(cfg->dev_fd, &arg);
    if (ret != 0) {
        (void)pthread_mutex_destroy(&ctx->mutex);
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }
    ctx->async_fd = arg.out.async_fd;
    return 0;
}

int urma_cmd_delete_context(urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    if (ctx->async_fd >= 0) {
        (void)close(ctx->async_fd);
        ctx->async_fd = -1;
    }

    uninit_urma_ctx(ctx);
    return 0;
}

static inline void ack_event_init(pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t *events_acked)
{
    *events_acked = 0;
    (void)pthread_mutex_init(mutex, NULL);
    (void)pthread_cond_init(cond, NULL);
}

static inline void wait_async_event_ack(pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t *events_acked,
                                        uint32_t events_reported)
{
    (void)pthread_mutex_lock(mutex);
    while (*events_acked != events_reported) {
        URMA_LOG_ERR("There is an event and it must be acked, acked:%u, reported:%u\n", *events_acked, events_reported);
        (void)pthread_cond_wait(cond, mutex);
    }
    (void)pthread_mutex_unlock(mutex);
}

static inline void ack_one_async_event(pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t *events_acked)
{
    (void)pthread_mutex_lock(mutex);
    ++(*events_acked);
    (void)pthread_cond_signal(cond);
    (void)pthread_mutex_unlock(mutex);
}

static inline void ack_comp_event(pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t *events_acked, uint32_t nevent)
{
    (void)pthread_mutex_lock(mutex);
    *events_acked = *events_acked + nevent;
    (void)pthread_cond_signal(cond);
    (void)pthread_mutex_unlock(mutex);
}

static inline void fill_ubva(urma_ubva_t *dst, urma_context_t *ctx, uint64_t va)
{
    dst->eid = ctx->eid;
    dst->uasid = ctx->uasid;
    dst->va = va;
}

static void fill_registered_tseg(urma_target_seg_t *tseg, urma_context_t *ctx, urma_seg_cfg_t *cfg, uint32_t token_id,
                                 uint64_t handle)
{
    fill_ubva(&tseg->seg.ubva, ctx, cfg->va);
    tseg->seg.len = cfg->len;
    tseg->token_id = cfg->token_id;
    tseg->seg.token_id = token_id;
    tseg->seg.attr.bs.token_policy = cfg->flag.bs.token_policy;
    tseg->seg.attr.bs.cacheable = cfg->flag.bs.cacheable;
    tseg->seg.attr.bs.dsva = false;
    tseg->seg.attr.bs.access = cfg->flag.bs.access;
    tseg->user_ctx = cfg->user_ctx;
    tseg->handle = handle;
    tseg->urma_ctx = ctx;
}

int urma_cmd_alloc_token_id(urma_context_t *ctx, urma_token_id_t *token_id, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || token_id == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_alloc_token_id_t arg = {0};
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_alloc_token_id(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_alloc_token_id, ret:%d, errno: %d.\n", ret, errno);
        return ret;
    }
    token_id->token_id = arg.out.token_id;
    token_id->urma_ctx = ctx;
    token_id->handle = arg.out.handle;
    token_id->flag.value = 0;
    return 0;
}

int urma_cmd_alloc_token_id_ex(urma_context_t *ctx, urma_token_id_t *token_id, urma_token_id_flag_t flag,
                               urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || token_id == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_alloc_token_id_t arg = {0};
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    arg.in.flag = flag;

    ret = urma_ioctl_alloc_token_id(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_alloc_token_id, ret:%d, errno: %d.\n", ret, errno);
        return ret;
    }
    token_id->token_id = arg.out.token_id;
    token_id->urma_ctx = ctx;
    token_id->handle = arg.out.handle;
    token_id->flag = flag;
    return 0;
}

int urma_cmd_free_token_id(urma_token_id_t *token_id)
{
    if (token_id == NULL || token_id->urma_ctx == NULL || token_id->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_free_token_id_t arg = {0};
    arg.in.handle = token_id->handle;
    arg.in.token_id = token_id->token_id;

    ret = urma_ioctl_free_token_id(token_id->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    return 0;
}

int urma_cmd_register_seg(urma_context_t *ctx, urma_target_seg_t *tseg, urma_seg_cfg_t *cfg,
                          urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tseg == NULL || cfg == NULL || cfg->va == 0) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_register_seg_t arg = {0};
    arg.in.va = cfg->va;
    arg.in.len = cfg->len;
    if (cfg->token_id != NULL) {
        arg.in.token_id = cfg->token_id->token_id;
        arg.in.token_id_handle = cfg->token_id->handle;
    }
    arg.in.token = cfg->token_value.token;
    arg.in.flag = cfg->flag.value;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_register_seg(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_register_seg, ret:%d, errno:%u.\n", ret, errno);
        return ret;
    }

    fill_registered_tseg(tseg, ctx, cfg, arg.out.token_id, arg.out.handle);
    return 0;
}

int urma_cmd_unregister_seg(urma_target_seg_t *tseg)
{
    if (tseg == NULL || tseg->urma_ctx == NULL || tseg->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_unregister_seg_t arg = {0};
    arg.in.handle = tseg->handle;

    ret = urma_ioctl_unregister_seg(tseg->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    return 0;
}

static inline void fill_imported_tseg(urma_target_seg_t *tseg, urma_context_t *ctx, urma_import_tseg_cfg_t *cfg,
                                      urma_cmd_import_seg_t *arg)
{
    tseg->seg.attr = cfg->attr;
    tseg->seg.ubva = cfg->ubva;
    tseg->seg.len = cfg->len;
    tseg->seg.token_id = cfg->token_id;
    tseg->mva = cfg->mva;
    tseg->handle = arg->out.handle;
    tseg->urma_ctx = ctx;
}

int urma_cmd_import_seg(urma_context_t *ctx, urma_target_seg_t *tseg, urma_import_tseg_cfg_t *cfg,
                        urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tseg == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_import_seg_t arg = {0};
    (void)memcpy(arg.in.eid, cfg->ubva.eid.raw, URMA_EID_SIZE);
    arg.in.va = cfg->ubva.va;
    arg.in.len = cfg->len;
    arg.in.flag = cfg->flag.value;
    arg.in.token_id = cfg->token_id;
    if (cfg->token != NULL) {
        arg.in.token = cfg->token->token;
    }
    arg.in.mva = cfg->mva;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_import_seg(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    fill_imported_tseg(tseg, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_unimport_seg(urma_target_seg_t *tseg)
{
    if (tseg == NULL || tseg->urma_ctx == NULL || tseg->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_unimport_seg_t arg = {0};
    arg.in.handle = tseg->handle;

    ret = urma_ioctl_unimport_seg(tseg->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }
    return 0;
}

static inline void fill_jetty_id(urma_jetty_id_t *dst, urma_context_t *ctx, uint32_t id)
{
    dst->eid = ctx->eid;
    dst->uasid = ctx->uasid;
    dst->id = id;
}

static inline void fill_jfs(urma_jfs_t *jfs, urma_context_t *ctx, urma_jfs_cfg_t *cfg, urma_cmd_create_jfs_t *arg)
{
    fill_jetty_id(&jfs->jfs_id, ctx, arg->out.id);
    jfs->jfs_cfg = *cfg;
    jfs->jfs_cfg.depth = arg->out.depth;
    jfs->jfs_cfg.max_sge = arg->out.max_sge;
    jfs->jfs_cfg.max_rsge = arg->out.max_rsge;
    jfs->jfs_cfg.max_inline_data = arg->out.max_inline_data;
    jfs->handle = arg->out.handle;
    jfs->urma_ctx = ctx;
    ack_event_init(&jfs->event_mutex, &jfs->event_cond, &jfs->async_events_acked);
}

static inline void fill_jfr(urma_jfr_t *jfr, urma_context_t *ctx, urma_jfr_cfg_t *cfg, urma_cmd_create_jfr_t *arg)
{
    fill_jetty_id(&jfr->jfr_id, ctx, arg->out.id);
    jfr->jfr_cfg.depth = arg->out.depth;
    jfr->jfr_cfg.max_sge = arg->out.max_sge;
    jfr->handle = arg->out.handle;
    jfr->urma_ctx = ctx;
    ack_event_init(&jfr->event_mutex, &jfr->event_cond, &jfr->async_events_acked);
}

static inline void fill_jfc(urma_jfc_t *jfc, urma_context_t *ctx, urma_jfc_cfg_t *cfg, urma_cmd_create_jfc_t *arg)
{
    fill_jetty_id(&jfc->jfc_id, ctx, arg->out.id);
    jfc->handle = arg->out.handle;
    jfc->jfc_cfg = *cfg;
    jfc->jfc_cfg.depth = arg->out.depth;
    jfc->urma_ctx = ctx;
    jfc->comp_events_acked = 0;
    ack_event_init(&jfc->event_mutex, &jfc->event_cond, &jfc->async_events_acked);
}

static inline void fill_jetty(urma_jetty_t *jetty, urma_context_t *ctx, urma_jetty_cfg_t *cfg,
                              urma_cmd_create_jetty_t *arg)
{
    fill_jetty_id(&jetty->jetty_id, ctx, arg->out.id);
    jetty->jetty_cfg.jfs_cfg.depth = arg->out.jfs_depth;
    jetty->jetty_cfg.jfs_cfg.max_sge = arg->out.max_send_sge;
    jetty->jetty_cfg.jfs_cfg.max_rsge = arg->out.max_send_rsge;
    jetty->jetty_cfg.jfs_cfg.max_inline_data = arg->out.max_inline_data;
    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR) {
        jetty->jetty_cfg.jfr_cfg->depth = arg->out.jfr_depth;
        jetty->jetty_cfg.jfr_cfg->max_sge = arg->out.max_recv_sge;
    }
    jetty->urma_ctx = ctx;
    jetty->handle = arg->out.handle;
    ack_event_init(&jetty->event_mutex, &jetty->event_cond, &jetty->async_events_acked);
}

static inline void fill_tjetty(urma_target_jetty_t *tjetty, urma_context_t *ctx, urma_tjetty_cfg_t *cfg,
                               urma_cmd_import_jetty_t *arg)
{
    tjetty->id = cfg->jetty_id;
    tjetty->trans_mode = cfg->trans_mode;
    tjetty->handle = arg->out.handle;
    tjetty->tp.tpn = arg->out.tpn;
    tjetty->urma_ctx = ctx;
    tjetty->type = cfg->type;
    tjetty->tp_type = cfg->tp_type;
    tjetty->policy = cfg->policy;
    tjetty->flag = cfg->flag;
}

static inline void fill_tjetty_async(urma_target_jetty_t *tjetty, urma_context_t *ctx, urma_tjetty_cfg_t *cfg,
                                     urma_cmd_import_jetty_async_t *arg)
{
    tjetty->id = cfg->jetty_id;
    tjetty->trans_mode = cfg->trans_mode;
    tjetty->handle = arg->out.handle;
    tjetty->tp.tpn = arg->out.tpn;
    tjetty->urma_ctx = ctx;
    tjetty->type = cfg->type;
    tjetty->policy = cfg->policy;
    tjetty->flag = cfg->flag;
}

int urma_cmd_create_jfs(urma_context_t *ctx, urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfs == NULL || cfg == NULL || cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_create_jfs_t arg = {0};

    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.priority = cfg->priority;
    arg.in.max_sge = cfg->max_sge;
    arg.in.max_rsge = cfg->max_rsge;
    arg.in.max_inline_data = cfg->max_inline_data;
    arg.in.rnr_retry = cfg->rnr_retry;
    arg.in.err_timeout = cfg->err_timeout;
    arg.in.jfc_id = cfg->jfc->jfc_id.id;
    arg.in.jfc_handle = cfg->jfc->handle;
    arg.in.urma_jfs = (uint64_t)(void *)jfs; /* for async event */
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = urma_ioctl_create_jfs(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    fill_jfs(jfs, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr, urma_cmd_udrv_priv_t *udata)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfs->urma_ctx;

    int ret;
    urma_cmd_modify_jfs_t arg = {0};
    arg.in.handle = jfs->handle;
    arg.in.mask = attr->mask;
    arg.in.state = (uint32_t)attr->state;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_modify_jfs(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jfs, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int urma_cmd_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfs->urma_ctx;

    int ret;
    urma_cmd_query_jfs_t arg = {0};
    arg.in.handle = jfs->handle;

    ret = urma_ioctl_query_jfs(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    cfg->depth = arg.out.depth;
    cfg->flag = (urma_jfs_flag_t)arg.out.flag;
    cfg->trans_mode = (urma_transport_mode_t)arg.out.trans_mode;
    cfg->priority = arg.out.priority;
    cfg->max_sge = arg.out.max_sge;
    cfg->max_rsge = arg.out.max_rsge;
    cfg->max_inline_data = arg.out.max_inline_data;
    cfg->rnr_retry = arg.out.rnr_retry;
    cfg->err_timeout = arg.out.err_timeout;
    cfg->jfc = jfs->jfs_cfg.jfc;
    cfg->user_ctx = jfs->jfs_cfg.user_ctx;

    attr->mask = 0;
    attr->state = (urma_jfs_state_t)arg.out.state;

    return ret;
}

int urma_cmd_delete_jfs(urma_jfs_t *jfs)
{
    int ret;
    urma_cmd_delete_jfs_t arg = {0};

    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    arg.in.handle = jfs->handle;

    ret = urma_ioctl_delete_jfs(jfs->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    wait_async_event_ack(&jfs->event_mutex, &jfs->event_cond, &jfs->async_events_acked, arg.out.async_events_reported);

    return 0;
}

int urma_cmd_delete_jfs_batch(urma_jfs_t **jfs_arr, int jfs_num, urma_jfs_t **bad_jfs)
{
    urma_cmd_delete_jfs_batch_t arg = {0};
    uint64_t *handle_arr = NULL;
    urma_jfs_t *jfs = NULL;
    uint32_t async_events_acked = 0;
    int ret;

    if (jfs_arr == NULL || jfs_num <= 0 || bad_jfs == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }

    for (int i = 0; i < jfs_num; ++i) {
        jfs = jfs_arr[i];
        if (jfs == NULL || jfs->urma_ctx == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfs = jfs_arr[0];
            return URMA_EINVAL;
        }
    }

    int dev_fd = jfs_arr[0]->urma_ctx->dev_fd;
    if (dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        *bad_jfs = jfs_arr[0];
        return URMA_EINVAL;
    }
    for (int i = 0; i < jfs_num; ++i) {
        if (jfs_arr[i]->urma_ctx->dev_fd != dev_fd) {
            URMA_LOG_ERR("jfs not from the same dev, cannot delete in a batch, index: %d.\n", i);
            *bad_jfs = jfs_arr[0];
            return URMA_EINVAL;
        }
    }

    handle_arr = malloc(jfs_num * sizeof(uint64_t));
    if (handle_arr == NULL) {
        URMA_LOG_ERR("Failed to malloc buffer.");
        *bad_jfs = jfs_arr[0];
        return URMA_ENOMEM;
    }
    arg.in.jfs_num = jfs_num;
    arg.in.jfs_ptr = (uint64_t)(void *)handle_arr;

    for (int i = 0; i < jfs_num; ++i) {
        handle_arr[i] = jfs_arr[i]->handle;
        URMA_LOG_DEBUG("jfs_arr[%d]->handle is %lu.", i, handle_arr[i]);
    }

    ret = urma_ioctl_delete_jfs_batch(dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfs_batch , ret:%d, errno:%d.\n", ret, errno);
        if (arg.out.bad_jfs_index >= jfs_num) {
            URMA_LOG_ERR("bad jfs index exceed array length, bad_jfs_index: %u.\n", arg.out.bad_jfs_index);
            arg.out.bad_jfs_index = 0;
        }
        *bad_jfs = jfs_arr[arg.out.bad_jfs_index];
        free(handle_arr);
        return ret;
    }

    do {
        for (int i = 0; i < jfs_num; ++i) {
            async_events_acked += jfs_arr[i]->async_events_acked;
        }
    } while (async_events_acked != arg.out.async_events_reported);

    free(handle_arr);
    return 0;
}

int urma_cmd_create_jfr(urma_context_t *ctx, urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfr == NULL || cfg == NULL || cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_create_jfr_t arg = {0};
    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.max_sge = cfg->max_sge;
    arg.in.min_rnr_timer = cfg->min_rnr_timer;
    arg.in.jfc_id = cfg->jfc->jfc_id.id;
    arg.in.jfc_handle = cfg->jfc->handle;
    arg.in.token = cfg->token_value.token;
    arg.in.id = cfg->id;
    arg.in.urma_jfr = (uint64_t)(void *)jfr; /* for async event */
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    jfr->jfr_cfg = *cfg;

    ret = urma_ioctl_create_jfr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfr, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }
    fill_jfr(jfr, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr, urma_cmd_udrv_priv_t *udata)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfr->urma_ctx;

    int ret;
    urma_cmd_modify_jfr_t arg = {0};
    arg.in.handle = jfr->handle;
    arg.in.mask = attr->mask;
    arg.in.rx_threshold = attr->rx_threshold;
    arg.in.state = (uint32_t)attr->state;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_modify_jfr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jfr, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int urma_cmd_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->urma_ctx->dev_fd < 0 || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfr->urma_ctx;

    int ret;
    urma_cmd_query_jfr_t arg = {0};
    arg.in.handle = jfr->handle;

    ret = urma_ioctl_query_jfr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    cfg->depth = arg.out.depth;
    cfg->flag = (urma_jfr_flag_t)arg.out.flag;
    cfg->trans_mode = (urma_transport_mode_t)arg.out.trans_mode;
    cfg->max_sge = arg.out.max_sge;
    cfg->min_rnr_timer = arg.out.min_rnr_timer;
    cfg->token_value.token = arg.out.token;
    cfg->id = arg.out.id;
    cfg->jfc = jfr->jfr_cfg.jfc;
    cfg->user_ctx = jfr->jfr_cfg.user_ctx;

    attr->mask = 0;
    attr->rx_threshold = arg.out.rx_threshold;
    attr->state = (urma_jfr_state_t)arg.out.state;

    return ret;
}

int urma_cmd_delete_jfr(urma_jfr_t *jfr)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_delete_jfr_t arg = {0};
    arg.in.handle = jfr->handle;

    ret = urma_ioctl_delete_jfr(jfr->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfr, ret:%d, errno:%d.\n", ret, errno);
    }

    wait_async_event_ack(&jfr->event_mutex, &jfr->event_cond, &jfr->async_events_acked, arg.out.async_events_reported);

    return ret;
}

int urma_cmd_delete_jfr_batch(urma_jfr_t **jfr_arr, int jfr_num, urma_jfr_t **bad_jfr)
{
    urma_cmd_delete_jfr_batch_t arg = {0};
    uint64_t *handle_arr = NULL;
    urma_jfr_t *jfr = NULL;
    uint32_t async_events_acked = 0;
    int ret;

    if (jfr_arr == NULL || jfr_num <= 0 || bad_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    for (int i = 0; i < jfr_num; ++i) {
        jfr = jfr_arr[i];
        if (jfr == NULL || jfr->urma_ctx == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfr = jfr_arr[0];
            return URMA_EINVAL;
        }
    }

    int dev_fd = jfr_arr[0]->urma_ctx->dev_fd;
    if (dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        *bad_jfr = jfr_arr[0];
        return URMA_EINVAL;
    }
    for (int i = 0; i < jfr_num; ++i) {
        if (jfr_arr[i]->urma_ctx->dev_fd != dev_fd) {
            URMA_LOG_ERR("jfr not from the same dev, cannot delete in a batch, index: %d.\n", i);
            *bad_jfr = jfr_arr[0];
            return URMA_EINVAL;
        }
    }

    handle_arr = malloc(jfr_num * sizeof(uint64_t));
    if (handle_arr == NULL) {
        URMA_LOG_ERR("Failed to malloc buffer.");
        *bad_jfr = jfr_arr[0];
        return URMA_ENOMEM;
    }
    arg.in.jfr_num = jfr_num;
    arg.in.jfr_ptr = (uint64_t)(void *)handle_arr;

    for (int i = 0; i < jfr_num; ++i) {
        handle_arr[i] = jfr_arr[i]->handle;
        URMA_LOG_DEBUG("jfr_arr[%d]->handle is %lu.", i, handle_arr[i]);
    }

    ret = urma_ioctl_delete_jfr_batch(dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfr_batch , ret:%d, errno:%d.\n", ret, errno);
        if (arg.out.bad_jfr_index >= jfr_num) {
            URMA_LOG_ERR("bad jfr index exceed array length, bad_jfr_index: %u.", arg.out.bad_jfr_index);
            arg.out.bad_jfr_index = 0;
        }
        *bad_jfr = jfr_arr[arg.out.bad_jfr_index];
        free(handle_arr);
        return ret;
    }

    do {
        for (int i = 0; i < jfr_num; ++i) {
            async_events_acked += jfr_arr[i]->async_events_acked;
        }
    } while (async_events_acked != arg.out.async_events_reported);

    free(handle_arr);
    return 0;
}

int urma_cmd_create_jfc(urma_context_t *ctx, urma_jfc_t *jfc, urma_jfc_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfc == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_create_jfc_t arg = {0};

    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.jfce_fd = (cfg->jfce == NULL ? -1 : cfg->jfce->fd);
    /* UBcore gets userspace jfc for a completion event */
    arg.in.urma_jfc = (uint64_t)(void *)jfc;
    arg.in.ceqn = cfg->ceqn;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = urma_ioctl_create_jfc(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfc, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }
    fill_jfc(jfc, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr, urma_cmd_udrv_priv_t *udata)
{
    if (jfc == NULL || jfc->urma_ctx == NULL || jfc->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfc->urma_ctx;

    int ret;
    urma_cmd_modify_jfc_t arg = {0};

    arg.in.handle = jfc->handle;
    arg.in.mask = attr->mask;
    arg.in.moderate_count = attr->moderate_count;
    arg.in.moderate_period = attr->moderate_period;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = urma_ioctl_modify_jfc(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jfc, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }
    return 0;
}

int urma_cmd_delete_jfc(urma_jfc_t *jfc)
{
    if (jfc == NULL || jfc->urma_ctx == NULL || jfc->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_delete_jfc_t arg = {0};
    arg.in.handle = jfc->handle;

    ret = urma_ioctl_delete_jfc(jfc->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfc , ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    (void)pthread_mutex_lock(&jfc->event_mutex);
    while (jfc->comp_events_acked != arg.out.comp_events_reported ||
           jfc->async_events_acked != arg.out.async_events_reported) {
        URMA_LOG_ERR("There is jfc event and it must be acked, jfc_comp:%u, comp:%u, jfc_async:%u, async:%u\n",
                     jfc->comp_events_acked, arg.out.comp_events_reported, jfc->async_events_acked,
                     arg.out.async_events_reported);
        (void)pthread_cond_wait(&jfc->event_cond, &jfc->event_mutex);
    }
    (void)pthread_mutex_unlock(&jfc->event_mutex);

    return 0;
}

int urma_cmd_delete_jfc_batch(urma_jfc_t **jfc_arr, int jfc_num, urma_jfc_t **bad_jfc)
{
    urma_cmd_delete_jfc_batch_t arg = {0};
    uint64_t *handle_arr = NULL;
    urma_jfc_t *jfc = NULL;
    uint32_t comp_events_acked = 0;
    uint32_t async_events_acked = 0;
    int ret;

    if (jfc_arr == NULL || jfc_num <= 0 || bad_jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }

    for (int i = 0; i < jfc_num; ++i) {
        jfc = jfc_arr[i];
        if (jfc == NULL || jfc->urma_ctx == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfc = jfc_arr[0];
            return URMA_EINVAL;
        }
    }

    int dev_fd = jfc_arr[0]->urma_ctx->dev_fd;
    if (dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        *bad_jfc = jfc_arr[0];
        return URMA_EINVAL;
    }
    for (int i = 0; i < jfc_num; ++i) {
        if (jfc_arr[i]->urma_ctx->dev_fd != dev_fd) {
            URMA_LOG_ERR("jfc not from the same dev, cannot delete in a batch, index: %d.\n", i);
            *bad_jfc = jfc_arr[0];
            return URMA_EINVAL;
        }
    }

    handle_arr = malloc(jfc_num * sizeof(uint64_t));
    if (handle_arr == NULL) {
        URMA_LOG_ERR("Failed to malloc buffer.");
        *bad_jfc = jfc_arr[0];
        return URMA_ENOMEM;
    }
    arg.in.jfc_num = jfc_num;
    arg.in.jfc_ptr = (uint64_t)(void *)handle_arr;

    for (int i = 0; i < jfc_num; ++i) {
        handle_arr[i] = jfc_arr[i]->handle;
        URMA_LOG_DEBUG("jfc_arr[%d]->handle is %lu.", i, handle_arr[i]);
    }

    ret = urma_ioctl_delete_jfc_batch(dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfc_batch , ret:%d, errno:%d.\n", ret, errno);
        if (arg.out.bad_jfc_index >= jfc_num) {
            URMA_LOG_ERR("bad jfc index exceed array length, bad_jfc_index: %u.", arg.out.bad_jfc_index);
            arg.out.bad_jfc_index = 0;
        }
        *bad_jfc = jfc_arr[arg.out.bad_jfc_index];
        free(handle_arr);
        return ret;
    }

    do {
        for (int i = 0; i < jfc_num; ++i) {
            comp_events_acked += jfc_arr[i]->comp_events_acked;
            async_events_acked += jfc_arr[i]->async_events_acked;
        }
    } while (comp_events_acked != arg.out.comp_events_reported || async_events_acked != arg.out.async_events_reported);

    free(handle_arr);
    return 0;
}

int urma_cmd_create_jfce(urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_create_jfce_t arg = {0};

    ret = urma_ioctl_create_jfce(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfce, ret:%d, errno:%d.\n", ret, errno);
        return -1;
    }
    return arg.out.fd;
}

static inline void fill_tjfr(urma_target_jetty_t *tjfr, urma_context_t *ctx, urma_tjfr_cfg_t *cfg,
                             urma_cmd_import_jfr_t *arg)
{
    tjfr->id = cfg->jfr_id;
    tjfr->trans_mode = cfg->trans_mode;
    tjfr->flag = cfg->flag;
    tjfr->tp_type = cfg->tp_type;
    tjfr->handle = arg->out.handle;
    tjfr->tp.tpn = arg->out.tpn;
    tjfr->urma_ctx = ctx;
}

int urma_cmd_import_jfr(urma_context_t *ctx, urma_target_jetty_t *tjfr, urma_tjfr_cfg_t *cfg,
                        urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjfr == NULL || cfg == NULL || cfg->token == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_import_jfr_t arg = {0};

    (void)memcpy(arg.in.eid, cfg->jfr_id.eid.raw, URMA_EID_SIZE);
    arg.in.id = cfg->jfr_id.id;
    arg.in.token = cfg->token->token;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.flag = cfg->flag.value;
    arg.in.tp_type = cfg->tp_type;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_import_jfr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    fill_tjfr(tjfr, ctx, cfg, &arg);
    return 0;
}

static inline void fill_tjfr_ex(urma_target_jetty_t *tjfr, urma_context_t *ctx, urma_tjfr_cfg_t *cfg,
                                urma_cmd_import_jfr_ex_t *arg)
{
    tjfr->urma_ctx = ctx;
    tjfr->id = cfg->jfr_id;
    tjfr->handle = arg->out.handle;
    tjfr->trans_mode = cfg->trans_mode;
    tjfr->tp.tpn = arg->out.tpn;
    tjfr->flag = cfg->flag;
    tjfr->tp_type = cfg->tp_type;
}

int urma_cmd_import_jfr_ex(urma_context_t *ctx, urma_target_jetty_t *tjfr, urma_tjfr_cfg_t *cfg,
                           urma_import_jfr_ex_cfg_t *ex_cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjfr == NULL || cfg == NULL || cfg->token == NULL || ex_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_import_jfr_ex_t arg = {0};

    (void)memcpy(arg.in.eid, cfg->jfr_id.eid.raw, URMA_EID_SIZE);
    arg.in.id = cfg->jfr_id.id;
    arg.in.flag = cfg->flag.value;
    arg.in.token = cfg->token->token;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.tp_type = (uint32_t)cfg->tp_type;
    arg.in.tp_handle = ex_cfg->tp_handle;
    arg.in.peer_tp_handle = ex_cfg->peer_tp_handle;
    arg.in.tag = ex_cfg->tag;
    arg.in.tx_psn = ex_cfg->tp_attr.tx_psn;
    arg.in.rx_psn = ex_cfg->tp_attr.rx_psn;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = urma_ioctl_import_jfr_ex(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    fill_tjfr_ex(tjfr, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_unimport_jfr(urma_target_jetty_t *tjfr)
{
    if (tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unimport_jfr_t arg = {
        .in.handle = tjfr->handle,
    };

    int ret = urma_ioctl_unimport_jfr(tjfr->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    return 0;
}

int urma_cmd_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, urma_cmd_udrv_priv_t *udata)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_advise_jetty_t arg = {
        .in.jetty_handle = jfs->handle,
        .in.tjetty_handle = tjfr->handle,
    };
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    return urma_ioctl_advise_jfr(jfs->urma_ctx->dev_fd, &arg);
}

int urma_cmd_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unadvise_jetty_t arg = {
        .in.jetty_handle = jfs->handle,
        .in.tjetty_handle = tjfr->handle,
    };
    return urma_ioctl_unadvise_jfr(jfs->urma_ctx->dev_fd, &arg);
}

int urma_cmd_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_advise_jetty_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = tjetty->handle,
    };
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    return urma_ioctl_advise_jetty(jetty->urma_ctx->dev_fd, &arg);
}

int urma_cmd_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unadvise_jetty_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = tjetty->handle,
    };
    return urma_ioctl_unadvise_jetty(jetty->urma_ctx->dev_fd, &arg);
}

int urma_cmd_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return EINVAL;
    }
    urma_cmd_bind_jetty_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = tjetty->handle,
    };

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    int ret = urma_ioctl_bind_jetty(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }
    tjetty->tp.tpn = arg.out.tpn;
    jetty->remote_jetty = (urma_target_jetty_t *)tjetty;
    return ret;
}

int urma_cmd_bind_jetty_ex(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_bind_jetty_ex_cfg_t *ex_cfg,
                           urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL || ex_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return EINVAL;
    }

    urma_cmd_bind_jetty_ex_t arg = {0};
    arg.in.jetty_handle = jetty->handle;
    arg.in.tjetty_handle = tjetty->handle;
    arg.in.tp_handle = ex_cfg->tp_handle;
    arg.in.peer_tp_handle = ex_cfg->peer_tp_handle;
    arg.in.tag = ex_cfg->tag;
    arg.in.tx_psn = ex_cfg->tp_attr.tx_psn;
    arg.in.rx_psn = ex_cfg->tp_attr.rx_psn;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_bind_jetty_ex(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }
    tjetty->tp.tpn = arg.out.tpn;
    jetty->remote_jetty = (urma_target_jetty_t *)tjetty;
    return ret;
}

int urma_cmd_unbind_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unadvise_jetty_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = jetty->remote_jetty->handle,
    };
    int ret = urma_ioctl_unbind_jetty(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }
    jetty->remote_jetty = NULL;
    return 0;
}

static int init_create_jetty_cmd(urma_cmd_create_jetty_t *arg, urma_jetty_t *jetty, urma_jetty_cfg_t *cfg,
                                 urma_cmd_udrv_priv_t *udata)
{
    arg->in.id = cfg->id;
    arg->in.jetty_flag = cfg->flag.value;

    arg->in.jfs_depth = cfg->jfs_cfg.depth;
    arg->in.jfs_flag = cfg->jfs_cfg.flag.value;
    arg->in.trans_mode = (uint32_t)cfg->jfs_cfg.trans_mode;
    arg->in.priority = cfg->jfs_cfg.priority;
    arg->in.max_send_sge = cfg->jfs_cfg.max_sge;
    arg->in.max_send_rsge = cfg->jfs_cfg.max_rsge;
    arg->in.max_inline_data = cfg->jfs_cfg.max_inline_data;
    arg->in.rnr_retry = cfg->jfs_cfg.rnr_retry;
    arg->in.err_timeout = cfg->jfs_cfg.err_timeout;

    if (cfg->jfs_cfg.jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    arg->in.send_jfc_id = cfg->jfs_cfg.jfc->jfc_id.id;
    arg->in.send_jfc_handle = cfg->jfs_cfg.jfc->handle;

    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR && cfg->jfr_cfg != NULL && cfg->jfr_cfg->jfc != NULL) {
        arg->in.jfr_depth = cfg->jfr_cfg->depth;
        arg->in.jfr_flag = cfg->jfr_cfg->flag.value;
        arg->in.max_recv_sge = cfg->jfr_cfg->max_sge;
        arg->in.min_rnr_timer = cfg->jfr_cfg->min_rnr_timer;
        arg->in.recv_jfc_id = cfg->jfr_cfg->jfc->jfc_id.id;
        arg->in.recv_jfc_handle = cfg->jfr_cfg->jfc->handle;
        arg->in.token = cfg->jfr_cfg->token_value.token;
    } else if (cfg->flag.bs.share_jfr == URMA_SHARE_JFR && cfg->shared.jfr != NULL) {
        arg->in.jfr_id = cfg->shared.jfr->jfr_id.id;
        arg->in.jfr_handle = cfg->shared.jfr->handle;
        arg->in.token = cfg->shared.jfr->jfr_cfg.token_value.token;

        if (cfg->shared.jfc != NULL) {
            arg->in.recv_jfc_id = cfg->shared.jfc->jfc_id.id;
            arg->in.recv_jfc_handle = cfg->shared.jfc->handle;
        } else {
            arg->in.recv_jfc_id = cfg->shared.jfr->jfr_cfg.jfc->jfc_id.id;
            arg->in.recv_jfc_handle = cfg->shared.jfr->jfr_cfg.jfc->handle;
        }
    } else {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    if (cfg->jetty_grp == NULL) {
        arg->in.is_jetty_grp = 0;
    } else {
        arg->in.is_jetty_grp = 1;
        arg->in.jetty_grp_handle = cfg->jetty_grp->handle;
    }
    arg->in.urma_jetty = (uint64_t)(void *)jetty;
    urma_cmd_set_udrv_priv(&arg->udata, udata);
    return 0;
}

int urma_cmd_create_jetty(urma_context_t *ctx, urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jetty == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    urma_cmd_create_jetty_t arg = {0};
    if (init_create_jetty_cmd(&arg, jetty, cfg, udata) != 0) {
        URMA_LOG_ERR("failed to init create jetty cmd");
        errno = EINVAL;
        return -1;
    }

    /* allocate jfs cfg and jfr cfg just before ioctl to reduce rollback overhead */
    if (urma_init_jetty_cfg(&jetty->jetty_cfg, cfg) != 0) {
        URMA_LOG_ERR("failed to fill jetty cfg");
        errno = ENOMEM;
        return -1;
    }

    int ret = urma_ioctl_create_jetty(ctx->dev_fd, &arg);
    if (ret != 0) {
        urma_uninit_jetty_cfg(&jetty->jetty_cfg);
        return ret;
    }
    fill_jetty(jetty, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr, urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_cmd_modify_jetty_t arg = {0};
    arg.in.handle = jetty->handle;
    arg.in.mask = attr->mask;
    arg.in.rx_threshold = attr->rx_threshold;
    arg.in.state = (uint32_t)attr->state;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    return urma_ioctl_modify_jetty(jetty->urma_ctx->dev_fd, &arg);
}

int urma_cmd_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_cmd_query_jetty_t arg = {0};
    arg.in.handle = jetty->handle;

    int ret = urma_ioctl_query_jetty(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }

    cfg->id = arg.out.id;
    cfg->flag = (urma_jetty_flag_t)arg.out.jetty_flag;

    cfg->jfs_cfg.depth = arg.out.jfs_depth;
    cfg->jfs_cfg.flag = (urma_jfs_flag_t)arg.out.jfs_flag;
    cfg->jfs_cfg.trans_mode = (urma_transport_mode_t)arg.out.trans_mode;
    cfg->jfs_cfg.priority = arg.out.priority;
    cfg->jfs_cfg.max_sge = arg.out.max_send_sge;
    cfg->jfs_cfg.max_rsge = arg.out.max_send_rsge;
    cfg->jfs_cfg.max_inline_data = arg.out.max_inline_data;
    cfg->jfs_cfg.rnr_retry = arg.out.rnr_retry;
    cfg->jfs_cfg.err_timeout = arg.out.err_timeout;
    cfg->jfs_cfg.jfc = jetty->jetty_cfg.jfs_cfg.jfc;
    cfg->jfs_cfg.user_ctx = jetty->jetty_cfg.jfs_cfg.user_ctx;

    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR) {
        if (cfg->jfr_cfg == NULL) {
            URMA_LOG_ERR("Invalid parameter");
            return -1;
        }
        cfg->jfr_cfg->depth = arg.out.jfr_depth;
        cfg->jfr_cfg->flag = (urma_jfr_flag_t)arg.out.jfr_flag;
        cfg->jfr_cfg->trans_mode = (urma_transport_mode_t)arg.out.trans_mode;
        cfg->jfr_cfg->max_sge = arg.out.max_recv_sge;
        cfg->jfr_cfg->min_rnr_timer = arg.out.min_rnr_timer;
        cfg->jfr_cfg->token_value.token = arg.out.token;
        cfg->jfr_cfg->id = arg.out.jfr_id;
        cfg->jfr_cfg->jfc = jetty->jetty_cfg.jfr_cfg->jfc;
        cfg->jfr_cfg->user_ctx = jetty->jetty_cfg.jfr_cfg->user_ctx;
    } else {
        cfg->shared.jfr = jetty->jetty_cfg.shared.jfr;
        cfg->shared.jfc = jetty->jetty_cfg.shared.jfc;
    }
    cfg->user_ctx = jetty->jetty_cfg.user_ctx;
    cfg->jetty_grp = jetty->jetty_cfg.jetty_grp;

    attr->mask = 0;
    attr->rx_threshold = arg.out.rx_threshold;
    attr->state = arg.out.state;

    return ret;
}

int urma_cmd_delete_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_delete_jetty_t arg = {
        .in.handle = jetty->handle,
    };
    int ret = urma_ioctl_delete_jetty(jetty->urma_ctx->dev_fd, &arg);

    urma_uninit_jetty_cfg(&jetty->jetty_cfg);

    wait_async_event_ack(&jetty->event_mutex, &jetty->event_cond, &jetty->async_events_acked,
                         arg.out.async_events_reported);

    return ret;
}

int urma_cmd_delete_jetty_batch(urma_jetty_t **jetty_arr, int jetty_num, urma_jetty_t **bad_jetty)
{
    urma_cmd_delete_jetty_batch_t arg = {0};
    uint64_t *handle_arr = NULL;
    urma_jetty_t *jetty = NULL;
    uint32_t async_events_acked = 0;
    int ret;

    if (jetty_arr == NULL || jetty_num <= 0 || bad_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }

    for (int i = 0; i < jetty_num; ++i) {
        jetty = jetty_arr[i];
        if (jetty == NULL || jetty->urma_ctx == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jetty = jetty_arr[0];
            return URMA_EINVAL;
        }
    }

    int dev_fd = jetty_arr[0]->urma_ctx->dev_fd;
    if (dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        *bad_jetty = jetty_arr[0];
        return URMA_EINVAL;
    }
    for (int i = 0; i < jetty_num; ++i) {
        if (jetty_arr[i]->urma_ctx->dev_fd != dev_fd) {
            URMA_LOG_ERR("jetty not from the same dev, cannot delete in a batch, index: %d.\n", i);
            *bad_jetty = jetty_arr[0];
            return URMA_EINVAL;
        }
    }

    handle_arr = malloc(jetty_num * sizeof(uint64_t));
    if (handle_arr == NULL) {
        URMA_LOG_ERR("Failed to malloc buffer.");
        *bad_jetty = jetty_arr[0];
        return URMA_ENOMEM;
    }
    arg.in.jetty_num = jetty_num;
    arg.in.jetty_ptr = (uint64_t)(void *)handle_arr;

    for (int i = 0; i < jetty_num; ++i) {
        handle_arr[i] = jetty_arr[i]->handle;
        URMA_LOG_DEBUG("jetty_arr[%d]->handle is %lu.", i, handle_arr[i]);
    }

    ret = urma_ioctl_delete_jetty_batch(dev_fd, &arg);
    for (int i = 0; i < jetty_num; ++i) {
        jetty = jetty_arr[i];
        urma_uninit_jetty_cfg(&jetty->jetty_cfg);
    }
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jetty_batch , ret:%d, errno:%d.\n", ret, errno);
        if (arg.out.bad_jetty_index >= jetty_num) {
            URMA_LOG_ERR("bad jetty index exceed array length, bad_jetty_index: %u.", arg.out.bad_jetty_index);
            arg.out.bad_jetty_index = 0;
        }
        *bad_jetty = jetty_arr[arg.out.bad_jetty_index];
        free(handle_arr);
        return ret;
    }

    do {
        for (int i = 0; i < jetty_num; ++i) {
            async_events_acked += jetty_arr[i]->async_events_acked;
        }
    } while (async_events_acked != arg.out.async_events_reported);

    free(handle_arr);
    return 0;
}

int urma_cmd_import_jetty(urma_context_t *ctx, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                          urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjetty == NULL || cfg == NULL || cfg->token == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    urma_cmd_import_jetty_t arg = {
        .in.id = cfg->jetty_id.id,
        .in.flag = cfg->flag.value,
        .in.token = cfg->token->token,
        .in.trans_mode = (uint32_t)cfg->trans_mode,
        .in.policy = (uint32_t)cfg->policy,
        .in.type = (uint32_t)cfg->type,
        .in.tp_type = cfg->tp_type,
    };
    (void)memcpy(arg.in.eid, cfg->jetty_id.eid.raw, URMA_EID_SIZE);
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_import_jetty(ctx->dev_fd, &arg);
    if (ret == 0) {
        fill_tjetty(tjetty, ctx, cfg, &arg);
    }
    return ret;
}

static inline void fill_tjetty_ex(urma_target_jetty_t *tjetty, urma_context_t *ctx, urma_tjetty_cfg_t *cfg,
                                  urma_cmd_import_jetty_ex_t *arg)
{
    tjetty->urma_ctx = ctx;
    tjetty->id = cfg->jetty_id;
    tjetty->handle = arg->out.handle;
    tjetty->trans_mode = cfg->trans_mode;
    tjetty->tp.tpn = arg->out.tpn;
    tjetty->type = cfg->type;
    tjetty->flag = cfg->flag;
    tjetty->policy = cfg->policy;
    tjetty->tp_type = cfg->tp_type;
}

int urma_cmd_import_jetty_ex(urma_context_t *ctx, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                             urma_import_jetty_ex_cfg_t *ex_cfg, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjetty == NULL || cfg == NULL || cfg->token == NULL || ex_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    urma_cmd_import_jetty_ex_t arg = {0};
    (void)memcpy(arg.in.eid, cfg->jetty_id.eid.raw, URMA_EID_SIZE);
    arg.in.id = cfg->jetty_id.id;
    arg.in.flag = cfg->flag.value;
    arg.in.token = cfg->token->token;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.policy = (uint32_t)cfg->policy;
    arg.in.type = (uint32_t)cfg->type;
    arg.in.tp_type = (uint32_t)cfg->tp_type;
    arg.in.tp_handle = ex_cfg->tp_handle;
    arg.in.peer_tp_handle = ex_cfg->peer_tp_handle;
    arg.in.tag = ex_cfg->tag;
    arg.in.tx_psn = ex_cfg->tp_attr.tx_psn;
    arg.in.rx_psn = ex_cfg->tp_attr.rx_psn;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    int ret = urma_ioctl_import_jetty_ex(ctx->dev_fd, &arg);
    if (ret == 0) {
        fill_tjetty_ex(tjetty, ctx, cfg, &arg);
    }
    return ret;
}

int urma_cmd_unimport_jetty(urma_target_jetty_t *tjetty)
{
    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unimport_jetty_t arg = {
        .in.handle = tjetty->handle,
    };
    int ret = urma_ioctl_unimport_jetty(tjetty->urma_ctx->dev_fd, &arg);
    return ret;
}

int urma_cmd_create_jetty_grp(urma_context_t *ctx, urma_jetty_grp_t *jetty_grp, urma_jetty_grp_cfg_t *cfg,
                              urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jetty_grp == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    urma_cmd_create_jetty_grp_t arg = {
        .in.token = cfg->token_value.token,
        .in.id = cfg->id,
        .in.policy = (uint32_t)cfg->policy,
        .in.flag = cfg->flag.value,
        .in.urma_jetty_grp = (uint64_t)(void *)jetty_grp, /* for async event */
    };
    (void)memcpy(arg.in.name, cfg->name, URMA_MAX_NAME);
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_create_jetty_grp(ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }

    jetty_grp->jetty_grp_id.id = arg.out.id;
    jetty_grp->jetty_grp_id.eid = ctx->eid;
    jetty_grp->cfg = *cfg;
    jetty_grp->handle = arg.out.handle;
    jetty_grp->urma_ctx = ctx;
    ack_event_init(&jetty_grp->event_mutex, &jetty_grp->event_cond, &jetty_grp->async_events_acked);
    return 0;
}

int urma_cmd_delete_jetty_grp(urma_jetty_grp_t *jetty_grp)
{
    if (jetty_grp == NULL || jetty_grp->urma_ctx == NULL || jetty_grp->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_cmd_delete_jetty_grp_t arg = {
        .in.handle = jetty_grp->handle,
    };

    int ret = urma_ioctl_delete_jetty_grp(jetty_grp->urma_ctx->dev_fd, &arg);
    uburma_is_destroy_err(&ret);
    if (ret != 0) {
        return ret;
    }

    wait_async_event_ack(&jetty_grp->event_mutex, &jetty_grp->event_cond, &jetty_grp->async_events_acked,
                         arg.out.async_events_reported);

    return 0;
}

int urma_cmd_get_eid_list(int dev_fd, uint32_t max_eid_cnt, urma_eid_info_t *eid_list, uint32_t *eid_cnt)
{
    if (eid_list == NULL || max_eid_cnt > URMA_MAX_EID_CNT || eid_cnt == NULL) {
        return -EINVAL;
    }

    urma_cmd_get_eid_list_t *arg = calloc(1, sizeof(urma_cmd_get_eid_list_t));
    if (arg == NULL) {
        return -ENOMEM;
    }
    arg->in.max_eid_cnt = max_eid_cnt;

    int ret = urma_ioctl_get_eid_list(dev_fd, arg);
    if (ret != 0) {
        free(arg);
        return ret;
    }

    *eid_cnt = MIN(max_eid_cnt, arg->out.eid_cnt);
    for (uint32_t i = 0; i < *eid_cnt; i++) {
        eid_list[i].eid_index = arg->out.eid_list[i].eid_index;
        eid_list[i].eid = arg->out.eid_list[i].eid;
    }
    free(arg);
    return 0;
}

int urma_cmd_wait_jfc(int jfce_fd, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[])
{
    urma_cmd_jfce_wait_t arg = {0};

    if (jfce_fd < 0 || jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    arg.in.max_event_cnt = jfc_cnt;
    arg.in.time_out = time_out;

    /* ubcore jfce ioctl will return 0 on success and negative on error */
    int ret = urma_ioctl_wait_jfc(jfce_fd, &arg);
    if (ret != 0) {
        /* Handle non-block wait error, this function should return 0 */
        if (time_out == 0 && errno == EAGAIN) {
            return 0;
        }
        if (time_out == 0 && errno != EAGAIN) {
            URMA_LOG_ERR("Faile to wait jfc non-block, ret: %d, errno: %d.\n", ret, errno);
        }
        return -1;
    }
    for (uint32_t i = 0; i < arg.out.event_cnt && i < jfc_cnt; i++) {
        jfc[i] = (urma_jfc_t *)(void *)arg.out.event_data[i];
    }
    return (int)arg.out.event_cnt;
}

void urma_cmd_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt)
{
    if (jfc == NULL || nevents == NULL || jfc_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter");
        return;
    }

    for (uint32_t i = 0; i < jfc_cnt; i++) {
        if (jfc[i] == NULL || nevents[i] == 0) {
            continue;
        }
        ack_comp_event(&jfc[i]->event_mutex, &jfc[i]->event_cond, &jfc[i]->comp_events_acked, nevents[i]);
    }
}

urma_status_t urma_cmd_get_async_event(urma_context_t *ctx, urma_async_event_t *event)
{
    if (ctx == NULL || ctx->async_fd < 0 || event == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }

    urma_cmd_async_event_t arg = {0};
    int ret = urma_ioctl_get_async_event(ctx->async_fd, &arg);
    if (ret != 0) {
        return URMA_FAIL;
    }
    event->event_type = arg.event_type;
    event->priv = NULL;
    event->urma_ctx = ctx;
    switch (arg.event_type) {
        case URMA_EVENT_JFC_ERR:
            event->element.jfc = (urma_jfc_t *)arg.event_data;
            break;
        case URMA_EVENT_JFS_ERR:
            event->element.jfs = (urma_jfs_t *)arg.event_data;
            break;
        case URMA_EVENT_JFR_ERR:
        case URMA_EVENT_JFR_LIMIT:
            event->element.jfr = (urma_jfr_t *)arg.event_data;
            break;
        case URMA_EVENT_JETTY_ERR:
        case URMA_EVENT_JETTY_LIMIT:
            event->element.jetty = (urma_jetty_t *)arg.event_data;
            break;
        case URMA_EVENT_JETTY_GRP_ERR:
            event->element.jetty_grp = (urma_jetty_grp_t *)arg.event_data;
            break;
        case URMA_EVENT_PORT_ACTIVE:
        case URMA_EVENT_PORT_DOWN:
            event->element.port_id = (uint32_t)arg.event_data;
            break;
        case URMA_EVENT_DEV_FATAL:
            return URMA_SUCCESS;
        case URMA_EVENT_EID_CHANGE:
            event->element.eid_idx = (uint32_t)arg.event_data;
            break;
        default:
            return URMA_FAIL;
    }
    return URMA_SUCCESS;
}

void urma_cmd_ack_async_event(urma_async_event_t *event)
{
    urma_jfc_t *jfc;
    urma_jfs_t *jfs;
    urma_jfr_t *jfr;
    urma_jetty_t *jetty;
    urma_jetty_grp_t *jetty_grp;

    if (event == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return;
    }

    switch (event->event_type) {
        case URMA_EVENT_JFC_ERR:
            jfc = event->element.jfc;
            ack_one_async_event(&jfc->event_mutex, &jfc->event_cond, &jfc->async_events_acked);
            break;
        case URMA_EVENT_JFS_ERR:
            jfs = event->element.jfs;
            ack_one_async_event(&jfs->event_mutex, &jfs->event_cond, &jfs->async_events_acked);
            break;
        case URMA_EVENT_JFR_ERR:
        case URMA_EVENT_JFR_LIMIT:
            jfr = event->element.jfr;
            ack_one_async_event(&jfr->event_mutex, &jfr->event_cond, &jfr->async_events_acked);
            break;
        case URMA_EVENT_JETTY_ERR:
        case URMA_EVENT_JETTY_LIMIT:
            jetty = event->element.jetty;
            ack_one_async_event(&jetty->event_mutex, &jetty->event_cond, &jetty->async_events_acked);
            break;
        case URMA_EVENT_JETTY_GRP_ERR:
            jetty_grp = event->element.jetty_grp;
            ack_one_async_event(&jetty_grp->event_mutex, &jetty_grp->event_cond, &jetty_grp->async_events_acked);
            break;
        default:
            return;
    }
}

int urma_cmd_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out, urma_udrv_t *udrv_data)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    urma_cmd_user_ctl_t arg = {
        .in.opcode = in->opcode,
        .in.addr = in->addr,
        .in.len = in->len,
        .out.addr = out->addr,
        .out.len = out->len,
    };
    arg.udrv.in_addr = udrv_data->in_addr;
    arg.udrv.in_len = udrv_data->in_len;
    arg.udrv.out_addr = udrv_data->out_addr;
    arg.udrv.out_len = udrv_data->out_len;
    return urma_ioctl_user_ctl(ctx->dev_fd, &arg);
}

int urma_cmd_get_net_addr_list(urma_context_t *ctx, uint32_t max_netaddr_cnt, urma_net_addr_info_t *net_addr_info,
                               uint32_t *cnt)
{
    if (ctx == NULL || ctx->dev_fd < 0 || net_addr_info == NULL || cnt == NULL || max_netaddr_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    urma_cmd_get_net_addr_list_t arg = {0};
    uint64_t len = max_netaddr_cnt * sizeof(urma_cmd_net_addr_info_t);
    urma_cmd_net_addr_info_t *addr_info = (urma_cmd_net_addr_info_t *)calloc(1, len);
    if (addr_info == NULL) {
        return -ENOMEM;
    }
    arg.in.max_netaddr_cnt = max_netaddr_cnt;
    arg.out.addr = (uint64_t)addr_info;
    arg.out.len = len;

    int ret = urma_ioctl_get_netaddr_list(ctx->dev_fd, &arg);
    if (ret != 0) {
        free(addr_info);
        return ret;
    }

    *cnt = MIN(max_netaddr_cnt, arg.out.netaddr_cnt);
    for (uint32_t i = 0; i < *cnt; i++) {
        net_addr_info[i].index = addr_info[i].index;
        urma_cmd_net_addr_t *netaddr = &addr_info[i].netaddr;
        if (netaddr->type == URMA_CMD_NET_ADDR_TYPE_IPV4) {
            net_addr_info[i].netaddr.sin_family = AF_INET;
            net_addr_info[i].netaddr.in4.s_addr = netaddr->net_addr.in4.addr;
        } else {
            net_addr_info[i].netaddr.sin_family = AF_INET6;
            (void)memcpy(&net_addr_info[i].netaddr.in6, &netaddr->net_addr, sizeof(union urma_cmd_net_addr_union));
        }
        net_addr_info[i].netaddr.vlan = netaddr->vlan;
        (void)memcpy(net_addr_info[i].netaddr.mac, netaddr->mac, URMA_MAC_BYTES);
        net_addr_info[i].netaddr.prefix_len = netaddr->prefix_len;
    }
    free(addr_info);
    return 0;
}

int urma_cmd_modify_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg, urma_tp_attr_t *attr,
                       urma_tp_attr_mask_t mask)
{
    if (ctx == NULL || ctx->dev_fd < 0 || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }
    urma_cmd_modify_tp_t arg = {
        .in.tpn = tpn,
        .in.tp_cfg = *cfg,
        .in.attr = *attr,
        .in.mask = mask,
    };
    return urma_ioctl_modify_tp(ctx->dev_fd, &arg);
}

int urma_cmd_query_device_attr(int dev_fd, struct urma_sysfs_dev *sysfs_dev)
{
    if (dev_fd < 0 || sysfs_dev == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    urma_cmd_query_device_attr_t arg = {0};
    (void)strcpy(arg.in.dev_name, sysfs_dev->dev_name);

    int ret = urma_ioctl_query_dev_attr(dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }

    urma_device_attr_t *dev_attr = &sysfs_dev->dev_attr;
    (void)memcpy(dev_attr, &arg.out.attr, sizeof(urma_device_attr_t));

    return 0;
}

int urma_cmd_import_jetty_async(urma_notifier_t *notifier, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                                uint64_t user_ctx, int timeout, urma_cmd_udrv_priv_t *udata)
{
    if (notifier == NULL || notifier->urma_ctx == NULL || notifier->urma_ctx->dev_fd < 0 || tjetty == NULL ||
        cfg == NULL || cfg->token == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    urma_cmd_import_jetty_async_t arg = {
        .in.id = cfg->jetty_id.id,
        .in.flag = cfg->flag.value,
        .in.token = cfg->token->token,
        .in.trans_mode = (uint32_t)cfg->trans_mode,
        .in.policy = (uint32_t)cfg->policy,
        .in.type = (uint32_t)cfg->type,
        .in.urma_tjetty = (uint64_t)(uintptr_t)tjetty,
        .in.user_ctx = user_ctx,
        .in.fd = notifier->fd,
        .in.timeout = timeout,
    };
    (void)memcpy(arg.in.eid, cfg->jetty_id.eid.raw, URMA_EID_SIZE);
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_import_jetty_async(notifier->urma_ctx->dev_fd, &arg);
    if (ret == 0) {
        fill_tjetty_async(tjetty, notifier->urma_ctx, cfg, &arg);
    }

    return ret;
}

int urma_cmd_unimport_jetty_async(urma_target_jetty_t *tjetty)
{
    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unimport_jetty_async_t arg = {
        .in.handle = tjetty->handle,
    };
    int ret = urma_ioctl_unimport_jetty_async(tjetty->urma_ctx->dev_fd, &arg);
    return ret;
}

int urma_cmd_bind_jetty_async(urma_notifier_t *notifier, urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                              uint64_t user_ctx, int timeout, urma_cmd_udrv_priv_t *udata)
{
    if (notifier == NULL || jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return EINVAL;
    }
    urma_cmd_bind_jetty_async_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = tjetty->handle,
        .in.urma_tjetty = (uint64_t)(uintptr_t)tjetty,
        .in.urma_jetty = (uint64_t)(uintptr_t)jetty,
        .in.fd = notifier->fd,
        .in.user_ctx = user_ctx,
        .in.timeout = timeout,
    };

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    int ret = urma_ioctl_bind_jetty_async(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }
    tjetty->tp.tpn = arg.out.tpn;
    jetty->remote_jetty = (urma_target_jetty_t *)tjetty;
    return ret;
}

int urma_cmd_unbind_jetty_async(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    urma_cmd_unbind_jetty_async_t arg = {
        .in.jetty_handle = jetty->handle,
        .in.tjetty_handle = jetty->remote_jetty->handle,
    };
    int ret = urma_ioctl_unbind_jetty_async(jetty->urma_ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }
    jetty->remote_jetty = NULL;
    return 0;
}

int urma_cmd_create_notifier(urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        errno = EINVAL;
        return -1;
    }

    int ret;
    urma_cmd_create_notifier_t arg = {0};

    ret = urma_ioctl_create_notifier(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_notifier, ret:%d, errno:%d.\n", ret, errno);
        return -1;
    }
    return arg.out.fd;
}

int urma_cmd_wait_notify(urma_notifier_t *notifier, uint32_t cnt, urma_notify_t *notify, int timeout)
{
    if (notifier == NULL || notifier->fd < 0 || notify == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_cmd_wait_notify_t arg = {0};
    arg.in.cnt = cnt;
    arg.in.timeout = timeout;

    int ret = urma_ioctl_wait_notify(notifier->fd, &arg);
    if (ret != 0) {
        return -1;
    }
    for (uint32_t i = 0; i < arg.out.cnt && i < cnt; i++) {
        urma_cmd_notify_t *notify_cmd = &arg.out.notify[i];
        notify[i].type = notify_cmd->type;
        notify[i].status = notify_cmd->status;
        notify[i].user_ctx = notify_cmd->user_ctx;
        if (notify[i].type == URMA_IMPORT_JETTY_NOTIFY) {
            notify[i].tjetty = (urma_target_jetty_t *)(uintptr_t)notify_cmd->urma_jetty;
            notify[i].tjetty->tp.tpn = notify_cmd->vtpn;
        } else {
            notify[i].jetty = (urma_jetty_t *)(uintptr_t)notify_cmd->urma_jetty;
            notify[i].jetty->remote_jetty->tp.tpn = notify_cmd->vtpn;
        }
    }
    return arg.out.cnt;
}

int urma_cmd_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt, urma_tp_info_t *tp_list,
                         urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || cfg == NULL || tp_cnt == NULL || *tp_cnt > URMA_CMD_MAX_TP_NUM ||
        tp_list == NULL || *tp_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_cmd_get_tp_list_t arg = {0};
    arg.in.flag = cfg->flag.value;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    (void)memcpy(arg.in.local_eid, &cfg->local_eid, sizeof(urma_eid_t));
    (void)memcpy(arg.in.peer_eid, &cfg->peer_eid, sizeof(urma_eid_t));
    arg.in.tp_cnt = *tp_cnt;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_get_tp_list(ctx->dev_fd, &arg);
    if (ret != 0) {
        return ret;
    }

    *tp_cnt = arg.out.tp_cnt;
    (void)memcpy(tp_list, arg.out.tp_handle, (*tp_cnt) * sizeof(urma_tp_info_t));

    return 0;
}

int urma_cmd_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, const uint8_t tp_attr_cnt,
                         const uint32_t tp_attr_bitmap, const urma_tp_attr_value_t *tp_attr,
                         urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || tp_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_cmd_set_tp_attr_t arg = {0};
    if (sizeof(urma_tp_attr_value_t) != sizeof(arg.in.tp_attr)) {
        URMA_LOG_ERR("Invalid tp_attr bytes.\n");
        return URMA_EINVAL;
    }
    arg.in.tp_handle = tp_handle;
    arg.in.tp_attr_cnt = tp_attr_cnt;
    arg.in.tp_attr_bitmap = tp_attr_bitmap;
    (void)memcpy(arg.in.tp_attr, tp_attr, sizeof(urma_tp_attr_value_t));
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_set_tp_attr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("Failed in ioctl set_tp_attr, ret: %d.\n", ret);
    }

    return ret;
}

int urma_cmd_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, uint8_t *tp_attr_cnt,
                         uint32_t *tp_attr_bitmap, urma_tp_attr_value_t *tp_attr, urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || tp_attr_cnt == NULL || tp_attr_bitmap == NULL || tp_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_cmd_get_tp_attr_t arg = {0};
    if (sizeof(urma_tp_attr_value_t) != sizeof(arg.out.tp_attr)) {
        URMA_LOG_ERR("Invalid tp_attr bytes.\n");
        return URMA_EINVAL;
    }
    arg.in.tp_handle = tp_handle;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    int ret = urma_ioctl_get_tp_attr(ctx->dev_fd, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("Failed in ioctl get_tp_attr, ret: %d.\n", ret);
        return ret;
    }
    *tp_attr_cnt = arg.out.tp_attr_cnt;
    *tp_attr_bitmap = arg.out.tp_attr_bitmap;
    (void)memcpy(tp_attr, arg.out.tp_attr, sizeof(arg.out.tp_attr));

    return 0;
}

int urma_cmd_exchange_tp_info(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint64_t local_tp_handle, uint32_t tx_psn,
                              uint64_t *peer_tp_handle, uint32_t *rx_psn)
{
    if (ctx == NULL || cfg == NULL || peer_tp_handle == NULL || rx_psn == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_cmd_exchange_tp_info_t arg = {0};
    arg.in.get_tp_cfg = *cfg;
    arg.in.tp_handle = local_tp_handle;
    arg.in.tx_psn = tx_psn;

    int ret = urma_ioctl_exchange_tp_info(ctx->dev_fd, &arg);
    if (ret != URMA_SUCCESS) {
        return ret;
    }

    *peer_tp_handle = arg.out.peer_tp_handle;
    *rx_psn = arg.out.rx_psn;
    return 0;
}
