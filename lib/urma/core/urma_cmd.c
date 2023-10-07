/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: urma cmd implementation
 * Author: Ouyang Changchun, Qian Guoxin, Yan Fangfang
 * Create: 2021-11-12
 * Note:
 * History: 2021-11-12
 * History: 2022-07-25: Yan Fangfang Change the prefix ubp_ioctl_ to urma_cmd_
 */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "urma_provider.h"
#include "urma_private.h"
#include "urma_log.h"
#include "urma_cmd.h"

static inline void urma_cmd_set_udrv_priv(urma_cmd_udrv_priv_t *arg, const urma_cmd_udrv_priv_t *udata)
{
    if (arg != NULL && udata != NULL) {
        *arg = *udata;
    }
}

int urma_cmd_set_uasid(int ubcore_fd, uint64_t token, uint32_t in_uasid, uint32_t *out_uasid)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_core_cmd_set_uasid_t arg = {0};

    if (out_uasid == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    if (in_uasid >= URMA_MAX_UASID) {
        URMA_LOG_ERR("uasid:%u exceeds the max value %d.\n", in_uasid, URMA_MAX_UASID);
        return -EINVAL;
    }
    hdr.command = (uint32_t)URMA_CORE_CMD_SET_UASID;
    hdr.args_len = sizeof(urma_core_cmd_set_uasid_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.token = token;
    arg.in.uasid = in_uasid;

    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    *out_uasid = arg.out.uasid;
    return 0;
}

int urma_cmd_put_uasid(int ubcore_fd, uint32_t in_uasid)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_core_cmd_put_uasid_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_PUT_UASID;
    hdr.args_len = sizeof(urma_core_cmd_put_uasid_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.uasid = in_uasid;

    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    return 0;
}

static int init_urma_ctx(urma_context_t *ctx, const urma_context_cfg_t *cfg)
{
    /* Alloc and init ref per urma context */
    ctx->ref = calloc(1, sizeof(urma_ref_t));
    if (ctx->ref == NULL) {
        URMA_LOG_ERR("failed to alloc memory.\n");
        return -1;
    }

    atomic_init(&ctx->ref->atomic_cnt, 1);
    ctx->ops = cfg->ops;
    ctx->dev_fd = cfg->dev_fd;
    ctx->dev = cfg->dev;
    ctx->eid = cfg->dev->eid;
    ctx->uasid = cfg->uasid;
    (void)pthread_mutex_init(&ctx->mutex, NULL);
    return 0;
}

static inline void uninit_urma_ctx(urma_context_t *ctx)
{
    if (ctx->ref != NULL) {
        free(ctx->ref);
        ctx->ref = NULL;
    }

    (void)pthread_mutex_destroy(&ctx->mutex);
}

int urma_cmd_create_context(urma_context_t *ctx, const urma_context_cfg_t *cfg, const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || cfg == NULL || cfg->dev_fd < 0 || cfg->dev == NULL || cfg->ops == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    if (init_urma_ctx(ctx, cfg) != 0) {
        URMA_LOG_ERR("Failed to init urma context");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_ctx_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_CTX;
    hdr.args_len = sizeof(urma_cmd_create_ctx_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.uasid = cfg->uasid;
    urma_cmd_set_udrv_priv(&arg.udata, udata);

    ret = ioctl(cfg->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        free(ctx->ref);
        ctx->ref = NULL;
        (void)pthread_mutex_destroy(&ctx->mutex);
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    ctx->async_fd = arg.out.async_fd;
    return 0;
}

int urma_cmd_delete_context(urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    if (ctx->async_fd >= 0) {
        (void)close(ctx->async_fd);
        ctx->async_fd = -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;

    hdr.command = (uint32_t)URMA_CMD_DESTORY_CTX;
    hdr.args_len = 0;
    hdr.args_addr = (uint64_t)NULL;

    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
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

static inline void wait_async_event_ack(pthread_mutex_t *mutex, pthread_cond_t *cond,
    const uint32_t *events_acked, uint32_t events_reported)
{
    (void)pthread_mutex_lock(mutex);
    while (*events_acked != events_reported) {
        (void)pthread_cond_wait(cond, mutex);
    }
    (void)pthread_mutex_unlock(mutex);
}

static inline void ack_one_async_event(pthread_mutex_t *mutex, pthread_cond_t *cond,
    uint32_t *events_acked)
{
    (void)pthread_mutex_lock(mutex);
    ++(*events_acked);
    (void)pthread_cond_signal(cond);
    (void)pthread_mutex_unlock(mutex);
}

static inline void ack_comp_event(pthread_mutex_t *mutex, pthread_cond_t *cond,
    uint32_t *events_acked, uint32_t nevent)
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

static void fill_registered_tseg(urma_target_seg_t *tseg, urma_context_t *ctx,
    const urma_seg_cfg_t *cfg, uint32_t key_id, uint64_t handle)
{
    fill_ubva(&tseg->seg.ubva, ctx, cfg->va);
    tseg->seg.len = cfg->len;
    tseg->keyid = cfg->keyid;
    tseg->seg.key_id = key_id;
    tseg->seg.attr.bs.key_policy = cfg->flag.bs.key_policy;
    tseg->seg.attr.bs.cacheable = cfg->flag.bs.cacheable;
    tseg->seg.attr.bs.dsva = false;
    tseg->seg.attr.bs.access = cfg->flag.bs.access;
    tseg->seg.user_ctx = cfg->user_ctx;
    tseg->handle = handle;
    tseg->urma_ctx = ctx;
}

int urma_cmd_alloc_key_id(urma_context_t *ctx, urma_key_id_t *key_id, const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || key_id == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_alloc_key_id_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_ALLOC_KEY_ID;
    hdr.args_len = sizeof(urma_cmd_alloc_key_id_t);
    hdr.args_addr = (uint64_t)&arg;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_alloc_key_id, ret:%d, cmd:%u.\n", ret, hdr.command);
        return ret;
    }
    key_id->key_id = arg.out.key_id;
    key_id->urma_ctx = ctx;
    key_id->handle = arg.out.handle;
    return 0;
}

int urma_cmd_free_key_id(urma_key_id_t *key_id)
{
    if (key_id == NULL || key_id->urma_ctx == NULL || key_id->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_free_key_id_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_FREE_KEY_ID;
    hdr.args_len = sizeof(urma_cmd_free_key_id_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = key_id->handle;

    ret = ioctl(key_id->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    return 0;
}

int urma_cmd_register_seg(urma_context_t *ctx, urma_target_seg_t *tseg, const urma_seg_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tseg == NULL || cfg == NULL || cfg->va == 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_register_seg_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_REGISTER_SEG;
    hdr.args_len = sizeof(urma_cmd_register_seg_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.va = cfg->va;
    arg.in.len = cfg->len;
    if (cfg->keyid != NULL) {
        arg.in.key_id = cfg->keyid->key_id;
        arg.in.keyid_handle = cfg->keyid->handle;
    }
    if (cfg->key != NULL) {
        arg.in.key = cfg->key->key;
    }
    arg.in.flag = cfg->flag.value;
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_register_seg, ret:%d, cmd:%u.\n", ret, hdr.command);
        return ret;
    }

    fill_registered_tseg(tseg, ctx, cfg, arg.out.key_id, arg.out.handle);
    return 0;
}

int urma_cmd_unregister_seg(urma_target_seg_t *tseg)
{
    if (tseg == NULL || tseg->urma_ctx == NULL || tseg->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_unregister_seg_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_UNREGISTER_SEG;
    hdr.args_len = sizeof(urma_cmd_unregister_seg_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = tseg->handle;

    ret = ioctl(tseg->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    return 0;
}

static inline void fill_imported_tseg(urma_target_seg_t *tseg, urma_context_t *ctx, const urma_import_tseg_cfg_t *cfg,
    const urma_cmd_import_seg_t *arg)
{
    tseg->seg.attr = cfg->attr;
    tseg->seg.ubva = cfg->ubva;
    tseg->seg.len = cfg->len;
    tseg->seg.key_id = cfg->key_id;
    tseg->mva = cfg->mva;
    tseg->handle = arg->out.handle;
    tseg->urma_ctx = ctx;
}

int urma_cmd_import_seg(urma_context_t *ctx, urma_target_seg_t *tseg, const urma_import_tseg_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tseg == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_import_seg_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_IMPORT_SEG;
    hdr.args_len = sizeof(urma_cmd_import_seg_t);
    hdr.args_addr = (uint64_t)&arg;
    (void)memcpy(arg.in.eid, cfg->ubva.eid.raw, URMA_EID_SIZE);
    arg.in.uasid = cfg->ubva.uasid;
    arg.in.va = cfg->ubva.va;
    arg.in.len = cfg->len;
    arg.in.flag = cfg->flag.value;
    arg.in.key_id = cfg->key_id;
    if (cfg->key != NULL) {
        arg.in.key = cfg->key->key;
    }
    arg.in.mva = cfg->mva;
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
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
    urma_cmd_hdr_t hdr;
    urma_cmd_unimport_seg_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_UNIMPORT_SEG;
    hdr.args_len = sizeof(urma_cmd_unimport_seg_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = tseg->handle;

    ret = ioctl(tseg->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

static inline void fill_jetty_id(urma_jetty_id_t *dst, const urma_context_t *ctx, uint32_t id)
{
    dst->eid = ctx->eid;
    dst->uasid = ctx->uasid;
    dst->id = id;
}

static inline void fill_jfs(urma_jfs_t *jfs, urma_context_t *ctx, const urma_jfs_cfg_t *cfg,
    const urma_cmd_create_jfs_t *arg)
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

static inline void fill_jfr(urma_jfr_t *jfr, urma_context_t *ctx, const urma_jfr_cfg_t *cfg,
    const urma_cmd_create_jfr_t *arg)
{
    fill_jetty_id(&jfr->jfr_id, ctx, arg->out.id);
    jfr->jfr_cfg.depth = arg->out.depth;
    jfr->jfr_cfg.max_sge = arg->out.max_sge;
    jfr->handle = arg->out.handle;
    jfr->urma_ctx = ctx;
    ack_event_init(&jfr->event_mutex, &jfr->event_cond, &jfr->async_events_acked);
}

static inline void fill_jfc(urma_jfc_t *jfc, urma_context_t *ctx, const urma_jfc_cfg_t *cfg,
    const urma_cmd_create_jfc_t *arg)
{
    fill_jetty_id(&jfc->jfc_id, ctx, arg->out.id);
    jfc->handle = arg->out.handle;
    jfc->jfc_cfg = *cfg;
    jfc->jfc_cfg.depth = arg->out.depth;
    jfc->urma_ctx = ctx;
    jfc->comp_events_acked = 0;
    ack_event_init(&jfc->event_mutex, &jfc->event_cond, &jfc->async_events_acked);
}

static inline void fill_jetty(urma_jetty_t *jetty, urma_context_t *ctx, const urma_jetty_cfg_t *cfg,
    const urma_cmd_create_jetty_t *arg)
{
    fill_jetty_id(&jetty->jetty_id, ctx, arg->out.id);
    jetty->jetty_cfg.jfs_cfg->depth = arg->out.jfs_depth;
    jetty->jetty_cfg.jfs_cfg->max_sge = arg->out.max_send_sge;
    jetty->jetty_cfg.jfs_cfg->max_rsge = arg->out.max_send_rsge;
    jetty->jetty_cfg.jfs_cfg->max_inline_data = arg->out.max_inline_data;
    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR) {
        jetty->jetty_cfg.jfr_cfg->depth = arg->out.jfr_depth;
        jetty->jetty_cfg.jfr_cfg->max_sge = arg->out.max_recv_sge;
    }
    jetty->urma_ctx = ctx;
    jetty->handle = arg->out.handle;
    ack_event_init(&jetty->event_mutex, &jetty->event_cond, &jetty->async_events_acked);
}

static inline void fill_tjetty(urma_target_jetty_t *tjetty, urma_context_t *ctx, const urma_tjetty_cfg_t *cfg,
    const urma_cmd_import_jetty_t *arg)
{
    tjetty->id = cfg->jetty_id;
    tjetty->trans_mode = cfg->trans_mode;
    tjetty->handle = arg->out.handle;
    tjetty->tp.type = arg->out.tp_type;
    tjetty->tp.tpn = arg->out.tpn;
    tjetty->urma_ctx = ctx;
    tjetty->type = URMA_JETTY;
}

int urma_cmd_create_jfs(urma_context_t *ctx, urma_jfs_t *jfs, const urma_jfs_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfs == NULL || cfg == NULL || cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_jfs_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_JFS;
    hdr.args_len = sizeof(urma_cmd_create_jfs_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.priority = cfg->priority;
    arg.in.max_sge = cfg->max_sge;
    arg.in.max_rsge = cfg->max_rsge;
    arg.in.max_inline_data = cfg->max_inline_data;
    arg.in.retry_cnt = cfg->retry_cnt;
    arg.in.rnr_retry = cfg->rnr_retry;
    arg.in.err_timeout = cfg->err_timeout;
    arg.in.jfc_id = cfg->jfc->jfc_id.id;
    arg.in.jfc_handle = cfg->jfc->handle;
    arg.in.urma_jfs = (uint64_t)(void*)jfs; /* for async event */
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    fill_jfs(jfs, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_delete_jfs(urma_jfs_t *jfs)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_delete_jfs_t arg = {0};

    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    hdr.command = (uint32_t)URMA_CMD_DELETE_JFS;
    hdr.args_len = sizeof(urma_cmd_delete_jfs_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = jfs->handle;

    ret = ioctl(jfs->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    wait_async_event_ack(&jfs->event_mutex, &jfs->event_cond,
        &jfs->async_events_acked, arg.out.async_events_reported);

    return 0;
}

int urma_cmd_create_jfr(urma_context_t *ctx, urma_jfr_t *jfr, const urma_jfr_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfr == NULL || cfg == NULL || cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_jfr_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_JFR;
    hdr.args_len = sizeof(urma_cmd_create_jfr_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.max_sge = cfg->max_sge;
    arg.in.min_rnr_timer = cfg->min_rnr_timer;
    arg.in.jfc_id = cfg->jfc->jfc_id.id;
    arg.in.jfc_handle = cfg->jfc->handle;
    arg.in.key = cfg->ukey.key;
    arg.in.id = cfg->id;
    arg.in.urma_jfr = (uint64_t)(void*)jfr; /* for async event */
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    jfr->jfr_cfg = *cfg;
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfr, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    fill_jfr(jfr, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jfr(urma_jfr_t *jfr, const urma_jfr_attr_t *attr,
    const urma_cmd_udrv_priv_t *udata)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfr->urma_ctx;

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_modify_jfr_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_MODIFY_JFR;
    hdr.args_len = sizeof(urma_cmd_modify_jfr_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.handle = jfr->handle;
    arg.in.mask = attr->mask;
    arg.in.rx_threshold = attr->rx_threshold;
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jfr, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
    }
    return ret;
}

int urma_cmd_delete_jfr(urma_jfr_t *jfr)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_delete_jfr_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_DELETE_JFR;
    hdr.args_len = sizeof(urma_cmd_delete_jfr_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = jfr->handle;

    ret = ioctl(jfr->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfr, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
    }

    wait_async_event_ack(&jfr->event_mutex, &jfr->event_cond,
        &jfr->async_events_acked, arg.out.async_events_reported);

    return ret;
}

int urma_cmd_create_jfc(urma_context_t *ctx, urma_jfc_t *jfc, const urma_jfc_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jfc == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_jfc_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_JFC;
    hdr.args_len = sizeof(urma_cmd_create_jfc_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.depth = cfg->depth;
    arg.in.flag = cfg->flag.value;
    arg.in.jfce_fd = (cfg->jfce == NULL ? -1 : cfg->jfce->fd);
    /* UBcore gets userspace jfc for a completion event */
    arg.in.urma_jfc = (uint64_t)(void*)jfc;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfc, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    fill_jfc(jfc, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jfc(urma_jfc_t *jfc, const urma_jfc_attr_t *attr,
    const urma_cmd_udrv_priv_t *udata)
{
    if (jfc == NULL || jfc->urma_ctx == NULL || jfc->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jfc->urma_ctx;

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_modify_jfc_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_MODIFY_JFC;
    hdr.args_len = sizeof(urma_cmd_modify_jfc_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.handle = jfc->handle;
    arg.in.mask = attr->mask;
    arg.in.moderate_count = attr->moderate_count;
    arg.in.moderate_period = attr->moderate_period;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jfc, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
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
    urma_cmd_hdr_t hdr;
    urma_cmd_delete_jfc_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_DELETE_JFC;
    hdr.args_len = sizeof(urma_cmd_create_jfc_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = jfc->handle;

    ret = ioctl(jfc->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jfc , ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    (void)pthread_mutex_lock(&jfc->event_mutex);
    while (jfc->comp_events_acked != arg.out.comp_events_reported ||
           jfc->async_events_acked != arg.out.async_events_reported) {
        (void)pthread_cond_wait(&jfc->event_cond, &jfc->event_mutex);
    }
    (void)pthread_mutex_unlock(&jfc->event_mutex);

    return 0;
}

int urma_cmd_create_jfce(const urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_jfce_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_JFCE;
    hdr.args_len = sizeof(urma_cmd_create_jfce_t);
    hdr.args_addr = (uint64_t)&arg;

    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jfce, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return -1;
    }
    return arg.out.fd;
}

static inline void fill_tjfr(urma_target_jetty_t *tjfr, urma_context_t *ctx, const urma_tjfr_cfg_t *cfg,
    const urma_cmd_import_jfr_t *arg)
{
    tjfr->id = cfg->jfr_id;
    tjfr->trans_mode = cfg->trans_mode;
    tjfr->handle = arg->out.handle;
    tjfr->tp.type = arg->out.tp_type;
    tjfr->tp.tpn = arg->out.tpn;
    tjfr->urma_ctx = ctx;
}

int urma_cmd_import_jfr(urma_context_t *ctx, urma_target_jetty_t *tjfr, const urma_tjfr_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjfr == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_import_jfr_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_IMPORT_JFR;
    hdr.args_len = sizeof(urma_cmd_import_jfr_t);
    hdr.args_addr = (uint64_t)&arg;
    (void)memcpy(arg.in.eid, cfg->jfr_id.eid.raw, URMA_EID_SIZE);
    arg.in.uasid = cfg->jfr_id.uasid;
    arg.in.id = cfg->jfr_id.id;
    arg.in.key = cfg->key->key;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    fill_tjfr(tjfr, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_unimport_jfr(urma_target_jetty_t *tjfr)
{
    if (tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_unimport_jfr_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_UNIMPORT_JFR;
    hdr.args_len = sizeof(urma_cmd_unimport_jfr_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = tjfr->handle;

    ret = ioctl(tjfr->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    return 0;
}

static int advise_jetty(int dev_fd, uint64_t jetty_handle, uint64_t tjetty_handle,
    const urma_cmd_udrv_priv_t *udata, urma_cmd_t cmd)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_advise_jetty_t arg = {0};

    hdr.command = (uint32_t)cmd;
    hdr.args_len = sizeof(urma_cmd_advise_jetty_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.jetty_handle = jetty_handle;
    arg.in.tjetty_handle = tjetty_handle;
    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

static int unadvise_jetty(int dev_fd, uint64_t jetty_handle, uint64_t tjetty_handle, urma_cmd_t cmd)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_unadvise_jetty_t arg = {0};

    hdr.command = (uint32_t)cmd;
    hdr.args_len = sizeof(urma_cmd_unadvise_jetty_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.jetty_handle = jetty_handle;
    arg.in.tjetty_handle = tjetty_handle;
    ret = ioctl(dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

int urma_cmd_advise_jfr(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr, const urma_cmd_udrv_priv_t *udata)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    return advise_jetty(jfs->urma_ctx->dev_fd, jfs->handle, tjfr->handle, udata, URMA_CMD_ADVISE_JFR);
}

int urma_cmd_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->urma_ctx->dev_fd < 0 || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    return unadvise_jetty(jfs->urma_ctx->dev_fd, jfs->handle, tjfr->handle, URMA_CMD_UNADVISE_JFR);
}

int urma_cmd_advise_jetty(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty,
    const urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    return advise_jetty(jetty->urma_ctx->dev_fd, jetty->handle, tjetty->handle, udata, URMA_CMD_ADVISE_JETTY);
}

int urma_cmd_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL)  {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    return unadvise_jetty(jetty->urma_ctx->dev_fd, jetty->handle, tjetty->handle, URMA_CMD_UNADVISE_JETTY);
}

int urma_cmd_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
    const urma_cmd_udrv_priv_t *udata)
{
    int ret;

    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    ret = advise_jetty(jetty->urma_ctx->dev_fd, jetty->handle, tjetty->handle, udata, URMA_CMD_BIND_JETTY);
    if (ret == 0) {
        jetty->remote_jetty = (urma_target_jetty_t *)tjetty;
    }
    return ret;
}

int urma_cmd_unbind_jetty(urma_jetty_t *jetty)
{
    int ret;

    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    ret = unadvise_jetty(jetty->urma_ctx->dev_fd, jetty->handle, jetty->remote_jetty->handle,
        URMA_CMD_UNBIND_JETTY);
    if (ret == 0) {
        jetty->remote_jetty = NULL;
    }
    return ret;
}

static int init_create_jetty_cmd(urma_cmd_create_jetty_t *arg, urma_jetty_t *jetty, const urma_jetty_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    arg->in.id = cfg->id;
    arg->in.jfs_depth = cfg->jfs_cfg->depth;
    if (cfg->jfs_cfg->jfc != NULL) {
        arg->in.send_jfc_id = cfg->jfs_cfg->jfc->jfc_id.id;
        arg->in.send_jfc_handle = cfg->jfs_cfg->jfc->handle;
    }
    arg->in.max_send_sge = cfg->jfs_cfg->max_sge;
    arg->in.max_send_rsge = cfg->jfs_cfg->max_rsge;
    arg->in.max_inline_data = cfg->jfs_cfg->max_inline_data;
    arg->in.priority = cfg->jfs_cfg->priority;
    arg->in.retry_cnt = cfg->jfs_cfg->retry_cnt;
    arg->in.rnr_retry = cfg->jfs_cfg->rnr_retry;
    arg->in.err_timeout = cfg->jfs_cfg->err_timeout;
    arg->in.flag = cfg->flag.value;
    arg->in.trans_mode = (uint32_t)cfg->jfs_cfg->trans_mode;
    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR && cfg->jfr_cfg != NULL && cfg->jfr_cfg->jfc != NULL) {
        arg->in.jfr_depth = cfg->jfr_cfg->depth;
        arg->in.recv_jfc_id = cfg->jfr_cfg->jfc->jfc_id.id;
        arg->in.recv_jfc_handle = cfg->jfr_cfg->jfc->handle;
        arg->in.max_recv_sge = cfg->jfr_cfg->max_sge;
        arg->in.min_rnr_timer = cfg->jfr_cfg->min_rnr_timer;
        arg->in.key = cfg->jfr_cfg->ukey.key;
    } else if (cfg->flag.bs.share_jfr == URMA_SHARE_JFR && cfg->shared.jfr != NULL) {
        arg->in.jfr_id = cfg->shared.jfr->jfr_id.id;
        arg->in.jfr_handle = cfg->shared.jfr->handle;
        arg->in.key = cfg->shared.jfr->jfr_cfg.ukey.key;

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
    arg->in.urma_jetty = (uint64_t)(void*)jetty;
    urma_cmd_set_udrv_priv(&arg->udata, udata);
    return 0;
}

int urma_cmd_create_jetty(urma_context_t *ctx, urma_jetty_t *jetty, const urma_jetty_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || jetty == NULL || cfg == NULL || cfg->jfs_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_create_jetty_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_CREATE_JETTY;
    hdr.args_len = sizeof(urma_cmd_create_jetty_t);
    hdr.args_addr = (uint64_t)&arg;

    if (init_create_jetty_cmd(&arg, jetty, cfg, udata) != 0) {
        URMA_LOG_ERR("failed to init create jetty cmd");
        return -1;
    }

    /* allocate jfs cfg and jfr cfg just before ioctl to reduce rollback overhead */
    if (urma_init_jetty_cfg(&jetty->jetty_cfg, cfg) != 0) {
        URMA_LOG_ERR("failed to fill jetty cfg");
        return -1;
    }
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_create_jetty, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        urma_uninit_jetty_cfg(&jetty->jetty_cfg);
        return ret;
    }
    fill_jetty(jetty, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_modify_jetty(urma_jetty_t *jetty, const urma_jetty_attr_t *attr,
    const urma_cmd_udrv_priv_t *udata)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0 || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    urma_context_t *ctx = jetty->urma_ctx;
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_modify_jetty_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_MODIFY_JETTY;
    hdr.args_len = sizeof(urma_cmd_modify_jetty_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.handle = jetty->handle;
    arg.in.mask = attr->mask;
    arg.in.rx_threshold = attr->rx_threshold;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_modify_jetty, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}


int urma_cmd_delete_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev_fd < 0) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_delete_jetty_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_DELETE_JETTY;
    hdr.args_len = sizeof(urma_cmd_delete_jetty_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = jetty->handle;

    ret = ioctl(jetty->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_delete_jetty, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
    }
    urma_uninit_jetty_cfg(&jetty->jetty_cfg);

    wait_async_event_ack(&jetty->event_mutex, &jetty->event_cond,
        &jetty->async_events_acked, arg.out.async_events_reported);

    return ret;
}

int urma_cmd_import_jetty(urma_context_t *ctx, urma_target_jetty_t *tjetty, const urma_tjetty_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata)
{
    if (ctx == NULL || ctx->dev_fd < 0 || tjetty == NULL || cfg == NULL || cfg->key == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_import_jetty_t arg = {0};

    hdr.command = (uint32_t)URMA_CMD_IMPORT_JETTY;
    hdr.args_len = sizeof(urma_cmd_import_jetty_t);
    hdr.args_addr = (uint64_t)&arg;
    (void)memcpy(arg.in.eid, cfg->jetty_id.eid.raw, URMA_EID_SIZE);
    arg.in.uasid = cfg->jetty_id.uasid;
    arg.in.id = cfg->jetty_id.id;
    arg.in.trans_mode = (uint32_t)cfg->trans_mode;
    arg.in.key = cfg->key->key;

    urma_cmd_set_udrv_priv(&arg.udata, udata);
    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    fill_tjetty(tjetty, ctx, cfg, &arg);
    return 0;
}

int urma_cmd_unimport_jetty(urma_target_jetty_t *tjetty)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_unimport_jetty_t arg = {0};

    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -1;
    }
    hdr.command = (uint32_t)URMA_CMD_UNIMPORT_JETTY;
    hdr.args_len = sizeof(urma_cmd_unimport_jetty_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.handle = tjetty->handle;

    ret = ioctl(tjetty->urma_ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

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
    int ret = ioctl(jfce_fd, URMA_CMD_WAIT_JFC, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("wait jfc ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return -1;
    }
    for (uint32_t i = 0; i < arg.out.event_cnt && i < jfc_cnt; i++) {
        jfc[i] = (urma_jfc_t *)(void*)arg.out.event_data[i];
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

urma_status_t urma_cmd_get_async_event(const urma_context_t *ctx, urma_async_event_t *event)
{
    if (ctx == NULL || ctx->async_fd < 0 || event == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return URMA_EINVAL;
    }

    urma_cmd_async_event_t arg = {0};
    int ret = ioctl(ctx->async_fd, URMA_CMD_GET_ASYNC_EVENT, &arg);
    if (ret != 0) {
        URMA_LOG_ERR("get async event ioctl failed, ret:%d, errno:%d.\n", ret, errno);
        return URMA_FAIL;
    }
    event->event_type = arg.event_type;
    event->priv = NULL;
    event->urma_ctx = ctx;
    switch (arg.event_type) {
        case URMA_EVENT_JFC_ERR:
            event->element.jfc = (urma_jfc_t *)arg.event_data;
            break;
        case URMA_EVENT_JFS_FATAL:
        case URMA_EVENT_JFS_ACCESS_ERR:
            event->element.jfs = (urma_jfs_t *)arg.event_data;
            break;
        case URMA_EVENT_JFR_FATAL:
        case URMA_EVENT_JFR_ACCESS_ERR:
            event->element.jfr = (urma_jfr_t *)arg.event_data;
            break;
        case URMA_EVENT_JETTY_FATAL:
        case URMA_EVENT_JETTY_ACCESS_ERR:
            event->element.jetty = (urma_jetty_t *)arg.event_data;
            break;
        case URMA_EVENT_PORT_ACTIVE:
        case URMA_EVENT_PORT_ERR:
        case URMA_EVENT_DEV_FATAL:
        case URMA_EVENT_ID_CHANGE:
            event->element.port_id = (uint32_t)arg.event_data;
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

    if (event == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return;
    }

    switch (event->event_type) {
        case URMA_EVENT_JFC_ERR:
            jfc = event->element.jfc;
            ack_one_async_event(&jfc->event_mutex, &jfc->event_cond, &jfc->async_events_acked);
            break;
        case URMA_EVENT_JFS_FATAL:
        case URMA_EVENT_JFS_ACCESS_ERR:
            jfs = event->element.jfs;
            ack_one_async_event(&jfs->event_mutex, &jfs->event_cond, &jfs->async_events_acked);
            break;
        case URMA_EVENT_JFR_FATAL:
        case URMA_EVENT_JFR_ACCESS_ERR:
            jfr = event->element.jfr;
            ack_one_async_event(&jfr->event_mutex, &jfr->event_cond, &jfr->async_events_acked);
            break;
        case URMA_EVENT_JETTY_FATAL:
        case URMA_EVENT_JETTY_ACCESS_ERR:
            jetty = event->element.jetty;
            ack_one_async_event(&jetty->event_mutex, &jetty->event_cond, &jetty->async_events_acked);
            break;
        default:
            return;
    }
}

int urma_cmd_user_ctl(const urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out,
    urma_udrv_t *udrv_data)
{
    int ret;
    urma_cmd_hdr_t hdr;
    urma_cmd_user_ctl_t arg = {0};

    if (ctx == NULL || in == NULL || out == NULL) {
        URMA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    hdr.command = (uint32_t)URMA_CMD_USER_CTL;
    hdr.args_len = sizeof(urma_cmd_user_ctl_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.opcode = in->opcode;
    arg.in.addr = in->addr;
    arg.in.len = in->len;

    arg.out.addr = out->addr;
    arg.out.len = out->len;

    arg.udrv.in_addr = udrv_data->in_addr;
    arg.udrv.in_len = udrv_data->in_len;
    arg.udrv.out_addr = udrv_data->out_addr;
    arg.udrv.out_len = udrv_data->out_len;

    ret = ioctl(ctx->dev_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed in urma_cmd_user_ctl, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}
