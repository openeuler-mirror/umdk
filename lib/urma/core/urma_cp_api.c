/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: liburma control path API file
 * Author: Ouyang Changchun, Qian Guoxin
 * Create: 2021-08-11
 * Note:
 * History: 2021-08-11
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "urma_log.h"
#include "urma_types.h"
#include "urma_private.h"
#include "urma_provider.h"
#ifdef L2API_ENABLE
#include "ub_usmp.h"
#include "urma_manage.h"
#include "urma_local_sock.h"
#endif
#include "urma_api.h"
#include "urma_ex_api.h"

#define URMA_CHECK_OP_INVALID_RETURN_POINTER(urma_ctx, ops, op_name)  \
    do {  \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) || \
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) {  \
            URMA_LOG_ERR("Invalid parameter.\n");  \
            return NULL;  \
        }  \
    } while (0)

#define URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, op_name)  \
    do {  \
        if (((urma_ctx) == NULL) || ((urma_ctx)->ref == NULL) || ((urma_ctx)->dev == NULL) || \
            ((urma_ctx)->dev->sysfs_dev == NULL) || (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) { \
            URMA_LOG_ERR("Invalid parameter.\n");  \
            return URMA_EINVAL;  \
        }  \
    } while (0)

static inline bool urma_check_trans_mode_valid(urma_transport_mode_t trans_mode)
{
    return trans_mode == URMA_TM_RM || trans_mode == URMA_TM_RC || trans_mode == URMA_TM_UM;
}

urma_jfc_t *urma_create_jfc(urma_context_t *ctx, const urma_jfc_cfg_t *jfc_cfg)
{
    if (ctx == NULL || jfc_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfc);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfc_cfg->depth == 0 || jfc_cfg->depth > attr->dev_cap.max_jfc_depth) {
        URMA_LOG_ERR("jfc cfg depth of range, depth: %u, max_depth: %u.\n", jfc_cfg->depth, attr->dev_cap.max_jfc_depth);
        return NULL;
    }

    urma_jfc_t *jfc = ops->create_jfc(ctx, jfc_cfg);
    if (jfc != NULL && jfc->jfc_cfg.jfce != NULL) {
        jfc->jfc_cfg.jfce->refcnt++;
    }
    if (jfc != NULL) {
        atomic_fetch_add(&ctx->ref->atomic_cnt, 1);
    }
    return jfc;
}

urma_status_t urma_modify_jfc(urma_jfc_t *jfc, const urma_jfc_attr_t *attr)
{
    if (jfc == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfc->urma_ctx;
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, modify_jfc);

    return ops->modify_jfc(jfc, attr);
}

urma_status_t urma_delete_jfc(urma_jfc_t *jfc)
{
    if (jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfc->urma_ctx;
    urma_ops_t *ops = NULL;
    urma_jfce_t *jfce = jfc->jfc_cfg.jfce;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfc);

    urma_status_t ret = ops->delete_jfc(jfc);
    if (ret == URMA_SUCCESS && jfce != NULL) {
        jfce->refcnt--;
    }
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref->atomic_cnt, 1);
    }
    return ret;
}

urma_jfs_t *urma_create_jfs(urma_context_t *ctx, const urma_jfs_cfg_t *jfs_cfg)
{
    if (ctx == NULL || jfs_cfg == NULL || jfs_cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_check_trans_mode_valid(jfs_cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jfs_cfg->trans_mode);
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfs);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if ((jfs_cfg->depth == 0 || jfs_cfg->depth > attr->dev_cap.max_jfs_depth) ||
        (jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > attr->dev_cap.max_jfs_inline_len) ||
        (jfs_cfg->max_sge > attr->dev_cap.max_jfs_sge) || (jfs_cfg->max_rsge > attr->dev_cap.max_jfs_rsge)) {
        URMA_LOG_ERR("jfs cfg out of range, depth:%u, max_depth:%u, inline_data:%u, max_inline_len:%u, " \
            "sge:%hhu, max_sge:%u, rsge:%hhu, max_rsge:%u.\n",
            jfs_cfg->depth, attr->dev_cap.max_jfs_depth,
            jfs_cfg->max_inline_data, attr->dev_cap.max_jfs_inline_len,
            jfs_cfg->max_sge, attr->dev_cap.max_jfs_sge,
            jfs_cfg->max_rsge, attr->dev_cap.max_jfs_rsge);
        return NULL;
    }

    urma_jfs_t *jfs = ops->create_jfs(ctx, jfs_cfg);
    if (jfs != NULL) {
        atomic_fetch_add(&ctx->ref->atomic_cnt, 1);
    }
    return jfs;
}

urma_status_t urma_delete_jfs(urma_jfs_t *jfs)
{
    if (jfs == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfs);

    atomic_fetch_sub(&jfs->urma_ctx->ref->atomic_cnt, 1);
    return ops->delete_jfs(jfs);
}

urma_jfr_t *urma_create_jfr(urma_context_t *ctx, const urma_jfr_cfg_t *jfr_cfg)
{
    if (ctx == NULL || jfr_cfg == NULL || jfr_cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_check_trans_mode_valid(jfr_cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jfr_cfg->trans_mode);
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfr);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfr_cfg->depth == 0 || jfr_cfg->depth > attr->dev_cap.max_jfr_depth ||
        jfr_cfg->max_sge > attr->dev_cap.max_jfr_sge) {
        URMA_LOG_ERR("jfr cfg out of range, depth:%u, max_depth:%u, sge:%u, max_sge:%u.\n",
            jfr_cfg->depth, attr->dev_cap.max_jfr_depth, jfr_cfg->max_sge, attr->dev_cap.max_jfr_sge);
        return NULL;
    }

    urma_jfr_t *jfr = ops->create_jfr(ctx, jfr_cfg);
    if (jfr != NULL) {
        atomic_fetch_add(&ctx->ref->atomic_cnt, 1);
    }
    return jfr;
}

urma_status_t urma_modify_jfr(urma_jfr_t *jfr, const urma_jfr_attr_t *attr)
{
    if (jfr == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfr->urma_ctx;
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, modify_jfr);

    return ops->modify_jfr(jfr, attr);
}

urma_status_t urma_delete_jfr(urma_jfr_t *jfr)
{
    if (jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jfr->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfr);

    atomic_fetch_sub(&jfr->urma_ctx->ref->atomic_cnt, 1);
    return ops->delete_jfr(jfr);
}

urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, const urma_rjfr_t *rjfr, const urma_key_t *key)
{
    if (ctx == NULL || key == NULL || rjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jfr);

    urma_target_jetty_t *tjfr = ops->import_jfr(ctx, rjfr, key);
    if (tjfr != NULL) {
        atomic_fetch_add(&tjfr->urma_ctx->ref->atomic_cnt, 1);
    }
    return tjfr;
}

urma_status_t urma_unimport_jfr(urma_target_jetty_t *target_jfr, bool force)
{
    if (target_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = target_jfr->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_jfr);
    atomic_fetch_sub(&target_jfr->urma_ctx->ref->atomic_cnt, 1);
    return ops->unimport_jfr(target_jfr, force);
}

urma_jfce_t *urma_create_jfce(urma_context_t *ctx)
{
    urma_ops_t *ops;

    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfce);

    urma_jfce_t *jfce = ops->create_jfce(ctx);
    if (jfce != NULL) {
        atomic_fetch_add(&ctx->ref->atomic_cnt, 1);
    }
    return jfce;
}

urma_status_t urma_delete_jfce(urma_jfce_t *jfce)
{
    if (jfce == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    } else if (jfce->refcnt > 0) {
        URMA_LOG_ERR("Jfce is still used by at least one jfc, refcnt:%u.\n", jfce->refcnt);
        return URMA_FAIL;
    }
    const urma_context_t *urma_ctx = jfce->urma_ctx;
    urma_ops_t *ops;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfce);

    atomic_fetch_sub(&jfce->urma_ctx->ref->atomic_cnt, 1);
    return ops->delete_jfce(jfce);
}

static int urma_create_jetty_check_trans_mode(const urma_jetty_cfg_t *jetty_cfg)
{
    if (urma_check_trans_mode_valid(jetty_cfg->jfs_cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jetty_cfg->jfs_cfg->trans_mode);
        return -1;
    }

    if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR &&
        (jetty_cfg->jfr_cfg == NULL || urma_check_trans_mode_valid(jetty_cfg->jfr_cfg->trans_mode) != true ||
        jetty_cfg->jfs_cfg->trans_mode != jetty_cfg->jfr_cfg->trans_mode)) {
        URMA_LOG_ERR("jfr cfg is null or trans_mode invalid with non shared jfr flag.\n");
        return -1;
    } else if (jetty_cfg->flag.bs.share_jfr == URMA_SHARE_JFR && (jetty_cfg->shared.jfr == NULL ||
        jetty_cfg->jfs_cfg->trans_mode != jetty_cfg->shared.jfr->jfr_cfg.trans_mode)) {
        URMA_LOG_ERR("jfr is null or trans_mode invalid with shared jfr flag.\n");
        return -1;
    }
    return 0;
}

static int urma_create_jetty_check_dev_cap(urma_context_t *ctx, const urma_jetty_cfg_t *jetty_cfg)
{
    urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
    urma_jfs_cfg_t *jfs_cfg = jetty_cfg->jfs_cfg;
    urma_jfr_cfg_t *jfr_cfg =
        jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR ? jetty_cfg->jfr_cfg : &jetty_cfg->shared.jfr->jfr_cfg;

    if ((jfs_cfg->depth == 0 || jfs_cfg->depth > cap->max_jfs_depth) ||
        (jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > cap->max_jfs_inline_len) ||
        (jfr_cfg->depth == 0 || jfr_cfg->depth > cap->max_jfr_depth) ||
        (jfs_cfg->max_sge > cap->max_jfs_sge || jfs_cfg->max_rsge > cap->max_jfs_rsge || \
        jfr_cfg->max_sge > cap->max_jfr_sge)) {
        URMA_LOG_ERR("jetty cfg out of range, jfs_depth:%u, max_jfs_depth: %u, " \
            "inline_data:%u, max_jfs_inline_len: %u, jfr_depth:%u, max_jfr_depth: %u, " \
            "jfs_sge:%hhu, max_jfs_sge:%u, jfs_rsge:%hhu, max_jfs_rsge:%u, jfr_sge:%hhu, max_jfr_sge:%u.\n",
            jfs_cfg->depth, cap->max_jfs_depth, jfs_cfg->max_inline_data, cap->max_jfs_inline_len,
            jfr_cfg->depth, cap->max_jfr_depth, jfs_cfg->max_sge, cap->max_jfs_sge, jfs_cfg->max_rsge, cap->max_jfs_rsge,
            jfr_cfg->max_sge, cap->max_jfr_sge);
        return -1;
    }
    return 0;
}

urma_jetty_t *urma_create_jetty(urma_context_t *ctx, const urma_jetty_cfg_t *jetty_cfg)
{
    if (ctx == NULL || jetty_cfg == NULL || jetty_cfg->jfs_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_create_jetty_check_trans_mode(jetty_cfg) != 0) {
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jetty);

    if (urma_create_jetty_check_dev_cap(ctx, jetty_cfg) != 0) {
        return NULL;
    }

    urma_jetty_t *jetty = ops->create_jetty(ctx, jetty_cfg);
    if (jetty != NULL) {
        atomic_fetch_add(&ctx->ref->atomic_cnt, 1);
    }
    return jetty;
}

urma_status_t urma_modify_jetty(urma_jetty_t *jetty, const urma_jetty_attr_t *attr)
{
    if (jetty == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, modify_jetty);

    return ops->modify_jetty(jetty, attr);
}

urma_status_t urma_delete_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jetty);

    atomic_fetch_sub(&jetty->urma_ctx->ref->atomic_cnt, 1);
    return ops->delete_jetty(jetty);
}

urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, const urma_rjetty_t *rjetty, const urma_key_t *rjetty_key)
{
    if (ctx == NULL || rjetty == NULL || rjetty_key == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    urma_ops_t *ops = NULL;
    urma_target_jetty_t *tjetty = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jetty);
    tjetty = ops->import_jetty(ctx, rjetty, rjetty_key);
    if (tjetty != NULL) {
        atomic_fetch_add(&tjetty->urma_ctx->ref->atomic_cnt, 1);
    }
    return tjetty;
}

urma_status_t urma_unimport_jetty(urma_target_jetty_t *tjetty, bool force)
{
    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = tjetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_jetty);
    atomic_fetch_sub(&tjetty->urma_ctx->ref->atomic_cnt, 1);
    return ops->unimport_jetty(tjetty, force);
}

urma_status_t urma_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg->trans_mode != URMA_TM_RC || tjetty->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%d of mode:%d with remote jetty:%d of mode:%d.\n",
            jetty->jetty_id.id, jetty->jetty_cfg.jfs_cfg->trans_mode, tjetty->id.id, tjetty->trans_mode);
        return URMA_ENOPERM;
    }

    const urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, bind_jetty);
    return ops->bind_jetty(jetty, tjetty);
}

urma_status_t urma_unbind_jetty(urma_jetty_t *jetty, bool force)
{
    if (jetty == NULL || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to call unbind as the tp mode of jetty :%d is:%d.\n",
            jetty->jetty_id.id, jetty->jetty_cfg.jfs_cfg->trans_mode);
        return URMA_ENOPERM;
    }

    const urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unbind_jetty);
    return ops->unbind_jetty(jetty, force);
}

urma_status_t urma_advise_jetty(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL || (jetty->jetty_cfg.jfs_cfg != NULL &&
        jetty->jetty_cfg.jfs_cfg->trans_mode != URMA_TM_RM) || tjetty->trans_mode != URMA_TM_RM) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, advise_jetty);
    return ops->advise_jetty(jetty, tjetty);
}

urma_status_t urma_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, bool force)
{
    if (jetty == NULL || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unadvise_jetty);
    return ops->unadvise_jetty(jetty, tjetty, force);
}

urma_target_seg_t *urma_import_seg(urma_context_t *ctx, const urma_seg_t *seg,
    const urma_key_t *key,  uint64_t addr, urma_import_seg_flag_t flag)
{
    if (ctx == NULL || seg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (seg->attr.bs.key_policy != URMA_KEY_NONE && key == NULL) {
        URMA_LOG_ERR("Key must be set when key_policy is not URMA_KEY_NONE.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_target_seg_t *tseg = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_seg);
    tseg = ops->import_seg(ctx, seg, key, addr, flag);
    if (tseg != NULL) {
        atomic_fetch_add(&tseg->urma_ctx->ref->atomic_cnt, 1);
    }
    return tseg;
}

urma_status_t urma_unimport_seg(urma_target_seg_t *tseg, bool force)
{
    if (tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(tseg->urma_ctx, ops, unimport_seg);
    atomic_fetch_sub(&tseg->urma_ctx->ref->atomic_cnt, 1);
    return ops->unimport_seg(tseg, force);
}

urma_key_id_t *urma_alloc_key_id(urma_context_t *ctx)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_key_id_t *key_id = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, alloc_key_id);
    key_id = ops->alloc_key_id(ctx);
    if (key_id != NULL) {
        atomic_fetch_add(&key_id->urma_ctx->ref->atomic_cnt, 1);
    }
    return key_id;
}

urma_status_t urma_free_key_id(urma_key_id_t *key_id)
{
    if (key_id == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(key_id->urma_ctx, ops, free_key_id);
    atomic_fetch_sub(&key_id->urma_ctx->ref->atomic_cnt, 1);
    return ops->free_key_id(key_id);
}

urma_target_seg_t *urma_register_seg(urma_context_t *ctx, const urma_seg_cfg_t *seg_cfg)
{
    if (ctx == NULL || seg_cfg == NULL || seg_cfg->va == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (seg_cfg->flag.bs.key_policy != URMA_KEY_NONE && seg_cfg->key == NULL) {
        URMA_LOG_ERR("Key must be set when key_policy is not URMA_KEY_NONE.\n");
        return NULL;
    }

    if ((seg_cfg->flag.bs.access & (URMA_ACCESS_REMOTE_WRITE | URMA_ACCESS_REMOTE_ATOMIC)) &&
        !(seg_cfg->flag.bs.access & URMA_ACCESS_LOCAL_WRITE)) {
        URMA_LOG_ERR("Local write must be set when either remote write or remote atomic is declared.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_target_seg_t *seg = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, register_seg);
    seg = ops->register_seg(ctx, seg_cfg);
    if (seg != NULL) {
        atomic_fetch_add(&seg->urma_ctx->ref->atomic_cnt, 1);
    }
    return seg;
}

urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg, bool force)
{
    if (target_seg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(target_seg->urma_ctx, ops, unregister_seg);
    atomic_fetch_sub(&target_seg->urma_ctx->ref->atomic_cnt, 1);
    return ops->unregister_seg(target_seg, force);
}

urma_status_t urma_advise_jfr(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM ||
        tjfr->trans_mode != URMA_TM_RM)) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, advise_jfr);
    return ops->advise_jfr(jfs, tjfr);
}

urma_status_t urma_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, bool force)
{
    if (jfs == NULL || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    const urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unadvise_jfr);
    return ops->unadvise_jfr(jfs, tjfr, force);
}

urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr,
    urma_advise_async_cb_func cb_fun, void *cb_arg)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM ||
        tjfr->trans_mode != URMA_TM_RM) || cb_fun == NULL || cb_arg == NULL ||
        jfs->urma_ctx != tjfr->urma_ctx) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(jfs->urma_ctx, ops, advise_jfr_async);
    return ops->advise_jfr_async(jfs, tjfr, cb_fun, cb_arg);
}

urma_status_t urma_get_async_event(const urma_context_t *ctx, urma_async_event_t *event)
{
    if (ctx == NULL || event == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, get_async_event);

    return ops->get_async_event(ctx, event);
}

void urma_ack_async_event(urma_async_event_t *event)
{
    if (event == NULL || event->urma_ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return;
    }

    urma_ops_t *ops = event->urma_ctx->ops;
    if (ops == NULL || ops->ack_async_event == NULL) {
        URMA_LOG_ERR("Invalid parameter with ops nullptr.\n");
        return;
    }
    ops->ack_async_event(event);
}

#ifdef L2API_ENABLE
urma_status_t urma_create_ur(const char *name, uint64_t size, urma_ur_attr_t flag,
    uintptr_t user_ctx, urma_ur_t **ur)
{
    urma_status_t ret;
    urma_msg_create_ur_t msg_data_in = {0};
    local_sock_api_arg_t arg = {0};

    if (ur == NULL) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", name);
        return URMA_EINVAL;
    }
    if (name == NULL || strlen(name) == 0 || strlen(name) + 1 > UR_NAME_MAX_LEN || size == 0) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", name);
        *ur = NULL;
        return URMA_EINVAL;
    }

    *ur = calloc(1, sizeof(urma_ur_t));
    if (*ur == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        return URMA_ENOMEM;
    }
    (void)strncpy((*ur)->name, name, UR_NAME_MAX_LEN - 1);
    (*ur)->size = size;
    (*ur)->attr = flag;
    (*ur)->user_ctx = user_ctx;
    // to notify ubsc.
    (void)strncpy(msg_data_in.ur_name, name, UR_NAME_MAX_LEN - 1);
    msg_data_in.size = size;
    msg_data_in.flag = flag.value;
    arg.in.len = sizeof(urma_msg_create_ur_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_CREATE);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_CREATE, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        goto free_ur;
    }
    if (arg.out.status != (uint8_t)USMP_STAT_SUCCEED) {
        if (arg.out.status == (uint8_t)USMP_STAT_EXISTS) {
            URMA_LOG_ERR("UBSC return existed.\n");
            ret = URMA_EEXIST;
        } else {
            URMA_LOG_ERR("UBSC return failed.\n");
            ret = URMA_FAIL;
        }
        goto free_ur;
    }
    return ret;

free_ur:
    free(*ur);
    *ur = NULL;
    return ret;
}

urma_status_t urma_destroy_ur(urma_ur_t *ur, bool force)
{
    urma_status_t ret;
    urma_msg_destroy_ur_t msg_data_in = {0};
    local_sock_api_arg_t arg = {0};

    if (ur == NULL || strlen(ur->name) + 1 > UR_NAME_MAX_LEN || strlen(ur->name) == 0) {
        URMA_LOG_ERR("Invalid parameter, ur_name: %s.\n", ur->name);
        return URMA_EINVAL;
    }

    // to notify ubsc.
    (void)strncpy(msg_data_in.ur_name, ur->name, UR_NAME_MAX_LEN);
    msg_data_in.size = ur->size;
    msg_data_in.force = (uint32_t)force;

    arg.in.len = sizeof(urma_msg_destroy_ur_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_DESTROY);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_DESTROY, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        return URMA_ENOPERM;
    }
    if (arg.out.status == (uint8_t)USMP_STAT_INVAL) {
        URMA_LOG_ERR("Invalid parameter, USBC can not find ur, %s.\n", ur->name);
        return URMA_EINVAL;
    } else if (arg.out.status != (uint8_t)USMP_STAT_SUCCEED) {
        URMA_LOG_ERR("UBSC return failed.\n");
        return URMA_ENOPERM;
    }

    free(ur);
    return URMA_SUCCESS;
}

uint32_t urma_attach_ur(const char *ur_name, uint32_t start_idx, const urma_target_seg_t **seg_list, uint32_t seg_cnt)
{
    uint32_t i;
    urma_status_t ret;
    urma_msg_attach_ur_in_t *msg_data_in = NULL;
    local_sock_api_arg_t arg = {0};
    urma_target_seg_t *tgt_seg;

    if (ur_name == NULL || strlen(ur_name) == 0 || strlen(ur_name) + 1 > UR_NAME_MAX_LEN ||
        seg_list == NULL || seg_cnt == 0 || seg_cnt > URMA_MAX_SEGS_PER_UR_OPT) {
        URMA_LOG_ERR("Invalid parameter, name: %s, seg_cnt: %u.\n", ur_name, seg_cnt);
        return 0;
    }

    // to notify ubsc.
    msg_data_in = calloc(1, sizeof(urma_msg_attach_ur_in_t) + seg_cnt * sizeof(urma_target_seg_t));
    if (msg_data_in == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        return 0;
    }

    (void)strncpy(msg_data_in->ur_name, ur_name, UR_NAME_MAX_LEN);
    msg_data_in->start_idx = start_idx;
    msg_data_in->seg_cnt = seg_cnt;
    tgt_seg = msg_data_in->seg_list;
    for (i = 0; i < seg_cnt; i++) {
        (void)memcpy(tgt_seg + i, seg_list[i], sizeof(urma_target_seg_t));
    }

    arg.in.len = sizeof(urma_msg_attach_ur_in_t) + seg_cnt * sizeof(urma_target_seg_t);
    arg.in.data = msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_ATTACH);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_ATTACH, &arg);
    free(msg_data_in);
    msg_data_in = NULL;
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        goto err_ret;
    }

    urma_msg_attach_ur_out_t *msg_data_out = (urma_msg_attach_ur_out_t *)arg.out.buf;
    if (arg.out.len != sizeof(urma_msg_attach_ur_out_t) || arg.out.status != USMP_STAT_SUCCEED) {
        URMA_LOG_ERR("The data length of the received message is inconsistent, usmp_status:%u.\n", arg.out.status);
        goto err_ret;
    }

    uint32_t good_cnt = msg_data_out->good_seg_cnt;

    free(arg.out.buf);
    return good_cnt;

err_ret:
    free(arg.out.buf);
    return 0;
}

uint32_t urma_detach_ur(const char *ur_name, const urma_target_seg_t **seg_list, uint32_t seg_cnt,
    bool force)
{
    uint32_t i;
    urma_status_t ret;
    urma_msg_detach_ur_in_t *msg_data_in = NULL;
    local_sock_api_arg_t arg = {0};
    urma_target_seg_t *tgt_seg;

    if (ur_name == NULL || strlen(ur_name) == 0 || strlen(ur_name) + 1 > UR_NAME_MAX_LEN ||
        seg_list == NULL || seg_cnt == 0 || seg_cnt > URMA_MAX_SEGS_PER_UR_OPT) {
        URMA_LOG_ERR("Invalid parameter, name: %s, seg_cnt: %u.\n", ur_name, seg_cnt);
        return 0;
    }

    // to notify ubsc.
    msg_data_in = calloc(1, sizeof(urma_msg_detach_ur_in_t) + seg_cnt * sizeof(urma_target_seg_t));
    if (msg_data_in == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        return 0;
    }

    (void)strncpy(msg_data_in->ur_name, ur_name, UR_NAME_MAX_LEN);
    msg_data_in->seg_cnt = seg_cnt;
    msg_data_in->force = (uint32_t)force;
    tgt_seg = msg_data_in->seg_list;
    for (i = 0; i < seg_cnt; i++) {
        (void)memcpy(tgt_seg + i, seg_list[i], sizeof(urma_target_seg_t));
    }

    arg.in.len = sizeof(urma_msg_detach_ur_in_t) + seg_cnt * sizeof(urma_target_seg_t);
    arg.in.data = msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_DETACH);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_DETACH, &arg);
    free(msg_data_in);
    msg_data_in = NULL;
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        goto err_ret;
    }

    urma_msg_detach_ur_out_t *msg_data_out = (urma_msg_detach_ur_out_t *)arg.out.buf;
    if (arg.out.len != sizeof(urma_msg_detach_ur_out_t) || arg.out.status != USMP_STAT_SUCCEED) {
        URMA_LOG_ERR("The data length of the received message is inconsistent, usmp_status:%u.\n", arg.out.status);
        goto err_ret;
    }

    uint32_t good_cnt = msg_data_out->good_seg_cnt;

    free(arg.out.buf);
    return good_cnt;

err_ret:
    free(arg.out.buf);
    return 0;
}

urma_target_ur_t *urma_import_ur(urma_context_t *ctx, const urma_ur_info_t *ur_info,
    const urma_key_t **token_list, uint32_t token_cnt, uint64_t addr, urma_import_ur_flag_t flag)
{
    uint32_t i, j;
    uint64_t addr_offset = 0;
    urma_import_seg_flag_t import_seg_flag;
    urma_ops_t *ops = NULL;
    const urma_seg_info_t *seg_info;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_seg);
    if (ur_info == NULL || token_list == NULL || token_cnt != ur_info->cnt) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    urma_target_ur_t *tgt_ur = calloc(1, sizeof(urma_target_ur_t));
    if (tgt_ur == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        return NULL;
    }

    tgt_ur->tseg_list = calloc(1, sizeof(urma_target_seg_t *) * ur_info->cnt);
    if (tgt_ur->tseg_list == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        goto free_tgt_ur;
    }

    (void)strncpy(tgt_ur->name, ur_info->name, UR_NAME_MAX_LEN);
    tgt_ur->size = ur_info->size;
    tgt_ur->flag = flag;

    seg_info = ur_info->seg_list;
    for (i = 0; i < ur_info->cnt; i++) {
        import_seg_flag.bs.cacheable = seg_info[i].seg.attr.bs.cacheable;
        import_seg_flag.bs.access    = seg_info[i].seg.attr.bs.access;
        import_seg_flag.bs.mapping   = flag.bs.mapping;

        tgt_ur->tseg_list[i] = ops->import_seg(ctx, &(seg_info[i].seg), token_list[i],
            (addr == 0 ? 0 : addr + addr_offset), import_seg_flag);
        if (tgt_ur->tseg_list[i] == NULL) {
            URMA_LOG_ERR("import_seg failed, ur_name: %s, idx:%u.\n", ur_info->name, i);
            goto unimport_ur;
        }

        tgt_ur->cnt++;
        addr_offset += seg_info[i].seg.len;
    }

    return tgt_ur;

unimport_ur:
    for (j = 0; j < i; j++) {
        urma_status_t ret = ops->unimport_seg(tgt_ur->tseg_list[j], true);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_ERR("unimport_seg failed, ur_name: %s, idx:%u.\n", ur_info->name, j);
        }
        tgt_ur->cnt--;
    }
    free(tgt_ur->tseg_list);
free_tgt_ur:
    free(tgt_ur);
    return NULL;
}

urma_status_t urma_unimport_ur(urma_target_ur_t *tgt_ur, bool force)
{
    uint32_t i;
    uint32_t cnt;
    urma_context_t *ctx;
    urma_ops_t *ops;
    urma_status_t ret = URMA_SUCCESS;

    if (tgt_ur == NULL || tgt_ur->tseg_list == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    cnt = tgt_ur->cnt;

    for (i = 0; i < cnt; i++) {
        if (tgt_ur->tseg_list[i] == NULL || (ctx = tgt_ur->tseg_list[i]->urma_ctx) == NULL ||
            (ops = ctx->ops) == NULL || ops->unimport_jfr == NULL) {
            URMA_LOG_ERR("Invalid parameter.\n");
            continue;
        }

        ret = ops->unimport_seg(tgt_ur->tseg_list[i], force);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_ERR("unimport_seg failed, ur_name: %s, idx:%u.\n", tgt_ur->name, i);
            if (force == false) {
                break;
            }
        }
        tgt_ur->cnt--;
    }

    if (ret != URMA_SUCCESS) {
        if (force == true) {
            free(tgt_ur->tseg_list);
            free(tgt_ur);
        }
    } else {
        free(tgt_ur->tseg_list);
        free(tgt_ur);
    }
    return ret;
}

urma_status_t urma_get_ur_list(uint32_t req_cnt, char *ur_list, uint32_t *ret_cnt)
{
    urma_status_t ret;
    urma_msg_get_ur_in_t msg_data_in;
    urma_msg_get_ur_out_t *msg_data_out;
    local_sock_api_arg_t arg = {0};

    if (ur_list == NULL || req_cnt == 0 || ret_cnt == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    // to get information from ubsc
    msg_data_in.get_ur_cnt = req_cnt;
    arg.in.len = sizeof(urma_msg_get_ur_in_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_GET_LIST);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_GET_LIST, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    msg_data_out = (urma_msg_get_ur_out_t *)arg.out.buf;
    if (arg.out.status == USMP_STAT_OUTRANGE && msg_data_out->ret_ur_cnt > req_cnt) {
        *ret_cnt = msg_data_out->ret_ur_cnt;
        URMA_LOG_INFO("Not enough memory allocated and it needs to be reallocated, "
            "usmp_status:%u, req_cnt:%u, ret_cnt%u.\n", arg.out.status, req_cnt, *ret_cnt);
        free(arg.out.buf);
        return URMA_EAGAIN;
    } else if (arg.out.status != USMP_STAT_SUCCEED) {
        URMA_LOG_INFO("UBSC return status failed, usmp_status:%u.\n", arg.out.status);
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    *ret_cnt = msg_data_out->ret_ur_cnt;
    uint32_t offset = 0;
    uint8_t *ur_name_len;

    for (uint32_t i = 0; i < *ret_cnt; i++) {
        /* ur_list: ret_ur_cnt * (UR_NAME_MAX_LEN)
         * usmp pkt:ret_ur_cnt * (sizeof(uint8_t) + strlen(ur_name)) */
        ur_name_len = (uint8_t *)(msg_data_out->ur_name + offset);
        offset += sizeof(uint8_t);
        (void)strncpy(ur_list + i * UR_NAME_MAX_LEN, msg_data_out->ur_name + offset, *ur_name_len);
        offset += *ur_name_len;
    }

    free(arg.out.buf);
    return URMA_SUCCESS;
}

urma_status_t urma_lookup_ur(const char *ur_name, uint32_t req_cnt, urma_ur_info_t *ur_info)
{
    urma_status_t ret;
    urma_msg_lookup_ur_in_t msg_data_in;
    urma_msg_lookup_ur_out_t *msg_data_out;
    local_sock_api_arg_t arg = {0};

    if (ur_name == NULL || strlen(ur_name) == 0 || strlen(ur_name) + 1 > UR_NAME_MAX_LEN ||
        req_cnt == 0 || ur_info == NULL) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", ur_name);
        return URMA_EINVAL;
    }

    (void)strncpy(msg_data_in.ur_name, ur_name, UR_NAME_MAX_LEN);
    msg_data_in.get_seg_cnt = req_cnt;
    arg.in.len = sizeof(urma_msg_lookup_ur_in_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_UR_GET_INFO);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_UR_GET_INFO, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    msg_data_out = (urma_msg_lookup_ur_out_t *)arg.out.buf;
    if (arg.out.status == USMP_STAT_OUTRANGE && msg_data_out->ret_seg_cnt > req_cnt) {
        ur_info->cnt = msg_data_out->ret_seg_cnt;
        URMA_LOG_INFO("Not enough memory allocated and it needs to be reallocated, "
            "usmp_status:%u, req_cnt:%u, ret_cnt%u.\n", arg.out.status, req_cnt, ur_info->cnt);
        free(arg.out.buf);
        return URMA_EAGAIN;
    } else if (arg.out.status != USMP_STAT_SUCCEED) {
        URMA_LOG_INFO("UBSC return status failed, usmp_status:%u.\n", arg.out.status);
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    (void)strncpy(ur_info->name, ur_name, UR_NAME_MAX_LEN - 1);
    ur_info->size = msg_data_out->size;
    ur_info->attr.value = msg_data_out->flag;
    ur_info->cnt = msg_data_out->ret_seg_cnt;
    for (uint32_t i = 0; i < msg_data_out->ret_seg_cnt; i++) {
        (void)memcpy(&ur_info->seg_list[i].seg, &msg_data_out->seg_list[i].seg, sizeof(urma_seg_t));
    }

    free(arg.out.buf);
    return URMA_SUCCESS;
}

urma_status_t urma_register_named_jfr(const char *jfr_name, const urma_jfr_t *jfr)
{
    urma_status_t ret;
    urma_msg_create_njfr_t msg_data_in = {0};
    local_sock_api_arg_t arg = {0};

    if (jfr_name == NULL || strlen(jfr_name) == 0 || strlen(jfr_name) + 1 > JFR_NAME_MAX_LEN || jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", jfr_name);
        return URMA_EINVAL;
    }

    // to notify ubsc.
    (void)strncpy(msg_data_in.jfr_name, jfr_name, JFR_NAME_MAX_LEN);
    (void)memcpy(&msg_data_in.jfr, jfr, sizeof(urma_jfr_t));

    arg.in.len = sizeof(urma_msg_create_njfr_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_NJFR_CREATE);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_NJFR_CREATE, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        return URMA_ENOPERM;
    }
    if (arg.out.status != (uint8_t)USMP_STAT_SUCCEED) {
        URMA_LOG_ERR("UBSC return failed.\n");
        return URMA_ENOPERM;
    }
    return URMA_SUCCESS;
}

urma_status_t urma_unregister_named_jfr(const char *jfr_name)
{
    urma_status_t ret;
    urma_msg_destroy_njfr_t msg_data_in = {0};
    local_sock_api_arg_t arg = {0};

    if (jfr_name == NULL || strlen(jfr_name) == 0 || strlen(jfr_name) + 1 > JFR_NAME_MAX_LEN) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", jfr_name);
        return URMA_EINVAL;
    }

    // to notify ubsc.
    (void)strncpy(msg_data_in.jfr_name, jfr_name, JFR_NAME_MAX_LEN);

    arg.in.len = sizeof(urma_msg_destroy_njfr_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_NJFR_DESTROY);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_NJFR_DESTROY, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        return URMA_ENOPERM;
    }
    if (arg.out.status != (uint8_t)USMP_STAT_SUCCEED) {
        URMA_LOG_ERR("UBSC return failed.\n");
        return URMA_ENOPERM;
    }
    return URMA_SUCCESS;
}

urma_status_t urma_get_named_jfr_list(uint32_t req_cnt, char *jfr_list, uint32_t *ret_cnt)
{
    urma_status_t ret;
    urma_msg_get_njfr_in_t msg_data_in;
    urma_msg_get_njfr_out_t *msg_data_out;
    local_sock_api_arg_t arg = {0};

    if (jfr_list == NULL || req_cnt == 0 || ret_cnt == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    // to get information from ubsc
    msg_data_in.get_njfr_cnt = req_cnt;
    arg.in.len = sizeof(urma_msg_get_njfr_in_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_NJFR_GET_LIST);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_NJFR_GET_LIST, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    msg_data_out = (urma_msg_get_njfr_out_t *)arg.out.buf;
    if (arg.out.status == USMP_STAT_OUTRANGE && msg_data_out->ret_cnt > req_cnt) {
        *ret_cnt = msg_data_out->ret_cnt;
        URMA_LOG_INFO("Not enough memory allocated and it needs to be reallocated, "
            "usmp_status:%u, req_cnt:%u, ret_cnt%u.\n", arg.out.status, req_cnt, *ret_cnt);
        free(arg.out.buf);
        return URMA_EAGAIN;
    } else if (arg.out.status != USMP_STAT_SUCCEED) {
        URMA_LOG_INFO("UBSC return status failed, usmp_status:%u.\n", arg.out.status);
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    *ret_cnt = msg_data_out->ret_cnt;
    uint32_t offset = 0;
    uint8_t *jfr_name_len;

    for (uint32_t i = 0; i < *ret_cnt; i++) {
        /* ur_list: ret_ur_cnt * (JFR_NAME_MAX_LEN)
         * usmp pkt:ret_ur_cnt * (sizeof(uint8_t) + strlen(jfr_name)) */
        jfr_name_len = (uint8_t *)(msg_data_out->njfr_name + offset);
        offset += sizeof(uint8_t);
        (void)strncpy(jfr_list + i * JFR_NAME_MAX_LEN, msg_data_out->njfr_name + offset, *jfr_name_len);
        offset += *jfr_name_len;
    }

    free(arg.out.buf);
    return URMA_SUCCESS;
}

urma_status_t urma_lookup_named_jfr(const char *jfr_name, urma_jfr_info_t *jfr_info)
{
    urma_status_t ret;
    urma_msg_lookup_njfr_in_t msg_data_in;
    urma_msg_lookup_njfr_out_t *msg_data_out;
    local_sock_api_arg_t arg = {0};

    if (jfr_name == NULL || strlen(jfr_name) == 0 || strlen(jfr_name) + 1 > JFR_NAME_MAX_LEN ||
        jfr_info == NULL) {
        URMA_LOG_ERR("Invalid parameter, name:%s.\n", jfr_name);
        return URMA_EINVAL;
    }

    (void)strncpy(msg_data_in.jfr_name, jfr_name, JFR_NAME_MAX_LEN);
    arg.in.len = sizeof(urma_msg_lookup_njfr_in_t);
    arg.in.data = &msg_data_in;
    arg.in.timeout_ns = urma_get_cmd_timeout(URMA_MSG_NJFR_GET_INFO);
    ret = urma_send_cmd_to_ubsc(USMP_UR_SERVICE, URMA_MSG_NJFR_GET_INFO, &arg);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Remote synchronous call failed.\n");
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    msg_data_out = (urma_msg_lookup_njfr_out_t *)arg.out.buf;
    if (arg.out.status != USMP_STAT_SUCCEED || arg.out.len != sizeof(urma_msg_lookup_njfr_out_t)) {
        URMA_LOG_INFO("UBSC return status failed, usmp_status:%u.\n", arg.out.status);
        free(arg.out.buf);
        return URMA_ENOPERM;
    }

    (void)strncpy(jfr_info->name, msg_data_out->jfr_name, JFR_NAME_MAX_LEN);
    jfr_info->eid = msg_data_out->jfr.jfr_id.eid;
    jfr_info->uasid = msg_data_out->jfr.jfr_id.uasid;
    jfr_info->id = msg_data_out->jfr.jfr_id.id;

    free(arg.out.buf);
    return URMA_SUCCESS;
}
#endif

urma_status_t urma_user_ctl(const urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    if ((ctx == NULL) || (in == NULL) || (out == NULL)) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, user_ctl);

    if (in->opcode == URMA_USER_CTL_IGNORE_JETTY_IN_CR &&
        strcmp(ops->name, "provider_ib") != 0) {
        URMA_LOG_WARN("Only provider_ib can configure URMA_USER_CTL_IGNORE_JETTY_IN_CR.\n");
        return URMA_SUCCESS;
    }
    if (in->opcode == URMA_USER_CTL_IP_NON_BLOCK_SEND && ctx->dev->type != URMA_TRANSPORT_IP) {
        URMA_LOG_WARN("Only in IP mode can configure URMA_USER_CTL_IP_NON_BLOCK_SEND.\n");
        return URMA_SUCCESS;
    }

    int ret = ops->user_ctl(ctx, in, out);
    if ((urma_status_t)ret != URMA_SUCCESS && (urma_status_t)ret != URMA_ENOPERM) {
        URMA_LOG_ERR("Failed to excecute user_ctl, ret: %d.\n", ret);
        return URMA_FAIL;
    }
    return (urma_status_t)ret;
}

int urma_init_jetty_cfg(urma_jetty_cfg_t *p, const urma_jetty_cfg_t *cfg)
{
    urma_jfs_cfg_t *jfs_cfg;

    *p = *cfg;

    /* deep copy of jfs cfg */
    jfs_cfg = calloc(1, sizeof(urma_jfs_cfg_t));
    if (jfs_cfg == NULL) {
        URMA_LOG_ERR("Failed to calloc jfs cfg.\n");
        return -1;
    }
    *jfs_cfg = *(cfg->jfs_cfg);

    /* deep copy of jfr cfg */
    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR) {
        p->jfr_cfg = calloc(1, sizeof(urma_jfr_cfg_t));
        if (p->jfr_cfg == NULL) {
            free(jfs_cfg);
            URMA_LOG_ERR("Failed to calloc jfs cfg.\n");
            return -1;
        }
        (void)memcpy(p->jfr_cfg, cfg->jfr_cfg, sizeof(urma_jfr_cfg_t));
    }

    p->jfs_cfg = jfs_cfg;
    return 0;
}

void urma_uninit_jetty_cfg(urma_jetty_cfg_t *p)
{
    free(p->jfs_cfg);
    p->jfs_cfg = NULL;
    if (p->flag.bs.share_jfr == URMA_SHARE_JFR) {
        return;
    }
    free(p->jfr_cfg);
    p->jfr_cfg = NULL;
}