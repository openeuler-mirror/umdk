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
#include "urma_api.h"
#include "urma_ex_api.h"

#define URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx)  \
        do {  \
            if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL)) { \
                URMA_LOG_ERR("Invalid parameter.\n");  \
                return URMA_EINVAL;  \
            }  \
        } while (0)

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
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || \
            ((urma_ctx)->dev->sysfs_dev == NULL) || (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) { \
            URMA_LOG_ERR("Invalid parameter.\n");  \
            return URMA_EINVAL;  \
        }  \
    } while (0)

#define URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, op_name)  \
    do {  \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || \
            ((urma_ctx)->dev->sysfs_dev == NULL) || (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) { \
            URMA_LOG_ERR("Invalid parameter.\n");  \
            return -URMA_EINVAL;  \
        }  \
    } while (0)

static inline bool urma_check_trans_mode_valid(urma_transport_mode_t trans_mode)
{
    return trans_mode == URMA_TM_RM || trans_mode == URMA_TM_RC || trans_mode == URMA_TM_UM;
}

urma_jfc_t *urma_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg)
{
    if (ctx == NULL || jfc_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfc);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfc_cfg->depth == 0 || jfc_cfg->depth > attr->dev_cap.max_jfc_depth) {
        URMA_LOG_ERR("jfc cfg depth of range, depth: %u, max_depth: %u.\n",
            jfc_cfg->depth, attr->dev_cap.max_jfc_depth);
        return NULL;
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jfc_t *jfc = ops->create_jfc(ctx, jfc_cfg);
    if (jfc != NULL && jfc->jfc_cfg.jfce != NULL) {
        atomic_fetch_add(&jfc->jfc_cfg.jfce->ref.atomic_cnt, 1);
    }
    if (jfc == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return jfc;
}

urma_status_t urma_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
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
        atomic_fetch_sub(&jfce->ref.atomic_cnt, 1);
    }
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }
    return ret;
}

urma_jfs_t *urma_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *jfs_cfg)
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

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jfs_t *jfs = ops->create_jfs(ctx, jfs_cfg);
    if (jfs == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return jfs;
}

urma_status_t urma_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr)
{
    if (jfs == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, modify_jfs);

    return ops->modify_jfs(jfs, attr);
}

urma_status_t urma_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr)
{
    if (jfs == NULL || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, query_jfs);

    return ops->query_jfs(jfs, cfg, attr);
}

urma_status_t urma_delete_jfs(urma_jfs_t *jfs)
{
    if (jfs == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfs);

    urma_status_t ret = ops->delete_jfs(jfs);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfs.\n");
        return ret;
    }

    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

int urma_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr)
{
    if (jfs == NULL || cr == NULL || cr_cnt <= 0 || (uint32_t)cr_cnt > jfs->jfs_cfg.depth) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return (int)(-URMA_EINVAL);
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, flush_jfs);

    return ops->flush_jfs(jfs, cr_cnt, cr);
}

urma_jfr_t *urma_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *jfr_cfg)
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

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jfr_t *jfr = ops->create_jfr(ctx, jfr_cfg);
    if (jfr == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return jfr;
}

urma_status_t urma_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr)
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

urma_status_t urma_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr)
{
    if (jfr == NULL || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfr->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, query_jfr);

    return ops->query_jfr(jfr, cfg, attr);
}

urma_status_t urma_delete_jfr(urma_jfr_t *jfr)
{
    if (jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfr->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfr);
    urma_status_t status = ops->delete_jfr(jfr);
    if (status != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfr.\n");
        return status;
    }

    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value)
{
    if (ctx == NULL || token_value == NULL || rjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jfr);

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjfr = ops->import_jfr(ctx, rjfr, token_value);
    if (tjfr == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return tjfr;
}

urma_status_t urma_unimport_jfr(urma_target_jetty_t *target_jfr)
{
    if (target_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = target_jfr->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_jfr);
    urma_status_t status = ops->unimport_jfr(target_jfr);
    if (status != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport jfr.\n");
        return status;
    }
    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

urma_jfce_t *urma_create_jfce(urma_context_t *ctx)
{
    urma_ops_t *ops;

    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfce);

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jfce_t *jfce = ops->create_jfce(ctx);
    if (jfce == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    atomic_init(&jfce->ref.atomic_cnt, 1);
    return jfce;
}

urma_status_t urma_delete_jfce(urma_jfce_t *jfce)
{
    if (jfce == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    } else if (atomic_load(&jfce->ref.atomic_cnt) > 1) {
        URMA_LOG_ERR("Jfce is still used by at least one jfc, refcnt:%u.\n",
            (uint32_t)atomic_load(&jfce->ref.atomic_cnt));
        return URMA_FAIL;
    }
    urma_context_t *urma_ctx = jfce->urma_ctx;
    urma_ops_t *ops;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfce);

    urma_status_t ret = ops->delete_jfce(jfce);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfce, ret: %d\n", (int)ret);
        return ret;
    }

    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

static int urma_create_jetty_check_trans_mode(urma_jetty_cfg_t *jetty_cfg)
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

static int urma_create_jetty_check_dev_cap(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
    urma_jfs_cfg_t *jfs_cfg = jetty_cfg->jfs_cfg;
    urma_jfr_cfg_t *jfr_cfg =
        jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR ? jetty_cfg->jfr_cfg : &jetty_cfg->shared.jfr->jfr_cfg;

    if (jetty_cfg->jetty_grp != NULL) {
        (void)pthread_mutex_lock(&jetty_cfg->jetty_grp->list_mutex);
        if (jetty_cfg->jetty_grp->jetty_cnt >= cap->max_jetty_in_jetty_grp) {
            (void)pthread_mutex_unlock(&jetty_cfg->jetty_grp->list_mutex);
            URMA_LOG_ERR("jetty_grp jetty cnt:%u, max_jetty in grp:%u\n", jetty_cfg->jetty_grp->jetty_cnt,
                cap->max_jetty_in_jetty_grp);
            return -1;
        }
        (void)pthread_mutex_unlock(&jetty_cfg->jetty_grp->list_mutex);
    }
    if ((jfs_cfg->depth == 0 || jfs_cfg->depth > cap->max_jfs_depth) ||
        (jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > cap->max_jfs_inline_len) ||
        (jfr_cfg->depth == 0 || jfr_cfg->depth > cap->max_jfr_depth) ||
        (jfs_cfg->max_sge > cap->max_jfs_sge || jfs_cfg->max_rsge > cap->max_jfs_rsge || \
        jfr_cfg->max_sge > cap->max_jfr_sge)) {
        URMA_LOG_ERR("jetty cfg out of range, jfs_depth:%u, max_jfs_depth: %u, " \
            "inline_data:%u, max_jfs_inline_len: %u, jfr_depth:%u, max_jfr_depth: %u, " \
            "jfs_sge:%hhu, max_jfs_sge:%u, jfs_rsge:%hhu, max_jfs_rsge:%u, jfr_sge:%hhu, max_jfr_sge:%u.\n",
            jfs_cfg->depth, cap->max_jfs_depth, jfs_cfg->max_inline_data, cap->max_jfs_inline_len,
            jfr_cfg->depth, cap->max_jfr_depth, jfs_cfg->max_sge, cap->max_jfs_sge,
            jfs_cfg->max_rsge, cap->max_jfs_rsge, jfr_cfg->max_sge, cap->max_jfr_sge);
        return -1;
    }
    return 0;
}


static int urma_check_jetty_cfg_with_jetty_grp(urma_jetty_cfg_t *cfg)
{
    if (cfg->jetty_grp == NULL) {
        return 0;
    }

    if (cfg->flag.bs.share_jfr == 1) {
        if (cfg->jetty_grp->cfg.token_value.token != cfg->shared.jfr->jfr_cfg.token_value.token ||
            cfg->shared.jfr->jfr_cfg.trans_mode != URMA_TM_RM) {
            return -1;
        }
    } else {
        if (cfg->jetty_grp->cfg.token_value.token != cfg->jfr_cfg->token_value.token ||
            cfg->jfr_cfg->trans_mode != URMA_TM_RM) {
            return -1;
        }
    }

    return 0;
}

static int urma_add_jetty_to_jetty_grp(urma_jetty_t *jetty, urma_jetty_grp_t *jetty_grp)
{
    uint32_t i;

    urma_device_cap_t *cap = &jetty->urma_ctx->dev->sysfs_dev->dev_attr.dev_cap;
    (void)pthread_mutex_lock(&jetty_grp->list_mutex);
    for (i = 0; i < cap->max_jetty_in_jetty_grp; i++) {
        if (jetty_grp->jetty_list[i] == NULL) {
            jetty_grp->jetty_list[i] = jetty;
            jetty_grp->jetty_cnt++;
            (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
    URMA_LOG_ERR("failed to add jetty to jetty_grp.\n");
    return -1;
}

static int urma_delete_jetty_to_jetty_grp(urma_jetty_t *jetty, urma_jetty_grp_t *jetty_grp)
{
    uint32_t i;

    if (jetty == NULL || jetty_grp == NULL) {
        return 0;
    }

    urma_device_cap_t *cap = &jetty->urma_ctx->dev->sysfs_dev->dev_attr.dev_cap;
    (void)pthread_mutex_lock(&jetty_grp->list_mutex);
    for (i = 0; i < cap->max_jetty_in_jetty_grp; i++) {
        if (jetty_grp->jetty_list[i] == jetty) {
            jetty_grp->jetty_list[i] = NULL;
            jetty_grp->jetty_cnt--;
            (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
    URMA_LOG_ERR("failed to delete jetty to jetty_grp.\n");
    return -1;
}

static int urma_create_jetty_check_jfc(urma_jetty_cfg_t *jetty_cfg)
{
    if (jetty_cfg->jfs_cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter, jfc is NULL in jfs_cfg.\n");
        return -1;
    }
    if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR &&
        (jetty_cfg->jfr_cfg == NULL || jetty_cfg->jfr_cfg->jfc == NULL)) {
        URMA_LOG_ERR("Invalid parameter, jfr cfg is null or jfc is NULL with non shared jfr flag.\n");
        return -1;
    } else if (jetty_cfg->flag.bs.share_jfr == URMA_SHARE_JFR && (jetty_cfg->shared.jfr == NULL ||
        jetty_cfg->shared.jfr->jfr_cfg.jfc == NULL)) {
        URMA_LOG_ERR("Invalid parameter, jfr is null or jfc is NULL with shared jfr flag.\n");
        return -1;
    }
    return 0;
}

urma_jetty_t *urma_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    if (ctx == NULL || jetty_cfg == NULL || jetty_cfg->jfs_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_create_jetty_check_jfc(jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_create_jetty_check_trans_mode(jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (urma_check_jetty_cfg_with_jetty_grp(jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jetty);

    if (urma_create_jetty_check_dev_cap(ctx, jetty_cfg) != 0) {
        return NULL;
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jetty_t *jetty = ops->create_jetty(ctx, jetty_cfg);
    if (jetty == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
        URMA_LOG_ERR("create_jetty failed.\n");
        return NULL;
    }

    if (jetty_cfg->jetty_grp != NULL && urma_add_jetty_to_jetty_grp(jetty, jetty_cfg->jetty_grp) != 0) {
        ops->delete_jetty(jetty);
        return NULL;
    }

    return jetty;
}

urma_status_t urma_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr)
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

urma_status_t urma_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr)
{
    if (jetty == NULL || cfg == NULL || cfg->jfs_cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, query_jetty);

    return ops->query_jetty(jetty, cfg, attr);
}

urma_status_t urma_delete_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jetty);

    if (jetty->jetty_cfg.jetty_grp != NULL &&
        urma_delete_jetty_to_jetty_grp(jetty, jetty->jetty_cfg.jetty_grp) != 0) {
        return URMA_FAIL;
    }

    urma_status_t ret = ops->delete_jetty(jetty);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    } else {
        if (jetty->jetty_cfg.jetty_grp != NULL) {
            (void)urma_add_jetty_to_jetty_grp(jetty, jetty->jetty_cfg.jetty_grp);
        }
    }
    return ret;
}

int urma_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr)
{
    if (jetty == NULL || cr == NULL || cr_cnt <= 0 || (uint32_t)cr_cnt > jetty->jetty_cfg.jfs_cfg->depth) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return (int)(-URMA_EINVAL);
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, flush_jetty);

    return ops->flush_jetty(jetty, cr_cnt, cr);
}

urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
    urma_token_t *token_value)
{
    if (ctx == NULL || rjetty == NULL || token_value == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    urma_ops_t *ops = NULL;
    urma_target_jetty_t *tjetty = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jetty);
    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);

    tjetty = ops->import_jetty(ctx, rjetty, token_value);
    if (tjetty == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return tjetty;
}

urma_status_t urma_unimport_jetty(urma_target_jetty_t *tjetty)
{
    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = tjetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_jetty);
    urma_status_t status = ops->unimport_jetty(tjetty);
    if (status != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport jetty.\n");
        return status;
    }
    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
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

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, bind_jetty);
    return ops->bind_jetty(jetty, tjetty);
}

urma_status_t urma_unbind_jetty(urma_jetty_t *jetty)
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

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unbind_jetty);
    return ops->unbind_jetty(jetty);
}

urma_status_t urma_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL || (jetty->jetty_cfg.jfs_cfg != NULL &&
        jetty->jetty_cfg.jfs_cfg->trans_mode != URMA_TM_RM) || tjetty->trans_mode != URMA_TM_RM) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx);

    if (urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        return URMA_SUCCESS;
    }

    urma_ops_t *ops = urma_ctx->ops;
    if (ops == NULL || ops->advise_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return ops->advise_jetty(jetty, tjetty);
}

urma_status_t urma_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx);

    if (urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        return URMA_SUCCESS;
    }

    urma_ops_t *ops = urma_ctx->ops;
    if (ops == NULL || ops->unadvise_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return ops->unadvise_jetty(jetty, tjetty);
}

urma_jetty_grp_t *urma_create_jetty_grp(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg)
{
    if (ctx == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jetty_grp);

    urma_jetty_grp_t *jetty_grp = ops->create_jetty_grp(ctx, cfg);
    if (jetty_grp == NULL) {
        URMA_LOG_ERR("create_jetty_grp failed.\n");
        return NULL;
    }

    urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
    jetty_grp->jetty_list = calloc(1, sizeof(urma_jetty_t *) * cap->max_jetty_in_jetty_grp);
    if (jetty_grp->jetty_list == NULL) {
        if (ops->delete_jetty_grp == NULL || ops->delete_jetty_grp(jetty_grp) != 0) {
            URMA_LOG_ERR("delete_jetty_grp failed.\n");
            return NULL;
        }
        URMA_LOG_ERR("alloc jetty_list failed.\n");
        return NULL;
    }
    jetty_grp->jetty_cnt = 0;
    (void)pthread_mutex_init(&jetty_grp->list_mutex, NULL);

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);

    return jetty_grp;
}

urma_status_t urma_delete_jetty_grp(urma_jetty_grp_t *jetty_grp)
{
    if (jetty_grp == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty_grp->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jetty_grp);

    (void)pthread_mutex_lock(&jetty_grp->list_mutex);
    if (jetty_grp->jetty_list == NULL) {
        (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
        URMA_LOG_ERR("Invalid parameter: jetty_list\n");
        return URMA_EINVAL;
    }

    if (jetty_grp->jetty_cnt > 0) {
        (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
        URMA_LOG_ERR("jetty grp in use, jetty_cnt:%u.\n", jetty_grp->jetty_cnt);
        return URMA_ENOPERM;
    }
    free(jetty_grp->jetty_list);
    jetty_grp->jetty_list = NULL;
    (void)pthread_mutex_unlock(&jetty_grp->list_mutex);
    (void)pthread_mutex_destroy(&jetty_grp->list_mutex);

    urma_status_t ret = ops->delete_jetty_grp(jetty_grp);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }
    return ret;
}

urma_target_seg_t *urma_import_seg(urma_context_t *ctx, urma_seg_t *seg,
    urma_token_t *token_value,  uint64_t addr, urma_import_seg_flag_t flag)
{
    if (ctx == NULL || seg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (seg->attr.bs.token_policy != URMA_TOKEN_NONE && token_value == NULL) {
        URMA_LOG_ERR("Key must be set when token_policy is not URMA_TOKEN_NONE.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_target_seg_t *tseg = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_seg);
    tseg = ops->import_seg(ctx, seg, token_value, addr, flag);
    if (tseg != NULL) {
        atomic_fetch_add(&tseg->urma_ctx->ref.atomic_cnt, 1);
    }
    return tseg;
}

urma_status_t urma_unimport_seg(urma_target_seg_t *tseg)
{
    if (tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = tseg->urma_ctx;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_seg);

    urma_status_t ret = ops->unimport_seg(tseg);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }
    return ret;
}

urma_token_id_t *urma_alloc_token_id(urma_context_t *ctx)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_token_id_t *token_id = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, alloc_token_id);
    token_id = ops->alloc_token_id(ctx);
    if (token_id != NULL) {
        atomic_fetch_add(&token_id->urma_ctx->ref.atomic_cnt, 1);
    }
    return token_id;
}

urma_status_t urma_free_token_id(urma_token_id_t *token_id)
{
    if (token_id == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = token_id->urma_ctx;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, free_token_id);

    urma_status_t ret = ops->free_token_id(token_id);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }
    return ret;
}

urma_target_seg_t *urma_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg)
{
    if (ctx == NULL || seg_cfg == NULL || seg_cfg->va == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    if (seg_cfg->flag.bs.token_policy != URMA_TOKEN_NONE && seg_cfg->token_value == NULL) {
        URMA_LOG_ERR("Key must be set when token_policy is not URMA_TOKEN_NONE.\n");
        return NULL;
    }

    if (ctx->dev->type == URMA_TRANSPORT_UB &&
        ((seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_VALID && seg_cfg->token_id == NULL) ||
        (seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID && seg_cfg->token_id != NULL))) {
        URMA_LOG_ERR("token_id must set when token_id_valid is true, or must NULL when token_id_valid is false.\n");
        return NULL;
    }

    if ((seg_cfg->flag.bs.access & (URMA_ACCESS_REMOTE_WRITE | URMA_ACCESS_REMOTE_ATOMIC)) &&
        !(seg_cfg->flag.bs.access & URMA_ACCESS_LOCAL_WRITE)) {
        URMA_LOG_ERR("Local write must be set when either remote write or remote atomic is declared.\n");
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_target_seg_t *seg = NULL;

    urma_seg_cfg_t tmp_cfg = *seg_cfg;      // The const variable cannot be directly modified.
    if (seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID && ctx->dev->type == URMA_TRANSPORT_UB) {
        tmp_cfg.token_id = urma_alloc_token_id(ctx);
        if (tmp_cfg.token_id == NULL) {
            URMA_LOG_ERR("alloc token id failed.\n");
            return NULL;
        }
        tmp_cfg.flag.bs.token_id_valid = URMA_TOKEN_ID_VALID;     // If not set, ubcore verification fails.
    }

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, register_seg);
    seg = ops->register_seg(ctx, &tmp_cfg);
    if (seg == NULL) {
        if (seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID && ctx->dev->type == URMA_TRANSPORT_UB) {
            (void)urma_free_token_id(tmp_cfg.token_id);
        }
        URMA_LOG_ERR("register seg failed.\n");
        return NULL;
    }
    seg->seg.attr.bs.user_token_id = seg_cfg->flag.bs.token_id_valid;
    atomic_fetch_add(&seg->urma_ctx->ref.atomic_cnt, 1);

    return seg;
}

urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg)
{
    urma_status_t ret;
    if (target_seg == NULL || target_seg->urma_ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_token_id_t *token_id = target_seg->token_id;
    bool free_token_id = false;
    if (target_seg->seg.attr.bs.user_token_id == URMA_TOKEN_ID_INVALID &&
        target_seg->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        free_token_id = true;
    }

    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = target_seg->urma_ctx;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unregister_seg);

    ret = ops->unregister_seg(target_seg);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }

    if (free_token_id == true) {
        (void)urma_free_token_id(token_id);
    }

    return ret;
}

urma_status_t urma_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM ||
        tjfr->trans_mode != URMA_TM_RM)) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx);

    if (urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        return URMA_SUCCESS;
    }

    urma_ops_t *ops = urma_ctx->ops;
    if (ops == NULL || ops->advise_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return ops->advise_jfr(jfs, tjfr);
}

urma_status_t urma_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || tjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx);

    if (urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        return URMA_SUCCESS;
    }

    urma_ops_t *ops = urma_ctx->ops;
    if (ops == NULL || ops->unadvise_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return ops->unadvise_jfr(jfs, tjfr);
}

urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, urma_target_jetty_t *tjfr,
    urma_advise_async_cb_func cb_fun, void *cb_arg)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM ||
        tjfr->trans_mode != URMA_TM_RM) || cb_fun == NULL || cb_arg == NULL ||
        jfs->urma_ctx != tjfr->urma_ctx) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jfs->urma_ctx;
    URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx);

    if (urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        return URMA_SUCCESS;
    }

    urma_ops_t *ops = urma_ctx->ops;
    if (ops == NULL || ops->advise_jfr_async == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return ops->advise_jfr_async(jfs, tjfr, cb_fun, cb_arg);
}

urma_status_t urma_get_async_event(urma_context_t *ctx, urma_async_event_t *event)
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

urma_status_t urma_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    if ((ctx == NULL) || (in == NULL) || (out == NULL)) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, user_ctl);

    if (in->opcode == URMA_USER_CTL_IGNORE_JETTY_IN_CR &&
        strcmp(ops->name, "IB_OPS") != 0) {
        URMA_LOG_WARN("Only provider_ib can configure URMA_USER_CTL_IGNORE_JETTY_IN_CR.\n");
        return URMA_SUCCESS;
    }
    if ((in->opcode == URMA_USER_CTL_IP_NON_BLOCK_SEND || in->opcode == URMA_USER_CTL_IP_STOP_RECV) &&
        ctx->dev->type != URMA_TRANSPORT_IP) {
        URMA_LOG_WARN("Only in IP mode can configure opcode: %d.\n", (int)in->opcode);
        return URMA_SUCCESS;
    }

    int ret = ops->user_ctl(ctx, in, out);
    if ((urma_status_t)ret != URMA_SUCCESS && (urma_status_t)ret != URMA_ENOPERM) {
        URMA_LOG_ERR("Failed to excecute user_ctl, ret: %d.\n", ret);
        return URMA_FAIL;
    }
    return (urma_status_t)ret;
}

int urma_init_jetty_cfg(urma_jetty_cfg_t *p, urma_jetty_cfg_t *cfg)
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
