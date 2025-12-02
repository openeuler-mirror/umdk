/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: liburma control path API file
 * Author: Ouyang Changchun, Qian Guoxin
 * Create: 2021-08-11
 * Note:
 * History: 2021-08-11
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/eventfd.h>

#include "ub_list.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_provider.h"
#include "urma_types.h"

#define URMA_CHECK_CTX_INVALID_RETURN_STATUS(urma_ctx)                                                                 \
    do {                                                                                                               \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL)) {               \
            URMA_LOG_ERR("Invalid parameter.\n");                                                                      \
            return URMA_EINVAL;                                                                                        \
        }                                                                                                              \
    } while (0)

#define URMA_CHECK_OP_INVALID_RETURN_POINTER(urma_ctx, ops, op_name)                                                   \
    do {                                                                                                               \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||               \
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) {                                         \
            errno = EINVAL;                                                                                            \
            URMA_LOG_ERR("Invalid parameter.\n");                                                                      \
            return NULL;                                                                                               \
        }                                                                                                              \
    } while (0)

#define URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, op_name)                                                    \
    do {                                                                                                               \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||               \
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) {                                         \
            URMA_LOG_ERR("Invalid parameter.\n");                                                                      \
            return URMA_EINVAL;                                                                                        \
        }                                                                                                              \
    } while (0)

#define URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, op_name)                                                \
    do {                                                                                                               \
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||               \
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->op_name == NULL)) {                                         \
            URMA_LOG_ERR("Invalid parameter.\n");                                                                      \
            return -URMA_EINVAL;                                                                                       \
        }                                                                                                              \
    } while (0)

typedef struct urma_notifier_incomplete_tjetty {
    struct ub_list node;
    urma_target_jetty_t *tjetty;
} urma_notifier_incomplete_tjetty_t;

typedef struct urma_notifier_incomplete_tjetty_list {
    pthread_spinlock_t lock;
    struct ub_list list;
} urma_notifier_incomplete_tjetty_list_t;

static inline bool urma_check_trans_mode_valid(urma_transport_mode_t trans_mode)
{
    return trans_mode == URMA_TM_RM || trans_mode == URMA_TM_RC || trans_mode == URMA_TM_UM;
}

urma_jfc_t *urma_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg)
{
    if (ctx == NULL || jfc_cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfc);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfc_cfg->depth == 0 || jfc_cfg->depth > attr->dev_cap.max_jfc_depth) {
        URMA_LOG_ERR("jfc cfg depth of range, depth: %u, max_depth: %u.\n", jfc_cfg->depth,
                     attr->dev_cap.max_jfc_depth);
        errno = EINVAL;
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

urma_status_t urma_delete_jfc_batch(urma_jfc_t **jfc_arr, int jfc_num, urma_jfc_t **bad_jfc)
{
    urma_jfc_t *jfc = NULL;
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = NULL;
    urma_context_t **urma_ctx_arr = NULL;
    urma_jfce_t *jfce = NULL;
    urma_jfce_t **jfce_arr = NULL;
    urma_status_t ret;

    if (jfc_arr == NULL || jfc_num <= 0 || bad_jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ctx_arr = calloc(jfc_num, sizeof(urma_context_t *));
    if (urma_ctx_arr == NULL) {
        URMA_LOG_ERR("Failed to alloc memory.\n");
        *bad_jfc = jfc_arr[0];
        return URMA_ENOMEM;
    }
    jfce_arr = calloc(jfc_num, sizeof(urma_jfce_t *));
    if (jfce_arr == NULL) {
        URMA_LOG_ERR("Failed to alloc memory.\n");
        ret = URMA_ENOMEM;
        *bad_jfc = jfc_arr[0];
        goto free_urma_ctx_arr;
    }

    for (int i = 0; i < jfc_num; ++i) {
        jfc = jfc_arr[i];
        if (jfc == NULL) {
            URMA_LOG_ERR("Invalid parameter, %d jfc in the array is NULL.\n", i);
            *bad_jfc = jfc_arr[0];
            ret = URMA_EINVAL;
            goto free_jfce_arr;
        }

        urma_ctx = jfc->urma_ctx;
        urma_ctx_arr[i] = urma_ctx;
        jfce_arr[i] = jfc->jfc_cfg.jfce;
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->delete_jfc_batch == NULL)) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfc = jfc_arr[0];
            ret = URMA_EINVAL;
            goto free_jfce_arr;
        }
    }

    ret = ops->delete_jfc_batch(jfc_arr, jfc_num, bad_jfc);

    for (int i = 0; i < jfc_num; ++i) {
        jfce = jfce_arr[i];
        urma_ctx = urma_ctx_arr[i];
        if (ret == URMA_SUCCESS && jfce != NULL) {
            atomic_fetch_sub(&jfce->ref.atomic_cnt, 1);
        }
        if (ret == URMA_SUCCESS) {
            atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
        }
    }

free_jfce_arr:
    free(jfce_arr);
free_urma_ctx_arr:
    free(urma_ctx_arr);
    return ret;
}

urma_jfs_t *urma_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *jfs_cfg)
{
    if (ctx == NULL || jfs_cfg == NULL || jfs_cfg->jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (urma_check_trans_mode_valid(jfs_cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jfs_cfg->trans_mode);
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfs);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if ((jfs_cfg->depth == 0 || jfs_cfg->depth > attr->dev_cap.max_jfs_depth) ||
        (jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > attr->dev_cap.max_jfs_inline_len) ||
        (jfs_cfg->max_sge > attr->dev_cap.max_jfs_sge) || (jfs_cfg->max_rsge > attr->dev_cap.max_jfs_rsge)) {
        URMA_LOG_ERR("jfs cfg out of range, depth:%u, max_depth:%u, inline_data:%u, max_inline_len:%u, "
                     "sge:%hhu, max_sge:%u, rsge:%hhu, max_rsge:%u.\n",
                     jfs_cfg->depth, attr->dev_cap.max_jfs_depth, jfs_cfg->max_inline_data,
                     attr->dev_cap.max_jfs_inline_len, jfs_cfg->max_sge, attr->dev_cap.max_jfs_sge, jfs_cfg->max_rsge,
                     attr->dev_cap.max_jfs_rsge);
        errno = EINVAL;
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

urma_status_t urma_delete_jfs_batch(urma_jfs_t **jfs_arr, int jfs_num, urma_jfs_t **bad_jfs)
{
    urma_jfs_t *jfs = NULL;
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = NULL;
    urma_context_t **urma_ctx_arr = NULL;
    urma_status_t ret;

    if (jfs_arr == NULL || jfs_num <= 0 || bad_jfs == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ctx_arr = calloc(jfs_num, sizeof(urma_context_t *));
    if (urma_ctx_arr == NULL) {
        URMA_LOG_ERR("Failed to alloc memory.\n");
        *bad_jfs = jfs_arr[0];
        return URMA_ENOMEM;
    }

    for (int i = 0; i < jfs_num; ++i) {
        jfs = jfs_arr[i];
        if (jfs == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d jfs in the array is NULL.\n", i);
            *bad_jfs = jfs_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }

        urma_ctx = jfs->urma_ctx;
        urma_ctx_arr[i] = urma_ctx;
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->delete_jfs_batch == NULL)) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfs = jfs_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }
    }

    ret = ops->delete_jfs_batch(jfs_arr, jfs_num, bad_jfs);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfs batch.\n");
        goto free_urma_ctx_arr;
    }

    for (int i = 0; i < jfs_num; ++i) {
        urma_ctx = urma_ctx_arr[i];
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }

free_urma_ctx_arr:
    free(urma_ctx_arr);
    return ret;
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
        errno = EINVAL;
        return NULL;
    }

    if (urma_check_trans_mode_valid(jfr_cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jfr_cfg->trans_mode);
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfr);

    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfr_cfg->depth == 0 || jfr_cfg->depth > attr->dev_cap.max_jfr_depth ||
        jfr_cfg->max_sge > attr->dev_cap.max_jfr_sge) {
        URMA_LOG_ERR("jfr cfg out of range, depth:%u, max_depth:%u, sge:%u, max_sge:%u.\n", jfr_cfg->depth,
                     attr->dev_cap.max_jfr_depth, jfr_cfg->max_sge, attr->dev_cap.max_jfr_sge);
        errno = EINVAL;
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

urma_status_t urma_delete_jfr_batch(urma_jfr_t **jfr_arr, int jfr_num, urma_jfr_t **bad_jfr)
{
    urma_jfr_t *jfr = NULL;
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = NULL;
    urma_context_t **urma_ctx_arr = NULL;
    urma_status_t ret;

    if (jfr_arr == NULL || jfr_num <= 0 || bad_jfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ctx_arr = calloc(jfr_num, sizeof(urma_context_t *));
    if (urma_ctx_arr == NULL) {
        URMA_LOG_ERR("Failed to alloc memory.\n");
        *bad_jfr = jfr_arr[0];
        return URMA_ENOMEM;
    }

    for (int i = 0; i < jfr_num; ++i) {
        jfr = jfr_arr[i];
        if (jfr == NULL) {
            URMA_LOG_ERR("Invalid parameter, index: %d jfr in the array is NULL.\n", i);
            *bad_jfr = jfr_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }

        urma_ctx = jfr->urma_ctx;
        urma_ctx_arr[i] = urma_ctx;
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->delete_jfr_batch == NULL)) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jfr = jfr_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }
    }

    ret = ops->delete_jfr_batch(jfr_arr, jfr_num, bad_jfr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfr batch.\n");
        goto free_urma_ctx_arr;
    }

    for (int i = 0; i < jfr_num; ++i) {
        urma_ctx = urma_ctx_arr[i];
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    }

free_urma_ctx_arr:
    free(urma_ctx_arr);
    return ret;
}

static inline bool urma_check_ctrlplane_compat(void *op_ptr)
{
    return (op_ptr == NULL);
}

static void urma_fill_get_tp_cfg(urma_get_tp_cfg_t *get_tp_cfg, urma_transport_mode_t trans_mode,
                                 urma_tp_type_t tp_type, urma_eid_t *local_eid, urma_eid_t *peer_eid)
{
    if (tp_type == URMA_CTP) {
        get_tp_cfg->flag.bs.ctp = 1;
    } else if (tp_type == URMA_RTP) {
        get_tp_cfg->flag.bs.rtp = 1;
    } else {
        get_tp_cfg->flag.bs.utp = 1;
    }

    get_tp_cfg->trans_mode = trans_mode;
    get_tp_cfg->local_eid = *local_eid;
    get_tp_cfg->peer_eid = *peer_eid;
}

static urma_target_jetty_t *urma_import_jfr_compat(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value)
{
    urma_ops_t *ops = ctx->ops;
    urma_transport_mode_t trans_mode = rjfr->trans_mode;
    urma_active_tp_cfg_t active_tp_cfg = {0};

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, get_tp_list);
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jfr_ex);

    if (trans_mode == URMA_TM_RM || trans_mode == URMA_TM_UM) {
        urma_get_tp_cfg_t get_tp_cfg = {0};
        urma_fill_get_tp_cfg(&get_tp_cfg, trans_mode, rjfr->tp_type, &ctx->eid, &rjfr->jfr_id.eid);
        uint32_t tp_cnt = 1;
        urma_tp_info_t tp_info = {0};
        urma_status_t status = ops->get_tp_list(ctx, &get_tp_cfg, &tp_cnt, &tp_info);
        if (status != URMA_SUCCESS || tp_cnt != 1) {
            URMA_LOG_ERR("Failed to get tp list, status: %d, tp_cnt: %u.\n", status, tp_cnt);
            errno = EIO;
            return NULL;
        }
        URMA_LOG_INFO("Get tp list, leid: " EID_FMT ", deid: " EID_FMT ".\n", EID_ARGS(get_tp_cfg.local_eid),
                      EID_ARGS(get_tp_cfg.peer_eid));

        active_tp_cfg.tp_handle = tp_info.tp_handle;
        active_tp_cfg.tp_attr.tx_psn = rand();

        /* Only exchange tp info for RM TP */
        if (trans_mode == URMA_TM_RM && rjfr->tp_type == URMA_RTP) {
            int ret = urma_cmd_exchange_tp_info(ctx, &get_tp_cfg, active_tp_cfg.tp_handle, active_tp_cfg.tp_attr.tx_psn,
                                                &active_tp_cfg.peer_tp_handle, &active_tp_cfg.tp_attr.rx_psn);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to exchange tp info.\n");
                errno = EIO;
                return NULL;
            }
            URMA_LOG_INFO("Finish to exchange tp info, local eid " EID_FMT ", peer eid " EID_FMT ".\n",
                          EID_ARGS(ctx->eid), EID_ARGS(rjfr->jfr_id.eid));
        }
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjetty = ops->import_jfr_ex(ctx, rjfr, token_value, &active_tp_cfg);
    if (tjetty == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return tjetty;
}

urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value)
{
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->sysfs_dev == NULL || ctx->ops == NULL || rjfr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (rjfr->flag.bs.token_policy != URMA_TOKEN_NONE && token_value == NULL) {
        URMA_LOG_ERR("Token value must be set when token policy is not URMA_TOKEN_NONE.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = ctx->ops;
    if (urma_check_ctrlplane_compat(ops->import_jfr)) {
        return urma_import_jfr_compat(ctx, rjfr, token_value);
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjfr = ops->import_jfr(ctx, rjfr, token_value);
    if (tjfr == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return tjfr;
}

urma_target_jetty_t *urma_import_jfr_ex(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value,
                                        urma_import_jfr_ex_cfg_t *cfg)
{
    if (ctx == NULL || token_value == NULL || rjfr == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jfr_ex);

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjfr = ops->import_jfr_ex(ctx, rjfr, token_value, cfg);
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
    urma_ops_t *ops = NULL;

    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jfce);

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_jfce_t *jfce = ops->create_jfce(ctx);
    if (jfce == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
        return NULL;
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
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jfce);

    urma_status_t ret = ops->delete_jfce(jfce);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jfce, ret: %d\n", (int)ret);
        return ret;
    }

    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

static inline int urma_check_order_type(urma_transport_mode_t trans_mode, uint32_t order_type)
{
    if ((trans_mode != URMA_TM_RC && order_type == URMA_OT) || (trans_mode != URMA_TM_RC && order_type == URMA_OL) ||
        (trans_mode != URMA_TM_RM && order_type == URMA_OI) || (trans_mode == URMA_TM_RM && order_type == URMA_NO)) {
        return -1;
    }

    return 0;
}

static int urma_create_jetty_check_trans_mode(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    if (urma_check_trans_mode_valid(jetty_cfg->jfs_cfg.trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)jetty_cfg->jfs_cfg.trans_mode);
        return -1;
    }
    if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR && ctx->dev->type == URMA_TRANSPORT_UB) {
        URMA_LOG_ERR("UB dev should use share jfr!");
        return -1;
    }

    uint32_t order_type = jetty_cfg->jfs_cfg.flag.bs.order_type;
    if (urma_check_order_type(jetty_cfg->jfs_cfg.trans_mode, order_type) != 0) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d, order_type: %u.\n", (int)jetty_cfg->jfs_cfg.trans_mode,
                     order_type);
        return -1;
    }

    if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR &&
        (jetty_cfg->jfr_cfg == NULL || urma_check_trans_mode_valid(jetty_cfg->jfr_cfg->trans_mode) != true ||
         jetty_cfg->jfs_cfg.trans_mode != jetty_cfg->jfr_cfg->trans_mode ||
         order_type != jetty_cfg->jfr_cfg->flag.bs.order_type)) {
        URMA_LOG_ERR("jfr cfg is null or trans_mode or order_type invalid with non shared jfr flag.\n");
        return -1;
    } else if (jetty_cfg->flag.bs.share_jfr == URMA_SHARE_JFR &&
               (jetty_cfg->shared.jfr == NULL ||
                jetty_cfg->jfs_cfg.trans_mode != jetty_cfg->shared.jfr->jfr_cfg.trans_mode ||
                order_type != jetty_cfg->shared.jfr->jfr_cfg.flag.bs.order_type)) {
        URMA_LOG_ERR("jfr is null or trans_mode or order_type invalid with shared jfr flag.\n");
        return -1;
    }
    return 0;
}

static int urma_create_jetty_check_dev_cap(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
    urma_jfs_cfg_t *jfs_cfg = &jetty_cfg->jfs_cfg;
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
        (jfs_cfg->max_sge > cap->max_jfs_sge || jfs_cfg->max_rsge > cap->max_jfs_rsge ||
         jfr_cfg->max_sge > cap->max_jfr_sge)) {
        URMA_LOG_ERR("jetty cfg out of range, jfs_depth:%u, max_jfs_depth: %u, "
                     "inline_data:%u, max_jfs_inline_len: %u, jfr_depth:%u, max_jfr_depth: %u, "
                     "jfs_sge:%hhu, max_jfs_sge:%u, jfs_rsge:%hhu, max_jfs_rsge:%u, jfr_sge:%hhu, max_jfr_sge:%u.\n",
                     jfs_cfg->depth, cap->max_jfs_depth, jfs_cfg->max_inline_data, cap->max_jfs_inline_len,
                     jfr_cfg->depth, cap->max_jfr_depth, jfs_cfg->max_sge, cap->max_jfs_sge, jfs_cfg->max_rsge,
                     cap->max_jfs_rsge, jfr_cfg->max_sge, cap->max_jfr_sge);
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
            cfg->jetty_grp->cfg.flag.bs.token_policy != cfg->shared.jfr->jfr_cfg.flag.bs.token_policy ||
            cfg->shared.jfr->jfr_cfg.trans_mode != URMA_TM_RM) {
            return -1;
        }
    } else {
        if (cfg->jetty_grp->cfg.token_value.token != cfg->jfr_cfg->token_value.token ||
            cfg->jetty_grp->cfg.flag.bs.token_policy != cfg->jfr_cfg->flag.bs.token_policy ||
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
    if (jetty_cfg->jfs_cfg.jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter, jfc is NULL in jfs_cfg.\n");
        return -1;
    }
    if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR &&
        (jetty_cfg->jfr_cfg == NULL || jetty_cfg->jfr_cfg->jfc == NULL)) {
        URMA_LOG_ERR("Invalid parameter, jfr cfg is null or jfc is NULL with non shared jfr flag.\n");
        return -1;
    } else if (jetty_cfg->flag.bs.share_jfr == URMA_SHARE_JFR &&
               (jetty_cfg->shared.jfr == NULL || jetty_cfg->shared.jfr->jfr_cfg.jfc == NULL)) {
        URMA_LOG_ERR("Invalid parameter, jfr is null or jfc is NULL with shared jfr flag.\n");
        return -1;
    }
    return 0;
}

urma_jetty_t *urma_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
    if (ctx == NULL || jetty_cfg == NULL || ctx->dev == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (urma_create_jetty_check_jfc(jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (urma_create_jetty_check_trans_mode(ctx, jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (urma_check_jetty_cfg_with_jetty_grp(jetty_cfg) != 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jetty);

    if (urma_create_jetty_check_dev_cap(ctx, jetty_cfg) != 0) {
        errno = EINVAL;
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
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
        errno = EPERM;
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
    if (jetty == NULL || cfg == NULL || attr == NULL) {
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

    if (jetty->jetty_cfg.jfs_cfg.trans_mode == URMA_TM_RC && jetty->remote_jetty != NULL) {
        URMA_LOG_ERR("Failed to delete jetty because it has remote jetty, try unbind first");
        return URMA_ENOPERM;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_jetty);

    if (jetty->jetty_cfg.jetty_grp != NULL && urma_delete_jetty_to_jetty_grp(jetty, jetty->jetty_cfg.jetty_grp) != 0) {
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

urma_status_t urma_delete_jetty_batch(urma_jetty_t **jetty_arr, int jetty_num, urma_jetty_t **bad_jetty)
{
    urma_jetty_t *jetty = NULL;
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = NULL;
    urma_context_t **urma_ctx_arr = NULL;
    urma_status_t ret;

    if (jetty_arr == NULL || jetty_num <= 0 || bad_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ctx_arr = calloc(jetty_num, sizeof(urma_context_t *));
    if (urma_ctx_arr == NULL) {
        URMA_LOG_ERR("Failed to alloc memory.\n");
        *bad_jetty = jetty_arr[0];
        return URMA_ENOMEM;
    }

    for (int i = 0; i < jetty_num; ++i) {
        jetty = jetty_arr[i];
        if (jetty == NULL) {
            URMA_LOG_ERR("Invalid parameter, index %d jetty in the array is NULL.\n", i);
            *bad_jetty = jetty_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }

        if (jetty->jetty_cfg.jfs_cfg.trans_mode == URMA_TM_RC && jetty->remote_jetty != NULL) {
            URMA_LOG_ERR("Failed to delete as jetty has remote jetty, try unbind, index: %d", i);
            *bad_jetty = jetty_arr[0];
            ret = URMA_ENOPERM;
            goto free_urma_ctx_arr;
        }

        urma_ctx = jetty->urma_ctx;
        urma_ctx_arr[i] = urma_ctx;
        if (((urma_ctx) == NULL) || ((urma_ctx)->dev == NULL) || ((urma_ctx)->dev->sysfs_dev == NULL) ||
            (((ops) = (urma_ctx)->ops) == NULL) || ((ops)->delete_jetty_batch == NULL)) {
            URMA_LOG_ERR("Invalid parameter, index: %d.\n", i);
            *bad_jetty = jetty_arr[0];
            ret = URMA_EINVAL;
            goto free_urma_ctx_arr;
        }

        if (jetty->jetty_cfg.jetty_grp != NULL &&
            urma_delete_jetty_to_jetty_grp(jetty, jetty->jetty_cfg.jetty_grp) != 0) {
            ret = URMA_FAIL;
            *bad_jetty = jetty_arr[0];
            goto free_urma_ctx_arr;
        }
    }

    ret = ops->delete_jetty_batch(jetty_arr, jetty_num, bad_jetty);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete jetty batch, ret: %d.\n", ret);
    }

    for (int i = 0; i < jetty_num; ++i) {
        jetty = jetty_arr[i];
        urma_ctx = urma_ctx_arr[i];
        if (ret == URMA_SUCCESS) {
            atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
            continue;
        }
        if (jetty->jetty_cfg.jetty_grp != NULL) {
            (void)urma_add_jetty_to_jetty_grp(jetty, jetty->jetty_cfg.jetty_grp);
        }
    }

free_urma_ctx_arr:
    free(urma_ctx_arr);
    return ret;
}

int urma_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr)
{
    if (jetty == NULL || cr == NULL || cr_cnt <= 0 || (uint32_t)cr_cnt > jetty->jetty_cfg.jfs_cfg.depth) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return (int)(-URMA_EINVAL);
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, flush_jetty);

    return ops->flush_jetty(jetty, cr_cnt, cr);
}

static urma_target_jetty_t *urma_import_jetty_compat(urma_context_t *ctx, urma_rjetty_t *rjetty,
                                                     urma_token_t *token_value)
{
    urma_ops_t *ops = ctx->ops;
    urma_transport_mode_t trans_mode = rjetty->trans_mode;
    urma_active_tp_cfg_t active_tp_cfg = {0};

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, get_tp_list);
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jetty_ex);

    if (trans_mode == URMA_TM_RM || trans_mode == URMA_TM_UM) {
        urma_get_tp_cfg_t get_tp_cfg = {0};
        urma_fill_get_tp_cfg(&get_tp_cfg, trans_mode, rjetty->tp_type, &ctx->eid, &rjetty->jetty_id.eid);
        uint32_t tp_cnt = 1;
        urma_tp_info_t tp_info = {0};
        urma_status_t status = ops->get_tp_list(ctx, &get_tp_cfg, &tp_cnt, &tp_info);
        if (status != URMA_SUCCESS || tp_cnt != 1) {
            URMA_LOG_ERR("Failed to get tp list, status: %d, tp_cnt: %u.\n", status, tp_cnt);
            errno = EIO;
            return NULL;
        }
        URMA_LOG_INFO("Get tp list, leid: " EID_FMT ", deid: " EID_FMT ".\n", EID_ARGS(get_tp_cfg.local_eid),
                      EID_ARGS(get_tp_cfg.peer_eid));

        active_tp_cfg.tp_handle = tp_info.tp_handle;
        active_tp_cfg.tp_attr.tx_psn = rand();

        /* Only exchange tp info for RM TP */
        if (trans_mode == URMA_TM_RM && rjetty->tp_type == URMA_RTP) {
            int ret = urma_cmd_exchange_tp_info(ctx, &get_tp_cfg, active_tp_cfg.tp_handle, active_tp_cfg.tp_attr.tx_psn,
                                                &active_tp_cfg.peer_tp_handle, &active_tp_cfg.tp_attr.rx_psn);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to exchange tp info.\n");
                errno = EIO;
                return NULL;
            }
            URMA_LOG_INFO("Finish to exchange tp info, local eid " EID_FMT ", peer eid " EID_FMT ".\n",
                          EID_ARGS(ctx->eid), EID_ARGS(rjetty->jetty_id.eid));
        }
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjetty = ops->import_jetty_ex(ctx, rjetty, token_value, &active_tp_cfg);
    if (tjetty == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
        URMA_LOG_INFO("Failed in import jetty ex.\n");
    }
    return tjetty;
}

urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value)
{
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->sysfs_dev == NULL || ctx->ops == NULL || rjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (rjetty->flag.bs.token_policy != URMA_TOKEN_NONE && token_value == NULL) {
        URMA_LOG_ERR("Token value must be set when token policy is not URMA_TOKEN_NONE.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = ctx->ops;
    if (urma_check_ctrlplane_compat(ops->import_jetty)) {
        return urma_import_jetty_compat(ctx, rjetty, token_value);
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjetty = ops->import_jetty(ctx, rjetty, token_value);
    if (tjetty == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    return tjetty;
}

urma_target_jetty_t *urma_import_jetty_ex(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value,
                                          urma_import_jetty_ex_cfg_t *cfg)
{
    if (ctx == NULL || rjetty == NULL || token_value == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }
    urma_ops_t *ops = NULL;
    urma_target_jetty_t *tjetty = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, import_jetty_ex);
    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);

    tjetty = ops->import_jetty_ex(ctx, rjetty, token_value, cfg);
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

static urma_status_t urma_bind_jetty_compat(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    urma_context_t *ctx = jetty->urma_ctx;
    urma_ops_t *ops = ctx->ops;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, get_tp_list);
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, bind_jetty_ex);

    urma_get_tp_cfg_t get_tp_cfg = {0};
    urma_fill_get_tp_cfg(&get_tp_cfg, tjetty->trans_mode, tjetty->tp_type, &jetty->jetty_id.eid, &tjetty->id.eid);
    uint32_t tp_cnt = 1;
    urma_tp_info_t tp_info = {0};
    urma_status_t status = ops->get_tp_list(ctx, &get_tp_cfg, &tp_cnt, &tp_info);
    if (status != URMA_SUCCESS || tp_cnt != 1) {
        URMA_LOG_ERR("Failed to get tp list, status: %d, tp_cnt: %u.\n", status, tp_cnt);
        errno = EIO;
        return URMA_FAIL;
    }
    URMA_LOG_INFO("Get tp list, leid: " EID_FMT ", deid: " EID_FMT ".\n", EID_ARGS(get_tp_cfg.local_eid),
                  EID_ARGS(get_tp_cfg.peer_eid));

    urma_active_tp_cfg_t active_tp_cfg = {
        .tp_handle = tp_info.tp_handle,
        .tp_attr.tx_psn = rand(),
    };
    /* Only exchange tp info for RC TP */
    if (tjetty->tp_type == URMA_RTP) {
        int ret = urma_cmd_exchange_tp_info(ctx, &get_tp_cfg, active_tp_cfg.tp_handle, active_tp_cfg.tp_attr.tx_psn,
                                            &active_tp_cfg.peer_tp_handle, &active_tp_cfg.tp_attr.rx_psn);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to exchange tp info.\n");
            return URMA_FAIL;
        }
        URMA_LOG_INFO("Finish to exchange tp info, local eid " EID_FMT ", peer eid " EID_FMT ".\n",
                      EID_ARGS(jetty->jetty_id.eid), EID_ARGS(tjetty->id.eid));
    }

    return ops->bind_jetty_ex(jetty, tjetty, &active_tp_cfg);
}

urma_status_t urma_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *ctx = jetty->urma_ctx;
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->sysfs_dev == NULL || ctx->ops == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RC || tjetty->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%d of mode:%d with remote jetty:%d of mode:%d.\n",
                     jetty->jetty_id.id, jetty->jetty_cfg.jfs_cfg.trans_mode, tjetty->id.id, tjetty->trans_mode);
        return URMA_ENOPERM;
    }

    uint32_t order_type = jetty->jetty_cfg.jfs_cfg.flag.bs.order_type;
    uint32_t remote_order_type = tjetty->flag.bs.order_type;
    if (remote_order_type != order_type) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%u, with remote jetty:%u.\n", jetty->jetty_id.id, tjetty->id.id);
        return URMA_ENOPERM;
    }

    urma_ops_t *ops = ctx->ops;
    if (urma_check_ctrlplane_compat(ops->bind_jetty)) {
        return urma_bind_jetty_compat(jetty, tjetty);
    }

    return ops->bind_jetty(jetty, tjetty);
}

urma_status_t urma_bind_jetty_ex(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_bind_jetty_ex_cfg_t *cfg)
{
    if (jetty == NULL || tjetty == NULL || cfg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RC || tjetty->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%d of mode:%d with remote jetty:%d of mode:%d.\n",
                     jetty->jetty_id.id, jetty->jetty_cfg.jfs_cfg.trans_mode, tjetty->id.id, tjetty->trans_mode);
        return URMA_ENOPERM;
    }

    uint32_t order_type = jetty->jetty_cfg.jfs_cfg.flag.bs.order_type;
    uint32_t remote_order_type = tjetty->flag.bs.order_type;
    if (remote_order_type != order_type) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%u, with remote jetty:%u.\n", jetty->jetty_id.id, tjetty->id.id);
        return URMA_ENOPERM;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, bind_jetty_ex);
    return ops->bind_jetty_ex(jetty, tjetty, cfg);
}

urma_status_t urma_unbind_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to call unbind as the tp mode of jetty :%d is:%d.\n", jetty->jetty_id.id,
                     jetty->jetty_cfg.jfs_cfg.trans_mode);
        return URMA_ENOPERM;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unbind_jetty);
    return ops->unbind_jetty(jetty);
}

urma_status_t urma_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    if (jetty == NULL || tjetty == NULL || tjetty->trans_mode != URMA_TM_RM ||
        jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RM) {
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

urma_target_jetty_t *urma_import_jetty_async(urma_notifier_t *notifier, const urma_rjetty_t *rjetty,
                                             const urma_token_t *token_value, uint64_t user_ctx, int timeout)
{
    if (notifier == NULL || notifier->urma_ctx == NULL || rjetty == NULL || token_value == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(notifier->urma_ctx, ops, import_jetty_async);

    urma_notifier_incomplete_tjetty_t *incomplete_tjetty = calloc(1, sizeof(urma_notifier_incomplete_tjetty_t));
    if (incomplete_tjetty == NULL) {
        URMA_LOG_ERR("Failed to alloc incomplete_tjetty.\n");
        errno = ENOMEM;
        return NULL;
    }

    atomic_fetch_add(&notifier->urma_ctx->ref.atomic_cnt, 1);
    urma_target_jetty_t *tjetty = ops->import_jetty_async(notifier, rjetty, token_value, user_ctx, timeout);
    if (tjetty != NULL) {
        urma_notifier_incomplete_tjetty_list_t *list = notifier->incomplete_tjetty_list;
        pthread_spin_lock(&list->lock);
        incomplete_tjetty->tjetty = tjetty;
        ub_list_push_back(&list->list, &incomplete_tjetty->node);
        pthread_spin_unlock(&list->lock);
    } else {
        atomic_fetch_sub(&notifier->urma_ctx->ref.atomic_cnt, 1);
        free(incomplete_tjetty);
    }
    return tjetty;
}

urma_status_t urma_unimport_jetty_async(urma_target_jetty_t *tjetty)
{
    if (tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_context_t *urma_ctx = tjetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unimport_jetty_async);
    urma_status_t status = ops->unimport_jetty_async(tjetty);
    if (status != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport jetty.\n");
        return status;
    }
    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

urma_status_t urma_bind_jetty_async(urma_notifier_t *notifier, urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                                    uint64_t user_ctx, int timeout)
{
    if (notifier == NULL || jetty == NULL || tjetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RC || tjetty->trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%d of mode:%d with remote jetty:%d of mode:%d.\n",
                     jetty->jetty_id.id, jetty->jetty_cfg.jfs_cfg.trans_mode, tjetty->id.id, tjetty->trans_mode);
        return URMA_ENOPERM;
    }

    uint32_t order_type = jetty->jetty_cfg.jfs_cfg.flag.bs.order_type;
    uint32_t remote_order_type = tjetty->flag.bs.order_type;
    if (remote_order_type != order_type) {
        URMA_LOG_ERR("Not allowed to bind local jetty:%u, with remote jetty:%u.\n", jetty->jetty_id.id, tjetty->id.id);
        return URMA_ENOPERM;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, bind_jetty_async);
    return ops->bind_jetty_async(notifier, jetty, tjetty, user_ctx, timeout);
}

urma_status_t urma_unbind_jetty_async(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->remote_jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (jetty->jetty_cfg.jfs_cfg.trans_mode != URMA_TM_RC) {
        URMA_LOG_ERR("Not allowed to call unbind as the tp mode of jetty :%u is:%d.\n", jetty->jetty_id.id,
                     jetty->jetty_cfg.jfs_cfg.trans_mode);
        return URMA_ENOPERM;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unbind_jetty_async);
    return ops->unbind_jetty_async(jetty);
}

urma_notifier_t *urma_create_notifier(urma_context_t *ctx)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_notifier);

    urma_notifier_incomplete_tjetty_list_t *list = calloc(1, sizeof(urma_notifier_incomplete_tjetty_list_t));
    if (list == NULL) {
        URMA_LOG_ERR("Failed to alloc notifier.\n");
        errno = ENOMEM;
        return NULL;
    }

    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    urma_notifier_t *notifier = ops->create_notifier(ctx);
    if (notifier == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
        free(list);
        return NULL;
    }
    pthread_spin_init(&list->lock, PTHREAD_PROCESS_SHARED);
    ub_list_init(&list->list);
    notifier->incomplete_tjetty_list = list;
    return notifier;
}

urma_status_t urma_delete_notifier(urma_notifier_t *notifier)
{
    if (notifier == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_context_t *urma_ctx = notifier->urma_ctx;
    urma_ops_t *ops = NULL;

    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, delete_notifier);
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, ack_notify);

    urma_notifier_incomplete_tjetty_list_t *list = notifier->incomplete_tjetty_list;

    urma_status_t ret = ops->delete_notifier(notifier);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete notifier, ret: %d\n", (int)ret);
        return ret;
    }

    pthread_spin_lock(&list->lock);
    urma_notify_t notify = {
        .type = URMA_IMPORT_JETTY_NOTIFY,
        .status = URMA_ETIMEOUT,
    };
    urma_notifier_incomplete_tjetty_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE (cur, next, node, &list->list) {
        notify.tjetty = cur->tjetty;
        ops->ack_notify(1, &notify);
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
        ub_list_remove(&cur->node);
        free(cur);
    }
    pthread_spin_unlock(&list->lock);
    pthread_spin_destroy(&list->lock);
    free(list);

    atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);
    return URMA_SUCCESS;
}

int urma_wait_notify(urma_notifier_t *notifier, uint32_t cnt, urma_notify_t *notify, int timeout)
{
    if (notifier == NULL || notifier->urma_ctx == NULL || notify == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return -1;
    } else if (cnt == 0) {
        return 0;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(notifier->urma_ctx, ops, wait_notify);
    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(notifier->urma_ctx, ops, ack_notify);

    int ret = ops->wait_notify(notifier, cnt, notify, timeout);
    if (ret > 0) {
        uint32_t notify_cnt = (uint32_t)ret;

        urma_notifier_incomplete_tjetty_list_t *list = notifier->incomplete_tjetty_list;
        pthread_spin_lock(&list->lock);
        urma_notifier_incomplete_tjetty_t *cur, *next;
        UB_LIST_FOR_EACH_SAFE (cur, next, node, &list->list) {
            for (uint32_t i = 0; i < notify_cnt; i++) {
                if (notify[i].tjetty == cur->tjetty && notify[i].type == URMA_IMPORT_JETTY_NOTIFY) {
                    ub_list_remove(&cur->node);
                    free(cur);
                    break;
                }
            }
        }
        pthread_spin_unlock(&list->lock);

        ops->ack_notify(notify_cnt, notify);
        for (uint32_t i = 0; i < notify_cnt; i++) {
            if (notify[i].status != URMA_SUCCESS && notify[i].type == URMA_IMPORT_JETTY_NOTIFY) {
                atomic_fetch_sub(&notifier->urma_ctx->ref.atomic_cnt, 1);
            }
        }
    }
    return ret;
}

urma_status_t urma_ack_notify(urma_context_t *ctx, uint32_t cnt, urma_notify_t *notify)
{
    if (ctx == NULL || notify == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(ctx, ops, ack_notify);
    return URMA_SUCCESS;
}

urma_jetty_grp_t *urma_create_jetty_grp(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg)
{
    if (ctx == NULL || cfg == NULL || strnlen(cfg->name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, create_jetty_grp);
    uint32_t max_jetty_in_jetty_grp = ctx->dev->sysfs_dev->dev_attr.dev_cap.max_jetty_in_jetty_grp;
    if (max_jetty_in_jetty_grp == 0 || max_jetty_in_jetty_grp > URMA_MAX_JETTY_IN_JETTY_GRP) {
        URMA_LOG_ERR("max_jetty_in_jetty_grp %u is err.\n", max_jetty_in_jetty_grp);
        errno = EINVAL;
        return NULL;
    }

    urma_jetty_grp_t *jetty_grp = ops->create_jetty_grp(ctx, cfg);
    if (jetty_grp == NULL) {
        URMA_LOG_ERR("create_jetty_grp failed.\n");
        return NULL;
    }

    jetty_grp->jetty_list = calloc(1, sizeof(urma_jetty_t *) * max_jetty_in_jetty_grp);
    if (jetty_grp->jetty_list == NULL) {
        URMA_LOG_ERR("alloc jetty list failed.\n");
        if (ops->delete_jetty_grp == NULL || ops->delete_jetty_grp(jetty_grp) != 0) {
            URMA_LOG_ERR("delete_jetty_grp failed.\n");
        }
        errno = ENOMEM;
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
                                   urma_token_t *token_value, uint64_t addr, urma_import_seg_flag_t flag)
{
    if (ctx == NULL || seg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    if (seg->attr.bs.token_policy != URMA_TOKEN_NONE && token_value == NULL) {
        URMA_LOG_ERR("Token value must be set when token policy is not URMA_TOKEN_NONE.\n");
        errno = EINVAL;
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
        errno = EINVAL;
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

urma_token_id_t *urma_alloc_token_id_ex(urma_context_t *ctx, urma_token_id_flag_t flag)
{
    if (ctx == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_ops_t *ops = NULL;
    urma_token_id_t *token_id = NULL;

    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, alloc_token_id_ex);
    urma_device_attr_t dev_attr = ctx->dev->sysfs_dev->dev_attr;
    if (flag.bs.multi_seg == 1 && dev_attr.dev_cap.feature.bs.muti_seg_per_token_id == 0) {
        URMA_LOG_ERR("dev not support token id table mode.\n");
        return NULL;
    }

    token_id = ops->alloc_token_id_ex(ctx, flag);
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
    if (atomic_load(&token_id->ref.atomic_cnt) != 0) {
        URMA_LOG_ERR("ref:%lu, not zero\n", (uint64_t)atomic_load(&token_id->ref.atomic_cnt));
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

static bool urma_check_seg_cfg(urma_transport_type_t transport_type, urma_seg_cfg_t *seg_cfg)
{
    if (transport_type == URMA_TRANSPORT_UB &&
        ((seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_VALID && seg_cfg->token_id == NULL) ||
         (seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID && seg_cfg->token_id != NULL))) {
        URMA_LOG_ERR("token_id must set when token_id_valid is true, or must NULL when token_id_valid is false.\n");
        return false;
    }

    if ((seg_cfg->flag.bs.access & URMA_ACCESS_LOCAL_ONLY) &&
        (seg_cfg->flag.bs.access & (URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC))) {
        URMA_LOG_ERR("Local only access is not allowed to config with other accesses.\n");
        return false;
    }
    if ((seg_cfg->flag.bs.access & URMA_ACCESS_WRITE) && !(seg_cfg->flag.bs.access & URMA_ACCESS_READ)) {
        URMA_LOG_ERR("Write access should be config with read access.\n");
        return false;
    }
    if ((seg_cfg->flag.bs.access & URMA_ACCESS_ATOMIC) &&
        !((seg_cfg->flag.bs.access & URMA_ACCESS_READ) && (seg_cfg->flag.bs.access & URMA_ACCESS_WRITE))) {
        URMA_LOG_ERR("Atomic access should be config with read and write access.\n");
        return false;
    }

    return true;
}

urma_target_seg_t *urma_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg)
{
    urma_target_seg_t *seg = NULL;
    urma_ops_t *ops = NULL;
    if (ctx == NULL || seg_cfg == NULL || seg_cfg->va == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }
    URMA_CHECK_OP_INVALID_RETURN_POINTER(ctx, ops, register_seg);
    if (!urma_check_seg_cfg(ctx->dev->type, seg_cfg)) {
        errno = EINVAL;
        return NULL;
    }

    urma_seg_cfg_t tmp_cfg = *seg_cfg; // The const variable cannot be directly modified.
    if (seg_cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_INVALID && ctx->dev->type == URMA_TRANSPORT_UB) {
        tmp_cfg.token_id = urma_alloc_token_id(ctx);
        if (tmp_cfg.token_id == NULL) {
            URMA_LOG_ERR("alloc token id failed.\n");
            return NULL;
        }
        tmp_cfg.flag.bs.token_id_valid = URMA_TOKEN_ID_VALID; // If not set, ubcore verification fails.
    }

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

    if (ctx->dev->type == URMA_TRANSPORT_UB && seg->token_id != NULL) {
        atomic_fetch_add(&seg->token_id->ref.atomic_cnt, 1);
    }
    return seg;
}

urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg)
{
    urma_status_t ret;
    if (target_seg == NULL || target_seg->urma_ctx == NULL || target_seg->urma_ctx->dev == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_token_id_t *token_id = target_seg->token_id;
    urma_transport_type_t type = target_seg->urma_ctx->dev->type;
    bool free_token_id = false;
    urma_ops_t *ops = NULL;
    urma_context_t *urma_ctx = target_seg->urma_ctx;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(urma_ctx, ops, unregister_seg);
    if (target_seg->seg.attr.bs.user_token_id == URMA_TOKEN_ID_INVALID &&
        target_seg->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        free_token_id = true;
    }

    ret = ops->unregister_seg(target_seg);
    if (ret == URMA_SUCCESS) {
        atomic_fetch_sub(&urma_ctx->ref.atomic_cnt, 1);

        if (type == URMA_TRANSPORT_UB && token_id != NULL) {
            atomic_fetch_sub(&token_id->ref.atomic_cnt, 1);
        }
    }

    if (free_token_id == true) {
        (void)urma_free_token_id(token_id);
    }

    return ret;
}

urma_status_t urma_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM || tjfr->trans_mode != URMA_TM_RM)) {
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

urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, urma_advise_async_cb_func cb_fun,
                                    void *cb_arg)
{
    if (jfs == NULL || tjfr == NULL || (jfs->jfs_cfg.trans_mode != URMA_TM_RM || tjfr->trans_mode != URMA_TM_RM) ||
        cb_fun == NULL || cb_arg == NULL || jfs->urma_ctx != tjfr->urma_ctx) {
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

    int ret = ops->user_ctl(ctx, in, out);
    if ((urma_status_t)ret != URMA_SUCCESS && (urma_status_t)ret != URMA_ENOPERM) {
        URMA_LOG_ERR("Failed to excecute user_ctl, ret: %d.\n", ret);
        return URMA_FAIL;
    }
    return (urma_status_t)ret;
}

int urma_init_jetty_cfg(urma_jetty_cfg_t *p, urma_jetty_cfg_t *cfg)
{
    *p = *cfg;

    /* deep copy of jfr cfg */
    if (cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR) {
        p->jfr_cfg = calloc(1, sizeof(urma_jfr_cfg_t));
        if (p->jfr_cfg == NULL) {
            errno = ENOMEM;
            return -1;
        }
        (void)memcpy(p->jfr_cfg, cfg->jfr_cfg, sizeof(urma_jfr_cfg_t));
    }

    return 0;
}

void urma_uninit_jetty_cfg(urma_jetty_cfg_t *p)
{
    if (p->flag.bs.share_jfr == URMA_SHARE_JFR) {
        return;
    }
    free(p->jfr_cfg);
    p->jfr_cfg = NULL;
}

int urma_get_tpn(urma_jetty_t *jetty)
{
    if (jetty == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -URMA_EINVAL;
    }

    urma_context_t *urma_ctx = jetty->urma_ctx;
    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_NEG_STATUS(urma_ctx, ops, get_tpn);

    return ops->get_tpn(jetty);
}

urma_net_addr_info_t *urma_get_net_addr_list(urma_context_t *ctx, uint32_t *cnt)
{
    if (cnt == NULL || ctx == NULL || ctx->dev == NULL || ctx->dev->sysfs_dev == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }
    urma_device_cap_t *dev_cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
    uint32_t max_netaddr_cnt = dev_cap->max_netaddr_cnt;
    if (max_netaddr_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter with max_netaddr_cnt as 0.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_net_addr_info_t *net_addr_info =
        (urma_net_addr_info_t *)calloc(1, max_netaddr_cnt * sizeof(urma_net_addr_info_t));
    if (net_addr_info == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    int ret = urma_cmd_get_net_addr_list(ctx, max_netaddr_cnt, net_addr_info, cnt);
    if (ret < 0) {
        URMA_LOG_ERR("Failed to get netaddr list, ret: %d, max_netaddr_cnt: %u.\n", ret, max_netaddr_cnt);
        free(net_addr_info);
        return NULL;
    }
    return net_addr_info;
}

void urma_free_net_addr_list(urma_net_addr_info_t *net_addr_list)
{
    if (net_addr_list == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return;
    }
    free(net_addr_list);
}

int urma_modify_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg, urma_tp_attr_t *attr,
                   urma_tp_attr_mask_t mask)
{
    if (ctx == NULL || cfg == NULL || attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, modify_tp);

    return ops->modify_tp(ctx, tpn, cfg, attr, mask);
}

urma_status_t urma_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt, urma_tp_info_t *tp_list)
{
    if (ctx == NULL || cfg == NULL || tp_cnt == NULL || tp_list == NULL || *tp_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (urma_check_trans_mode_valid(cfg->trans_mode) != true) {
        URMA_LOG_ERR("Invalid parameter, trans_mode: %d.\n", (int)cfg->trans_mode);
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, get_tp_list);

    return ops->get_tp_list(ctx, cfg, tp_cnt, tp_list);
}

urma_status_t urma_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, const uint8_t tp_attr_cnt,
                               const uint32_t tp_attr_bitmap, const urma_tp_attr_value_t *tp_attr)
{
    if (ctx == NULL || tp_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, set_tp_attr);

    return ops->set_tp_attr(ctx, tp_handle, tp_attr_cnt, tp_attr_bitmap, tp_attr);
}

urma_status_t urma_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, uint8_t *tp_attr_cnt,
                               uint32_t *tp_attr_bitmap, urma_tp_attr_value_t *tp_attr)
{
    if (ctx == NULL || tp_attr_cnt == NULL || tp_attr_bitmap == NULL || tp_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_ops_t *ops = NULL;
    URMA_CHECK_OP_INVALID_RETURN_STATUS(ctx, ops, get_tp_attr);

    return ops->get_tp_attr(ctx, tp_handle, tp_attr_cnt, tp_attr_bitmap, tp_attr);
}
