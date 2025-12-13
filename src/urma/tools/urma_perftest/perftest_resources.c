/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: resource operation for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/mman.h>

#include "ub_util.h"
#include "urma_api.h"

#include "perftest_resources.h"

#define PERFTEST_DEF_ACCESS (URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC)

#define PERFTEST_DEF_UM_MAX_SGE (2)

static urma_token_t g_perftest_token = {
    .token = 0xABCDEF,
};

static void check_device_inline(perftest_config_t *cfg)
{
    uint32_t default_inline = 0;
    uint32_t expect_inline = 0;
    if (cfg->tp_type == URMA_TRANSPORT_UB) {
        if (cfg->type == PERFTEST_LAT) {
            if (cfg->api_type == PERFTEST_WRITE) {
                default_inline = PERFTEST_DEF_INLINE_LAT;
                expect_inline = default_inline;
            } else if (cfg->api_type == PERFTEST_SEND) {
                default_inline = PERFTEST_DEF_INLINE_LAT;
                expect_inline = (cfg->trans_mode == URMA_TM_RC) ? PERFTEST_INLINE_LAT_RC :
                    (cfg->trans_mode == URMA_TM_RM) ? PERFTEST_INLINE_LAT_RM : PERFTEST_INLINE_LAT_UM;
            }
        }
    }

    if (cfg->inline_size == default_inline) {
        cfg->inline_size = expect_inline;
    }
    /* inline_size check only available for latency test */
    if (cfg->type == PERFTEST_LAT && cfg->inline_size != default_inline &&
        cfg->inline_size > expect_inline) {
        (void)fprintf(stderr, "The recommended inline_size is no larger than: %u, but it is: %u, "
            "which may lead to performance reduction.\n", expect_inline, cfg->inline_size);
    }
}

static int check_share_jfr(perftest_config_t *cfg, urma_device_t *urma_dev)
{
    if (urma_dev->type == URMA_TRANSPORT_UB && cfg->share_jfr == false) {
        (void)printf("Warning: URMA_TRANSPORT_UB only support share_jfr.\n");
        cfg->share_jfr = true;
    }

    // share_jfr updated, check realted cfg
    if (cfg->share_jfr && !is_jfr_depth_valid(cfg)) {
        (void)fprintf(stderr, "Using share jfr depth should be greater than number of " \
            "cfg->jettys_pre_jfr * jfr_post_list.\n");
        return -1;
    }

    return 0;
}

static int check_dev_cap(perftest_context_t *ctx, perftest_config_t *cfg)
{
    struct urma_device *urma_dev = ctx->urma_ctx->dev;
    bool jfc_inline = (bool)ctx->dev_attr.dev_cap.feature.bs.jfc_inline;
    if (cfg->jfc_inline && (!jfc_inline)) {
        (void)printf("Warning: device NOT support jfc_inline.\n");
        cfg->jfc_inline = false;
    }
    if (check_share_jfr(cfg, urma_dev) != 0) {
        return -1;
    }

    cfg->tp_type = urma_dev->type;
    check_device_inline(cfg);

    if (cfg->sge_num > ctx->dev_attr.dev_cap.max_jfs_sge) {
        (void)printf("Error: max_jfs_sge out of range, max_jfs_sge:%u.\n", ctx->dev_attr.dev_cap.max_jfs_sge);
        return -1;
    }

    if (cfg->sge_num > ctx->dev_attr.dev_cap.max_jfr_sge) {
        (void)printf("Error: max_jfr_sge out of range, max_jfr_sge:%u.\n", ctx->dev_attr.dev_cap.max_jfr_sge);
        return -1;
    }

    if (cfg->sge_num > ctx->dev_attr.dev_cap.max_jfs_rsge) {
        (void)printf("Error: max_jfs_rsge out of range, max_jfs_rsge:%u.\n", ctx->dev_attr.dev_cap.max_jfs_rsge);
        return -1;
    }

    if (cfg->jetty_mode == PERFTEST_JETTY_DUPLEX && cfg->jettys > ctx->dev_attr.dev_cap.max_jetty) {
        (void)printf("Error: jettys: %u out of range, max_jetty: %u.\n", cfg->jettys,
            ctx->dev_attr.dev_cap.max_jetty);
        return -1;
    }

    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX && cfg->jettys > ctx->dev_attr.dev_cap.max_jfs) {
        (void)printf("Error: jettys: %u out of range, max_jfs: %u.\n", cfg->jettys,
            ctx->dev_attr.dev_cap.max_jfs);
        return -1;
    }

    if (cfg->jettys > ctx->dev_attr.dev_cap.max_jfr) {
        (void)printf("Error: jettys: %u out of range, max_jfr: %u.\n", cfg->jettys,
            ctx->dev_attr.dev_cap.max_jfr);
        return -1;
    }

    if (cfg->jfc_depth > ctx->dev_attr.dev_cap.max_jfc_depth) {
        (void)printf("Error: jfc_depth: %u out of range, max_jfc_depth: %u.\n", cfg->jfc_depth,
            ctx->dev_attr.dev_cap.max_jfc_depth);
        return -1;
    }

    if (cfg->jfs_depth > ctx->dev_attr.dev_cap.max_jfs_depth) {
        (void)printf("Error: jfs_depth: %u out of range, max_jfs_depth: %u.\n", cfg->jfs_depth,
            ctx->dev_attr.dev_cap.max_jfs_depth);
        return -1;
    }

    if (cfg->jfr_depth > ctx->dev_attr.dev_cap.max_jfr_depth) {
        (void)printf("Error: jfr_depth: %u out of range, max_jfr_depth: %u.\n", cfg->jfr_depth,
            ctx->dev_attr.dev_cap.max_jfr_depth);
        return -1;
    }

    return 0;
}

static int init_device(perftest_context_t *ctx, perftest_config_t *cfg)
{
    urma_status_t status;
    urma_init_attr_t init_attr = {
        .token = 0,
        .uasid = 0
    };

    status = urma_init(&init_attr);
    if (status != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to urma init, status:%d!\n", (int)status);
        return -1;
    }

    if (strlen(cfg->dev_name) == 0 || strnlen(cfg->dev_name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        (void)fprintf(stderr, "dev name invailed!\n");
        goto uninit;
    }

    urma_device_t *urma_dev = urma_get_device_by_name(cfg->dev_name);
    if (urma_dev == NULL) {
        (void)fprintf(stderr, "Failed to get device by name %s.\n", cfg->dev_name);
        goto uninit;
    }

    if (urma_query_device(urma_dev, &ctx->dev_attr) != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to query device, name: %s.\n", cfg->dev_name);
        goto uninit;
    }

    if (cfg->enable_user_tp == true &&
        (ctx->dev_attr.dev_cap.sub_trans_mode_cap & URMA_RC_USER_TP) == 0) {
        (void)fprintf(stderr, "The UB device does not support!\n");
        goto uninit;
    }

    ctx->urma_ctx = urma_create_context(urma_dev, cfg->eid_idx);
    if (ctx->urma_ctx == NULL) {
        (void)fprintf(stderr, "Failed to create urma instance!\n");
        goto uninit;
    }
    ctx->eid = ctx->urma_ctx->eid;

    if (cfg->enable_aggr_mode) {
        status = urma_set_context_opt( ctx->urma_ctx, URMA_OPT_AGGR_MODE, &cfg->aggr_mode, sizeof(cfg->aggr_mode));
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to set aggregation mode, status:%d!\n", (int)status);
            goto del_ctx;
        }
    }

    if (check_dev_cap(ctx, cfg) != 0) {
        goto del_ctx;
    }

    return 0;
del_ctx:
    (void)urma_delete_context(ctx->urma_ctx);
uninit:
    (void)urma_uninit();
    return -1;
}

static void uninit_device(perftest_context_t *ctx)
{
    urma_status_t status;

    status = urma_delete_context(ctx->urma_ctx);
    if (status != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to delete context, status:%d!\n", (int)status);
        return;
    }

    status = urma_uninit();
    if (status != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to uninit, status:%d!\n", (int)status);
        return;
    }
}

static int alloc_jfc(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->use_jfce == true) {
        ctx->jfce_s = calloc(1, sizeof(urma_jfce_t *) * cfg->jettys);
        if (ctx->jfce_s == NULL) {
            return -1;
        }

        ctx->jfce_r = calloc(1, sizeof(urma_jfce_t *) * cfg->jettys);
        if (ctx->jfce_r == NULL) {
            free(ctx->jfce_s);
            return -1;
        }
    }

    ctx->jfc_s = calloc(1, sizeof(urma_jfce_t *) * cfg->jettys);
    if (ctx->jfc_s == NULL) {
        goto free_jfce;
    }
    ctx->jfc_r = calloc(1, sizeof(urma_jfce_t *) * cfg->jettys);
    if (ctx->jfc_r == NULL) {
        free(ctx->jfc_s);
        goto free_jfce;
    }

    return 0;

free_jfce:
    if (cfg->use_jfce == true) {
        free(ctx->jfce_s);
        free(ctx->jfce_r);
    }
    return -1;
}

static void destroy_jfc(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    for (uint32_t i = 0; i < cfg->jettys; i++) {
        if (i > 0 && (cfg->pair_flag == false || cfg->type == PERFTEST_BW)) {
            break;
        }
        (void)urma_delete_jfc(ctx->jfc_r[i]);
        (void)urma_delete_jfc(ctx->jfc_s[i]);
        if (cfg->use_jfce == true) {
            (void)urma_delete_jfce(ctx->jfce_r[i]);
            (void)urma_delete_jfce(ctx->jfce_s[i]);
        }
    }
    free(ctx->jfc_r);
    free(ctx->jfc_s);
    ctx->jfc_r = NULL;
    ctx->jfc_s = NULL;
    if (cfg->use_jfce == true) {
        free(ctx->jfce_r);
        free(ctx->jfce_s);
        ctx->jfce_r = NULL;
        ctx->jfce_s = NULL;
    }
}

static int create_jfc(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (alloc_jfc(ctx, cfg) != 0) {
        return -ENOMEM;
    }

    urma_jfc_cfg_t jfc_cfg = {
        .depth = cfg->jfc_depth,
        .flag = {
            .bs.lock_free = cfg->lock_free ? 1 : 0,
            .bs.jfc_inline = cfg->jfc_inline ? 1 : 0,
        },
        .jfce = NULL,
        .user_ctx = (uint64_t)NULL,
    };

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        if (i > 0 && (cfg->pair_flag == false || cfg->type == PERFTEST_BW)) {
            if (cfg->use_jfce == true) {
                ctx->jfce_s[i] =  ctx->jfce_s[0];
                ctx->jfce_r[i] = ctx->jfce_r[0];
            }
            ctx->jfc_s[i] = ctx->jfc_s[0];
            ctx->jfc_r[i] = ctx->jfc_r[0];
            continue;
        }

        if (cfg->use_jfce == true) {
            ctx->jfce_s[i] = urma_create_jfce(ctx->urma_ctx);
            if (ctx->jfce_s[i] == NULL) {
                (void)fprintf(stderr, "Failed to create jfce_s!\n");
                goto delete_jfc;
            }

            ctx->jfce_r[i] = urma_create_jfce(ctx->urma_ctx);
            if (ctx->jfce_r[i] == NULL) {
                (void)fprintf(stderr, "Failed to create jfce_r!\n");
                goto delete_jfc;
            }
        }

        jfc_cfg.jfce = cfg->use_jfce == true ? ctx->jfce_s[i] : NULL;
        ctx->jfc_s[i] = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
        if (ctx->jfc_s[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfc_s, tx jfc_depth: %u.\n", cfg->jfc_depth);
            goto delete_jfc;
        }

        jfc_cfg.jfce = cfg->use_jfce == true ? ctx->jfce_r[i] : NULL;
        ctx->jfc_r[i] = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
        if (ctx->jfc_r[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfc_r, rx jfc_depth: %u.\n", cfg->jfc_depth);
            goto delete_jfc;
        }
    }
    return 0;
delete_jfc:
    destroy_jfc(ctx, cfg);
    return -1;
}

static inline void destroy_jfs(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_delete_jfs(ctx->jfs[k]);
    }

    free(ctx->jfs);
}

static int create_jfs(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    if (cfg->inline_size > ctx->dev_attr.dev_cap.max_jfs_inline_len) {
        (void)fprintf(stderr, "Failed parameter, jfs inline size %u exceeds the device max_inline_data %u\n",
            cfg->inline_size, ctx->dev_attr.dev_cap.max_jfs_inline_len);
        return -1;
    }

    urma_jfs_cfg_t jfs_cfg = {
        .depth = cfg->jfs_depth,
        .flag.bs.lock_free = cfg->lock_free ? 1 : 0,
        .trans_mode = cfg->trans_mode,
        .priority = cfg->priority, /* Highest priority */
        .max_sge = 1,
        .max_inline_data = cfg->inline_size,
        .rnr_retry = URMA_TYPICAL_RNR_RETRY,
        .err_timeout = cfg->err_timeout,
        .user_ctx = (uint64_t)NULL
    };
    if (cfg->use_bonding) {
        jfs_cfg.max_sge += 1; /* there is one more sge in bonding mode */
    }
    if (cfg->single_path) {
        jfs_cfg.flag.bs.multi_path = 0;
    } else {
        jfs_cfg.flag.bs.multi_path = 1;
    }

    ctx->jfs = calloc(1, sizeof(urma_jfs_t *) * cfg->jettys);
    if (ctx->jfs == NULL) {
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        jfs_cfg.jfc = ctx->jfc_s[i];
        ctx->jfs[i] = urma_create_jfs(ctx->urma_ctx, &jfs_cfg);
        if (ctx->jfs[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfs: %u!\n", i);
            goto delete_jfs;
        }
    }

    return 0;

delete_jfs:
    destroy_jfs(ctx, cfg->jettys);
    return -1;
}

static inline void destroy_jfr(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_delete_jfr(ctx->jfr[k]);
    }

    free(ctx->jfr);
    ctx->jfr = NULL;
}

static int create_jfr(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    urma_jfr_cfg_t jfr_cfg = {
        .depth = cfg->jfr_depth,
        .flag.bs.tag_matching = URMA_NO_TAG_MATCHING,
        .flag.bs.lock_free = cfg->lock_free ? 1 : 0,
        .trans_mode = cfg->trans_mode,
        .min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER,
        .max_sge = 1,
        .token_value = g_perftest_token,
        .id = 0,
        .user_ctx = (uint64_t)NULL
    };

    ctx->jfr = calloc(1, sizeof(urma_jfr_t *) * cfg->jettys);
    if (ctx->jfr == NULL) {
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        jfr_cfg.jfc = ctx->jfc_r[i];
        ctx->jfr[i] = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
        if (ctx->jfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfr: %u!\n", i);
            goto delete_jfr;
        }
    }

    return 0;

delete_jfr:
    destroy_jfr(ctx, cfg->jettys);
    return -1;
}

static void fill_jfs_cfg(perftest_context_t *ctx, const perftest_config_t *cfg, uint32_t jfs_max_inline_data,
    urma_jfs_cfg_t *jfs_cfg)
{
    jfs_cfg->depth = cfg->jfs_depth;
    jfs_cfg->flag.value = 0;
    jfs_cfg->flag.bs.lock_free = cfg->lock_free ? 1 : 0;
    jfs_cfg->trans_mode = cfg->trans_mode;
    jfs_cfg->priority = cfg->priority; /* Highest priority */
    jfs_cfg->max_sge = 1;
    jfs_cfg->max_rsge = 1;
    jfs_cfg->max_inline_data = jfs_max_inline_data;
    jfs_cfg->rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg->err_timeout = cfg->err_timeout;
    jfs_cfg->user_ctx = (uint64_t)NULL;
    if (cfg->sge_num != 1) {
        jfs_cfg->max_sge = cfg->sge_num;
        jfs_cfg->max_rsge = cfg->sge_num;
    }
    if (cfg->use_bonding) {
        jfs_cfg->max_sge += 1; /* there is one more sge in bonding mode */
    }
    if (cfg->single_path) {
        jfs_cfg->flag.bs.multi_path = 0;
    } else {
        jfs_cfg->flag.bs.multi_path = 1;
    }
    jfs_cfg->flag.bs.order_type = cfg->order_type;
    if (jfs_cfg->trans_mode == URMA_TM_RC &&
        (jfs_cfg->flag.bs.order_type == URMA_OT)) {
    }
}

static void fill_jfr_cfg(perftest_context_t *ctx, const perftest_config_t *cfg, urma_jfr_cfg_t *jfr_cfg)
{
    jfr_cfg->depth = cfg->jfr_depth;
    jfr_cfg->flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    jfr_cfg->flag.bs.lock_free = cfg->lock_free ? 1 : 0;
    jfr_cfg->trans_mode = cfg->trans_mode;
    jfr_cfg->flag.bs.order_type = cfg->order_type;
    jfr_cfg->min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg->max_sge = 1;
    jfr_cfg->token_value = g_perftest_token;
    jfr_cfg->id = 0;
    if (cfg->sge_num != 1) {
        jfr_cfg->max_sge = cfg->sge_num;
    }
    if (cfg->use_bonding) {
        jfr_cfg->max_sge += 1; /* there is one more sge in bonding mode */
    }
}

static void destroy_jetty(perftest_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        if (ctx->jetty[i] != NULL) {
            (void)urma_delete_jetty(ctx->jetty[i]);
        }
    }
    free(ctx->jetty);
    ctx->jetty = NULL;
}

static int create_jetty(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    uint32_t j = 0;
    uint32_t jfr_num = cfg->jettys / cfg->jettys_pre_jfr;
    urma_jetty_flag_t jetty_flag = {0};
    uint32_t jfs_max_inline_data = cfg->inline_size;
    if (jfs_max_inline_data > ctx->dev_attr.dev_cap.max_jfs_inline_len) {
        (void)fprintf(stderr, "Failed parameter, jfs_max_inline_data %u exceeds the device max_inline_data %u\n",
            jfs_max_inline_data, ctx->dev_attr.dev_cap.max_jfs_inline_len);
        return -1;
    }
    urma_jfs_cfg_t jfs_cfg = {0};
    fill_jfs_cfg(ctx, cfg, jfs_max_inline_data, &jfs_cfg);

    /* Independent jfr_cfg, no shared_jfr */
    urma_jfr_cfg_t jfr_cfg = {0};
    fill_jfr_cfg(ctx, cfg, &jfr_cfg);

    urma_jetty_cfg_t jetty_cfg = {0};
    if (cfg->share_jfr == false) {
        jetty_flag.bs.share_jfr = 0;   /* No shared jfr */
        jetty_cfg.flag = jetty_flag;
        jetty_cfg.jfs_cfg = jfs_cfg;
        jetty_cfg.jfr_cfg = &jfr_cfg;
    } else {
        ctx->jfr = calloc(1, sizeof(urma_jfr_t *) * jfr_num);
        if (ctx->jfr == NULL) {
            return -ENOMEM;
        }
        for (j = 0; j < jfr_num; j++) {
            jfr_cfg.jfc = ctx->jfc_r[j];
            ctx->jfr[j] = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
            if (ctx->jfr[j] == NULL) {
                (void)fprintf(stderr, "Failed to create share_jfr, %u!\n", j);
                goto err_delete_jfr;
            }
        }
        jetty_flag.bs.share_jfr = 1;
        jetty_cfg.flag = jetty_flag;
        jetty_cfg.jfs_cfg = jfs_cfg;
    }
    ctx->jetty = calloc(1, sizeof(urma_jetty_t *) * cfg->jettys);
    if (ctx->jetty == NULL) {
        goto err_delete_jfr;
    }
    for (uint32_t i = 0; i < cfg->jettys; i++) {
        jetty_cfg.jfs_cfg.jfc = ctx->jfc_s[i];
        if (cfg->share_jfr == false) {
            jetty_cfg.jfr_cfg->jfc = ctx->jfc_r[i];
        } else {
            jetty_cfg.shared.jfc = ctx->jfc_r[i / cfg->jettys_pre_jfr];
            jetty_cfg.shared.jfr = ctx->jfr[i / cfg->jettys_pre_jfr];
        }
        jetty_cfg.id = cfg->jetty_id;
        ctx->jetty[i] = urma_create_jetty(ctx->urma_ctx, &jetty_cfg);
        if (ctx->jetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jetty: %d!\n", i);
            goto err_delete_jetty;
        }
        (void)fprintf(stderr, "Set jetty id %u, actually jetty id %d\n",
            cfg->jetty_id, ctx->jetty[i]->jetty_id.id);
    }

    return 0;
err_delete_jetty:
    destroy_jetty(ctx);
err_delete_jfr:
    if (cfg->share_jfr == true) {
        destroy_jfr(ctx, (int)j);
    }
    return -1;
}

static int create_simplex_jettys(perftest_context_t *ctx, perftest_config_t *cfg)
{
    ctx->jetty_num = cfg->jettys;

    if (create_jfc(ctx, cfg) != 0) {
        return -1;
    }
    if (create_jfs(ctx, cfg) != 0) {
        goto delete_simp_jfc;
    }
    if (create_jfr(ctx, cfg) != 0) {
        goto delete_simp_jfs;
    }
    return 0;
delete_simp_jfs:
    destroy_jfs(ctx, (int)ctx->jetty_num);
delete_simp_jfc:
    destroy_jfc(ctx, cfg);
    return -1;
}

static int create_duplex_jettys(perftest_context_t *ctx, perftest_config_t *cfg)
{
    ctx->jetty_num = cfg->jettys;

    if (create_jfc(ctx, cfg) != 0) {
        return -1;
    }
    if (create_jetty(ctx, cfg) != 0) {
        goto delete_dup_jfc;
    }
    return 0;
delete_dup_jfc:
    destroy_jfc(ctx, cfg);
    return -1;
}

static inline void destroy_simplex_jettys(perftest_context_t *ctx, perftest_config_t *cfg)
{
    destroy_jfr(ctx, (int)ctx->jetty_num);
    destroy_jfs(ctx, (int)ctx->jetty_num);
    destroy_jfc(ctx, cfg);
    ctx->jetty_num = 0;
}

static void destroy_duplex_jettys(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i;
    uint32_t jfr_num = cfg->jettys / cfg->jettys_pre_jfr;

    destroy_jetty(ctx);
    if (cfg->share_jfr == true && ctx->jfr != NULL) {
        for (i = 0; i < jfr_num; i++) {
            (void)urma_delete_jfr(ctx->jfr[i]);
        }
        free(ctx->jfr);
        ctx->jfr = NULL;
    }
    destroy_jfc(ctx, cfg);
    ctx->jetty_num = 0;
}

static inline void unregister_seg(perftest_context_t *ctx, const perftest_config_t *cfg, const int idx)
{
    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;
    for (uint32_t k = 0; k < idx; k++) {
        if (k < seg_num) {
            (void)urma_unregister_seg(ctx->local_tseg[k]);
        }
    }
    free(ctx->local_tseg);
    ctx->local_tseg = NULL;
}

static inline void free_token_id(perftest_context_t *ctx, const perftest_config_t *cfg, const int idx)
{
    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;
    for (uint32_t k = 0; k < idx; k++) {
        if (k < seg_num) {
            (void)urma_free_token_id(ctx->token_id[k]);
        }
    }
    free(ctx->token_id);
    ctx->token_id = NULL;
}

static void free_memory(perftest_context_t *ctx, const perftest_config_t *cfg, const int idx)
{
    int ret = 0;
    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;
    for (uint32_t j = 0; j < idx; j++) {
        if (j < seg_num) {
            if (cfg->use_huge_page == false) {
                free(ctx->local_buf[j]);
            } else {
                ret = ub_hugefree(ctx->local_buf[j], ctx->buf_len);
                if (ret != 0) {
                    (void)fprintf(stderr, "Failed to free huge page, len: %lu.\n", ctx->buf_len);
                }
            }
        }
    }
    free(ctx->local_buf);
    ctx->local_buf = NULL;
}

static int register_mem(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i = 0, j = 0, k = 0;
    const uint64_t page_size_2MB = 2 * 1024 * 1024;
    const uint64_t page_size_1GB = 1024 * 1024 * 1024;
    ctx->local_buf = calloc(1, sizeof(void *) * cfg->jettys);
    if (ctx->local_buf == NULL) {
        return -ENOMEM;
    }

    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;

    ctx->page_size = cfg->page_size;
    if (cfg->use_huge_page) {
        switch (cfg->huge_page) {
        case UB_HUGE_PAGE_SIZE_2MB:
            ctx->page_size = page_size_2MB;
            break;
        case UB_HUGE_PAGE_SIZE_1GB:
            ctx->page_size = page_size_1GB;
            break;
        default:
            break;
        }
    }

    // holds the size of maximum between cfg->size and page_size, aligned to cache line.
    uint64_t max_size = MAX(cfg->size, ctx->page_size);
    ctx->buf_size = PERFTEST_ALIGN_CACHELINE(max_size, cfg->cache_line_size);
    // Buff is divided into two parts, one for recv and the other for send
    ctx->buf_len = ctx->buf_size * PERFTEST_BUF_NUM *
        ((cfg->seg_pre_jetty == true) ? 1 : cfg->jettys);

    for (i = 0; i < cfg->jettys; i++) {
        if (cfg->use_huge_page) {
            if (i < seg_num) {
                ctx->local_buf[i] = ub_hugemalloc(ctx->buf_len, cfg->huge_page, NULL);
            } else {
                ctx->local_buf[i] = ctx->local_buf[0];
            }
            if (ctx->local_buf[i] == NULL) {
                (void)fprintf(stderr, "Failed to alloc local buffer, i: %u.\n", i);
                goto free_memory;
            }
        } else {
            if (i < seg_num) {
                ctx->local_buf[i] = memalign(ctx->page_size, ctx->buf_len);
            } else {
                ctx->local_buf[i] = ctx->local_buf[0];
            }
            if (ctx->local_buf[i] == NULL) {
                (void)fprintf(stderr, "Failed to memalign local buffer, i: %u.\n", i);
                goto free_memory;
            }
        }
    }

    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        ctx->token_id = calloc(1, sizeof(urma_token_id_t *) * cfg->jettys);
        if (ctx->token_id == NULL) {
            goto free_memory;
        }
        for (k = 0; k < cfg->jettys; k++) {
            if (k < seg_num) {
                ctx->token_id[k] = urma_alloc_token_id(ctx->urma_ctx);
            } else {
                ctx->token_id[k] = ctx->token_id[0];
            }
            if (ctx->token_id[k] == NULL) {
                (void)fprintf(stderr, "Failed to alloc token id: %u!\n", k);
                goto free_token_id;
            }
        }
    }

    ctx->local_tseg = calloc(1, sizeof(urma_target_seg_t *) * cfg->jettys);
    if (ctx->local_tseg == NULL) {
            goto free_token_id;
    }

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = cfg->token_policy,
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = PERFTEST_DEF_ACCESS,
        .bs.token_id_valid = URMA_TOKEN_ID_VALID,
        .bs.reserved = 0
    };
    urma_seg_cfg_t seg_cfg = {
        .va = 0,
        .len = ctx->buf_len,
        .token_value = g_perftest_token,
        .flag = flag,
        .user_ctx = (uintptr_t)NULL,
        .iova = 0
    };
    for (j = 0; j < cfg->jettys; j++) {
        if (j < seg_num) {
            seg_cfg.va = (uint64_t)ctx->local_buf[j];
            if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
                seg_cfg.token_id = ctx->token_id[j];
            }
            ctx->local_tseg[j] = urma_register_seg(ctx->urma_ctx, &seg_cfg);
        } else {
            ctx->local_tseg[j] = ctx->local_tseg[0];
        }
        if (ctx->local_tseg[j] == NULL) {
            (void)fprintf(stderr, "Failed to register seg: %u!\n", j);
            goto unregister_seg;
        }
    }

    return 0;

unregister_seg:
    unregister_seg(ctx, cfg, j);
free_token_id:
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        free_token_id(ctx, cfg, k);
    }
free_memory:
    free_memory(ctx, cfg, i);
    return -1;
}

static void unregister_mem(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    unregister_seg(ctx, cfg, (int)ctx->jetty_num);
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        free_token_id(ctx, cfg, (int)ctx->jetty_num);
    }
    free_memory(ctx, cfg, (int)ctx->jetty_num);
}

static inline void free_remote_seg(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        free(ctx->remote_seg[k]);
        ctx->remote_seg[k] = NULL;
    }
    free(ctx->remote_seg);
    ctx->remote_seg = NULL;
}

static int exchange_seg_info(perftest_context_t *ctx, perftest_comm_t *comm, perftest_config_t *cfg)
{
    int i;
    ctx->remote_seg = calloc(1, sizeof(urma_seg_t *) * ctx->jetty_num);
    if (ctx->remote_seg == NULL) {
        return -1;
    }

    if (cfg->pair_flag) {
        for (i = 0; i < (int)cfg->pair_num; i++) {
            ctx->remote_seg[i] = calloc(1, sizeof(urma_seg_t));
            if (ctx->remote_seg[i] == NULL) {
                goto free_remote_seg_buf;
            }
            if (sock_sync_data(comm->sock_fd[i], sizeof(urma_seg_t), (char *)&ctx->local_tseg[i]->seg,
                (char *)ctx->remote_seg[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync seg, loop:%d!\n", i);
                goto free_remote_seg_buf;
            }
        }
    } else {
        for (i = 0; i < (int)ctx->jetty_num; i++) {
            ctx->remote_seg[i] = calloc(1, sizeof(urma_seg_t));
            if (ctx->remote_seg[i] == NULL) {
                goto free_remote_seg_buf;
            }
            if (sock_sync_data(comm->sock_fd[0], sizeof(urma_seg_t), (char *)&ctx->local_tseg[i]->seg,
                (char *)ctx->remote_seg[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync seg, loop:%d!\n", i);
                goto free_remote_seg_buf;
            }
        }
    }
    return 0;
free_remote_seg_buf:
    free_remote_seg(ctx, i);
    return -1;
}

static inline void free_remote_jfr(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        free(ctx->remote_jfr[k]);
        ctx->remote_jfr[k] = NULL;
    }
    free(ctx->remote_jfr);
    ctx->remote_jfr = NULL;
}

static int exchange_jfr_info(perftest_context_t *ctx, perftest_comm_t *comm, perftest_config_t *cfg)
{
    int i;
    ctx->remote_jfr = calloc(1, sizeof(urma_jfr_t *) * ctx->jetty_num);
    if (ctx->remote_jfr == NULL) {
        return -1;
    }

    if (cfg->pair_flag) {
        for (i = 0; i < (int)cfg->pair_num; i++) {
            ctx->remote_jfr[i] = calloc(1, sizeof(urma_jfr_t));
            if (ctx->remote_jfr[i] == NULL) {
                goto free_remote_jfr_buf;
            }
            if (sock_sync_data(comm->sock_fd[i], sizeof(urma_jfr_t), (char *)ctx->jfr[i],
                (char *)ctx->remote_jfr[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync jfr, loop:%d!\n", i);
                goto free_remote_jfr_buf;
            }
        }
    } else {
        for (i = 0; i < (int)ctx->jetty_num; i++) {
            ctx->remote_jfr[i] = calloc(1, sizeof(urma_jfr_t));
            if (ctx->remote_jfr[i] == NULL) {
                goto free_remote_jfr_buf;
            }
            if (sock_sync_data(comm->sock_fd[0], sizeof(urma_jfr_t), (char *)ctx->jfr[i],
                (char *)ctx->remote_jfr[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync jfr, loop:%d!\n", i);
                goto free_remote_jfr_buf;
            }
        }
    }
    return 0;

free_remote_jfr_buf:
    free_remote_jfr(ctx, i);
    return -1;
}

static inline void free_remote_jetty(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        free(ctx->remote_jetty[k]);
        ctx->remote_jetty[k] = NULL;
    }
    free(ctx->remote_jetty);
    ctx->remote_jetty = NULL;
}

static int exchange_jetty_info(perftest_context_t *ctx, perftest_comm_t *comm, perftest_config_t *cfg)
{
    int i;
    ctx->remote_jetty = calloc(1, sizeof(urma_jetty_t *) * ctx->jetty_num);
    if (ctx->remote_jetty == NULL) {
        return -1;
    }
    if (cfg->pair_flag) {
        for (i = 0; i < (int)cfg->pair_num; i++) {
            ctx->remote_jetty[i] = calloc(1, sizeof(urma_jetty_t));
            if (ctx->remote_jetty[i] == NULL) {
                goto free_remote_jetty_buf;
            }
            if (sock_sync_data(comm->sock_fd[i], sizeof(urma_jetty_t), (char *)ctx->jetty[i],
                (char *)ctx->remote_jetty[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync jetty, loop:%d!\n", i);
                goto free_remote_jetty_buf;
            }
        }
    } else {
        for (i = 0; i < (int)ctx->jetty_num; i++) {
            ctx->remote_jetty[i] = calloc(1, sizeof(urma_jetty_t));
            if (ctx->remote_jetty[i] == NULL) {
                goto free_remote_jetty_buf;
            }
            if (sock_sync_data(comm->sock_fd[0], sizeof(urma_jetty_t), (char *)ctx->jetty[i],
                (char *)ctx->remote_jetty[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync jetty, loop:%d!\n", i);
                goto free_remote_jetty_buf;
            }
        }
    }
    return 0;

free_remote_jetty_buf:
    free_remote_jetty(ctx, i);
    return -1;
}

static void free_remote_credit(perftest_context_t *ctx, const int idx)
{
    if (ctx->remote_credit_seg == NULL) {
        return;
    }
    for (int k = 0; k < idx; k++) {
        if (ctx->remote_credit_seg[k] != NULL) {
            free(ctx->remote_credit_seg[k]);
            ctx->remote_credit_seg[k] = NULL;
        }
    }
    if (ctx->remote_credit_seg != NULL) {
        free(ctx->remote_credit_seg);
        ctx->remote_credit_seg = NULL;
    }
}

static int exchange_credit_info(perftest_context_t *ctx, perftest_comm_t *comm, perftest_config_t *cfg)
{
    uint32_t i;
    ctx->remote_credit_seg = calloc(1, sizeof(urma_seg_t) * cfg->jettys);
    if (ctx->remote_credit_seg == NULL) {
        return -1;
    }
    if (cfg->pair_flag) {
        for (i = 0; i < cfg->pair_num; i++) {
            ctx->remote_credit_seg[i] = calloc(1, sizeof(urma_seg_t));
            if (ctx->remote_credit_seg[i] == NULL) {
                goto free_remote_credit_buf;
            }

            if (sock_sync_data(comm->sock_fd[i], sizeof(urma_seg_t), (char *)&ctx->credit_seg[i]->seg,
                (char *)ctx->remote_credit_seg[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync credit, loop:%u!\n", i);
                goto free_remote_credit_buf;
            }
        }
    } else {
        for (i = 0; i < ctx->jetty_num; i++) {
            ctx->remote_credit_seg[i] = calloc(1, sizeof(urma_seg_t));
            if (ctx->remote_credit_seg[i] == NULL) {
                goto free_remote_credit_buf;
            }

            if (sock_sync_data(comm->sock_fd[0], sizeof(urma_seg_t), (char *)&ctx->credit_seg[i]->seg,
                (char *)ctx->remote_credit_seg[i]) != 0) {
                (void)fprintf(stderr, "Failed to sync credit, loop:%u!\n", i);
                goto free_remote_credit_buf;
            }
        }
    }
    return 0;

free_remote_credit_buf:
    free_remote_credit(ctx, i);
    return -1;
}

static int exchange_simplex_info(perftest_context_t *ctx, perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;
    int ret = exchange_seg_info(ctx, comm, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_seg_info, ret: %d\n", ret);
        return -1;
    }
    ret = exchange_jfr_info(ctx, comm, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_jfr_info, ret: %d\n", ret);
        free_remote_seg(ctx, (int)ctx->jetty_num);
        return -1;
    }
    if (cfg->enable_credit == true) {
        ret = exchange_credit_info(ctx, comm, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to exchange_credit_info for sinplex, ret: %d\n", ret);
            free_remote_jfr(ctx, (int)ctx->jetty_num);
            free_remote_seg(ctx, (int)ctx->jetty_num);
            return -1;
        }
    }
    return 0;
}

static int exchange_duplex_info(perftest_context_t *ctx, perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;
    int ret = exchange_seg_info(ctx, comm, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_seg_info, ret: %d\n", ret);
        return -1;
    }
    ret = exchange_jetty_info(ctx, comm, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_jetty_info, ret: %d\n", ret);
        free_remote_seg(ctx, (int)ctx->jetty_num);
        return -1;
    }
    if (cfg->enable_credit == true) {
        ret = exchange_credit_info(ctx, comm, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to exchange_credit_info, ret: %d\n", ret);
            free_remote_jetty(ctx, (int)ctx->jetty_num);
            free_remote_seg(ctx, (int)ctx->jetty_num);
            return -1;
        }
    }
    return 0;
}

static void destroy_simplex_remote_info(perftest_context_t *ctx)
{
    free_remote_seg(ctx, (int)ctx->jetty_num);
    free_remote_jfr(ctx, (int)ctx->jetty_num);
}

static void destroy_duplex_remote_info(perftest_context_t *ctx)
{
    free_remote_credit(ctx, (int)ctx->jetty_num);
    free_remote_seg(ctx, (int)ctx->jetty_num);
    free_remote_jetty(ctx, (int)ctx->jetty_num);
}

static inline void unimport_seg(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_unimport_seg(ctx->import_tseg[k]);
    }
    if (ctx->import_tseg != NULL) {
        free(ctx->import_tseg);
    }
    ctx->import_tseg = NULL;
}

static inline void unimport_credit(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        if (ctx->import_credit_seg[k] != NULL) {
            (void)urma_unimport_seg(ctx->import_credit_seg[k]);
        }
    }
    if (ctx->import_credit_seg != NULL) {
        free(ctx->import_credit_seg);
    }
    ctx->import_credit_seg = NULL;
}

static int import_seg_for_simplex(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i;

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0
    };

    if (cfg->enable_credit == true) {
        ctx->import_credit_seg = calloc(1, sizeof(urma_target_seg_t *) * ctx->jetty_num);
        if (ctx->import_credit_seg == NULL) {
            return -ENOMEM;
        }
        for (i = 0; i < (int)ctx->jetty_num; i++) {
            ctx->import_credit_seg[i] = urma_import_seg(ctx->urma_ctx, ctx->remote_credit_seg[i],
                &g_perftest_token, 0, flag);
            if (ctx->import_credit_seg[i] == NULL) {
                (void)fprintf(stderr, "Failed to import seg for simplex, loop: %d!\n", i);
                goto free_credit;
            }
        }
    }

    ctx->import_tseg = calloc(1, sizeof(urma_target_seg_t *) * ctx->jetty_num);
    if (ctx->import_tseg == NULL) {
        return -1;
    }

    for (i = 0; i < (int)ctx->jetty_num; i++) {
        ctx->import_tseg[i] = urma_import_seg(ctx->urma_ctx, ctx->remote_seg[i], &g_perftest_token, 0, flag);
        if (ctx->import_tseg[i] == NULL) {
            (void)fprintf(stderr, "Failed to import seg, loop:%d!\n", i);
            goto unimp_simp_seg;
        }
    }

    return 0;
unimp_simp_seg:
    unimport_seg(ctx, i);
free_credit:
    if (cfg->enable_credit == true) {
        unimport_credit(ctx, ctx->jetty_num);
    }
    return -1;
}

static int import_seg_for_duplex(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i;

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0
    };

    if (cfg->enable_credit == true) {
        ctx->import_credit_seg = calloc(1, sizeof(urma_target_seg_t *) * ctx->jetty_num);
        if (ctx->import_credit_seg == NULL) {
            return -ENOMEM;
        }
        for (i = 0; i < (int)ctx->jetty_num; i++) {
            ctx->import_credit_seg[i] = urma_import_seg(ctx->urma_ctx, ctx->remote_credit_seg[i],
                &g_perftest_token, 0, flag);
            if (ctx->import_credit_seg[i] == NULL) {
                (void)fprintf(stderr, "Failed to import seg, loop:%d!\n", i);
                goto free_credit;
            }
        }
    }

    ctx->import_tseg = calloc(1, sizeof(urma_target_seg_t *) * ctx->jetty_num);
    if (ctx->import_tseg == NULL) {
        goto free_credit;
    }

    for (i = 0; i < (int)ctx->jetty_num; i++) {
        ctx->import_tseg[i] = urma_import_seg(ctx->urma_ctx, ctx->remote_seg[i], &g_perftest_token, 0, flag);
        if (ctx->import_tseg[i] == NULL) {
            (void)fprintf(stderr, "Failed to import seg, loop:%d!\n", i);
            goto unimp_dup_seg;
        }
    }

    return 0;

unimp_dup_seg:
    unimport_seg(ctx, i);
free_credit:
    if (cfg->enable_credit == true) {
        unimport_credit(ctx, ctx->jetty_num);
    }
    return -1;
}

typedef struct perftest_tp_info {
    uint64_t tp_handle;
    uint32_t psn;
} perftest_tp_info_t;

typedef struct perftest_tp_pair_info {
    urma_get_tp_cfg_t get_tp_cfg;
    perftest_tp_info_t local;
    perftest_tp_info_t peer;
} perftest_tp_pair_info_t;

static void disconnect_jfr_default(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        if (ctx->import_tjfr[i] == NULL) {
            continue;
        }
        if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            (void)urma_unadvise_jfr(ctx->jfs[i], ctx->import_tjfr[i]);
        }
        (void)urma_unimport_jfr(ctx->import_tjfr[i]);
    }
}

static int connect_jfr_default(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        urma_rjfr_t rjfr = {0};
        rjfr.jfr_id = ctx->remote_jfr[i]->jfr_id;
        rjfr.trans_mode = ctx->remote_jfr[i]->jfr_cfg.trans_mode;
        if (cfg->use_ctp) {
            rjfr.tp_type = URMA_CTP;
        } else if (rjfr.trans_mode == URMA_TM_UM) {
            rjfr.tp_type = URMA_UTP;
        } else {
            rjfr.tp_type = URMA_RTP;
        }

        ctx->import_tjfr[i] = urma_import_jfr(ctx->urma_ctx, &rjfr, &g_perftest_token);
        if (ctx->import_tjfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jfr, loop:%u!\n", i);
            goto disconnect_jfr;
        }

        if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            urma_status_t ret = urma_advise_jfr(ctx->jfs[i], ctx->import_tjfr[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to advise jfr, loop:%u!\n", i);
                (void)urma_unimport_jfr(ctx->import_tjfr[i]);
                ctx->import_tjfr[i] = NULL;
                goto disconnect_jfr;
            }
        }
    }
    return 0;

disconnect_jfr:
    disconnect_jfr_default(ctx, cfg);
    return -1;
}

static bool g_tp_info_updated = false;
static urma_tp_info_t g_tp_info = {0};

static int exchange_tp_info(perftest_context_t *ctx, const perftest_config_t *cfg, urma_get_tp_cfg_t *tp_cfg,
    urma_active_tp_cfg_t *active_cfg)
{
    urma_tp_info_t tp_info = {0};
    uint32_t tp_cnt = 1;
    urma_status_t ret;

    if (cfg->tp_reuse && cfg->trans_mode == URMA_TM_RM && g_tp_info_updated) {
        tp_info = g_tp_info;
    } else {
        ret = urma_get_tp_list(ctx->urma_ctx, tp_cfg, &tp_cnt, &tp_info);
        if (ret != URMA_SUCCESS || tp_cnt != 1) {
            (void)fprintf(stderr, "Failed to get tpid list, ret:%d, tp_cnt:%u!\n", ret, tp_cnt);
            return -1;
        }
        g_tp_info_updated = true;
        g_tp_info = tp_info;
    }

    if (cfg->trans_mode == URMA_TM_UM || cfg->use_ctp) {
        active_cfg->tp_handle = tp_info.tp_handle;
        active_cfg->tp_attr.tx_psn = (uint32_t)random();
    } else {
        perftest_tp_info_t tp_info_local = {0}, tp_info_peer = {0};
        tp_info_local.tp_handle = tp_info.tp_handle;
        tp_info_local.psn = (uint32_t)random();
        if (sock_sync_data(cfg->comm.sock_fd[0], sizeof(perftest_tp_info_t),
            (char *)&tp_info_local, (char *)&tp_info_peer) != 0) {
            (void)fprintf(stderr, "Failed to exchange tp info!\n");
            return -1;
        }
        active_cfg->tp_handle = tp_info_local.tp_handle;
        active_cfg->tp_attr.tx_psn = tp_info_local.psn;
        active_cfg->peer_tp_handle = tp_info_peer.tp_handle;
        active_cfg->tp_attr.rx_psn = tp_info_peer.psn;
    }
    return 0;
}

static int connect_jfr_tp_aware(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    if (ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        (void)fprintf(stderr, "TP aware connect only work on UB device!\n");
        return -1;
    }

    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        urma_get_tp_cfg_t tp_cfg = {0};

        if (cfg->use_ctp) {
            tp_cfg.flag.bs.ctp = 1;
        } else if (cfg->trans_mode == URMA_TM_UM) {
            tp_cfg.flag.bs.utp = 1;
        } else {
            tp_cfg.flag.bs.rtp = 1;
        }

        tp_cfg.trans_mode = cfg->trans_mode;
        tp_cfg.local_eid = ctx->jfs[i]->jfs_id.eid;
        tp_cfg.peer_eid = ctx->remote_jfr[i]->jfr_id.eid;

        urma_import_jfr_ex_cfg_t active_cfg = {0};
        if (exchange_tp_info(ctx, cfg, &tp_cfg, &active_cfg) != 0) {
            (void)fprintf(stderr, "Failed to exchange tp info, loop:%u!\n", i);
            goto disconnect_jfr;
        }

        urma_rjfr_t rjfr = {0};
        rjfr.jfr_id = ctx->remote_jfr[i]->jfr_id;
        rjfr.trans_mode = ctx->remote_jfr[i]->jfr_cfg.trans_mode;

        ctx->import_tjfr[i] = urma_import_jfr_ex(ctx->urma_ctx, &rjfr, &g_perftest_token, &active_cfg);
        if (ctx->import_tjfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jfr, loop:%u!\n", i);
            goto disconnect_jfr;
        }
    }

    if (sync_time(cfg->comm.sock_fd[0], "tp aware connect finished") != 0) {
        goto disconnect_jfr;
    }
    return 0;

disconnect_jfr:
    disconnect_jfr_default(ctx, cfg);
    return -1;
}

static void disconnect_jfr(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    disconnect_jfr_default(ctx, cfg);
    free(ctx->import_tjfr);
    ctx->import_tjfr = NULL;
}

static int connect_jfr(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    ctx->import_tjfr = calloc(ctx->jetty_num, sizeof(urma_target_jetty_t *));
    if (ctx->import_tjfr == NULL) {
        (void)fprintf(stderr, "Failed to alloc tjfr!\n");
        return -1;
    }

    int ret;
    if (cfg->tp_aware) {
        ret = connect_jfr_tp_aware(ctx, cfg);
    } else {
        ret = connect_jfr_default(ctx, cfg);
    }
    if (ret != 0) {
        goto disconnect;
    }
    return 0;

disconnect:
    free(ctx->import_tjfr);
    ctx->import_tjfr = NULL;
    return -1;
}

static void disconnect_jetty_default(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        if (ctx->import_tjetty[i] == NULL) {
            continue;
        }

        if (cfg->trans_mode == URMA_TM_RC) {
            (void)urma_unbind_jetty(ctx->jetty[i]);
        } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            (void)urma_unadvise_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
        }

        (void)urma_unimport_jetty(ctx->import_tjetty[i]);
    }
}

static int connect_jetty_default(perftest_context_t *ctx, perftest_config_t *cfg)
{
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        urma_rjetty_t rjetty = {0};
        rjetty.jetty_id = ctx->remote_jetty[i]->jetty_id;
        rjetty.trans_mode = cfg->trans_mode;
        rjetty.type = URMA_JETTY;
        rjetty.flag.bs.order_type = cfg->order_type;
        if (cfg->use_ctp) {
            rjetty.tp_type = URMA_CTP;
        } else if (rjetty.trans_mode == URMA_TM_UM) {
            rjetty.tp_type = URMA_UTP;
        } else {
            rjetty.tp_type = URMA_RTP;
        }
        if (rjetty.trans_mode == URMA_TM_RC &&
            (rjetty.flag.bs.order_type == URMA_OT)) {
            rjetty.flag.bs.share_tp = 1;
        }

        ctx->import_tjetty[i] = urma_import_jetty(ctx->urma_ctx, &rjetty, &g_perftest_token);
        if (ctx->import_tjetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jetty: %u!\n", i);
            goto disconnect_jetty;
        }

        if (cfg->trans_mode == URMA_TM_RC) {
            urma_status_t ret = urma_bind_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to bind jetty: %u!\n", i);
                urma_unimport_jetty(ctx->import_tjetty[i]);
                ctx->import_tjetty[i] = NULL;
                goto disconnect_jetty;
            }
        } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            urma_status_t ret = urma_advise_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to advise jetty: %u, trans_mode: %d.\n", i, (int)cfg->trans_mode);
                urma_unimport_jetty(ctx->import_tjetty[i]);
                ctx->import_tjetty[i] = NULL;
                goto disconnect_jetty;
            }
        }
        if (cfg->pair_flag) {
            sleep(1);
        }
    }
    return 0;

disconnect_jetty:
    disconnect_jetty_default(ctx, cfg);
    return -1;
}

static int connect_jetty_tp_aware(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        (void)fprintf(stderr, "TP aware connect only work on UB device!\n");
        return -1;
    }

    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        urma_get_tp_cfg_t tp_cfg = {0};

        if (cfg->use_ctp) {
            tp_cfg.flag.bs.ctp = 1;
        } else if (cfg->trans_mode == URMA_TM_UM) {
            tp_cfg.flag.bs.utp = 1;
        } else {
            tp_cfg.flag.bs.rtp = 1;
        }

        tp_cfg.trans_mode = cfg->trans_mode;
        tp_cfg.local_eid = ctx->jetty[i]->jetty_id.eid;
        tp_cfg.peer_eid = ctx->remote_jetty[i]->jetty_id.eid;

        urma_import_jetty_ex_cfg_t active_cfg = {0};
        if (exchange_tp_info(ctx, cfg, &tp_cfg, &active_cfg) != 0) {
            (void)fprintf(stderr, "Failed to exchange tp info, loop:%u!\n", i);
            goto disconnect_jetty;
        }

        urma_rjetty_t rjetty = {0};
        rjetty.jetty_id = ctx->remote_jetty[i]->jetty_id;
        rjetty.trans_mode = cfg->trans_mode;
        rjetty.type = URMA_JETTY;
        rjetty.flag.bs.order_type = cfg->order_type;
        if (rjetty.trans_mode == URMA_TM_RC &&
            (rjetty.flag.bs.order_type == URMA_OT)) {
            rjetty.flag.bs.share_tp = 1;
        }

        ctx->import_tjetty[i] = urma_import_jetty_ex(ctx->urma_ctx, &rjetty, &g_perftest_token, &active_cfg);
        if (ctx->import_tjetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jetty: %u!\n", i);
            goto disconnect_jetty;
        }

        if (cfg->trans_mode == URMA_TM_RC) {
            urma_status_t ret = urma_bind_jetty_ex(ctx->jetty[i], ctx->import_tjetty[i], &active_cfg);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to bind jetty: %u!\n", i);
                urma_unimport_jetty(ctx->import_tjetty[i]);
                ctx->import_tjetty[i] = NULL;
                goto disconnect_jetty;
            }
        }
    }

    return sync_time(cfg->comm.sock_fd[0], "tp aware connect finished");

disconnect_jetty:
    disconnect_jetty_default(ctx, cfg);
    return -1;
}

static int wait_jetty_async(perftest_context_t *ctx, urma_notifier_t *notifier, uint32_t expected)
{
    if (expected == 0) {
        return 0;
    }

    urma_notify_t *notify = calloc(expected, sizeof(urma_notify_t));
    if (notify == NULL) {
        return -1;
    }

    uint32_t current = 0;
    while (current < expected) {
        int ret = urma_wait_notify(notifier, expected - current, notify + current, 0);
        if (ret < 0) {
            (void)fprintf(stderr, "Failed to wait notify, exit!\n");
        } else {
            current += (uint32_t)ret;
        }
    }
    urma_ack_notify(notifier->urma_ctx, expected, notify);

    int ret = 0;
    for (uint32_t i = 0; i < expected; i++) {
        if (notify[i].status != 0) {
            ret = -1;
            if (notify[i].type == URMA_IMPORT_JETTY_NOTIFY) {
                ctx->import_tjetty[notify[i].user_ctx] = NULL;
            }
        }
    }
    free(notify);
    return ret;
}

static void disconnect_jetty_async(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    // Hope async ops finished
    const int async_duration = 3;

    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        if (cfg->trans_mode == URMA_TM_RC) {
            (void)urma_unbind_jetty_async(ctx->jetty[i]);
        } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            (void)urma_unadvise_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
        }
    }
    sleep(async_duration);

    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        (void)urma_unimport_jetty_async(ctx->import_tjetty[i]);
    }
    sleep(async_duration);
}

static int connect_jetty_async(perftest_context_t *ctx, perftest_config_t *cfg)
{
    urma_notifier_t *notifier = urma_create_notifier(ctx->urma_ctx);
    if (notifier == NULL) {
        return -1;
    }

    uint32_t expected;
    int waited;

    // Import jetty
    expected = 0;
    waited = 0;
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        urma_rjetty_t rjetty = {0};
        rjetty.jetty_id = ctx->remote_jetty[i]->jetty_id;
        rjetty.trans_mode = cfg->trans_mode;
        rjetty.type = URMA_JETTY;
        rjetty.flag.bs.order_type = cfg->order_type;
        if (rjetty.trans_mode == URMA_TM_RC &&
            (rjetty.flag.bs.order_type == URMA_OT)) {
            rjetty.flag.bs.share_tp = 1;
        }

        ctx->import_tjetty[i] = urma_import_jetty_async(notifier, &rjetty, &g_perftest_token, i, -1);
        if (ctx->import_tjetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jetty: %u!\n", i);
            break;
        }
        expected += 1;
    }

    // Import jetty wait
    waited = wait_jetty_async(ctx, notifier, expected);
    if (expected < ctx->jetty_num || waited < 0) {
        goto disconnect_jetty;
    }

    // Bind jetty
    expected = 0;
    waited = 0;
    for (uint32_t i = 0; i < ctx->jetty_num; i++) {
        if (cfg->trans_mode == URMA_TM_RC) {
            int ret = urma_bind_jetty_async(notifier, ctx->jetty[i], ctx->import_tjetty[i], i, 0);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to bind jetty: %u!\n", i);
                break;
            }
        } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            int ret = urma_advise_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to advise jetty: %u, trans_mode: %d.\n", i, (int)cfg->trans_mode);
                break;
            }
        }
        expected += 1;
    }

    // Bind jetty wait
    if (cfg->trans_mode == URMA_TM_RC) {
        waited = wait_jetty_async(ctx, notifier, expected);
    }
    if (expected < ctx->jetty_num || waited < 0) {
        goto disconnect_jetty;
    }

    urma_delete_notifier(notifier);
    return 0;

disconnect_jetty:
    disconnect_jetty_async(ctx, cfg);
    urma_delete_notifier(notifier);
    return -1;
}

static void disconnect_jetty(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    if (cfg->enable_async_import) {
        disconnect_jetty_async(ctx, cfg);
    } else {
        disconnect_jetty_default(ctx, cfg);
    }
    free(ctx->import_tjetty);
    ctx->import_tjetty = NULL;
}

static int connect_jetty(perftest_context_t *ctx, perftest_config_t *cfg)
{
    ctx->import_tjetty = calloc(ctx->jetty_num, sizeof(urma_target_jetty_t *));
    if (ctx->import_tjetty == NULL) {
        return -1;
    }

    int ret;
    if (cfg->enable_async_import) {
        ret = connect_jetty_async(ctx, cfg);
    } else if (cfg->tp_aware) {
        ret = connect_jetty_tp_aware(ctx, cfg);
    } else {
        ret = connect_jetty_default(ctx, cfg);
    }
    if (ret != 0) {
        goto disconnect;
    }
    return 0;

disconnect:
    free(ctx->import_tjetty);
    ctx->import_tjetty = NULL;
    return -1;
}

static int create_run_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t cycles_num;

    if (cfg->time_type.bs.duration == 1) {
        ctx->run_ctx.duration = cfg->duration;
        ctx->run_ctx.state = WARMUP_STATE;
    }
    ctx->run_ctx.rid = 0;

    cycles_num = cfg->no_peak == true ? 1 : cfg->iters * cfg->jettys;
    ctx->run_ctx.tposted = calloc(1, sizeof(uint64_t) * cycles_num);
    if (ctx->run_ctx.tposted == NULL) {
        return -1;
    }

    ctx->run_ctx.tcompleted = calloc(1, sizeof(uint64_t) * cycles_num);
    if (ctx->run_ctx.tcompleted == NULL) {
        goto free_tposted;
    }

    ctx->run_ctx.scnt = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (ctx->run_ctx.scnt == NULL) {
        goto free_tcompleted;
    }

    ctx->run_ctx.ccnt = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (ctx->run_ctx.ccnt == NULL) {
        goto free_scnt;
    }
    return 0;
free_scnt:
    free(ctx->run_ctx.scnt);
free_tcompleted:
    free(ctx->run_ctx.tcompleted);
free_tposted:
    free(ctx->run_ctx.tposted);
    return -1;
}

static inline void destroy_run_ctx(perftest_context_t *ctx)
{
    free(ctx->run_ctx.ccnt);
    free(ctx->run_ctx.scnt);
    free(ctx->run_ctx.tcompleted);
    free(ctx->run_ctx.tposted);
    ctx->run_ctx.duration = 0;
    ctx->run_ctx.state = WARMUP_STATE;
    ctx->run_ctx.rid = 0;
}

static void destroy_credit_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i = 0;

    for (i = 0; i < cfg->jettys; i++) {
        if (ctx->credit_seg[i] != NULL) {
            (void)urma_unregister_seg(ctx->credit_seg[i]);
        }
    }

    free(ctx->credit_seg);
    ctx->credit_seg = NULL;

    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        for (i = 0; i < cfg->jettys; i++) {
            if (ctx->credit_token_id[i] != NULL) {
                urma_free_token_id(ctx->credit_token_id[i]);
            }
        }
    }
    free(ctx->credit_token_id);
    for (i = 0; i < cfg->jettys; i++) {
        if (ctx->ctrl_buf[i] != NULL) {
            free(ctx->ctrl_buf[i]);
        }
    }
    free(ctx->ctrl_buf);
}

static int create_credit_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int buf_size = 2 * sizeof(uint64_t);
    uint32_t i = 0;

    ctx->ctrl_buf = (uint64_t **)calloc(1, sizeof(uint64_t *) * cfg->jettys);
    if (ctx->ctrl_buf == NULL) {
        return -1;
    }
    for (i = 0 ; i < cfg->jettys; i++) {
        ctx->ctrl_buf[i] = (uint64_t *)memalign(ctx->page_size, buf_size);
        if (ctx->ctrl_buf[i] == NULL) {
            goto free_buf;
        }
    }

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = cfg->token_policy,
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = PERFTEST_DEF_ACCESS,
        .bs.token_id_valid = URMA_TOKEN_ID_VALID,
        .bs.reserved = 0
    };
    urma_seg_cfg_t seg_cfg = {
        .va = 0,
        .len = buf_size,
        .token_value = g_perftest_token,
        .flag = flag,
        .user_ctx = (uintptr_t)NULL,
        .iova = 0
    };

    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        ctx->credit_token_id = calloc(1, sizeof(urma_token_id_t *) * cfg->jettys);
        if (ctx->credit_token_id == NULL) {
            goto free_buf;
        }

        for (i = 0; i < cfg->jettys; i++) {
            ctx->credit_token_id[i] = urma_alloc_token_id(ctx->urma_ctx);
            if (ctx->credit_token_id[i] == NULL) {
                goto free_token_id;
            }
        }
    }

    ctx->credit_seg = calloc(1, sizeof(urma_target_seg_t *) * cfg->jettys);
    if (ctx->credit_seg == NULL) {
        goto free_token_id;
    }

    for (i = 0; i < cfg->jettys; i++) {
        seg_cfg.va = (uintptr_t)ctx->ctrl_buf[i];
        if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
            seg_cfg.token_id = ctx->credit_token_id[i];
        }
        ctx->credit_seg[i] = urma_register_seg(ctx->urma_ctx, &seg_cfg);
        if (ctx->credit_seg[i] == NULL) {
            goto free_credit_seg;
        }
    }
    return 0;

free_credit_seg:
    for (i = 0; i < cfg->jettys; i++) {
        if (ctx->credit_seg[i] != NULL) {
            (void)urma_unregister_seg(ctx->credit_seg[i]);
        }
    }
    free(ctx->credit_seg);
free_token_id:
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        for (i = 0; i < cfg->jettys; i++) {
            if (ctx->credit_token_id[i] != NULL) {
                urma_free_token_id(ctx->credit_token_id[i]);
            }
        }
    }
    free(ctx->credit_token_id);
free_buf:
    for (i = 0; i < cfg->jettys; i++) {
        if (ctx->ctrl_buf[i] != NULL) {
            free(ctx->ctrl_buf[i]);
        }
    }
    free(ctx->ctrl_buf);
    return -1;
}

static int create_simplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)memset(ctx, 0, sizeof(perftest_context_t));
    if (init_device(ctx, cfg) != 0) {
        return -1;
    }

    if (create_simplex_jettys(ctx, cfg) != 0) {
        goto uninit_dev;
    }

    if (register_mem(ctx, cfg) != 0) {
        goto delete_jettys;
    }

    if (cfg->enable_credit == true && create_credit_ctx(ctx, cfg) != 0) {
        goto unregister_mem;
    }

    if (exchange_simplex_info(ctx, cfg) != 0) {
        goto delete_credit_ctx;
    }

    if (import_seg_for_simplex(ctx, cfg) != 0) {
        goto destroy_remote_info;
    }

    if (connect_jfr(ctx, cfg) != 0) {
        goto unimport_seg;
    }

    if (create_run_ctx(ctx, cfg) != 0) {
        goto disconnect_jfr;
    }
    return 0;

disconnect_jfr:
    disconnect_jfr(ctx, cfg);
unimport_seg:
    unimport_seg(ctx, (int)ctx->jetty_num);
destroy_remote_info:
    destroy_simplex_remote_info(ctx);
delete_credit_ctx:
    if (cfg->enable_credit == true) {
        destroy_credit_ctx(ctx, cfg);
    }
unregister_mem:
    unregister_mem(ctx, cfg);
delete_jettys:
    destroy_simplex_jettys(ctx, cfg);
uninit_dev:
    uninit_device(ctx);
    return -1;
}

int find_net_addr_by_eid(urma_net_addr_info_t *net_addr_list, uint32_t net_addr_cnt,
    urma_eid_t eid, urma_net_addr_info_t *addr_info)
{
    (void)fprintf(stderr, "eid: " EID_FMT ".\n", EID_ARGS(eid));
    for (uint32_t i = 0 ; i < net_addr_cnt; i++) {
        (void)fprintf(stderr, "netaddr: fam:%hu, ipv4:0x%x\n",
            net_addr_list[i].netaddr.sin_family, net_addr_list[i].netaddr.in4.s_addr);
        if ((net_addr_list[i].netaddr.sin_family == AF_INET &&
            net_addr_list[i].netaddr.in4.s_addr == eid.in4.addr) ||
            (net_addr_list[i].netaddr.sin_family == AF_INET6 &&
            memcmp(net_addr_list[i].netaddr.in6.__in6_u.__u6_addr8, eid.raw, sizeof(eid.in6)) == 0)) {
            *addr_info = net_addr_list[i];
            return 0;
        }
    }
    (void)fprintf(stderr, "Failed to find net_addr.\n");
    return -1;
}

static int fill_user_tp_info(perftest_context_t *ctx, perftest_config_t *cfg)
{
    urma_device_feature_t feature = ctx->dev_attr.dev_cap.feature;
    ctx->user_tp = calloc(1, sizeof(user_tp_ctx_t) * cfg->jettys);
    if (ctx->user_tp == NULL) {
        return -1;
    }
    ctx->remote_user_tp = calloc(1, sizeof(user_tp_ctx_t) * cfg->jettys);
    if (ctx->remote_user_tp == NULL) {
        goto free_user_tp;
    }

    ctx->user_tp->net_addr_list = urma_get_net_addr_list(ctx->urma_ctx, &ctx->user_tp->net_addr_cnt);
    if (ctx->user_tp->net_addr_list == NULL || ctx->user_tp->net_addr_cnt == 0) {
        (void)fprintf(stderr, "Failed to get net_addr.\n");
        goto free_remote_user_tp;
    }

    urma_net_addr_info_t net_addr = {0};
    (void)find_net_addr_by_eid(ctx->user_tp->net_addr_list, ctx->user_tp->net_addr_cnt, ctx->eid, &net_addr);

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        ctx->user_tp[i].cfg.flag.value = 0;
        ctx->user_tp[i].cfg.flag.bs.dca_enable = feature.bs.dca;
        ctx->user_tp[i].cfg.trans_mode = cfg->trans_mode;
        ctx->user_tp[i].cfg.retry_num = cfg->retry_num;
        ctx->user_tp[i].cfg.retry_factor = PERFTEST_DEF_RETRY_FACTOR;
        ctx->user_tp[i].cfg.ack_timeout = cfg->ack_timeout;
        ctx->user_tp[i].cfg.dscp = PERFTEST_DEF_DSCP;
        ctx->user_tp[i].cfg.oor_cnt = ctx->dev_attr.dev_cap.max_oor_cnt;

        ctx->user_tp[i].attr.flag.value = 0;
        ctx->user_tp[i].attr.flag.bs.oor_en = ((cfg->oor_en == true && feature.bs.oor == 1) ? 1 : 0);
        ctx->user_tp[i].attr.flag.bs.cc_en = (cfg->cc_en == true ? 1 : 0);
        ctx->user_tp[i].attr.flag.bs.spray_en = ((cfg->spray_en == true && feature.bs.spray_en == 1) ? 1 : 0);
        ctx->user_tp[i].attr.flag.bs.cc_alg = cfg->cc_alg;
        int peer_tpn = urma_get_tpn(ctx->jetty[i]);
        if (peer_tpn < 0) {
            (void)fprintf(stderr, "Failed to get tpn: %u.\n", i);
            goto free_net_addr_list;
        }
        ctx->user_tp[i].attr.peer_tpn = (uint32_t)peer_tpn;
        ctx->user_tp[i].attr.state = URMA_TP_STATE_ACTIVE;
        ctx->user_tp[i].attr.tx_psn = PERFTEST_DEF_PSN;
        ctx->user_tp[i].attr.rx_psn = PERFTEST_DEF_PSN;
        ctx->user_tp[i].attr.mtu = ctx->dev_attr.port_attr[0].active_mtu;
        ctx->user_tp[i].attr.cc_pattern_idx = 0;
        ctx->user_tp[i].attr.oos_cnt = ctx->dev_attr.dev_cap.max_oor_cnt;
        ctx->user_tp[i].attr.local_net_addr_idx = net_addr.index;
        ctx->user_tp[i].attr.data_udp_start = rand();
        ctx->user_tp[i].attr.ack_udp_start = rand();
        ctx->user_tp[i].attr.udp_range = 0;
        ctx->user_tp[i].attr.hop_limit = PERFTEST_DEF_HOP_LIMIT;
        ctx->user_tp[i].attr.flow_label = net_addr.netaddr.sin_family == AF_INET ? 0 : (uint32_t)rand();
        ctx->user_tp[i].attr.port_id = 0;
        ctx->user_tp[i].attr.mn = ctx->dev_attr.dev_cap.mn;
        ctx->user_tp[i].attr.peer_trans_type = cfg->tp_type;
    }

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(user_tp_ctx_t) * cfg->jettys, (char *)&ctx->user_tp[i],
            (char *)&ctx->remote_user_tp[i]) != 0) {
            (void)fprintf(stderr, "Failed to sync user tp info.\n");
            goto free_net_addr_list;
        }
        uint32_t net_addr_cnt = MIN(ctx->user_tp->net_addr_cnt, ctx->remote_user_tp[i].net_addr_cnt);
        if (net_addr_cnt == 0) {
            (void)fprintf(stderr, "net_addr_cnt == 0, local:%u, remote:%u.\n",
                ctx->user_tp[i].net_addr_cnt, ctx->remote_user_tp[i].net_addr_cnt);
            goto free_net_addr_list;
        }
        ctx->remote_user_tp[i].net_addr_list = calloc(1, sizeof(urma_net_addr_info_t) * net_addr_cnt);
        if (ctx->remote_user_tp[i].net_addr_list == NULL) {
            goto free_net_addr_list;
        }
        if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(urma_net_addr_info_t) * net_addr_cnt,
            (char *)ctx->user_tp[i].net_addr_list, (char *)ctx->remote_user_tp[i].net_addr_list) != 0) {
            (void)fprintf(stderr, "Failed to sync user tp info.\n");
            goto free_remote_net_addr_list;
        }
    }
    return 0;

free_remote_net_addr_list:
    free(ctx->remote_user_tp->net_addr_list);
free_net_addr_list:
    urma_free_net_addr_list(ctx->user_tp->net_addr_list);
free_remote_user_tp:
    free(ctx->remote_user_tp);
    ctx->remote_user_tp = NULL;
free_user_tp:
    free(ctx->user_tp);
    ctx->user_tp = NULL;
    return -1;
}

static void destroy_user_tp_info(perftest_context_t *ctx)
{
    free(ctx->remote_user_tp->net_addr_list);
    urma_free_net_addr_list(ctx->user_tp->net_addr_list);
    free(ctx->remote_user_tp);
    ctx->remote_user_tp = NULL;
    free(ctx->user_tp);
    ctx->user_tp = NULL;
}

static void negotiated_cc_algorithm(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i;
    for (i = 0; i < cfg->jettys; i++) {
        ctx->user_tp[i].attr.local_net_addr_idx = 0;
    }
    return;
}

static int modify_user_tp(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (fill_user_tp_info(ctx, cfg) != 0) {
        return -1;
    }

    urma_tp_attr_mask_t mask = {0};
    mask.value = 0xffffffff;
    urma_net_addr_info_t net_addr = {0};
    (void)find_net_addr_by_eid(ctx->remote_user_tp->net_addr_list, ctx->remote_user_tp->net_addr_cnt,
        ctx->remote_jetty[0]->jetty_id.eid, &net_addr);

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        uint32_t tpn = ctx->user_tp[i].attr.peer_tpn;
        ctx->user_tp[i].cfg.oor_cnt = MIN(ctx->remote_user_tp[i].cfg.oor_cnt, ctx->user_tp[i].cfg.oor_cnt);
        ctx->user_tp[i].attr.peer_tpn = ctx->remote_user_tp[i].attr.peer_tpn;
        ctx->user_tp[i].attr.mtu = MIN(ctx->remote_user_tp[i].attr.mtu, ctx->user_tp[i].attr.mtu);
        ctx->user_tp[i].attr.oos_cnt = MIN(ctx->remote_user_tp[i].attr.oos_cnt, ctx->user_tp[i].attr.oos_cnt);
        ctx->user_tp[i].attr.peer_net_addr = ctx->remote_user_tp[i].attr.peer_net_addr;
        ctx->user_tp[i].attr.mn = MIN(ctx->remote_user_tp[i].attr.mn, ctx->user_tp[i].attr.mn);
        ctx->user_tp[i].attr.peer_trans_type = ctx->remote_user_tp[i].attr.peer_trans_type;
        ctx->user_tp[i].attr.flag.bs.sr_en =
            ctx->remote_user_tp[i].attr.flag.bs.sr_en & ctx->user_tp[i].attr.flag.bs.sr_en;
        ctx->user_tp[i].attr.flag.bs.spray_en =
            ctx->remote_user_tp[i].attr.flag.bs.spray_en & ctx->user_tp[i].attr.flag.bs.spray_en;
        ctx->user_tp[i].attr.peer_net_addr = net_addr.netaddr;
        negotiated_cc_algorithm(ctx, cfg);

        if (urma_modify_tp(ctx->urma_ctx, tpn, &ctx->user_tp[i].cfg, &ctx->user_tp[i].attr, mask) != 0) {
            (void)fprintf(stderr, "Failed to modify_tp: %u.\n", i);
            goto free_remote_user_tp;
        }
    }
    destroy_user_tp_info(ctx);
    return 0;

free_remote_user_tp:
    destroy_user_tp_info(ctx);
    return -1;
}

static int create_duplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)memset(ctx, 0, sizeof(perftest_context_t));
    if (init_device(ctx, cfg) != 0) {
        return -1;
    }

    if (create_duplex_jettys(ctx, cfg) != 0) {
        goto uninit_dev;
    }

    if (register_mem(ctx, cfg) != 0) {
        goto delete_jettys;
    }

    if (cfg->enable_credit == true && create_credit_ctx(ctx, cfg) != 0) {
        goto unregister_mem;
    }

    if (exchange_duplex_info(ctx, cfg) != 0) {
        goto delete_credit_ctx;
    }

    if (import_seg_for_duplex(ctx, cfg) != 0) {
        goto delete_remote_info;
    }

    if (connect_jetty(ctx, cfg) != 0) {
        goto unimport_seg;
    }

    if (cfg->enable_user_tp && modify_user_tp(ctx, cfg)) {
        goto disconnect_jetty;
    }

    if (create_run_ctx(ctx, cfg) != 0) {
        goto destroy_user_tp;
    }

    return 0;

destroy_user_tp:
    if (cfg->enable_user_tp) {
        free(ctx->user_tp);
        free(ctx->remote_user_tp);
    }
disconnect_jetty:
    disconnect_jetty(ctx, cfg);
unimport_seg:
    unimport_seg(ctx, (int)ctx->jetty_num);
delete_remote_info:
    destroy_duplex_remote_info(ctx);
delete_credit_ctx:
    if (cfg->enable_credit == true) {
        destroy_credit_ctx(ctx, cfg);
    }
unregister_mem:
    unregister_mem(ctx, cfg);
delete_jettys:
    destroy_duplex_jettys(ctx, cfg);
uninit_dev:
    uninit_device(ctx);
    return -1;
}

int create_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return create_simplex_ctx(ctx, cfg);
    }
    return create_duplex_ctx(ctx, cfg);
}

static void destroy_simplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    destroy_run_ctx(ctx);
    disconnect_jfr(ctx, cfg);
    unimport_seg(ctx, (int)ctx->jetty_num);
    for (uint32_t i = 0; i < cfg->pair_num; i++) {
        (void)sync_time(cfg->comm.sock_fd[i], "unimport_jfr");
    }
    if (cfg->enable_credit == true) {
        unimport_credit(ctx, ctx->jetty_num);
    }
    destroy_simplex_remote_info(ctx);
    if (cfg->enable_credit == true) {
        destroy_credit_ctx(ctx, cfg);
    }
    unregister_mem(ctx, cfg);
    destroy_simplex_jettys(ctx, cfg);
    uninit_device(ctx);
    return;
}

static void destroy_duplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    destroy_run_ctx(ctx);
    if (cfg->enable_user_tp) {
        free(ctx->user_tp);
        free(ctx->remote_user_tp);
    }
    disconnect_jetty(ctx, cfg);
    for (uint32_t i = 0; i < cfg->pair_num; i++) {
        (void)sync_time(cfg->comm.sock_fd[i], "unimport_jetty");
    }
    if (cfg->enable_credit == true) {
        unimport_credit(ctx, ctx->jetty_num);
    }
    unimport_seg(ctx, (int)ctx->jetty_num);
    destroy_duplex_remote_info(ctx);
    if (cfg->enable_credit == true) {
        destroy_credit_ctx(ctx, cfg);
    }
    unregister_mem(ctx, cfg);
    destroy_duplex_jettys(ctx, cfg);
    uninit_device(ctx);
    return;
}

void destroy_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        destroy_simplex_ctx(ctx, cfg);
        return;
    }
    destroy_duplex_ctx(ctx, cfg);
}

static urma_status_t warm_up_post_send(perftest_context_t *ctx, uint32_t index, const perftest_config_t *cfg)
{
    urma_jfs_wr_t jfs_wr = ctx->run_ctx.jfs_wr[index * cfg->jfs_post_list];
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        jfs_wr.tjetty = ctx->import_tjfr[index];
    } else {
        jfs_wr.tjetty = ctx->import_tjetty[index];
    }
    jfs_wr.flag.bs.complete_enable = 1;
    jfs_wr.next = NULL;

    urma_jfs_wr_t *bad_wr = NULL;
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return urma_post_jfs_wr(ctx->jfs[index], &jfs_wr, &bad_wr);
    }
    return urma_post_jetty_send_wr(ctx->jetty[index], &jfs_wr, &bad_wr);
}

int perform_warm_up(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t warmupsession, warmindex;
    urma_cr_t cr;
    urma_status_t status;

    warmupsession = (cfg->jfs_post_list == 1) ? cfg->jfs_depth : cfg->jfs_post_list;
    urma_cr_t *cr_for_cleaning = (urma_cr_t *)calloc(1, sizeof(urma_cr_t) * cfg->jfs_depth);
    if (cr_for_cleaning == NULL) {
        return -1;
    }

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        (void)urma_poll_jfc(ctx->jfc_s[i], (int)cfg->jfs_depth, cr_for_cleaning);
        for (warmindex = 0; warmindex < warmupsession; warmindex += cfg->jfs_post_list) {
            status = warm_up_post_send(ctx, i, cfg);
            if (status) {
                (void)fprintf(stderr, "Failed to post send during warm up: index: %u, warmindex: %u, "
                "status: %d.\n", i, warmindex, (int)status);
                free(cr_for_cleaning);
                return -1;
            }
        }
        do {
            int poll_cnt = urma_poll_jfc(ctx->jfc_s[i], 1, &cr);
            if (poll_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed to poll jfc, status: %d.\n", (int)cr.status);
                    free(cr_for_cleaning);
                    return -1;
                }
                warmindex -= cfg->jfs_post_list;
            } else if (poll_cnt < 0) {
                free(cr_for_cleaning);
                return -1;
            }
        } while (warmindex);
    }
    free(cr_for_cleaning);
    return 0;
}
