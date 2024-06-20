/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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

#include "urma_api.h"
#include "perftest_resources.h"

#define PERFTEST_DEF_ACCESS (URMA_ACCESS_LOCAL_WRITE | URMA_ACCESS_REMOTE_READ | \
                        URMA_ACCESS_REMOTE_WRITE | URMA_ACCESS_REMOTE_ATOMIC)

#define PERFTEST_DEF_UM_MAX_SGE (2) /* there is one more sge in IB UD mode */

static urma_token_t g_perftest_token = {
    .token = 0xABCDEF,
};

static void check_device_inline(perftest_config_t *cfg)
{
    uint32_t default_inline = 0;
    uint32_t expect_inline = 0;
    if (cfg->tp_type == URMA_TRANSPORT_IB || cfg->tp_type == URMA_TRANSPORT_HNS_UB ||
        cfg->tp_type == URMA_TRANSPORT_UB) {
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

    if (cfg->tp_type == URMA_TRANSPORT_IP || cfg->inline_size == default_inline) {
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

    /* URMA_TRANSPORT_IP only support share_jfr */
    if (urma_dev->type == URMA_TRANSPORT_IP && cfg->share_jfr == true) {
        cfg->share_jfr = false;
    }

    /* Current, UM of URMA_TRANSPORT_IB only support share_jfr */
    if ((urma_dev->type == URMA_TRANSPORT_IB || urma_dev->type == URMA_TRANSPORT_HNS_UB) &&
        cfg->trans_mode == URMA_TM_UM &&
        cfg->share_jfr == true) {
        cfg->share_jfr = false;
    }

    // share_jfr updated, check realted cfg
    if (cfg->share_jfr && cfg->jfr_depth < cfg->jettys * cfg->jfr_post_list) {
        (void)fprintf(stderr, "Using share jfr depth should be greater than number of Jettys * jfr_post_list.\n");
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
        (void)fprintf(stderr, "urma get device by name failed!\n");
        goto uninit;
    }

    if (urma_query_device(urma_dev, &ctx->dev_attr) != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to query device, name: %s.\n", cfg->dev_name);
        goto uninit;
    }
    ctx->urma_ctx = urma_create_context(urma_dev, cfg->eid_idx);
    if (ctx->urma_ctx == NULL) {
        (void)fprintf(stderr, "Failed to create urma instance!\n");
        goto uninit;
    }
    bool jfc_inline = (bool)ctx->dev_attr.dev_cap.feature.bs.jfc_inline;
    if (cfg->jfc_inline && (!jfc_inline)) {
        (void)printf("Warning: device NOT support jfc_inline.\n");
        cfg->jfc_inline = false;
    }
    if (check_share_jfr(cfg, urma_dev) != 0) {
        goto del_ctx;
    }

    cfg->tp_type = urma_dev->type;
    check_device_inline(cfg);
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

static void adjust_jfc_depth(perftest_config_t *cfg, bool is_tx)
{
    /* Adjustment of jfc_depth, only for ub mode */
    if (cfg->tp_type != URMA_TRANSPORT_UB && cfg->tp_type != URMA_TRANSPORT_HNS_UB) {
        return;
    }
    uint32_t jetty_depth = is_tx ? cfg->jfs_depth : cfg->jfr_depth;
    uint32_t target_depth = cfg->jettys * jetty_depth + cfg->jettys;
    /* This adjustment may lead to create jfc failure, so jfc_depth should be as output for this error */
    cfg->jfc_depth = cfg->jfc_depth > target_depth ? cfg->jfc_depth : target_depth;
    if (is_tx) {
        (void)printf("Warning: Tx jfc_depth adjusted into %u due to jfs_depth and jettys.\n", cfg->jfc_depth);
        cfg->jfc_cfg.tx_jfc_depth = cfg->jfc_depth;
    } else {
        (void)printf("Warning: Rx jfc_depth adjusted into %u due to jfr_depth and jettys.\n", cfg->jfc_depth);
        cfg->jfc_cfg.rx_jfc_depth = cfg->jfc_depth;
    }
}

static int create_jfc(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->use_jfce == true) {
        ctx->jfce_s = urma_create_jfce(ctx->urma_ctx);
        if (ctx->jfce_s == NULL) {
            (void)fprintf(stderr, "Failed to create jfce_s!\n");
            return -1;
        }

        ctx->jfce_r = urma_create_jfce(ctx->urma_ctx);
        if (ctx->jfce_r == NULL) {
            (void)fprintf(stderr, "Failed to create jfce_r!\n");
            goto delete_jfce_s;
        }
    }
    /* too large jfc_depth may lead to create_jfc failure in ip mode */
    if (cfg->tp_type == URMA_TRANSPORT_IP) {
        cfg->jfc_depth = PERFTEST_DEF_JFC_DEPTH_BW_IP;
    }
    adjust_jfc_depth(cfg, true);
    urma_jfc_cfg_t jfc_cfg = {
        .depth = cfg->jfc_depth,
        .flag = {.value = 0},
        .jfce = NULL,
        .user_ctx = (uint64_t)NULL,
    };
    jfc_cfg.flag.bs.lock_free = cfg->lock_free ? 1 : 0;
    if (cfg->jfc_inline) {
        jfc_cfg.flag.bs.jfc_inline = 1;
    }

    jfc_cfg.jfce = cfg->use_jfce == true ? ctx->jfce_s : NULL;
    ctx->jfc_s = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
    if (ctx->jfc_s == NULL) {
        (void)fprintf(stderr, "Failed to create jfc_s, tx jfc_depth: %u.\n", cfg->jfc_depth);
        goto delete_jfce_r;
    }

    adjust_jfc_depth(cfg, false);
    jfc_cfg.depth = cfg->jfc_depth;
    jfc_cfg.jfce = cfg->use_jfce == true ? ctx->jfce_r : NULL;
    ctx->jfc_r = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
    if (ctx->jfc_r == NULL) {
        (void)fprintf(stderr, "Failed to create jfc_r, rx jfc_depth: %u.\n", cfg->jfc_depth);
        goto delete_jfc_s;
    }

    return 0;
delete_jfc_s:
    (void)urma_delete_jfc(ctx->jfc_s);
delete_jfce_r:
    (void)urma_delete_jfce(ctx->jfce_r);
delete_jfce_s:
    (void)urma_delete_jfce(ctx->jfce_s);
    return -1;
}

static inline void destroy_jfc(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    (void)urma_delete_jfc(ctx->jfc_r);
    (void)urma_delete_jfc(ctx->jfc_s);
    if (cfg->use_jfce == true) {
        (void)urma_delete_jfce(ctx->jfce_r);
        (void)urma_delete_jfce(ctx->jfce_s);
    }
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
    int i;
    uint32_t jfs_max_inline_data;

    jfs_max_inline_data = cfg->inline_size;
    if (jfs_max_inline_data > ctx->dev_attr.dev_cap.max_jfs_inline_len) {
        (void)fprintf(stderr, "Failed parameter, jfs_max_inline_data %u exceeds the device max_inline_data %u\n",
            jfs_max_inline_data, ctx->dev_attr.dev_cap.max_jfs_inline_len);
        return -1;
    }

    urma_jfs_cfg_t jfs_cfg = {
        .depth = cfg->jfs_depth,
        .flag.bs.lock_free = cfg->lock_free ? 1 : 0,
        .trans_mode = cfg->trans_mode,
        .priority = cfg->priority, /* Highest priority */
        .max_sge = 1,
        .max_inline_data = jfs_max_inline_data,
        .rnr_retry = URMA_TYPICAL_RNR_RETRY,
        .err_timeout = cfg->err_timeout,
        .jfc = ctx->jfc_s,
        .user_ctx = (uint64_t)NULL
    };
    if (cfg->trans_mode == URMA_TM_UM &&
        (cfg->tp_type == URMA_TRANSPORT_IB || cfg->tp_type == URMA_TRANSPORT_HNS_UB)) {
        jfs_cfg.max_sge = PERFTEST_DEF_UM_MAX_SGE;
    }

    ctx->jfs = calloc(1, sizeof(urma_jfs_t *) * cfg->jettys);
    if (ctx->jfs == NULL) {
        return -ENOMEM;
    }

    for (i = 0; i < (int)cfg->jettys; i++) {
        ctx->jfs[i] = urma_create_jfs(ctx->urma_ctx, &jfs_cfg);
        if (ctx->jfs[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfs, loop:%d!\n", i);
            goto delete_jfs;
        }
    }

    return 0;

delete_jfs:
    destroy_jfs(ctx, i);
    return -1;
}

static inline void destroy_jfr(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_delete_jfr(ctx->jfr[k]);
    }

    free(ctx->jfr);
}

static int create_jfr(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    int i;
    urma_jfr_cfg_t jfr_cfg = {
        .depth = cfg->jfr_depth,
        .flag.bs.tag_matching = URMA_NO_TAG_MATCHING,
        .flag.bs.lock_free = cfg->lock_free ? 1 : 0,
        .trans_mode = cfg->trans_mode,
        .min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER,
        .max_sge = 1,
        .jfc = ctx->jfc_r,
        .token_value = g_perftest_token,
        .id = 0,
        .user_ctx = (uint64_t)NULL
    };
    if (cfg->trans_mode == URMA_TM_UM &&
        (cfg->tp_type == URMA_TRANSPORT_IB || cfg->tp_type == URMA_TRANSPORT_HNS_UB)) {
        jfr_cfg.max_sge = PERFTEST_DEF_UM_MAX_SGE;
    }

    ctx->jfr = calloc(1, sizeof(urma_jfr_t *) * cfg->jettys);
    if (ctx->jfr == NULL) {
        return -ENOMEM;
    }

    for (i = 0; i < (int)cfg->jettys; i++) {
        ctx->jfr[i] = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
        if (ctx->jfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jfr, loop:%d!\n", i);
            goto delete_jfr;
        }
    }

    return 0;

delete_jfr:
    destroy_jfr(ctx, i);
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
    jfs_cfg->jfc = ctx->jfc_s;
    jfs_cfg->user_ctx = (uint64_t)NULL;
    if (cfg->trans_mode == URMA_TM_UM &&
        (cfg->tp_type == URMA_TRANSPORT_IB || cfg->tp_type == URMA_TRANSPORT_HNS_UB)) {
        jfs_cfg->max_sge = PERFTEST_DEF_UM_MAX_SGE;
        jfs_cfg->max_rsge = 1;
    }
    jfs_cfg->flag.bs.sub_trans_mode = cfg->sub_trans_mode;
    if (jfs_cfg->trans_mode == URMA_TM_RC &&
        (jfs_cfg->flag.bs.sub_trans_mode & URMA_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE)) {
        jfs_cfg->flag.bs.rc_share_tp = 1;
    }
}

static void fill_jfr_cfg(perftest_context_t *ctx, const perftest_config_t *cfg, urma_jfr_cfg_t *jfr_cfg)
{
    jfr_cfg->depth = cfg->jfr_depth;
    jfr_cfg->flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    jfr_cfg->flag.bs.lock_free = cfg->lock_free ? 1 : 0;
    jfr_cfg->trans_mode = cfg->trans_mode;
    jfr_cfg->flag.bs.sub_trans_mode = cfg->sub_trans_mode;
    jfr_cfg->min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg->max_sge = 1;
    jfr_cfg->jfc = ctx->jfc_r;
    jfr_cfg->token_value = g_perftest_token;
    jfr_cfg->id = 0;
    if (cfg->trans_mode == URMA_TM_UM &&
        (cfg->tp_type == URMA_TRANSPORT_IB || cfg->tp_type == URMA_TRANSPORT_HNS_UB)) {
        jfr_cfg->max_sge = PERFTEST_DEF_UM_MAX_SGE;
    }
}

static inline void destroy_jetty(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_delete_jetty(ctx->jetty[k]);
    }
    free(ctx->jetty);
    ctx->jetty = NULL;
}

static int create_jetty(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    int i, j = 0, k;
    uint32_t jfr_num = cfg->jettys / cfg->jettys_pre_jfr;
    urma_jetty_flag_t jetty_flag = {0};
    uint32_t jfs_max_inline_data = cfg->inline_size;
    if (jfs_max_inline_data > ctx->dev_attr.dev_cap.max_jfs_inline_len) {
        (void)fprintf(stderr, "Failed parameter, jfs_max_inline_data %u exceeds the device max_inline_data %u\n",
            jfs_max_inline_data, ctx->dev_attr.dev_cap.max_jfs_inline_len);
        return -1;
    }
    urma_jfs_cfg_t jfs_cfg = { 0 };
    fill_jfs_cfg(ctx, cfg, jfs_max_inline_data, &jfs_cfg);

    /* Independent jfr_cfg, no shared_jfr */
    urma_jfr_cfg_t jfr_cfg = { 0 };
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
            ctx->jfr[j] = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
            if (ctx->jfr[j] == NULL) {
                (void)fprintf(stderr, "Failed to create share_jfr, %u!\n", j);
                goto err_delete_jfr;
            }
        }
        jetty_flag.bs.share_jfr = 1;
        jetty_cfg.flag = jetty_flag;
        jetty_cfg.jfs_cfg = jfs_cfg;
        jetty_cfg.shared.jfc = ctx->jfc_r;
    }
    ctx->jetty = calloc(1, sizeof(urma_jetty_t *) * cfg->jettys);
    if (ctx->jetty == NULL) {
        goto err_delete_jfr;
    }
    for (i = 0; i < (int)cfg->jettys; i++) {
        if (cfg->share_jfr == true) {
            jetty_cfg.shared.jfr = ctx->jfr[i / cfg->jettys_pre_jfr];
        }
        ctx->jetty[i] = urma_create_jetty(ctx->urma_ctx, &jetty_cfg);
        if (ctx->jetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to create jetty, loop:%d!\n", i);
            goto err_delete_jetty;
        }
    }

    return 0;
err_delete_jetty:
    destroy_jetty(ctx, i);
err_delete_jfr:
    if (cfg->share_jfr == true) {
        for (k = 0; k < j; k++) {
            (void)urma_delete_jfr(ctx->jfr[k]);
        }
        free(ctx->jfr);
        ctx->jfr = NULL;
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

    destroy_jetty(ctx, (int)ctx->jetty_num);
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
    for (int k = 0; k < idx; k++) {
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
    for (int k = 0; k < idx; k++) {
        if (k < seg_num) {
            (void)urma_free_token_id(ctx->token_id[k]);
        }
    }
    free(ctx->token_id);
    ctx->token_id = NULL;
}

static inline void free_memory(perftest_context_t *ctx, const perftest_config_t *cfg, const int idx)
{
    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;
    for (int j = 0; j < idx; j++) {
        if (j < seg_num) {
            free(ctx->local_buf[j]);
        }
    }
    free(ctx->local_buf);
    ctx->local_buf = NULL;
}

static int register_mem(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i = 0, j = 0, k = 0;
    ctx->local_buf = calloc(1, sizeof(void *) * cfg->jettys);
    if (ctx->local_buf == NULL) {
        return -ENOMEM;
    }

    uint32_t seg_num = (cfg->seg_pre_jetty == false) ? 1 : cfg->jettys;

    ctx->page_size = cfg->page_size;

    // holds the size of maximum between cfg->size and page_size, aligned to cache line.
    uint64_t max_size = MAX(cfg->size, ctx->page_size);
    ctx->buf_size = PERFTEST_ALIGN_CACHELINE(max_size, cfg->cache_line_size);
    // Buff is divided into two parts, one for recv and the other for send
    ctx->buf_len = ctx->buf_size * PERFTEST_BUF_NUM *
        ((cfg->seg_pre_jetty == true) ? 1 : cfg->jettys);

    for (i = 0; i < (int)cfg->jettys; i++) {
        if (i < seg_num) {
            ctx->local_buf[i] = memalign(ctx->page_size, ctx->buf_len);
        } else {
            ctx->local_buf[i] = ctx->local_buf[0];
        }
        if (ctx->local_buf[i] == NULL) {
            (void)fprintf(stderr, "Failed to memalign local buff, loop:%d!\n", i);
            goto free_memory;
        }
    }

    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        ctx->token_id = calloc(1, sizeof(urma_token_id_t *) * cfg->jettys);
        if (ctx->token_id == NULL) {
            goto free_memory;
        }
        for (k = 0; k < (int)cfg->jettys; k++) {
            if (k < seg_num) {
                ctx->token_id[k] = urma_alloc_token_id(ctx->urma_ctx);
            } else {
                ctx->token_id[k] = ctx->token_id[0];
            }
            if (ctx->token_id[k] == NULL) {
                (void)fprintf(stderr, "Failed to alloc token id, loop:%d!\n", k);
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
    for (j = 0; j < (int)cfg->jettys; j++) {
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
            (void)fprintf(stderr, "Failed to register seg, loop:%d!\n", j);
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

static inline void free_credit_info(perftest_context_t *ctx, const int idx)
{
    if (ctx->remote_credit_seg != NULL) {
        free(ctx->remote_credit_seg);
    }
}

static int exchange_seg_info(perftest_context_t *ctx, perftest_comm_t *comm)
{
    int i;
    ctx->remote_seg = calloc(1, sizeof(urma_seg_t *) * ctx->jetty_num);
    if (ctx->remote_seg == NULL) {
        return -1;
    }

    for (i = 0; i < (int)ctx->jetty_num; i++) {
        ctx->remote_seg[i] = calloc(1, sizeof(urma_seg_t));
        if (ctx->remote_seg[i] == NULL) {
            goto free_remote_seg_buf;
        }
        if (sock_sync_data(comm->sock_fd, sizeof(urma_seg_t), (char *)&ctx->local_tseg[i]->seg,
            (char *)ctx->remote_seg[i]) != 0) {
            (void)fprintf(stderr, "Failed to sync seg, loop:%d!\n", i);
            goto free_remote_seg_buf;
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

static int exchange_jfr_info(perftest_context_t *ctx, perftest_comm_t *comm)
{
    int i;
    ctx->remote_jfr = calloc(1, sizeof(urma_jfr_t *) * ctx->jetty_num);
    if (ctx->remote_jfr == NULL) {
        return -1;
    }

    for (i = 0; i < (int)ctx->jetty_num; i++) {
        ctx->remote_jfr[i] = calloc(1, sizeof(urma_jfr_t));
        if (ctx->remote_jfr[i] == NULL) {
            goto free_remote_jfr_buf;
        }
        if (sock_sync_data(comm->sock_fd, sizeof(urma_jfr_t), (char *)ctx->jfr[i],
            (char *)ctx->remote_jfr[i]) != 0) {
            (void)fprintf(stderr, "Failed to sync jfr, loop:%d!\n", i);
            goto free_remote_jfr_buf;
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

static int exchange_jetty_info(perftest_context_t *ctx, perftest_comm_t *comm)
{
    int i;
    ctx->remote_jetty = calloc(1, sizeof(urma_jetty_t *) * ctx->jetty_num);
    if (ctx->remote_jetty == NULL) {
        return -1;
    }
    for (i = 0; i < (int)ctx->jetty_num; i++) {
        ctx->remote_jetty[i] = calloc(1, sizeof(urma_jetty_t));
        if (ctx->remote_jetty[i] == NULL) {
            goto free_remote_jetty_buf;
        }
        if (sock_sync_data(comm->sock_fd, sizeof(urma_jetty_t), (char *)ctx->jetty[i],
            (char *)ctx->remote_jetty[i]) != 0) {
            (void)fprintf(stderr, "Failed to sync jetty, loop:%d!\n", i);
            goto free_remote_jetty_buf;
        }
    }
    return 0;

free_remote_jetty_buf:
    free_remote_jetty(ctx, i);
    return -1;
}

static int exchange_credit_info(perftest_context_t *ctx, perftest_comm_t *comm)
{
        ctx->remote_credit_seg = calloc(1, sizeof(urma_seg_t));
        if (ctx->remote_credit_seg == NULL) {
            return -1;
        }
        if (sock_sync_data(comm->sock_fd, sizeof(urma_seg_t), (char *)&ctx->credit_seg->seg,
            (char *)ctx->remote_credit_seg) != 0) {
            (void)fprintf(stderr, "Failed to sync credit_seg!\n");
            free(ctx->remote_credit_seg);
            return -1;
        }
    return 0;
}

static int exchange_simplex_info(perftest_context_t *ctx, perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;
    int ret = exchange_seg_info(ctx, comm);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_seg_info, ret: %d\n", ret);
        return -1;
    }
    ret = exchange_jfr_info(ctx, comm);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_jfr_info, ret: %d\n", ret);
        free_remote_seg(ctx, (int)ctx->jetty_num);
        return -1;
    }
    return 0;
}

static int exchange_duplex_info(perftest_context_t *ctx, perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;
    int ret = exchange_seg_info(ctx, comm);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_seg_info, ret: %d\n", ret);
        return -1;
    }
    ret = exchange_jetty_info(ctx, comm);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to exchange_jetty_info, ret: %d\n", ret);
        free_remote_seg(ctx, (int)ctx->jetty_num);
        return -1;
    }
    if (cfg->enable_credit == true) {
        ret = exchange_credit_info(ctx, comm);
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
    free_credit_info(ctx, (int)ctx->jetty_num);
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

static int import_seg_for_simplex(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i;

    ctx->import_tseg = calloc(1, sizeof(urma_target_seg_t *) * ctx->jetty_num);
    if (ctx->import_tseg == NULL) {
        return -1;
    }

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_LOCAL_WRITE | URMA_ACCESS_REMOTE_READ |
            URMA_ACCESS_REMOTE_WRITE | URMA_ACCESS_REMOTE_ATOMIC,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0
    };

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
    return -1;
}

static int import_seg_for_duplex(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i;

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_LOCAL_WRITE | URMA_ACCESS_REMOTE_READ |
            URMA_ACCESS_REMOTE_WRITE | URMA_ACCESS_REMOTE_ATOMIC,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0
    };

    if (cfg->enable_credit == true) {
        ctx->import_credit_seg = urma_import_seg(ctx->urma_ctx, ctx->remote_credit_seg, &g_perftest_token, 0, flag);
        if (ctx->import_credit_seg == NULL) {
            (void)fprintf(stderr, "Failed to import credit seg!\n");
            return -ENOMEM;
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
        (void)urma_unimport_seg(ctx->import_credit_seg);
    }
    return -1;
}

static inline void unadvise_jfr(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_unadvise_jfr(ctx->jfs[k], ctx->import_tjfr[k]);
    }
}

static inline void unimport_jfr(perftest_context_t *ctx, const int idx)
{
    for (int k = 0; k < idx; k++) {
        (void)urma_unimport_jfr(ctx->import_tjfr[k]);
    }
    free(ctx->import_tjfr);
    ctx->import_tjfr = NULL;
}

static int import_jfr(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    int i;
    urma_status_t ret;

    ctx->import_tjfr = calloc(1, sizeof(urma_target_jetty_t *) * ctx->jetty_num);
    if (ctx->import_tjfr == NULL) {
        return -1;
    }

    urma_rjfr_t rjfr;
    rjfr.flag.value = 0;
    for (i = 0; i < (int)ctx->jetty_num; i++) {
        rjfr.jfr_id = ctx->remote_jfr[i]->jfr_id;
        rjfr.trans_mode = ctx->remote_jfr[i]->jfr_cfg.trans_mode;
        ctx->import_tjfr[i] = urma_import_jfr(ctx->urma_ctx, &rjfr, &g_perftest_token);
        if (ctx->import_tjfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jfr, loop:%d!\n", i);
            goto unimp_jfr;
        }
        // advise_jfr not called for UM mode
        if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            ret = urma_advise_jfr(ctx->jfs[i], ctx->import_tjfr[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to advise jfr, loop:%d!\n", i);
                i++;
                goto unadvise_jfr;
            }
        }
    }

    return 0;
unadvise_jfr:
    /* in this error branch [i > 0] */
    if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        unadvise_jfr(ctx, i - 1);
    }
unimp_jfr:
    unimport_jfr(ctx, i);
    return -1;
}

static inline void unbind_jetty(perftest_context_t *ctx, const int idx)
{
    for (int jetty_idx = 0; jetty_idx < idx; jetty_idx++) {
        (void)urma_unbind_jetty(ctx->jetty[jetty_idx]);
    }
}

static inline void unadvise_jetty(perftest_context_t *ctx, const int idx)
{
    for (int jetty_idx = 0; jetty_idx < idx; jetty_idx++) {
        (void)urma_unadvise_jetty(ctx->jetty[jetty_idx], ctx->import_tjetty[jetty_idx]);
    }
}

static inline void unimport_jetty(perftest_context_t *ctx, const int idx)
{
    for (int jetty_idx = 0; jetty_idx < idx; jetty_idx++) {
        (void)urma_unimport_jetty(ctx->import_tjetty[jetty_idx]);
    }
    free(ctx->import_tjetty);
    ctx->import_tjetty = NULL;
}

static int import_jetty(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i, k;
    urma_status_t ret;

    ctx->import_tjetty = calloc(1, sizeof(urma_target_jetty_t *) * ctx->jetty_num);
    if (ctx->import_tjetty == NULL) {
        return -1;
    }
    urma_rjetty_t rjetty = {0};
    for (i = 0; i < (int)ctx->jetty_num; i++) {
        rjetty.jetty_id = ctx->remote_jetty[i]->jetty_id;
        rjetty.trans_mode = cfg->trans_mode;
        rjetty.type = URMA_JETTY;
        rjetty.flag.bs.sub_trans_mode = cfg->sub_trans_mode;
        if (rjetty.trans_mode == URMA_TM_RC &&
            (rjetty.flag.bs.sub_trans_mode & URMA_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE)) {
            rjetty.flag.bs.rc_share_tp = 1;
        }
        ctx->import_tjetty[i] = urma_import_jetty(ctx->urma_ctx, &rjetty, &g_perftest_token);
        if (ctx->import_tjetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to import jetty, loop:%d!\n", i);
            goto unimp_jetty;
        }
        // import_jetty not called for UM mode
        if (cfg->trans_mode == URMA_TM_RC) {
            ret = urma_bind_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to bind jetty, loop:%d!\n", i);
                k = i++;
                goto disconn_jetty;
            }
        } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
            ret = urma_advise_jetty(ctx->jetty[i], ctx->import_tjetty[i]);
            if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
                (void)fprintf(stderr, "Failed to advise jetty, loop:%d, trans_mode: %d.\n", i,
                    (int)cfg->trans_mode);
                k = i++;
                goto disconn_jetty;
            }
        }
    }

    return 0;
disconn_jetty:
    // only unimport_jetty for UM mode
    if (cfg->trans_mode == URMA_TM_RC) {
        unbind_jetty(ctx, k);
    } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        unadvise_jetty(ctx, k);
    }
unimp_jetty:
    unimport_jetty(ctx, i);
    return -1;
}

static inline void force_unimport_jetty(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    // only unimport_jetty for UM mode
    if (cfg->trans_mode == URMA_TM_RC) {
        unbind_jetty(ctx, (int)ctx->jetty_num);
    } else if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        unadvise_jetty(ctx, (int)ctx->jetty_num);
    }

    unimport_jetty(ctx, (int)ctx->jetty_num);
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
    urma_unregister_seg(ctx->credit_seg);
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        urma_free_token_id(ctx->credit_token_id);
    }
    free(ctx->ctrl_buf);
}

static int create_credit_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int buf_size = 2 * cfg->jettys * sizeof(uint64_t);

    ctx->ctrl_buf = (uint64_t *)calloc(1, buf_size);
    if (ctx->ctrl_buf == NULL) {
        return -1;
    }
    ctx->credit_buf = ctx->ctrl_buf + cfg->jettys;

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = cfg->token_policy,
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = PERFTEST_DEF_ACCESS,
        .bs.token_id_valid = URMA_TOKEN_ID_VALID,
        .bs.reserved = 0
    };
    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)ctx->ctrl_buf,
        .len = buf_size,
        .token_value = g_perftest_token,
        .flag = flag,
        .user_ctx = (uintptr_t)NULL,
        .iova = 0
    };

    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        ctx->credit_token_id = urma_alloc_token_id(ctx->urma_ctx);
        if (ctx->credit_token_id == NULL) {
            goto free_buf;
        }
        seg_cfg.token_id = ctx->credit_token_id;
    }

    ctx->credit_seg = urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (ctx->credit_seg == NULL) {
        goto free_token_id;
    }
    return 0;

free_token_id:
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        urma_free_token_id(ctx->credit_token_id);
    }
free_buf:
    free(ctx->ctrl_buf);
    return -1;
}

static int create_simplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    memset(ctx, 0, sizeof(perftest_context_t));
    if (init_device(ctx, cfg) != 0) {
        return -1;
    }

    if (create_simplex_jettys(ctx, cfg) != 0) {
        goto uninit_dev_simp;
    }

    if (register_mem(ctx, cfg) != 0) {
        goto delete_jettys_simp;
    }
    if (exchange_simplex_info(ctx, cfg) != 0) {
        goto unreg_mem_simp;
    }
    if (import_seg_for_simplex(ctx, cfg) != 0) {
        goto delete_remote_info_simp;
    }

    if (import_jfr(ctx, cfg) != 0) {
        goto unimp_seg_simp;
    }

    if (create_run_ctx(ctx, cfg) != 0) {
        goto unimp_jfr_simp;
    }
    return 0;
unimp_jfr_simp:
    if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        unadvise_jfr(ctx, (int)ctx->jetty_num);
    }
    unimport_jfr(ctx, (int)ctx->jetty_num);
unimp_seg_simp:
    unimport_seg(ctx, (int)ctx->jetty_num);
delete_remote_info_simp:
    destroy_simplex_remote_info(ctx);
unreg_mem_simp:
    unregister_mem(ctx, cfg);
delete_jettys_simp:
    destroy_simplex_jettys(ctx, cfg);
uninit_dev_simp:
    uninit_device(ctx);
    return -1;
}

static int create_duplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    memset(ctx, 0, sizeof(perftest_context_t));
    if (init_device(ctx, cfg) != 0) {
        return -1;
    }

    if (create_duplex_jettys(ctx, cfg) != 0) {
        goto uninit_dev_dup;
    }

    if (register_mem(ctx, cfg) != 0) {
        goto delete_jettys_dup;
    }

    if (cfg->enable_credit == true && create_credit_ctx(ctx, cfg) != 0) {
        goto unreg_mem_dup;
    }

    if (exchange_duplex_info(ctx, cfg) != 0) {
        goto delete_credit_ctx;
    }

    if (import_seg_for_duplex(ctx, cfg) != 0) {
        goto delete_remote_info_dup;
    }

    if (import_jetty(ctx, cfg) != 0) {
        goto unimp_seg_dup;
    }

    if (create_run_ctx(ctx, cfg) != 0) {
        goto unimp_jetty_dup;
    }

    return 0;

unimp_jetty_dup:
    force_unimport_jetty(ctx, cfg);
unimp_seg_dup:
    unimport_seg(ctx, (int)ctx->jetty_num);
delete_remote_info_dup:
    destroy_duplex_remote_info(ctx);
delete_credit_ctx:
    if (cfg->enable_credit == true) {
        destroy_credit_ctx(ctx, cfg);
    }
unreg_mem_dup:
    unregister_mem(ctx, cfg);
delete_jettys_dup:
    destroy_duplex_jettys(ctx, cfg);
uninit_dev_dup:
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
    if (cfg->trans_mode == URMA_TM_RM && ctx->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        unadvise_jfr(ctx, (int)ctx->jetty_num);
    }
    unimport_jfr(ctx, (int)ctx->jetty_num);
    unimport_seg(ctx, (int)ctx->jetty_num);
    (void)sync_time(cfg->comm.sock_fd, "unimport_jfr");
    destroy_simplex_remote_info(ctx);
    unregister_mem(ctx, cfg);
    destroy_simplex_jettys(ctx, cfg);
    uninit_device(ctx);
    return;
}

static void destroy_duplex_ctx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    destroy_run_ctx(ctx);
    force_unimport_jetty(ctx, cfg);
    (void)sync_time(cfg->comm.sock_fd, "unimport_jetty");
    if (cfg->enable_credit == true) {
        (void)urma_unimport_seg(ctx->import_credit_seg);
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
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfs_wr_t jfs_wr;
    (void)memcpy(&jfs_wr, &run_ctx->jfs_wr[index * cfg->jfs_post_list], sizeof(urma_jfs_wr_t));
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        jfs_wr.tjetty = ctx->import_tjfr[index];
    } else {
        jfs_wr.tjetty = ctx->import_tjetty[index];
    }
    jfs_wr.flag.bs.complete_enable = 1;
    urma_jfs_wr_t *bad_wr = NULL;
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return urma_post_jfs_wr(ctx->jfs[index], &jfs_wr, &bad_wr);
    }
    return urma_post_jetty_send_wr(ctx->jetty[index], &jfs_wr, &bad_wr);
}

int perform_warm_up(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int poll_cnt;
    uint32_t warmupsession, index, warmindex;
    urma_cr_t cr;
    urma_cr_t *cr_for_cleaning = NULL;
    uint32_t num_of_jettys = cfg->jettys;
    urma_status_t status;

    warmupsession = (cfg->jfs_post_list == 1) ? cfg->jfs_depth : cfg->jfs_post_list;
    cr_for_cleaning = (urma_cr_t *)calloc(1, sizeof(urma_cr_t) * cfg->jfs_depth);
    if (cr_for_cleaning == NULL) {
        return -1;
    }

    poll_cnt = urma_poll_jfc(ctx->jfc_s, (int)cfg->jfs_depth, cr_for_cleaning);
    for (index = 0; index < num_of_jettys; index++) {
        for (warmindex = 0; warmindex < warmupsession; warmindex += cfg->jfs_post_list) {
            status = warm_up_post_send(ctx, index, cfg);
            if (status) {
                (void)fprintf(stderr, "Failed to post send during warm up: index: %u, warmindex: %u, "
                "status: %d.\n", index, warmindex, (int)status);
                free(cr_for_cleaning);
                return -1;
            }
        }
        do {
            poll_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
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
