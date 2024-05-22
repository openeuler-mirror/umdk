/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: resource operation for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2024-01-31   create file
 */
#include "urma_api.h"
#include "tp_test_comm.h"
#include "tp_test_res.h"

#define TP_TEST_DEFAULT_DEPTH 100

urma_token_t g_tp_test_token = {
    .token = 0xABCDEF,
};

static void destroy_urma_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i;
    for (i = 0; i < ctx->ctx_num; i++) {
        (void)urma_delete_context(ctx->urma_ctx[i]);
    }
    free(ctx->urma_ctx);
    ctx->urma_ctx = NULL;
    (void)urma_uninit();
}

static int create_urma_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;
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

    urma_device_t *urma_dev = urma_get_device_by_name(cfg->dev_name);
    if (urma_dev == NULL) {
        (void)fprintf(stderr, "urma get device by name failed!\n");
        goto uninit;
    }
    ctx->tp_type = urma_dev->type;

    if (urma_query_device(urma_dev, &ctx->dev_attr) != URMA_SUCCESS) {
        (void)fprintf(stderr, "Failed to query device, name: %s.\n", cfg->dev_name);
        goto uninit;
    }

    urma_eid_info_t *eid_list;
    uint32_t eid_cnt = 0;
    eid_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_cnt < cfg->eid_num) {
        (void)fprintf(stderr, "Number of EIDs is not enough, name: %s, eid_cnt:%u.\n",
            cfg->dev_name, eid_cnt);
        goto uninit;
    }

    ctx->ctx_num = cfg->eid_num * cfg->ctxs_pre_eid;
    ctx->urma_ctx = (urma_context_t **)calloc(1, sizeof(urma_context_t *) * ctx->ctx_num);
    if (ctx->urma_ctx == NULL) {
        goto free_eid_list;
    }
    for (i = 0; i < ctx->ctx_num; i++) {
        ctx->urma_ctx[i] = urma_create_context(urma_dev, eid_list[i / cfg->ctxs_pre_eid].eid_index);
        if (ctx->urma_ctx[i] == NULL) {
            (void)fprintf(stderr, "Failed to create urma instance!\n");
            goto delete_ctx;
        }
    }
    urma_free_eid_list(eid_list);
    return 0;

delete_ctx:
    for (j = 0; j < i; j++) {
        (void)urma_delete_context(ctx->urma_ctx[j]);
    }
    free(ctx->urma_ctx);
    ctx->urma_ctx = NULL;
free_eid_list:
    urma_free_eid_list(eid_list);
uninit:
    (void)urma_uninit();
    return -1;
}

static void destroy_jfc(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i;
    for (i = 0; i < ctx->jetty_num; i++) {
        (void)urma_delete_jfc(ctx->jfc[i]);
    }
    free(ctx->jfc);
    ctx->jfc = NULL;
}

static int create_jfc(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;
    urma_jfc_cfg_t jfc_cfg = {
        .depth = TP_TEST_DEFAULT_DEPTH,
        .flag = {.value = 0},
        .jfce = NULL,
        .user_ctx = (uint64_t)NULL,
    };

    ctx->jfc = (urma_jfc_t **)calloc(1, sizeof(urma_jfc_t *) * ctx->jetty_num);
    if (ctx->jfc == NULL) {
        return -1;
    }
    for (i = 0; i < ctx->jetty_num; i++) {
        ctx->jfc[i] = urma_create_jfc(ctx->urma_ctx[i / cfg->jettys_pre_ctx], &jfc_cfg);
        if (ctx->jfc[i] == NULL) {
            (void)fprintf(stderr, "Failed to create urma jfc!\n");
            goto delete_jfc;
        }
    }
    return 0;

delete_jfc:
    for (j = 0; j < i; j++) {
        (void)urma_delete_jfc(ctx->jfc[j]);
    }
    free(ctx->jfc);
    ctx->jfc = NULL;
    return -1;
}

static void init_jfr_cfg(tp_test_config_t *cfg, urma_jfr_cfg_t *jfr_cfg)
{
    jfr_cfg->depth = TP_TEST_DEFAULT_DEPTH;
    jfr_cfg->flag.value = 0;
    jfr_cfg->trans_mode = cfg->tp_mode;
    jfr_cfg->min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg->max_sge = 1;
    jfr_cfg->jfc = NULL;
    jfr_cfg->token_value = g_tp_test_token;
    jfr_cfg->id = 0;
    jfr_cfg->user_ctx = (uint64_t)NULL;
}

static void destroy_share_jfr(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i;
    for (i = 0; i < ctx->jetty_num; i++) {
        (void)urma_delete_jfr(ctx->jfr[i]);
    }
    free(ctx->jfr);
    ctx->jfr = NULL;
}

static int create_share_jfr(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;
    urma_jfr_cfg_t jfr_cfg = {0};

    init_jfr_cfg(cfg, &jfr_cfg);
    ctx->jfr = (urma_jfr_t **)calloc(1, sizeof(urma_jfr_t *) * ctx->jetty_num);
    if (ctx->jfr == NULL) {
        return -1;
    }
    for (i = 0; i < ctx->jetty_num; i++) {
        jfr_cfg.jfc = ctx->jfc[i];
        ctx->jfr[i] = urma_create_jfr(ctx->urma_ctx[i / cfg->jettys_pre_ctx], &jfr_cfg);
        if (ctx->jfr[i] == NULL) {
            (void)fprintf(stderr, "Failed to create urma jfr!\n");
            goto delete_jfr;
        }
    }
    return 0;

delete_jfr:
    for (j = 0; j < i; j++) {
        (void)urma_delete_jfr(ctx->jfr[j]);
    }
    free(ctx->jfr);
    ctx->jfr = NULL;
    return -1;
}

static void init_jfs_cfg(tp_test_config_t *cfg, urma_jfs_cfg_t *jfs_cfg)
{
    jfs_cfg->depth = TP_TEST_DEFAULT_DEPTH;
    jfs_cfg->flag.value = 0;
    jfs_cfg->trans_mode = cfg->tp_mode;
    jfs_cfg->priority = 0;
    jfs_cfg->max_sge = 1;
    jfs_cfg->max_rsge = 1;
    jfs_cfg->max_inline_data = 0;
    jfs_cfg->rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg->err_timeout = 0;
    jfs_cfg->jfc = NULL;     // to fill
    jfs_cfg->user_ctx = (uint64_t)NULL;
}

static void destroy_jettys(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i;
    for (i = 0; i < ctx->jetty_num; i++) {
        (void)urma_delete_jetty(ctx->jetty[i]);
    }
    free(ctx->jetty);
    ctx->jetty = NULL;

    if (ctx->tp_type == URMA_TRANSPORT_UB) {
        destroy_share_jfr(ctx, cfg);
    }

    destroy_jfc(ctx, cfg);
}

static int create_jettys(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;

    ctx->jetty_num = ctx->ctx_num * cfg->jettys_pre_ctx;

    if (create_jfc(ctx, cfg) != 0) {
        return -1;
    }

    if (ctx->tp_type == URMA_TRANSPORT_UB && create_share_jfr(ctx, cfg) != 0) {
        goto destroy_jfc;
    }

    urma_jfs_cfg_t jfs_cfg = { 0 };
    init_jfs_cfg(cfg, &jfs_cfg);
    urma_jfr_cfg_t jfr_cfg = { 0 };
    init_jfr_cfg(cfg, &jfr_cfg);
    urma_jetty_flag_t jetty_flag = {0};
    urma_jetty_cfg_t jetty_cfg = {0};

    if (ctx->tp_type == URMA_TRANSPORT_UB) {
        jetty_flag.bs.share_jfr = 1;
        jetty_cfg.flag = jetty_flag;
        jetty_cfg.jfs_cfg = &jfs_cfg;
        jetty_cfg.shared.jfr = NULL;
        jetty_cfg.shared.jfc = NULL;
    } else {
        jetty_flag.bs.share_jfr = 0;   /* No shared jfr */
        jetty_cfg.flag = jetty_flag;
        jetty_cfg.jfs_cfg = &jfs_cfg;
        jetty_cfg.jfr_cfg = &jfr_cfg;
    }

    ctx->jetty = (urma_jetty_t **)calloc(1, sizeof(urma_jetty_t *) * ctx->jetty_num);
    if (ctx->jetty == NULL) {
        goto destroy_jfr;
    }
    for (i = 0; i < ctx->jetty_num; i++) {
        jetty_cfg.jfs_cfg->jfc = ctx->jfc[i];
        if (ctx->tp_type == URMA_TRANSPORT_UB) {
            jetty_cfg.shared.jfr = ctx->jfr[i];
            jetty_cfg.shared.jfc = ctx->jfc[i];
        } else {
            jetty_cfg.jfr_cfg->jfc = ctx->jfc[i];
        }
        ctx->jetty[i] = urma_create_jetty(ctx->urma_ctx[i / cfg->jettys_pre_ctx], &jetty_cfg);
        if (ctx->jetty[i] == NULL) {
            (void)fprintf(stderr, "Failed to create urma jetty!\n");
            goto delete_jetty;
        }
    }
    return 0;
delete_jetty:
    for (j = 0; j < i; j++) {
        (void)urma_delete_jetty(ctx->jetty[j]);
    }
    free(ctx->jetty);
    ctx->jetty = NULL;
destroy_jfr:
    if (ctx->tp_type == URMA_TRANSPORT_UB) {
        destroy_share_jfr(ctx, cfg);
    }
destroy_jfc:
    destroy_jfc(ctx, cfg);
    return -1;
}

static int server_send_jetty_info(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    int i = 0;
    tp_test_client_node_t *client, *next;
    UB_LIST_FOR_EACH_SAFE(client, next, node, &cfg->server.client_list) {
        if (sock_send_data(client->sock_fd, sizeof(urma_jetty_t), (char *)ctx->jetty[0]) != 0) {
            (void)fprintf(stderr, "Failed to send jetty, loop:%d!\n", i);
            return -1;
        }
        i++;
    }
    return 0;
}

static int client_recv_jetty_info(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    return sock_recv_data(cfg->client.sock_fd, sizeof(urma_jetty_t), (char *)&ctx->remote_jetty);
}

static int exchange_server_jetty(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    if (cfg->is_server == false) {
        /* client side */
        return client_recv_jetty_info(ctx, cfg);
    } else {
        /* server side */
        return server_send_jetty_info(ctx, cfg);
    }
}

static void destroy_cycle(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t j;

    for (j = 0; j < cfg->thread_num; j++) {
        free(ctx->after[j]);
    }
    for (j = 0; j < cfg->thread_num; j++) {
        free(ctx->middle[j]);
    }
    for (j = 0; j < cfg->thread_num; j++) {
        free(ctx->before[j]);
    }
    free(ctx->after);
    free(ctx->middle);
    free(ctx->before);
}

static int create_cycle(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;
    uint32_t jetty_num_pre_thread = ctx->jetty_num / cfg->thread_num;
    ctx->before = calloc(1, sizeof(uint64_t *) * cfg->thread_num);
    if (ctx->before == NULL) {
        return -1;
    }
    ctx->middle = calloc(1, sizeof(uint64_t *) * cfg->thread_num);
    if (ctx->middle == NULL) {
        goto free_before;
    }
    ctx->after = calloc(1, sizeof(uint64_t *) * cfg->thread_num);
    if (ctx->after == NULL) {
        goto free_middle;
    }
    for (i = 0; i < cfg->thread_num; i++) {
        ctx->before[i] = calloc(1, sizeof(uint64_t) * jetty_num_pre_thread * cfg->iters);
        if (ctx->before[i] == NULL) {
            goto free_before_cycle;
        }
    }
    for (i = 0; i < cfg->thread_num; i++) {
        ctx->middle[i] = calloc(1, sizeof(uint64_t) * jetty_num_pre_thread * cfg->iters);
        if (ctx->middle[i] == NULL) {
            goto free_middle_cycle;
        }
    }
    for (i = 0; i < cfg->thread_num; i++) {
        ctx->after[i] = calloc(1, sizeof(uint64_t) * jetty_num_pre_thread * cfg->iters);
        if (ctx->after[i] == NULL) {
            goto free_after_cycle;
        }
    }
    return 0;
free_after_cycle:
    for (j = 0; j < i; j++) {
        free(ctx->after[j]);
    }
    i = cfg->thread_num;
free_middle_cycle:
    for (j = 0; j < i; j++) {
        free(ctx->middle[j]);
    }
    i = cfg->thread_num;
free_before_cycle:
    for (j = 0; j < i; j++) {
        free(ctx->before[j]);
    }
    free(ctx->after);
free_middle:
    free(ctx->middle);
free_before:
    free(ctx->before);
    return -1;
}

int create_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    if (create_urma_ctx(ctx, cfg) != 0) {
        return -1;
    }
    if (create_jettys(ctx, cfg) != 0) {
        goto delete_ctx;
    }
    if (exchange_server_jetty(ctx, cfg) != 0) {
        goto delete_jetty;
    }
    if (create_cycle(ctx, cfg) != 0) {
        goto delete_jetty;
    }
    ctx->tjetty = calloc(1, sizeof(urma_target_jetty_t *) * ctx->jetty_num);
    if (ctx->tjetty == NULL) {
        goto delete_cycle;
    }
    return 0;
delete_cycle:
    destroy_cycle(ctx, cfg);
delete_jetty:
    destroy_jettys(ctx, cfg);
delete_ctx:
    destroy_urma_ctx(ctx, cfg);
    return -1;
}

void destroy_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    free(ctx->tjetty);
    destroy_cycle(ctx, cfg);
    destroy_jettys(ctx, cfg);
    destroy_urma_ctx(ctx, cfg);
}