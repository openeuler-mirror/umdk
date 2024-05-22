/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: run test for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2022-01-31   create file
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <stddef.h>
#include <errno.h>
#include "urma_api.h"
#include "tp_test_comm.h"
#include "tp_test_res.h"

#define TP_TEST_ITERS_99 (0.99)
#define TP_RESULT_LAT_FMT "                 iterations  t_min[us]  t_max[us]  t_avg[us]  99""%""[us]"
#define TP_REPORT_LAT_FMT " %u       %-7.2lf    %-7.2lf    %-7.2lf    %-7.2lf\n"
static int run_lat_test(tp_test_context_t *ctx, tp_test_config_t *cfg, uint32_t idx)
{
    uint32_t i, j, k;
    uint32_t ctx_num_pre_thread = ctx->ctx_num / cfg->thread_num;
    urma_rjetty_t rjetty = {0};
    uint32_t ctx_cnt;
    uint32_t jetty_cnt;
    uint32_t test_cnt;

    rjetty.jetty_id = ctx->remote_jetty.jetty_id;
    rjetty.trans_mode = cfg->tp_mode;
    rjetty.type = URMA_JETTY;

    for (i = 0; i < ctx_num_pre_thread; i++) {
        for (j = 0; j < cfg->jettys_pre_ctx; j++) {
            for (k = 0; k < cfg->iters; k++) {
                ctx_cnt = idx * ctx_num_pre_thread + i;
                jetty_cnt = (idx * ctx_num_pre_thread + i) * cfg->jettys_pre_ctx + j;
                test_cnt = i * cfg->jettys_pre_ctx * cfg->iters + j * cfg->iters + k;  // pre thread
                ctx->before[idx][test_cnt] = get_cycles();
                ctx->tjetty[jetty_cnt] = urma_import_jetty(ctx->urma_ctx[ctx_cnt], &rjetty, &g_tp_test_token);
                if (ctx->tp_type != URMA_TRANSPORT_UB) {
                    (void)urma_advise_jetty(ctx->jetty[jetty_cnt], ctx->tjetty[jetty_cnt]);
                }
                ctx->middle[idx][test_cnt] = get_cycles();
                if (ctx->tp_type != URMA_TRANSPORT_UB) {
                    (void)urma_unadvise_jetty(ctx->jetty[jetty_cnt], ctx->tjetty[jetty_cnt]);
                }
                (void)urma_unimport_jetty(ctx->tjetty[jetty_cnt]);
                ctx->after[idx][test_cnt] = get_cycles();
            }
        }
    }
    return 0;
}

static int run_bw_test(tp_test_context_t *ctx, tp_test_config_t *cfg, uint32_t idx)
{
    return 0;
}

void *tp_test_thread_main(void *arg)
{
    tp_thread_arg_t *thread_arg = (tp_thread_arg_t *)arg;
    tp_test_context_t *ctx = thread_arg->ctx;
    tp_test_config_t *cfg = thread_arg->cfg;
    uint32_t idx = thread_arg->thread_idx;

    if (cfg->type == TP_TEST_LAT) {
        (void)run_lat_test(ctx, cfg, idx);
    } else {
        (void)run_bw_test(ctx, cfg, idx);
    }
    return NULL;
}

static int create_test_thread(tp_test_context_t *ctx, tp_test_config_t *cfg, uint32_t idx)
{
    pthread_attr_t attr;
    (void)pthread_attr_init(&attr);

    ctx->thread_arg[idx].stop = false;
    ctx->thread_arg[idx].cfg = cfg;
    ctx->thread_arg[idx].ctx = ctx;
    ctx->thread_arg[idx].thread_idx = idx;

    int ret = pthread_create(&ctx->thread[idx], &attr, tp_test_thread_main,
        (void *)&ctx->thread_arg[idx]);
    if (ret != 0) {
        printf("Failed to create thread, idx: %u, ret: %d, errno: %d.\n", idx, ret, errno);
    }
    (void)pthread_attr_destroy(&attr);
    return ret;
}

int client_run_test(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j;
    int ret;

    ctx->thread = (pthread_t *)calloc(1, sizeof(pthread_t) * cfg->thread_num);
    if (ctx->thread == NULL) {
        return -1;
    }
    ctx->thread_arg = calloc(1, sizeof(tp_thread_arg_t) * cfg->thread_num);
    if (ctx->thread_arg == NULL) {
        goto free_thread;
    }
    for (i = 0; i < cfg->thread_num; i++) {
        ret = create_test_thread(ctx, cfg, i);
        if (ret != 0) {
            goto delete_thread;
        }
    }

    for (i = 0; i < cfg->thread_num; i++) {
        (void)pthread_join(ctx->thread[i], NULL);
    }
    free(ctx->thread_arg);
    free(ctx->thread);

    return 0;

delete_thread:
    for (j = 0; j < i; j++) {
        (void)pthread_join(ctx->thread[j], NULL);
    }
    free(ctx->thread_arg);
free_thread:
    free(ctx->thread);
    return -1;
}

static int sync_test(tp_test_config_t *cfg, char *str)
{
    int ret = 0;
    if (cfg->is_server == false) {
        /* client side */
        if (sync_time(cfg->client.sock_fd, str) != 0) {
            (void)fprintf(stderr, "Failed to sync time, %s!\n", str);
            ret = -1;
        }
    } else {
        /* server side */
        tp_test_client_node_t *client, *next;
        UB_LIST_FOR_EACH_SAFE(client, next, node, &cfg->server.client_list) {
            if (sync_time(client->sock_fd, str) != 0) {
                (void)fprintf(stderr, "Failed to sync time, %s!\n", str);
                ret = -1;
            }
        }
    }
    return ret;
}

static int cycles_compare(const void *src, const void *dst)
{
    const uint64_t *a = (const uint64_t *)src;
    const uint64_t *b = (const uint64_t *)dst;

    if (*a < *b) {
        return -1;
    }
    if (*a > *b) {
        return 1;
    }
    return 0;
}

static void print_lat_report(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    uint32_t i, j, k = 0;
    uint32_t measure_cnt = ctx->jetty_num * cfg->iters;
    uint32_t jetty_num_pre_thread = ctx->jetty_num / cfg->thread_num;
    double cycles_to_units = get_cpu_mhz(true);

    uint64_t *import_delta = calloc(1, sizeof(uint64_t) * (uint32_t)measure_cnt);
    if (import_delta == NULL) {
        return;
    }
    uint64_t *unimport_delta = calloc(1, sizeof(uint64_t) * (uint32_t)measure_cnt);
    if (unimport_delta == NULL) {
        free(import_delta);
        return;
    }

    for (i = 0; i < cfg->thread_num; i++) {
        for (j = 0; j < jetty_num_pre_thread * cfg->iters; j++) {
            import_delta[k] = ctx->middle[i][j] - ctx->before[i][j];
            unimport_delta[k] = ctx->after[i][j] - ctx->middle[i][j];
            k++;
        }
    }
    qsort(import_delta, (size_t)measure_cnt, sizeof(uint64_t), cycles_compare);
    qsort(unimport_delta, (size_t)measure_cnt, sizeof(uint64_t), cycles_compare);

    /* average lat */
    double import_average_sum = 0.0, import_average = 0.0;
    for (i = 0; i < measure_cnt; i++) {
        import_average_sum += (import_delta[i] / cycles_to_units);
    }
    import_average = import_average_sum / measure_cnt;
    double unimport_average_sum = 0.0, unimport_average = 0.0;
    for (i = 0; i < measure_cnt; i++) {
        unimport_average_sum += (unimport_delta[i] / cycles_to_units);
    }
    unimport_average = unimport_average_sum / measure_cnt;

    /* tail lat */
    uint64_t iters_99 = (uint64_t)ceil((measure_cnt) * TP_TEST_ITERS_99);

    (void)printf("%s\n", TP_RESULT_LAT_FMT);
    (void)printf("import_jetty   : " TP_REPORT_LAT_FMT, measure_cnt, import_delta[0] / cycles_to_units,
        import_delta[measure_cnt - 1] / cycles_to_units, import_average,
        import_delta[iters_99 - 1] / cycles_to_units);
    (void)printf("unimport_jetty : " TP_REPORT_LAT_FMT, measure_cnt, unimport_delta[0] / cycles_to_units,
        unimport_delta[measure_cnt - 1] / cycles_to_units, unimport_average,
        unimport_delta[iters_99 - 1] / cycles_to_units);
    free(import_delta);
    free(unimport_delta);
}

static void print_bw_report(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    return;
}

static void print_report(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    if (cfg->type == TP_TEST_LAT) {
        print_lat_report(ctx, cfg);
    } else {
        print_bw_report(ctx, cfg);
    }
}

int run_test(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    if (sync_test(cfg, "Start test") != 0) {
        return -1;
    }

    if (cfg->is_server == false && client_run_test(ctx, cfg) != 0) {
        (void)fprintf(stderr, "Failed to run test!\n");
    }

    // server wait
    if (sync_test(cfg, "End test") != 0) {
        return -1;
    }
    if (cfg->is_server == false) {
        print_report(ctx, cfg);
    }
    return 0;
}
