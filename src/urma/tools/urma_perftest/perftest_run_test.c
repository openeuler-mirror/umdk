/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: run test for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <stddef.h>

#include "urma_api.h"

#include "perftest_parameters.h"
#include "perftest_resources.h"

#define PERFTEST_HALF (2)
#define PERFTEST_ITERS_99 (0.99)
#define PERFTEST_ITERS_99_9 (0.999)
#define PERFTEST_ITERS_99_99 (0.9999)
#define PERFTEST_ITERS_99_99_9 (0.99999)
#define PERFTEST_SGE_NUM_PRE_WR (2)
#define PERFTEST_POLL_BATCH (16)

#define LAT_MEASURE_TAIL (2)  // Remove the two max value
#define RESULT_LAT_FMT " bytes   iterations  t_min[us]  t_max[us]  t_median[us]  t_avg[us]  t_stdev[us]  " \
                        "99""%""[us]  99.9""%""[us]  99.99""%""[us]  99.999""%""[us]"
#define RESULT_LAT_DUR_FMT " bytes   iterations  t_avg[us]  pps"
#define RESULT_BW_FMT  " bytes   iterations  BW peak[MB/sec]  BW average[MB/sec]  MsgRate[Mpps]"
#define REPORT_LAT_FMT " %-7u %-10lu  %-7.2lf    %-7.2lf    %-7.2lf       %-7.2lf    %-7.2lf      " \
                        "%-7.2lf  %-7.2lf    %-7.2lf     %-7.2lf"
#define REPORT_LAT_DUR_FMT " %-7u %-10lu  %-7.2f    %-7.2f"
#define REPORT_BW_FMT " %-7u %-10lu  %-7.2lf          %-7.2lf             %-7.6lf"

#define INF_BI_FACTOR_SEND (1)
#define INF_BI_FACTOR_OTHER (2)
#define NON_INF_BI_FACTOR (1)
#define PERFTEST_IMM_DATA (0x20230416)
#define PERFTEST_FLAG_USER_CTX (63)

run_test_ctx_t *g_duration_ctx;

perftest_context_t *g_perftest_ctx;
perftest_config_t *g_perftest_cfg;

typedef struct bi_exchange_info {
    char *before;
    char *after;
} bi_exchange_info_t;

/* order of initialization refferred to [perftest_api_type_t] */
static const bi_exchange_info_t g_bi_exchange_info[] = {
    { "before_read_bw",     "after_read_bw" },
    { "before_write_bw",    "after_write_bw" },
    { "before_send_bw",     "after_send_bw" },  /* SEND not used currently */
    { "before_atomic_bw",   "after_atomic_bw" }
};

void catch_alarm(int sig)
{
    switch (g_duration_ctx->state) {
        case WARMUP_STATE:
            g_duration_ctx->state = START_STATE;
            g_duration_ctx->tposted[0] = get_cycles();
            (void)alarm(g_duration_ctx->duration / PERFTEST_DEF_TEST_TIME);
            break;
        case START_STATE:
            g_duration_ctx->state = STOP_STATE;
            g_duration_ctx->tcompleted[0] = get_cycles();
            (void)alarm(g_duration_ctx->duration / PERFTEST_DEF_WARMUP_TIME);
            break;
        case STOP_STATE:
            g_duration_ctx->state = END_STATE;
            break;
        case END_STATE:
            break;
        default:
            (void)fprintf(stderr, "unknown state.\n");
            break;
    }
}

static int wait_jfc_event(urma_jfce_t *jfce, int timeout)
{
    urma_jfc_t *jfc;
    if (urma_wait_jfc(jfce, 1, timeout, &jfc) != 1) {
        (void)printf("Failed to write wait_jfc\n");
        return -1;
    }
    uint32_t ack_cnt = 1;
    urma_ack_jfc((urma_jfc_t **)&jfc, &ack_cnt, 1);
    /* enable event mode */
    if (urma_rearm_jfc(jfc, false) != URMA_SUCCESS) {
        (void)printf("Failed to urma_rearm_jfc\n");
        return -1;
    }
    return 0;
}

static inline void update_duration_state(perftest_context_t *ctx, perftest_config_t *cfg)
{
    g_duration_ctx = &ctx->run_ctx;
    g_duration_ctx->state = WARMUP_STATE;
    (void)signal(SIGALRM, catch_alarm);
    cfg->iters = 0;
    (void)alarm(g_duration_ctx->duration / PERFTEST_DEF_WARMUP_TIME);
}

static int poll_jfc_until_expected_cqe(perftest_context_t *ctx, perftest_config_t *cfg, uint32_t id, urma_cr_t *cr)
{
    if (cfg->use_jfce == true) {
        if (wait_jfc_event(ctx->jfce_s[id], cfg->wait_jfc_timeout) != 0) {
            (void)fprintf(stderr, "Couldn't wait jfce event, id:%u\n", id);
            return -1;
        }
    }

    /*
     * Since cqes may not be generated simultaneously, it is necessary to poll continuously
     * until the number of cqes matches the expected count.
     */
    int cqe_expected = cfg->jfs_post_list / cfg->cq_mod;
    do {
        int cqe_cnt = urma_poll_jfc(ctx->jfc_s[id], cfg->jfc_depth, cr);
        if (cqe_cnt > 0) {
            for (int i = 0; i < cqe_cnt; i++) {
                if (cr[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status, id:%u, status:%d.\n", id, (int)cr[i].status);
                    return -1;
                }
            }
        } else if (cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed poll jfc, id:%u, cqe_cnt:%d\n", id, cqe_cnt);
            return -1;
        }
        cqe_expected -= cqe_cnt;
        if (cfg->time_type.bs.duration == 1 && ctx->run_ctx.state == END_STATE) {
            break;
        }
    } while (cqe_expected > 0);
    return 0;
}

static void *run_read_lat_simplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(cfg->jfc_depth, sizeof(urma_cr_t));
    if (cr == NULL) {
        (void)fprintf(stderr, "Failed alloc cr, id:%u\n", id);
        return NULL;
    }

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
        }

        urma_status_t status;
        if (cfg->use_flat_api) {
            uint64_t lva = (uint64_t)(uintptr_t)ctx->local_buf[0] + ctx->buf_size; // Second half for local memory
            uint64_t rva = ctx->remote_seg[0]->ubva.va;
            urma_jfs_wr_flag_t flag = {
                .bs.complete_enable = URMA_COMPLETE_ENABLE,
            };
            status = urma_read(ctx->jfs[0], ctx->import_tjfr[0], ctx->local_tseg[0], ctx->import_tseg[0], lva,
                rva, cfg->size, flag, (uintptr_t)++rid);
        } else {
            urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
            urma_jfs_wr_t *bad_wr = NULL;
            for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
                wr[i].user_ctx = (uintptr_t)++rid;
            }
            status = urma_post_jfs_wr(ctx->jfs[id], wr, &bad_wr);
        }

        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to post jfs wr, id:%u, status:%d, scnt:%lu\n", id, (int)status, scnt);
            goto free_cr;
        }
        scnt += cfg->jfs_post_list;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
            goto free_cr;
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
            run_ctx->scnt[id] += 1;
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}

static void *run_write_lat_simplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    uint64_t ccnt = 0;
    uint64_t rcnt = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(cfg->jfc_depth, sizeof(urma_cr_t));
    if (cr == NULL) {
        (void)fprintf(stderr, "Failed alloc cr, id:%u\n", id);
        return NULL;
    }

    bool is_server = cfg->comm.server_ip == NULL;

    volatile char *post_buf = (char *)ctx->local_buf[id] + ctx->buf_size + cfg->size - 1;
    volatile char *poll_buf = (char *)ctx->local_buf[id] + cfg->size - 1;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || ccnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && is_server)) {
            rcnt += cfg->jfs_post_list;
            while (*poll_buf != (char)(rcnt / cfg->jfs_post_list) && run_ctx->state != END_STATE) {};
        }

        if (scnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
            }

            scnt += cfg->jfs_post_list;
            *post_buf = (char)(scnt / cfg->jfs_post_list);

            urma_status_t status;
            if (cfg->use_flat_api) {
                uint64_t lva = (uint64_t)(uintptr_t)ctx->local_buf[0] + ctx->buf_size; // Second half for local memory
                uint64_t rva = ctx->remote_seg[0]->ubva.va;
                urma_jfs_wr_flag_t flag = {
                    .bs.complete_enable = 1,
                    .bs.inline_flag = (cfg->size <= cfg->inline_size) ? 1 : 0,
                };
                status = urma_write(ctx->jfs[0], ctx->import_tjfr[0], ctx->import_tseg[0], ctx->local_tseg[0],
                    rva, lva, cfg->size, flag, (uintptr_t)++rid);
            } else {
                urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
                urma_jfs_wr_t *bad_wr = NULL;
                for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
                    wr[i].user_ctx = (uintptr_t)++rid;
                }
                status = urma_post_jfs_wr(ctx->jfs[id], wr, &bad_wr);
            }
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Failed to post jfs wr, id:%u, status:%d, scnt:%lu, rcnt:%lu\n",
                    id, (int)status, scnt, rcnt);
                goto free_cr;
            }
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (ccnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
                goto free_cr;
            }
            ccnt += cfg->jfs_post_list;
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
            run_ctx->scnt[id] += 1;
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}

static int send_lat_post_recv(perftest_context_t *ctx, perftest_config_t *cfg, uint32_t id, int cnt)
{
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    urma_jfr_wr_t *jfr_wr = &run_ctx->jfr_wr[id * cfg->jfr_post_list];
    urma_jfr_wr_t *jfr_bad_wr = NULL;
    for (int i = 0; i < cnt; i++) {
        if (cfg->use_flat_api) {
            uint64_t recv_va = (uint64_t)ctx->local_buf[0];    // first half for recv
            status = urma_recv(ctx->jfr[0], ctx->local_tseg[0], recv_va, cfg->size, (uintptr_t)run_ctx->rid++);
        } else {
            status = urma_post_jfr_wr(ctx->jfr[id], jfr_wr, &jfr_bad_wr);
        }
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to post jfr wr, id:%u, status:%d, size:%u.\n", id, (int)status, cfg->size);
            return -1;
        }
    }

    return 0;
}

static inline void set_on_first_rx(perftest_context_t *ctx, perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    } else if (cfg->type == PERFTEST_BW) {
        run_ctx->tposted[0] = get_cycles();
    }
}

static void *run_send_lat_simplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    uint64_t rcnt = 0;
    uint64_t used_recv_wr = 0;
    int first_rx = 1;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(cfg->jfc_depth, sizeof(urma_cr_t));
    if (cr == NULL) {
        (void)fprintf(stderr, "Failed alloc cr, id:%u\n", id);
        return NULL;
    }

    bool is_server = cfg->comm.server_ip == NULL;

    /*
     * Sync between the client and server so the client won't send packets
     * before the server has posted his receive wqes.
     */
    if (send_lat_post_recv(ctx, cfg, id, (int)(cfg->jfr_depth / cfg->jfr_post_list)) != 0) {
        goto free_cr;
    }
    if (sync_time(cfg->comm.sock_fd[id], "send_lat_post_recv") != 0) {
        goto free_cr;
    }

    while (scnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        /*
         * Get the recv packet. make sure that the client won't enter here until he sends his first packet (scnt < 1)
         * server will enter here first and wait for a packet to arrive (from the client)
         */
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && !is_server)) {
            if (cfg->use_jfce == true) {
                if (wait_jfc_event(ctx->jfce_r[id], cfg->wait_jfc_timeout) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event, id:%u\n", id);
                    goto free_cr;
                }
            }

            /*
             * Using the ping-pong transmission model, the expected number of received CQEs equals
             * the number of sended WRs.
             */
            int cqe_expected = (int)cfg->jfs_post_list;
            do {
                int cqe_cnt = urma_poll_jfc(ctx->jfc_r[id], cfg->jfc_depth, cr);
                if (cqe_cnt > 0) {
                    for (int i = 0; i < cqe_cnt; i++) {
                        if (cr[i].status != URMA_CR_SUCCESS) {
                            (void)fprintf(stderr, "Failed CR status, id:%u, status:%d.\n", id, (int)cr[i].status);
                            goto free_cr;
                        }
                    }
                    if (first_rx != 0) {
                        set_on_first_rx(ctx, cfg);
                        first_rx = 0;
                    }
                    rcnt += (uint64_t)cqe_cnt;
                    cqe_expected -= cqe_cnt;

                    /*
                     * if we're in duration mode or there is enough space in the rx_depth,
                     * post that you received a packet.
                     */
                    used_recv_wr += (uint64_t)cqe_cnt;
                    if (used_recv_wr >= cfg->jfr_post_list &&
                        (cfg->time_type.bs.duration == 1 || rcnt + cfg->jfr_depth - used_recv_wr < cfg->iters)) {
                        if (send_lat_post_recv(ctx, cfg, id, used_recv_wr / cfg->jfr_post_list) != 0) {
                            goto free_cr;
                        }
                        used_recv_wr = used_recv_wr % cfg->jfr_post_list;
                    }
                } else if (cqe_cnt < 0) {
                    (void)fprintf(stderr, "Failed poll jfc_r, id:%u, cqe_cnt:%d.\n", id, cqe_cnt);
                    goto free_cr;
                }
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }
            } while (cqe_expected > 0);

            if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                run_ctx->scnt[id] += 1;
            }
        }

        if (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
            }

            scnt += cfg->jfs_post_list;

            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }

            urma_status_t status;
            if (cfg->use_flat_api) {
                uint64_t lva = (uint64_t)(uintptr_t)ctx->local_buf[0] + ctx->buf_size; // Second half for local memory
                urma_jfs_wr_flag_t flag = {
                    .bs.inline_flag = (cfg->size <= cfg->inline_size) ? 1 : 0,
                    .bs.complete_enable = URMA_COMPLETE_ENABLE,
                };
                status = urma_send(ctx->jfs[0], ctx->import_tjfr[0], ctx->local_tseg[0], lva, cfg->size,
                    flag, (uintptr_t)++rid);
            } else {
                urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
                urma_jfs_wr_t *bad_wr = NULL;
                for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
                    wr[i].user_ctx = (uintptr_t)++rid;
                }
                if (cfg->jfs_post_list == 1) {
                    if (scnt % cfg->cq_mod == 0) {
                        wr[0].flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
                    } else {
                        wr[0].flag.bs.complete_enable = URMA_COMPLETE_DISABLE;
                    }
                }
                status = urma_post_jfs_wr(ctx->jfs[id], wr, &bad_wr);
            }
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Failed to post jfs wr, id:%u, status:%d, scnt:%lu, rcnt:%lu\n",
                    id, (int)status, scnt, rcnt);
                goto free_cr;
            }

            if (cfg->jfs_post_list != 1 || scnt % cfg->cq_mod == 0) {
                if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
                    goto free_cr;
                }
            }
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}

static inline uint64_t get_median_delta(uint64_t num, uint64_t *delta_arr)
{
    if ((num - 1) % PERFTEST_HALF != 0) {
        return (delta_arr[num / PERFTEST_HALF] + delta_arr[num / PERFTEST_HALF - 1]) / PERFTEST_HALF;
    } else {
        return delta_arr[num / PERFTEST_HALF];
    }
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

static void print_lat_report(perftest_context_t *ctx, const perftest_config_t *cfg, uint64_t id)
{
    uint64_t i;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    int rtt_factor = (cfg->cmd == PERFTEST_READ_LAT || cfg->cmd == PERFTEST_ATOMIC_LAT) ? 1 : 2;
    double cycles_to_units = get_cpu_mhz(cfg->cpu_freq_f);
    double cycles_rtt_quotient = cycles_to_units * rtt_factor;

    uint64_t measure_cnt = cfg->iters / cfg->jfs_post_list - 1;
    uint64_t *delta = calloc(1, sizeof(uint64_t) * (uint32_t)measure_cnt);
    if (delta == NULL) {
        return;
    }

    // Get the cycle of a test
    for (i = 0; i < measure_cnt; i++) {
        uint64_t k = cfg->iters * id + i * cfg->jfs_post_list;
        delta[i] = run_ctx->tposted[k + cfg->jfs_post_list] - run_ctx->tposted[k];
    }

    qsort(delta, (size_t)measure_cnt, sizeof(uint64_t), cycles_compare);
    measure_cnt = measure_cnt - LAT_MEASURE_TAIL;  // Remove the two largest values

    /* median lat */
    double median = get_median_delta(measure_cnt, delta) / cycles_rtt_quotient;

    /* average lat */
    double average_sum = 0.0, average = 0.0;
    for (i = 0; i < measure_cnt; i++) {
        average_sum += (delta[i] / cycles_rtt_quotient);
    }
    average = average_sum / measure_cnt;

    /* variance lat */
#define PERFTEST_SQUARE  (2)
    double stdev, temp_var, pow_var, stdev_sum = 0;
    for (i = 0; i < measure_cnt; i++) {
        temp_var = average - (delta[i] / cycles_rtt_quotient);
        pow_var = pow(temp_var, PERFTEST_SQUARE);
        stdev_sum += pow_var;
    }
    stdev = sqrt(stdev_sum / measure_cnt);

    /* tail lat */
    uint64_t iters_99, iters_99_9, iters_99_99, iters_99_99_9;
    iters_99 = (uint64_t)ceil((measure_cnt) * PERFTEST_ITERS_99);
    iters_99_9 = (uint64_t)ceil((measure_cnt) * PERFTEST_ITERS_99_9);
    iters_99_99 = (uint64_t)ceil((measure_cnt) * PERFTEST_ITERS_99_99);
    iters_99_99_9 = (uint64_t)ceil((measure_cnt) * PERFTEST_ITERS_99_99_9);

    // " %-7u   %-7u          %-7.3lf        %-7.3lf      %-7.3lf          %-7.3lf          %-7.3lf          %-7.3lf"
    (void)printf(REPORT_LAT_FMT, cfg->size, cfg->iters,
        delta[0] / cycles_rtt_quotient, delta[measure_cnt] / cycles_rtt_quotient,
        median, average, stdev, delta[iters_99] / cycles_rtt_quotient, delta[iters_99_9] / cycles_rtt_quotient,
        delta[iters_99_99] / cycles_rtt_quotient, delta[iters_99_99_9] / cycles_rtt_quotient);
    (void)printf("\n");
    free(delta);
}

static void print_lat_duration_report(perftest_context_t *ctx, const perftest_config_t *cfg, uint64_t id)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    int rtt_factor = (cfg->cmd == PERFTEST_READ_LAT || cfg->cmd == PERFTEST_ATOMIC_LAT) ? 1 : 2;
    double cycles_to_units = get_cpu_mhz(cfg->cpu_freq_f);
    double cycles_rtt_quotient = cycles_to_units * rtt_factor;

    uint64_t test_time = run_ctx->tcompleted[0] - run_ctx->tposted[0];
    double avg_lat = (test_time / cycles_rtt_quotient) / run_ctx->scnt[id];
    double tps = run_ctx->scnt[id] / (test_time / (cycles_to_units * 1000000));

    (void)printf(REPORT_LAT_DUR_FMT, cfg->size, cfg->iters, avg_lat, tps);
    (void)printf("\n");
}

static void init_jfs_write_wr_opcode(urma_jfs_wr_t *wr, const perftest_config_t *cfg)
{
    if (cfg->enable_imm == true) {
        wr->opcode = URMA_OPC_WRITE_IMM;
        wr->rw.notify_data = PERFTEST_IMM_DATA;
        return;
    }
    if (cfg->enable_notify == true) {
        wr->opcode = URMA_OPC_WRITE_NOTIFY;
        wr->rw.notify_data = cfg->notify_data;
        return;
    }
    wr->opcode = URMA_OPC_WRITE;
}

static void init_jfs_wr_opcode(urma_jfs_wr_t *wr, const perftest_config_t *cfg)
{
    switch (cfg->cmd) {
        case PERFTEST_READ_LAT:
            wr->opcode = URMA_OPC_READ;
            break;
        case PERFTEST_WRITE_LAT:
            init_jfs_write_wr_opcode(wr, cfg);
            break;
        case PERFTEST_SEND_LAT:
            if (cfg->enable_imm == false) {
                wr->opcode = URMA_OPC_SEND;
            } else {
                wr->opcode = URMA_OPC_SEND_IMM;
                wr->send.imm_data = PERFTEST_IMM_DATA;
            }
            break;
        case PERFTEST_ATOMIC_LAT:
            wr->opcode = (cfg->atomic_type == PERFTEST_CAS ? URMA_OPC_CAS : URMA_OPC_FADD);
            break;
        case PERFTEST_READ_BW:
            wr->opcode = URMA_OPC_READ;
            break;
        case PERFTEST_WRITE_BW:
            init_jfs_write_wr_opcode(wr, cfg);
            break;
        case PERFTEST_SEND_BW:
            if (cfg->enable_imm == false) {
                wr->opcode = URMA_OPC_SEND;
            } else {
                wr->opcode = URMA_OPC_SEND_IMM;
                wr->send.imm_data = PERFTEST_IMM_DATA;
            }
            break;
        case PERFTEST_ATOMIC_BW:
            wr->opcode = (cfg->atomic_type == PERFTEST_CAS ? URMA_OPC_CAS : URMA_OPC_FADD);
            break;
        default:
            (void)fprintf(stderr, "invalid opcode.\n");
            break;
    }
}

static void init_jfs_wr_base(urma_jfs_wr_t *wr, perftest_context_t *ctx,
    const perftest_config_t *cfg, uint32_t jetty_index, uint32_t jfs_wr_index)
{
    init_jfs_wr_opcode(wr, cfg);
    wr->flag.bs.complete_enable = ((jfs_wr_index + 1) % cfg->cq_mod == 0) ? 1 : 0;
    wr->flag.bs.solicited_enable = 0;
    // set inline, inline_flag only filled in WRITE and SEND operation
    if (cfg->api_type == PERFTEST_WRITE || cfg->api_type == PERFTEST_SEND) {
        wr->flag.bs.inline_flag = (cfg->size <= cfg->inline_size) ? 1 : 0;
    } else {
        wr->flag.bs.inline_flag = 0;
    }
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        wr->tjetty = ctx->import_tjfr[jetty_index];
    } else {
        wr->tjetty = ctx->import_tjetty[jetty_index];
    }
    wr->user_ctx = (uintptr_t)jetty_index;     // CQ gets this value to distinguish which jetty.
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    wr->next = (jfs_wr_index == cfg->jfs_post_list - 1) ? NULL : &run_ctx->jfs_wr[jetty_index *
        cfg->jfs_post_list + jfs_wr_index + 1];
    wr->user_ctx = (uintptr_t)jetty_index;
}

static void init_read_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t sge_size = cfg->size / cfg->sge_num;
    uint32_t sge_idx;

    uint64_t lva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->local_buf[0] + (cfg->jettys + i) * ctx->buf_size :
        (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->remote_seg[0]->ubva.va + i * ctx->buf_size :
        (uint64_t)ctx->remote_seg[i]->ubva.va;

    uint32_t local_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
    uint32_t remote_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num;

    urma_sge_t *local_sge = &run_ctx->jfs_sge[local_sge_idx];    // First sge in sge arrays
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[remote_sge_idx];

    // Step increased value
    local_sge[0].addr = lva;  // all sges are configured with the same address and then offset.
    remote_sge[0].addr = rva;
    // it is only need to calculate sge addr offset when j > 0, for the offset is 0 when j == 0.
    if (j > 0) {
        uint32_t l_idx = (i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
        uint32_t r_idx = (i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num;
        local_sge[0].addr = run_ctx->jfs_sge[l_idx].addr;
        remote_sge[0].addr = run_ctx->jfs_sge[r_idx].addr;
        if (cfg->cmd == PERFTEST_READ_BW && cfg->size <= ctx->page_size / PERFTEST_BUF_NUM) {
            increase_loc_addr(&local_sge[0], cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
            increase_loc_addr(&remote_sge[0], cfg->size, j - 1, rva, cfg->cache_line_size, ctx->page_size);
        }
    }

    for (sge_idx = 0; sge_idx < cfg->sge_num; sge_idx++) {
        local_sge[sge_idx].addr = local_sge[0].addr + sge_size * sge_idx;  // offset
        local_sge[sge_idx].len = sge_size;
        local_sge[sge_idx].tseg = ctx->local_tseg[i];

        remote_sge[sge_idx].addr = remote_sge[0].addr + sge_size * sge_idx;  // offset
        remote_sge[sge_idx].len = sge_size;
        remote_sge[sge_idx].tseg = ctx->import_tseg[i];
    }
    wr->rw.src.sge = remote_sge;
    wr->rw.src.num_sge = cfg->sge_num;

    wr->rw.dst.sge = local_sge;
    wr->rw.dst.num_sge = cfg->sge_num;

    wr->rw.notify_data = 0;
}

static void init_write_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t sge_size = cfg->size / cfg->sge_num;
    uint32_t sge_idx;

    uint64_t lva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->local_buf[0] + (cfg->jettys + i) * ctx->buf_size :
        (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->remote_seg[0]->ubva.va + i * ctx->buf_size :
        (uint64_t)ctx->remote_seg[i]->ubva.va;

    uint32_t local_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
    uint32_t remote_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num;
    urma_sge_t *local_sge = &run_ctx->jfs_sge[local_sge_idx];    // First sge in sge arrays
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[remote_sge_idx];     // First sge in sge arrays

    // Step increased value
    local_sge[0].addr = lva;   // all sges are configured with the same address and then offset.
    remote_sge[0].addr = rva;  // all sges are configured with the same address and then offset.
    // it is only need to calculate sge addr offset when j > 0, for the offset is 0 when j == 0.
    // the following remote_sge addr judgement is the same.
    if (j > 0) {
        uint32_t l_idx = (i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
        uint32_t r_idx = (i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num;
        local_sge[0].addr = run_ctx->jfs_sge[l_idx].addr;
        remote_sge[0].addr = run_ctx->jfs_sge[r_idx].addr;
        if (cfg->cmd == PERFTEST_WRITE_BW && cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
            increase_loc_addr(&local_sge[0], cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
            increase_loc_addr(&remote_sge[0], cfg->size, j - 1, rva, cfg->cache_line_size, ctx->page_size);
        }
    }

    for (sge_idx = 0; sge_idx < cfg->sge_num; sge_idx++) {
        local_sge[sge_idx].addr = local_sge[0].addr + sge_size * sge_idx;  // offset
        local_sge[sge_idx].len = sge_size;
        local_sge[sge_idx].tseg = ctx->local_tseg[i];

        remote_sge[sge_idx].addr = remote_sge[0].addr + sge_size * sge_idx;  // offset
        remote_sge[sge_idx].len = sge_size;
        remote_sge[sge_idx].tseg = ctx->import_tseg[i];
    }

    wr->rw.src.sge = local_sge;
    wr->rw.src.num_sge = cfg->sge_num;
    wr->rw.dst.sge = remote_sge;
    wr->rw.dst.num_sge = cfg->sge_num;

    wr->rw.notify_data = 0;
}

static void init_send_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t sge_size = cfg->size / cfg->sge_num;
    uint32_t sge_idx;

    uint64_t lva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->local_buf[0] + (cfg->jettys + i) * ctx->buf_size :
        (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    uint32_t local_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;

    urma_sge_t *local_sge = &run_ctx->jfs_sge[local_sge_idx];
    // Step increased value
    local_sge[0].addr = lva;
    if (j > 0) {
        uint32_t l_idx = (i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
        local_sge[0].addr = run_ctx->jfs_sge[l_idx].addr;
        if (cfg->size <= ctx->page_size / PERFTEST_BUF_NUM) {
            increase_loc_addr(&local_sge[0], cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
        }
    }

    for (sge_idx = 0; sge_idx < cfg->sge_num; sge_idx++) {
        // Step increased value
        local_sge[sge_idx].addr = local_sge[0].addr + sge_size * sge_idx;
        local_sge[sge_idx].len = sge_size;
        local_sge[sge_idx].tseg = ctx->local_tseg[i];
    }

    wr->send.src.sge = local_sge;
    wr->send.src.num_sge = cfg->sge_num;

    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        wr->tjetty = ctx->import_tjfr[i];
    } else {
        wr->tjetty = ctx->import_tjetty[i];
    }
    wr->send.imm_data = 0;
}

static void init_atomic_jfs_wr(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    // Step increased value
    uint32_t align_size = PERFTEST_ALIGN_CACHELINE(cfg->size, cfg->cache_line_size);
    uint32_t remainder = (ctx->page_size / PERFTEST_BUF_NUM >= align_size) ?
        (j % ((ctx->page_size / PERFTEST_BUF_NUM) / align_size)) : 0;
    uint32_t local_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
    uint32_t remote_sge_idx = (i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num;

    uint8_t *lva = (cfg->seg_pre_jetty == false) ?
        (uint8_t *)ctx->local_buf[0] + (cfg->jettys + i) * ctx->buf_size + remainder * align_size :
        (uint8_t *)ctx->local_buf[i] + ctx->buf_size + remainder * align_size;
    uint8_t *rva = (cfg->seg_pre_jetty == false) ?
        (uint8_t *)ctx->remote_seg[i]->ubva.va + i * ctx->buf_size + remainder * align_size :
        (uint8_t *)ctx->remote_seg[i]->ubva.va + remainder * align_size;

    urma_sge_t *local_sge = &run_ctx->jfs_sge[local_sge_idx];
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[remote_sge_idx];
    local_sge->addr = (uint64_t)lva;
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[i];
    remote_sge->addr = (uint64_t)rva;
    remote_sge->len = cfg->size;
    remote_sge->tseg = ctx->import_tseg[i];

    if (cfg->atomic_type == PERFTEST_CAS) {
        wr->cas.dst = remote_sge;
        wr->cas.src = local_sge;
        wr->cas.cmp_data = *((uint64_t *)lva);
        wr->cas.swap_data = *((uint64_t *)lva);
    } else {
        wr->faa.dst = remote_sge;
        wr->faa.src = local_sge;
        wr->faa.operand = *((uint64_t *)lva);
    }
}

static void init_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg, uint32_t i, uint32_t j)
{
    switch (cfg->cmd) {
        case PERFTEST_READ_LAT:
            init_read_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_WRITE_LAT:
            init_write_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_SEND_LAT:
            init_send_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_ATOMIC_LAT:
            init_atomic_jfs_wr(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_READ_BW:
            init_read_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_WRITE_BW:
            init_write_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_SEND_BW:
            init_send_jfs_wr_sg(wr, ctx, cfg, i, j);
            return;
        case PERFTEST_ATOMIC_BW:
            init_atomic_jfs_wr(wr, ctx, cfg, i, j);
            return;
        default:
            (void)fprintf(stderr, "invalid opcode.\n");
            return;
    }
}

static void init_credit_wr(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    for (i = 0; i < cfg->jettys; i++) {
        run_ctx->credit_sge[i].addr = (uint64_t)(ctx->ctrl_buf[i]);
        run_ctx->credit_sge[i].len = sizeof(uint64_t);
        run_ctx->credit_sge[i].tseg = ctx->credit_seg[i];

        run_ctx->remote_credit_sge[i].addr = (uint64_t)(ctx->remote_credit_seg[i]->ubva.va + sizeof(uint64_t));
        run_ctx->remote_credit_sge[i].len = sizeof(uint64_t);
        run_ctx->remote_credit_sge[i].tseg = ctx->import_credit_seg[i];

        run_ctx->credit_wr[i].opcode = URMA_OPC_WRITE;
        run_ctx->credit_wr[i].flag.bs.complete_enable = 1;
        run_ctx->credit_wr[i].tjetty = (cfg->jetty_mode == PERFTEST_JETTY_DUPLEX) ? ctx->import_tjetty[i] :
            ctx->import_tjfr[i];
        run_ctx->credit_wr[i].user_ctx = i;
        run_ctx->credit_wr[i].user_ctx |= (1UL << PERFTEST_FLAG_USER_CTX);
        run_ctx->credit_wr[i].rw.src.sge = &run_ctx->credit_sge[i];
        run_ctx->credit_wr[i].rw.src.num_sge = 1;
        run_ctx->credit_wr[i].rw.dst.sge = &run_ctx->remote_credit_sge[i];
        run_ctx->credit_wr[i].rw.dst.num_sge = 1;
        run_ctx->credit_wr[i].next = NULL;
    }
}

static int prepare_credit_wr(perftest_context_t *ctx, perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    /* Handle half bidirectional test */
    if (!cfg->bidirection && cfg->type == PERFTEST_BW && cfg->comm.server_ip == NULL && cfg->enable_credit == false &&
        perftest_check_rs_mode(cfg) == false && !cfg->tp_aware) {
        return 0;
    }

    run_ctx->credit_wr = calloc(1, sizeof(urma_jfs_wr_t) * cfg->jettys);
    if (run_ctx->credit_wr == NULL) {
        return -1;
    }
    run_ctx->credit_sge = calloc(1, sizeof(urma_sge_t) * cfg->jettys);
    if (run_ctx->credit_sge == NULL) {
        goto free_creditwr;
    }
    run_ctx->remote_credit_sge = calloc(1, sizeof(urma_sge_t) * cfg->jettys);
    if (run_ctx->remote_credit_sge == NULL) {
        goto free_credit_sge;
    }

    init_credit_wr(ctx, cfg);

    return 0;
free_credit_sge:
    free(run_ctx->credit_sge);

free_creditwr:
    free(run_ctx->credit_wr);
    return -1;
}

static inline void destroy_credit_wr(perftest_context_t *ctx)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    if (run_ctx->remote_credit_sge != NULL) {
        free(run_ctx->remote_credit_sge);
    }
    if (run_ctx->credit_sge != NULL) {
        free(run_ctx->credit_sge);
    }
    if (run_ctx->credit_wr != NULL) {
        free(run_ctx->credit_wr);
    }
}

static int prepare_jfs_wr(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i, j;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfs_wr_t *wr;

    run_ctx->jfs_wr = calloc(1, sizeof(urma_jfs_wr_t) * cfg->jettys * cfg->jfs_post_list);
    if (run_ctx->jfs_wr == NULL) {
        return -1;
    }
    run_ctx->jfs_sge = calloc(1, sizeof(urma_sge_t) * cfg->jettys *
        cfg->jfs_post_list * cfg->sge_num * PERFTEST_SGE_NUM_PRE_WR);
    if (run_ctx->jfs_sge == NULL) {
        goto free_wr;
    }

    for (i = 0; i < cfg->jettys; i++) {
        run_ctx->scnt[i] = 0;
        run_ctx->ccnt[i] = 0;
        for (j = 0; j < cfg->jfs_post_list; j++) {
            wr = &run_ctx->jfs_wr[i * cfg->jfs_post_list + j];
            init_jfs_wr_base(wr, ctx, cfg, i, j);
            init_jfs_wr_sg(wr, ctx, cfg, i, j);
        }
    }
    return 0;
free_wr:
    free(run_ctx->jfs_wr);
    return -1;
}

static inline void destroy_jfs_wr(perftest_context_t *ctx)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    free(run_ctx->jfs_sge);
    free(run_ctx->jfs_wr);
}

static void init_jfr_wr(urma_jfr_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t sge_size = cfg->size / cfg->sge_num;
    uint32_t sge_idx;

    uint64_t lva = (cfg->seg_pre_jetty == false) ?
        (uint64_t)ctx->local_buf[0] + i * ctx->buf_size :
        (uint64_t)ctx->local_buf[i];

    uint32_t local_sge_idx = (i * cfg->jfr_post_list + j) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
    urma_sge_t *local_sge = &run_ctx->jfr_sge[local_sge_idx];

    local_sge[0].addr = lva;
    if (j > 0 && cfg->cmd == PERFTEST_SEND_BW && cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
        increase_loc_addr(&local_sge[0], cfg->size, j, lva, cfg->cache_line_size, ctx->page_size);
    }

    for (sge_idx = 0; sge_idx < cfg->sge_num; sge_idx++) {
        local_sge[sge_idx].addr = local_sge[0].addr + sge_size * sge_idx;
        local_sge[sge_idx].len = sge_size;
        local_sge[sge_idx].tseg = ctx->local_tseg[i];
    }

    wr->src.sge = local_sge;
    wr->src.num_sge = cfg->sge_num;
    wr->next = (j == cfg->jfr_post_list - 1) ? NULL : &run_ctx->jfr_wr[i * cfg->jfr_post_list + j + 1];
    wr->user_ctx = (uintptr_t)i;
}

static int alloc_jfr_ctx_buffer(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    run_ctx->jfr_wr = calloc(1, sizeof(urma_jfr_wr_t) * cfg->jettys * cfg->jfr_post_list);
    if (run_ctx->jfr_wr == NULL) {
        return -1;
    }
    run_ctx->jfr_sge = calloc(1, sizeof(urma_sge_t) *
        cfg->jettys * cfg->jfr_post_list * cfg->sge_num * PERFTEST_SGE_NUM_PRE_WR);
    if (run_ctx->jfr_sge == NULL) {
        goto free_jfr_wr;
    }

    run_ctx->rx_buf_addr = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (run_ctx->rx_buf_addr == NULL) {
        goto free_jfr_sge;
    }
    return 0;

free_jfr_sge:
    free(run_ctx->jfr_sge);
free_jfr_wr:
    free(run_ctx->jfr_wr);
    return -1;
}

static inline void destroy_jfr_wr(perftest_context_t *ctx)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    free(run_ctx->rx_buf_addr);
    free(run_ctx->jfr_sge);
    free(run_ctx->jfr_wr);
}

static int prepare_jfr_wr(perftest_context_t *ctx, perftest_config_t *cfg)
{
    urma_status_t status;
    uint32_t i, j;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfr_wr_t *wr, *bad_wr;
    uint32_t size_per_jetty = cfg->jfr_depth / cfg->jfr_post_list;
    uint32_t local_sge_idx;

    if (cfg->share_jfr) {
        size_per_jetty /= cfg->jettys;
    }
    run_ctx->rposted = (int)(size_per_jetty * cfg->jfr_post_list);

    if (alloc_jfr_ctx_buffer(ctx, cfg) != 0) {
        (void)fprintf(stderr, "Failed to calloc jfr ctx buffer.\n");
        return -1;
    }
    // todo: jfr_wr info need to be filled to guarantee success of urma_post_jfr_wr/urma_post_jetty_recv_wr
    for (i = 0; i < cfg->jettys; i++) {
        for (j = 0; j < cfg->jfr_post_list; j++) {
            wr = &run_ctx->jfr_wr[i * cfg->jfr_post_list + j];
            // init recv wr
            init_jfr_wr(wr, ctx, cfg, i, j);
        }

        local_sge_idx = (i * cfg->jfr_post_list) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num;
        run_ctx->rx_buf_addr[i] = run_ctx->jfr_sge[local_sge_idx].addr;
        for (j = 0; j < size_per_jetty; j++) {
            // no necessary to fill jfr_wr by using urma_post_jfr_wr in LAT test.
            if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX && cfg->type == PERFTEST_BW) {
                status = urma_post_jfr_wr(ctx->jfr[i], &run_ctx->jfr_wr[i * cfg->jfr_post_list], &bad_wr);
                if (status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Failed to post jfr wr.\n");
                    goto free_jfr;
                }
            // no necessary to fill jfr_wr by using urma_post_jetty_recv_wr in LAT test.
            } else if (cfg->jetty_mode == PERFTEST_JETTY_DUPLEX && cfg->type == PERFTEST_BW) {
                status = urma_post_jetty_recv_wr(ctx->jetty[i], &run_ctx->jfr_wr[i * cfg->jfr_post_list], &bad_wr);
                if (status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Failed to post jetty recv wr, status: %d.\n", status);
                    goto free_jfr;
                }
            }
            if (cfg->jfr_post_list == 1 && cfg->type == PERFTEST_BW &&
                cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
                urma_sge_t *jfr_sge = &run_ctx->jfr_sge[local_sge_idx];
                increase_loc_addr(&jfr_sge[0],
                    cfg->size, j, run_ctx->rx_buf_addr[i], cfg->cache_line_size, ctx->page_size);
                for (uint32_t sge_idx = 0; sge_idx < cfg->sge_num; sge_idx++) {
                    jfr_sge[sge_idx].addr = jfr_sge[0].addr + cfg->size / cfg->sge_num;
                }
            }
        }
        run_ctx->jfr_sge[local_sge_idx].addr =
            run_ctx->rx_buf_addr[i];
    }
    return 0;

free_jfr:
    destroy_jfr_wr(ctx);
    return -1;
}

static int run_lat_test(perftest_context_t *ctx, perftest_config_t *cfg, void *(*fn) (void *))
{
    perftest_thread_arg_t *args = calloc(cfg->jettys, sizeof(perftest_thread_arg_t));
    if (args == NULL) {
        return ENOMEM;
    }
    for (uint32_t i = 0; i < cfg->jettys; i++) {
        args[i].cfg = cfg;
        args[i].ctx = ctx;
        args[i].id = i;
    }

    for (uint32_t i = 0; i < cfg->jettys; i++) {
        (void)pthread_create(&args[i].thread_id, NULL, fn, (void *)&args[i]);
    }

    void *thread_ret;
    for (uint32_t i = 0; i < cfg->pair_num; i++) {
        (void)pthread_join(args[i].thread_id, &thread_ret);
    }

    free(args);

    for (uint64_t id = 0; id < cfg->jettys; id++) {
        if (cfg->time_type.bs.iterations == 1) {
            print_lat_report(ctx, cfg, id);
        } else {
            print_lat_duration_report(ctx, cfg, id);
        }
    }
    return 0;
}

static void *run_read_lat_duplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(cfg->jfc_depth, sizeof(urma_cr_t));
    if (cr == NULL) {
        (void)fprintf(stderr, "Failed alloc cr, id:%u\n", id);
        return NULL;
    }

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
        }
        urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
        urma_jfs_wr_t *bad_wr = NULL;
        for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
            wr[i].user_ctx = (uintptr_t)++rid;
        }
        urma_status_t status = urma_post_jetty_send_wr(ctx->jetty[id], wr, &bad_wr);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to post jfs wr, id:%u, status:%d, scnt:%lu\n", id, (int)status, scnt);
            goto free_cr;
        }
        scnt += cfg->jfs_post_list;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
            goto free_cr;
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
            run_ctx->scnt[id] += 1;
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}

static int run_read_lat_once(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return ret;
    }

    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        ret = run_lat_test(ctx, cfg, run_read_lat_simplex);
    } else {
        ret = run_lat_test(ctx, cfg, run_read_lat_duplex);
    }

    destroy_jfs_wr(ctx);

    return ret;
}

int run_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    /* Only Client read test. */
    if (cfg->comm.server_ip == NULL) {
        return 0;
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_read_lat_once(ctx, cfg) != 0) {
                (void)fprintf(stderr, "Failed to run once, size: %u.\n", cfg->size);
                return -1;
            }
        }
    } else {
        if (run_read_lat_once(ctx, cfg) != 0) {
            (void)fprintf(stderr, "Failed to run once, size: %u.\n", cfg->size);
            return -1;
        }
    }

    return 0;
}

static void *run_write_lat_duplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    uint64_t ccnt = 0;
    uint64_t rcnt = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * cfg->jfc_depth);
    if (cr == NULL) {
        (void)fprintf(stderr, "Failed alloc cr, id:%u\n", id);
        return NULL;
    }

    bool is_server = cfg->comm.server_ip == NULL;

    volatile char *post_buf = (char *)ctx->local_buf[id] + ctx->buf_size + cfg->size - 1;
    volatile char *poll_buf = (char *)ctx->local_buf[id] + cfg->size - 1;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || ccnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && is_server)) {
            rcnt += cfg->jfs_post_list;
            while (*poll_buf != (char)(rcnt / cfg->jfs_post_list) && run_ctx->state != END_STATE) {};
        }

        if (scnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
            }

            scnt += cfg->jfs_post_list;
            *post_buf = (char)(scnt / cfg->jfs_post_list);

            urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
            urma_jfs_wr_t *bad_wr = NULL;
            for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
                wr[i].user_ctx = (uintptr_t)++rid;
            }
            urma_status_t status = urma_post_jetty_send_wr(ctx->jetty[id], wr, &bad_wr);
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Failed to post jfs wr, id:%u, status:%d, scnt:%lu, rcnt:%lu\n",
                    id, (int)status, scnt, rcnt);
                goto free_cr;
            }
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (ccnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
                goto free_cr;
            }
            ccnt += cfg->jfs_post_list;
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
            run_ctx->scnt[id] += 1;
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}


static int run_write_lat_once(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return ret;
    }

    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        ret = run_lat_test(ctx, cfg, run_write_lat_simplex);
    } else {
        ret = run_lat_test(ctx, cfg, run_write_lat_duplex);
    }

    destroy_jfs_wr(ctx);

    return ret;
}

int run_send_lat(perftest_context_t *ctx, perftest_config_t *cfg);
int run_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->enable_imm == true) {
        return run_send_lat(ctx, cfg);
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_write_lat_once(ctx, cfg) != 0) {
                (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
                return -1;
            }
        }
    } else {
        if (run_write_lat_once(ctx, cfg) != 0) {
            (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
            return -1;
        }
    }

    return 0;
}

static int send_lat_post_jetty_recv(perftest_context_t *ctx, perftest_config_t *cfg, uint32_t id, int cnt)
{
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    urma_jfr_wr_t *jfr_bad_wr = NULL;
    urma_jfr_wr_t *jfr_wr = &run_ctx->jfr_wr[id * cfg->jfr_post_list];
    for (int i = 0; i < cnt; i++) {
        jfr_wr->user_ctx = (uintptr_t)run_ctx->rid++;
        status = urma_post_jetty_recv_wr(ctx->jetty[id], jfr_wr, &jfr_bad_wr);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to post jetty recv wr, id:%u, status:%d, size:%u.\n",
                id, (int)status, cfg->size);
            return -1;
        }
    }

    return 0;
}

static void *run_send_lat_duplex(void *arg)
{
    perftest_thread_arg_t *arg_typed = arg;
    perftest_context_t *ctx = arg_typed->ctx;
    perftest_config_t *cfg = arg_typed->cfg;
    uint32_t id = arg_typed->id;

    uint64_t scnt = 0;
    uint64_t rcnt = 0;
    uint64_t used_recv_wr = 0;
    int first_rx = 1;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rid = run_ctx->rid;

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * cfg->jfc_depth);
    if (cr == NULL) {
        (void)fprintf(stderr, "[%u] Failed alloc cr.\n", id);
        return NULL;
    }

    bool is_server = cfg->comm.server_ip == NULL;

    /*
     * Sync between the client and server so the client won't send packets
     * before the server has posted his receive wqes.
     */
    if (send_lat_post_jetty_recv(ctx, cfg, id, (int)(cfg->jfr_depth / cfg->jfr_post_list)) != 0) {
        goto free_cr;
    }
    if (sync_time(cfg->comm.sock_fd[id], "send_lat_post_recv") != 0) {
        goto free_cr;
    }

    while (scnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        /*
         * Get the recv packet. make sure that the client won't enter here until he sends his first packet (scnt < 1)
         * server will enter here first and wait for a packet to arrive (from the client)
         */
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && !is_server)) {
            if (cfg->use_jfce == true) {
                if (wait_jfc_event(ctx->jfce_r[id], cfg->wait_jfc_timeout) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event, id:%u\n", id);
                    goto free_cr;
                }
            }

            /*
             * Using the ping-pong transmission model, the expected number of received CQEs equals
             * the number of sended WRs.
             */
            int cqe_expected = (int)cfg->jfs_post_list;
            do {
                int cqe_cnt = urma_poll_jfc(ctx->jfc_r[id], cfg->jfc_depth, cr);
                if (cqe_cnt > 0) {
                    for (int i = 0; i < cqe_cnt; i++) {
                        if (cr[i].status != URMA_CR_SUCCESS) {
                            (void)fprintf(stderr, "Failed CR status, id:%u, status:%d.\n", id, (int)cr[i].status);
                            goto free_cr;
                        }
                    }
                    if (first_rx != 0) {
                        set_on_first_rx(ctx, cfg);
                        first_rx = 0;
                    }
                    rcnt += (uint64_t)cqe_cnt;
                    cqe_expected -= cqe_cnt;

                    /*
                     * if we're in duration mode or there is enough space in the rx_depth,
                     * post that you received a packet.
                     */
                    used_recv_wr += (uint64_t)cqe_cnt;
                    if (used_recv_wr >= cfg->jfr_post_list &&
                        (cfg->time_type.bs.duration == 1 || rcnt + cfg->jfr_depth - used_recv_wr < cfg->iters)) {
                        if (send_lat_post_jetty_recv(ctx, cfg, id, used_recv_wr / cfg->jfr_post_list) != 0) {
                            goto free_cr;
                        }
                        used_recv_wr = used_recv_wr % cfg->jfr_post_list;
                    }
                } else if (cqe_cnt < 0) {
                    (void)fprintf(stderr, "Failed poll jfc_r, id:%u, cqe_cnt:%d.\n", id, cqe_cnt);
                    goto free_cr;
                }
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }
            } while (cqe_expected > 0);

            if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                run_ctx->scnt[id] += 1;
            }
        }

        if (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[id * cfg->iters + scnt] = get_cycles();
            }

            scnt += cfg->jfs_post_list;

            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }

            urma_jfs_wr_t *wr = &run_ctx->jfs_wr[id * cfg->jfs_post_list];
            urma_jfs_wr_t *bad_wr = NULL;
            for (uint32_t i = 0; i < cfg->jfs_post_list; i++) {
                wr[i].user_ctx = (uintptr_t)++rid;
            }
            if (cfg->jfs_post_list == 1) {
                if (scnt % cfg->cq_mod == 0) {
                    wr[0].flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
                } else {
                    wr[0].flag.bs.complete_enable = URMA_COMPLETE_DISABLE;
                }
            }
            urma_status_t status = urma_post_jetty_send_wr(ctx->jetty[id], wr, &bad_wr);
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Failed to post jetty send wr, id:%u, status:%d, scnt:%lu, rcnt:%lu\n",
                    id, (int)status, scnt, rcnt);
                goto free_cr;
            }

            if (cfg->jfs_post_list != 1 || scnt % cfg->cq_mod == 0) {
                if (poll_jfc_until_expected_cqe(ctx, cfg, id, cr) != 0) {
                    goto free_cr;
                }
            }
        }
    }

    free(cr);
    return NULL;

free_cr:
    free(cr);
    return NULL;
}

int run_send_lat_once(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return ret;
    }
    ret = prepare_jfr_wr(ctx, cfg);
    if (ret != 0) {
        goto destroy_post_jfs;
    }

    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        ret = run_lat_test(ctx, cfg, run_send_lat_simplex);
    } else {
        ret = run_lat_test(ctx, cfg, run_send_lat_duplex);
    }

    destroy_jfr_wr(ctx);
destroy_post_jfs:
    destroy_jfs_wr(ctx);
    return ret;
}

int run_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_send_lat_once(ctx, cfg) != 0) {
                (void)fprintf(stderr, "Failed to run once, size: %u.\n", cfg->size);
                return -1;
            }
        }
    } else {
        if (run_send_lat_once(ctx, cfg) != 0) {
            (void)fprintf(stderr, "Failed to run once, size: %u.\n", cfg->size);
            return -1;
        }
    }

    return 0;
}

int run_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    return run_read_lat(ctx, cfg);
}

static int run_once_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t tot_scnt = 0;
    uint64_t tot_ccnt = 0;
    uint32_t index;
    int cqe_cnt = 0;
    int cr_id;    // completion_record_data
    /* Rate limiter */
    uint64_t gap_deadline = 0;  /* cycle */
    uint32_t burst_iter = 0;
    bool is_send_burst = false;

    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        return -1;
    }

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    uint64_t tot_iters = cfg->iters * cfg->jettys;

    if (cfg->time_type.bs.iterations == 1 && cfg->no_peak == true) {
        run_ctx->tposted[0] = get_cycles();
    }

    while (tot_scnt < tot_iters || tot_ccnt < tot_iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        /* main loop to run over all the jetty and post each time n messages */
        for (index = 0; index < cfg->jettys; index++) {
            if (cfg->is_rate_limit == true && is_send_burst == false) {
                if (gap_deadline > get_cycles()) {
                    continue;
                }
                gap_deadline = get_cycles() + cfg->gap_cycles;
                is_send_burst = true;
                burst_iter = 0;
            }
            while ((run_ctx->scnt[index] < cfg->iters || cfg->time_type.bs.duration == 1) &&
                (run_ctx->scnt[index] - run_ctx->ccnt[index] + cfg->jfs_post_list) <= cfg->jfs_depth &&
                !(cfg->is_rate_limit == true && is_send_burst == false)) {
                if (cfg->enable_credit == true) {
                    uint64_t swinow = (run_ctx->scnt[index] + cfg->jfs_post_list) > ctx->ctrl_buf[index][1] ?
                        (run_ctx->scnt[index] + cfg->jfs_post_list - ctx->ctrl_buf[index][1]) : 0;
                    if (swinow >= (uint64_t)cfg->credit_threshold) {
                        break;
                    }
                }
                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == 0 && cfg->cq_mod > 1) &&
                    !(run_ctx->scnt[index] == (cfg->iters - 1) && cfg->time_type.bs.iterations == 1)) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 0;
                }

                if (cfg->no_peak == false) {
                    run_ctx->tposted[tot_scnt] = get_cycles();
                }

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }
                urma_jfs_wr_t *bad_wr = NULL;
                if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                    status = urma_post_jfs_wr(ctx->jfs[index], &run_ctx->jfs_wr[index * cfg->jfs_post_list], &bad_wr);
                } else {
                    status = urma_post_jetty_send_wr(ctx->jetty[index], &run_ctx->jfs_wr[index * cfg->jfs_post_list],
                        &bad_wr);
                }

                if (status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Couldn't post jfs: jetty %u scnt:%lu, tot_scnt:%lu, status:%d, \
                        ccnt:%lu, tot_ccnt:%lu.\n", index, run_ctx->scnt[index], tot_scnt, (int)status,
                        run_ctx->ccnt[index], tot_ccnt);
                    goto free_cr;
                }

                /* In the case of non wr_list, the address of each wqe is also incremented. */
                if (cfg->jfs_post_list == 1 && cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
                    uint32_t local_sge_idx = (index * cfg->jfs_post_list) * PERFTEST_SGE_NUM_PRE_WR *
                        cfg->sge_num + cfg->sge_num;
                    // Step increased value
                    urma_sge_t *local_sge = &run_ctx->jfs_sge[local_sge_idx];
                    increase_loc_addr(local_sge, cfg->size, run_ctx->scnt[index],
                        (uint64_t)ctx->local_buf[index] + ctx->buf_size, cfg->cache_line_size, ctx->page_size);

                    if (cfg->api_type != PERFTEST_SEND) {
                        urma_sge_t *remote_sge =
                            &run_ctx->jfs_sge[(index * cfg->jfs_post_list) * PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num];
                        increase_loc_addr(remote_sge, cfg->size, run_ctx->scnt[index],
                            (uint64_t)ctx->remote_seg[index]->ubva.va, cfg->cache_line_size, ctx->page_size);
                    }
                }

                run_ctx->scnt[index] += cfg->jfs_post_list;
                tot_scnt += cfg->jfs_post_list;

                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == cfg->cq_mod - 1 ||
                    (cfg->time_type.bs.iterations == 1 && run_ctx->scnt[index] == cfg->iters - 1))) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 1;
                }

                if (cfg->is_rate_limit == true) {
                    burst_iter += cfg->jfs_post_list;
                    if (burst_iter >= cfg->burst_size) {
                        is_send_burst = false;
                    }
                }
            }
        }

        if (tot_ccnt < tot_iters || (cfg->time_type.bs.duration == 1 && tot_ccnt < tot_scnt)) {
            if (cfg->use_jfce == true && cqe_cnt == 0) {
                if (wait_jfc_event(ctx->jfce_s[0], cfg->wait_jfc_timeout) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event\n");
                    goto free_cr;
                }
            }
            cqe_cnt = urma_poll_jfc(ctx->jfc_s[0], PERFTEST_POLL_BATCH, cr);
            if (cqe_cnt > 0) {
                for (int i = 0; i < cqe_cnt; i++) {
                    cr_id = (int)cr[i].user_ctx; // todo jfs_id
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, tot_scnt: %lu, tot_ccnt: %lu.\n",
                            (int)cr[i].status, tot_scnt, tot_ccnt);
                        if (cfg->enable_err_continue == false) {
                            goto free_cr;
                        } else {
                            tot_scnt = tot_scnt - (cqe_cnt - i) * cfg->cq_mod;
                            continue;
                        }
                    }

                    run_ctx->ccnt[cr_id] += cfg->cq_mod;
                    tot_ccnt += cfg->cq_mod;

                    if (cfg->no_peak == false) {
                        if (tot_ccnt > tot_iters) {
                            run_ctx->tcompleted[cfg->iters * cfg->jettys - 1] = get_cycles();
                        } else {
                            run_ctx->tcompleted[tot_ccnt - 1] = get_cycles();
                        }
                    }

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters += cfg->cq_mod;
                    }
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                goto free_cr;
            }
        }
    }

    if (cfg->no_peak == true && cfg->time_type.bs.iterations == 1) {
        run_ctx->tcompleted[0] = get_cycles();
    }
    free(cr);
    return 0;
free_cr:
    free(cr);
    return -1;
}

static int clean_scq_credit(int send_cnt, perftest_context_t *ctx, perftest_config_t *cfg)
{
    int i = 0, sne = 0;
    int ret = 0;

    if (!send_cnt) {
        return 0;
    }
    urma_cr_t *swc = calloc(1, sizeof(urma_cr_t) * cfg->jfs_depth);
    if (swc == NULL) {
        return -1;
    }

    do {
        sne = urma_poll_jfc(ctx->jfc_s[0], cfg->jfs_depth, swc);
        if (sne > 0) {
            for (i = 0; i < sne; i++) {
                if (swc[i].status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Poll send CQ error status=%u qp %d\n",
                        swc[i].status, (int)swc[i].user_ctx);
                    ret = -1;
                    goto cleaning;
                }
                send_cnt--;
            }
        } else if (sne < 0) {
            fprintf(stderr, "Poll send CR to clean credit failed ne=%d\n", sne);
            ret = -1;
            goto cleaning;
        }
    } while (send_cnt > 0);

cleaning:
    free(swc);
    return ret;
}

static int run_once_bw_recv(perftest_context_t *ctx, perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t rcnt = 0;
    int cqe_cnt = 0;
    int first_rx = 1;
    uint32_t i;
    uint32_t cr_id;
    urma_jfr_wr_t *bad_wr = NULL;
    int ret = 0;
    int tot_scredit = 0;
    urma_status_t status;

    uint64_t *posted_per_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (posted_per_jetty == NULL) {
        return -1;
    }
    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        ret = -1;
        goto free_recv_jetty;
    }
    urma_cr_t *scr = calloc(1, sizeof(urma_cr_t) * cfg->jfs_depth);
    if (scr == NULL) {
        ret = -1;
        goto free_recv_cr;
    }
    uint64_t *rcnt_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (rcnt_pre_jetty == NULL) {
        ret = -1;
        goto free_scredit_cr;
    }

    uint64_t *unused_recv_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (unused_recv_pre_jetty == NULL) {
        ret = -1;
        goto free_rcnt;
    }
    uint64_t *scredit_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (scredit_pre_jetty == NULL) {
        ret = -1;
        goto free_unused_recv;
    }

    for (i = 0; i < cfg->jettys; i++) {
        posted_per_jetty[i] = (uint32_t)run_ctx->rposted;
    }
    uint64_t tot_iters = cfg->iters * cfg->jettys;

    while (rcnt < tot_iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_r[0], cfg->wait_jfc_timeout) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfc event.\n");
                ret = -1;
                goto cleaning;
            }
        }

        do {
            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }
            cqe_cnt = urma_poll_jfc(ctx->jfc_r[0], PERFTEST_POLL_BATCH, &cr[0]);
            if (cqe_cnt > 0) {
                if (first_rx) {
                    set_on_first_rx(ctx, cfg);
                    first_rx = 0;
                }

                for (i = 0; i < cqe_cnt; i++) {
                    cr_id = cr[i].user_ctx;
                    if (cr_id >= cfg->jettys) {
                        (void)fprintf(stderr, "Out of range, cr_id: %u, jettys: %u\n", cr_id, cfg->jettys);
                        ret = -1;
                        goto cleaning;
                    }
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, rcnt: %lu.\n", (int)cr[i].status, rcnt);
                        if (cfg->enable_err_continue == false) {
                            ret = -1;
                            goto cleaning;
                        } else {
                            if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                                status = urma_post_jfr_wr(ctx->jfr[cr_id],
                                    &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                            } else {
                                status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                                    &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                            }
                            if (status != 0) {
                                (void)fprintf(stderr, "Failed to post jfr wr, " \
                                        "status: %d, i: %u, rcnt: %lu, cr_id: %u.\n",
                                    status, i, rcnt, cr_id);
                                ret = -1;
                                goto cleaning;
                            }
                            continue;
                        }
                    }
                    rcnt_pre_jetty[cr_id]++;
                    rcnt++;
                    unused_recv_pre_jetty[cr_id]++;

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters++;
                    }
                    if ((cfg->time_type.bs.duration == 1 ||
                        posted_per_jetty[cr_id] + cfg->jfr_post_list <= cfg->iters) &&
                        unused_recv_pre_jetty[cr_id] >= cfg->jfr_post_list) {
                        if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                            status = urma_post_jfr_wr(ctx->jfr[cr_id],
                                &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                        } else {
                            status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                                &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                        }
                        if (status != 0) {
                            (void)fprintf(stderr, "Failed to post jfr wr, status: %d, i: %u, rcnt: %lu, cr_id: %u.\n",
                                status, i, rcnt, cr_id);
                            ret = -1;
                            goto cleaning;
                        }
                        unused_recv_pre_jetty[cr_id] -= cfg->jfr_post_list;
                        posted_per_jetty[cr_id] += cfg->jfr_post_list;

                        if (cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM) && cfg->jfr_post_list == 1) {
                            urma_sge_t *local_sge = &run_ctx->jfr_sge[(cr_id * cfg->jfr_post_list) *
                                PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num];

                            increase_loc_addr(local_sge, cfg->size, posted_per_jetty[cr_id],
                                (uint64_t)ctx->local_buf[cr_id], cfg->cache_line_size, ctx->page_size);
                        }
                    }

                    if (cfg->enable_credit == true) {
                        int credit_cnt = rcnt_pre_jetty[cr_id] % cfg->jfr_depth;
                        if (credit_cnt % cfg->credit_notify_cnt == 0) {
                            urma_jfs_wr_t *bad_send_wr = NULL;
                            int sne = 0, j = 0;
                            ctx->ctrl_buf[cr_id][0] = rcnt_pre_jetty[cr_id];
                            while (scredit_pre_jetty[cr_id] == cfg->jfs_depth) {
                                sne = urma_poll_jfc(ctx->jfc_s[0], cfg->jfs_depth, scr);
                                if (sne > 0) {
                                    for (j = 0; j < sne; j++) {
                                        if (scr[j].status != URMA_CR_SUCCESS) {
                                            (void)fprintf(stderr, "Poll send CQ error status=%u jetty %d \n",
                                                scr[j].status, (int)scr[j].user_ctx);
                                            (void)fprintf(stderr, "credit=%lu scredit=%lu\n",
                                                rcnt_pre_jetty[scr[j].user_ctx], scredit_pre_jetty[scr[j].user_ctx]);
                                            ret = -1;
                                            goto cleaning;
                                        }
                                        scredit_pre_jetty[scr[j].user_ctx]--;
                                        tot_scredit--;
                                    }
                                } else if (sne < 0) {
                                        (void)fprintf(stderr, "Poll send cr failed ne=%d\n", sne);
                                        ret = -1;
                                        goto cleaning;
                                }
                            }
                            if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                                status = urma_post_jfs_wr(ctx->jfs[cr_id], &run_ctx->credit_wr[cr_id],
                                    &bad_send_wr);
                            } else {
                                status = urma_post_jetty_send_wr(ctx->jetty[cr_id], &run_ctx->credit_wr[cr_id],
                                    &bad_send_wr);
                            }
                            if (status != URMA_SUCCESS) {
                                (void)fprintf(stderr, "Couldn't post send jetty %u credit = %lu scredit = %lu\n",
                                    cr_id, rcnt_pre_jetty[cr_id], scredit_pre_jetty[cr_id]);
                                    ret = -1;
                                    goto cleaning;
                            }
                            scredit_pre_jetty[cr_id]++;
                            tot_scredit++;
                        }
                    }
                }
            }
        } while (cqe_cnt > 0);

        if (cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc, cqe_cnt %d\n", cqe_cnt);
            ret = -1;
            goto cleaning;
        }
    }
    if (cfg->time_type.bs.iterations == 1) {
        run_ctx->tcompleted[0] = get_cycles();
    }
    ret = 0;
cleaning:
    if (cfg->enable_credit == true) {
        if (clean_scq_credit(tot_scredit, ctx, cfg)) {
            ret = -1;
        }
    }
    free(scredit_pre_jetty);
free_unused_recv:
    free(unused_recv_pre_jetty);
free_rcnt:
    free(rcnt_pre_jetty);
free_scredit_cr:
    free(scr);
free_recv_cr:
    free(cr);
free_recv_jetty:
    free(posted_per_jetty);
    return ret;
}

static int run_once_bi_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t tot_scnt = 0;
    uint64_t tot_ccnt = 0;
    uint64_t tot_rcnt = 0;
    uint32_t index;
    int send_cqe_cnt = 0;
    int recv_cqe_cnt = 0;
    uint32_t cr_id;
    int tot_scredit = 0;
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    bool before_first_recv = true;
    uint32_t jettys = cfg->jettys;
    urma_jfs_wr_t *bad_jfs_wr = NULL;
    urma_jfr_wr_t *bad_jfr_wr = NULL;
    int ret = 0;

    urma_cr_t *cr_recv = (urma_cr_t *)calloc(1, sizeof(urma_cr_t) * cfg->jfr_depth);
    if (cr_recv == NULL) {
        return -1;
    }
    urma_cr_t *cr_send = (urma_cr_t *)calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr_send == NULL) {
        ret = -1;
        goto free_cr_recv;
    }
    uint64_t *rcnt_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (rcnt_pre_jetty == NULL) {
        ret = -1;
        goto free_cr_send;
    }
    uint64_t *scredit_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (scredit_pre_jetty == NULL) {
        ret = -1;
        goto free_rcnt;
    }
    uint32_t *unused_recv_for_jetty = (uint32_t *)calloc(1, sizeof(uint32_t) * cfg->jettys);
    if (unused_recv_for_jetty == NULL) {
        ret = -1;
        goto free_scredit;
    }
    uint32_t *posted_per_jetty = (uint32_t *)calloc(1, sizeof(uint32_t) * jettys);
    if (posted_per_jetty == NULL) {
        ret = -1;
        goto free_unused_recv_for_jetty;
    }
    for (uint32_t i = 0; i < jettys; i++) {
        posted_per_jetty[i] = (uint32_t)run_ctx->rposted;
    }

    if (cfg->no_peak) {
        run_ctx->tposted[0] = get_cycles();
    }

    if (cfg->comm.server_ip != NULL) {
        before_first_recv = false;
        if (cfg->time_type.bs.duration == 1) {
            update_duration_state(ctx, cfg);
        }
    }

    uint64_t tot_iters = cfg->iters * jettys;

    while ((cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE) ||
        tot_ccnt < tot_iters || tot_rcnt < tot_iters) {
        for (index = 0; index < jettys; index++) {
            while (before_first_recv == false &&
                (run_ctx->scnt[index] < cfg->iters || cfg->time_type.bs.duration == 1) &&
                (((run_ctx->scnt[index] + scredit_pre_jetty[index] - run_ctx->ccnt[index]) + cfg->jfs_post_list) <=
                cfg->jfs_depth)) {
                if (cfg->enable_credit == true) {
                    uint64_t swinow = (run_ctx->scnt[index] + cfg->jfs_post_list) > ctx->ctrl_buf[index][1] ?
                        (run_ctx->scnt[index] + cfg->jfs_post_list - ctx->ctrl_buf[index][1]) : 0;
                    if (swinow >= (uint64_t)cfg->credit_threshold) {
                        break;
                    }
                }
                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == 0 && cfg->cq_mod > 1) &&
                    !(run_ctx->scnt[index] == (cfg->iters - 1) && cfg->time_type.bs.iterations == 1)) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 0;
                }
                if (!cfg->no_peak) {
                    run_ctx->tposted[tot_scnt] = get_cycles();
                }
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }
                if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                    status = urma_post_jfs_wr(ctx->jfs[index], &run_ctx->jfs_wr[index * cfg->jfs_post_list],
                        &bad_jfs_wr);
                } else {
                    status = urma_post_jetty_send_wr(ctx->jetty[index], &run_ctx->jfs_wr[index * cfg->jfs_post_list],
                        &bad_jfs_wr);
                }
                if (status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Failed to post jfs: jetty %u, scnt=%lu, tot_scnt:%lu, ccnt:%lu, \
                        tot_ccnt:%lu, tot_rcnt:%lu, status:%d.\n", index, run_ctx->scnt[index], tot_scnt,
                        run_ctx->scnt[index], tot_ccnt, tot_rcnt, (int)status);
                    ret = -1;
                    goto cleaning;
                }

                if (cfg->jfs_post_list == 1 && cfg->size <= (cfg->page_size / PERFTEST_BUF_NUM)) {
                    urma_sge_t *local_sge = &run_ctx->jfs_sge[(index * cfg->jfs_post_list) *
                        PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num];
                    increase_loc_addr(local_sge, cfg->size, run_ctx->scnt[index],
                        (uint64_t)ctx->local_buf[index] + ctx->buf_size, cfg->cache_line_size, ctx->page_size);
                }

                run_ctx->scnt[index] += cfg->jfs_post_list;
                tot_scnt += cfg->jfs_post_list;

                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == cfg->cq_mod - 1 ||
                    (cfg->time_type.bs.iterations == 1 && run_ctx->scnt[index] == cfg->iters - 1))) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 1;
                }
            }
        }
        if (cfg->use_jfce && recv_cqe_cnt == 0 && send_cqe_cnt == 0) {
            if (tot_rcnt < tot_iters && wait_jfc_event(ctx->jfce_r[0], cfg->wait_jfc_timeout) != 0) {
                (void)fprintf(stderr, "Failed to wait jfce_r event.\n");
                ret = -1;
                goto cleaning;
            }
            if (before_first_recv == false && tot_ccnt < tot_iters &&
                wait_jfc_event(ctx->jfce_s[0], cfg->wait_jfc_timeout) != 0) {
                (void)fprintf(stderr, "Failed to wait jfce_s event.\n");
                ret = -1;
                goto cleaning;
            }
        }

        recv_cqe_cnt = urma_poll_jfc(ctx->jfc_r[0], (int)cfg->jfr_depth, cr_recv);
        if (recv_cqe_cnt > 0) {
            if (cfg->comm.server_ip == NULL && before_first_recv) {
                before_first_recv = false;
                if (cfg->time_type.bs.duration == 1) {
                    update_duration_state(ctx, cfg);
                }
            }

            for (int i = 0; i < recv_cqe_cnt; i++) {
                cr_id = (uint32_t)cr_recv[i].user_ctx;
                if (cr_id >= cfg->jettys) {
                    ret = -1;
                    goto cleaning;
                }
                if (cr_recv[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status: %d, tot_scnt: %lu, tot_ccnt: %lu, tot_rcnt: %lu.\n",
                        (int)cr_recv[i].status, tot_scnt, tot_ccnt, tot_rcnt);
                    if (cfg->enable_err_continue == false) {
                        ret = -1;
                        goto cleaning;
                    } else {
                        if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                            status = urma_post_jfr_wr(ctx->jfr[cr_id], &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list],
                                &bad_jfr_wr);
                        } else {
                            status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                                &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_jfr_wr);
                        }
                        if (status != URMA_SUCCESS) {
                            (void)fprintf(stderr, "Failed to post jfr, status:%d, i: %d, tot_rcnt: %lu, cr_id: %u \
                                tot_scnt: %lu, tot_ccnt: %lu.\n", (int)status, i, tot_rcnt, cr_id, tot_scnt, tot_ccnt);
                            ret = -1;
                            goto cleaning;
                        }
                        continue;
                    }
                }

                rcnt_pre_jetty[cr_id]++;
                unused_recv_for_jetty[cr_id]++;
                tot_rcnt++;

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }

                if ((cfg->time_type.bs.duration == 1 ||
                    posted_per_jetty[cr_id] + cfg->jfr_post_list <= cfg->iters) &&
                    unused_recv_for_jetty[cr_id] >= cfg->jfr_post_list) {
                    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                        status = urma_post_jfr_wr(ctx->jfr[cr_id], &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list],
                            &bad_jfr_wr);
                    } else {
                        status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                            &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_jfr_wr);
                    }
                    if (status != URMA_SUCCESS) {
                        (void)fprintf(stderr, "Failed to post jfr, status:%d, i: %d, tot_rcnt: %lu, cr_id: %u \
                            tot_scnt: %lu, tot_ccnt: %lu.\n", (int)status, i, tot_rcnt, cr_id, tot_scnt, tot_ccnt);
                        ret = -1;
                        goto cleaning;
                    }
                    unused_recv_for_jetty[cr_id] -= cfg->jfr_post_list;
                    posted_per_jetty[cr_id] += cfg->jfr_post_list;
                    if (cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM) && cfg->jfr_post_list == 1) {
                        urma_sge_t *local_sge = &run_ctx->jfr_sge[(cr_id * cfg->jfr_post_list) *
                            PERFTEST_SGE_NUM_PRE_WR * cfg->sge_num + cfg->sge_num];
                        increase_loc_addr(local_sge, cfg->size, posted_per_jetty[cr_id],
                            (uint64_t)ctx->local_buf[cr_id], cfg->cache_line_size, ctx->page_size);
                    }
                }
                if (cfg->enable_credit == true) {
                    uint32_t credit_cnt = rcnt_pre_jetty[cr_id] % cfg->jfr_depth;
                    if (credit_cnt % cfg->credit_notify_cnt == 0) {
                        int sne = 0;
                        urma_cr_t credit_cr;
                        urma_jfs_wr_t *bad_send_wr = NULL;
                        ctx->ctrl_buf[cr_id][0] = rcnt_pre_jetty[cr_id];

                        while ((run_ctx->scnt[cr_id] + scredit_pre_jetty[cr_id] -  run_ctx->ccnt[cr_id]) >=
                                cfg->jfs_depth) {
                            sne = urma_poll_jfc(ctx->jfc_s[0], 1, &credit_cr);
                            bool is_credit = credit_cr.user_ctx & (1UL << PERFTEST_FLAG_USER_CTX);
                            uint64_t credit_id = credit_cr.user_ctx & ~(1UL << PERFTEST_FLAG_USER_CTX);
                            if (sne > 0) {
                                if (credit_cr.status != URMA_CR_SUCCESS) {
                                    (void)fprintf(stderr, "Poll send CQ error status=%u jetty %d \n",
                                        credit_cr.status, (int)credit_id);
                                    (void)fprintf(stderr, "credit=%lu scredit=%lu\n",
                                        rcnt_pre_jetty[credit_id], scredit_pre_jetty[credit_id]);
                                    ret = -1;
                                    goto cleaning;
                                }
                                if (credit_cr.flag.bs.s_r == 0 && is_credit) {
                                        scredit_pre_jetty[credit_id]--;
                                        tot_scredit--;
                                } else {
                                    tot_ccnt += cfg->cq_mod;
                                    run_ctx->ccnt[credit_id] += cfg->cq_mod;
                                    if (cfg->no_peak == false) {
                                        if ((cfg->time_type.bs.iterations == 1 && (tot_ccnt > tot_iters))) {
                                            run_ctx->tcompleted[tot_iters - 1] = get_cycles();
                                        } else {
                                            run_ctx->tcompleted[tot_ccnt - 1] = get_cycles();
                                        }
                                    }
                                    if (cfg->time_type.bs.duration == 1 && g_duration_ctx->state == START_STATE) {
                                        cfg->iters += cfg->cq_mod;
                                    }
                                }
                            } else if (sne < 0) {
                                        (void)fprintf(stderr, "Poll send cr failed ne=%d\n", sne);
                                        ret = -1;
                                        goto cleaning;
                            }
                        }
                        if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                            status = urma_post_jfs_wr(ctx->jfs[cr_id], &run_ctx->credit_wr[cr_id],
                                &bad_send_wr);
                        } else {
                            status = urma_post_jetty_send_wr(ctx->jetty[cr_id], &run_ctx->credit_wr[cr_id],
                                &bad_send_wr);
                        }
                        if (status != URMA_SUCCESS) {
                            (void)fprintf(stderr, "Couldn't post send jetty %u credit = %lu scredit = %lu\n",
                                cr_id, rcnt_pre_jetty[cr_id], scredit_pre_jetty[cr_id]);
                                ret = -1;
                                goto cleaning;
                        }
                        scredit_pre_jetty[cr_id]++;
                        tot_scredit++;
                    }
                }
            }
        } else if (recv_cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc, recv_cqe_cnt: %d.\n", recv_cqe_cnt);
            ret = -1;
            goto cleaning;
        }
        send_cqe_cnt = urma_poll_jfc(ctx->jfc_s[0], PERFTEST_POLL_BATCH, cr_send);
        bool is_credit_send = false;
        if (send_cqe_cnt > 0) {
            for (int i = 0; i < send_cqe_cnt; i++) {
                if (cr_send[i].user_ctx & (1UL << PERFTEST_FLAG_USER_CTX)) {
                    cr_id = cr_send[i].user_ctx & ~(1UL << PERFTEST_FLAG_USER_CTX);
                    is_credit_send = true;
                } else {
                    cr_id = (uint32_t)cr_send[i].user_ctx;
                    is_credit_send = false;
                }
                if (cr_id > cfg->jettys) {
                    ret = -1;
                    goto cleaning;
                }
                if (cr_send[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed cr_send, status: %d, i: %d, tot_ccnt: %lu\n.",
                        (int)cr_send[i].status, i, tot_ccnt);
                    if (cfg->enable_err_continue == false) {
                        ret = -1;
                        goto cleaning;
                    } else {
                        tot_scnt = tot_scnt - (send_cqe_cnt - i) * cfg->cq_mod;
                        continue;
                    }
                }
                if (is_credit_send == true) {
                    if (!cfg->enable_credit) {
                        (void)fprintf(stderr, "Polled WRITE completion without recv credit request\n");
                        ret = -1;
                        goto cleaning;
                    }
                    scredit_pre_jetty[cr_id]--;
                    tot_scredit--;
                } else {
                    tot_ccnt += cfg->cq_mod;
                    run_ctx->ccnt[cr_id] += cfg->cq_mod;
                    if (tot_ccnt > tot_iters) {
                        tot_scredit -= cfg->cq_mod;
                    }
                    if (!cfg->no_peak) {
                        if (cfg->time_type.bs.iterations == 1 && (tot_ccnt > tot_iters)) {
                            run_ctx->tcompleted[tot_iters - 1] = get_cycles();
                        } else {
                            run_ctx->tcompleted[tot_ccnt - 1] = get_cycles();
                        }
                    }

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters += cfg->cq_mod;
                    }
                }
            }
        } else if (send_cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc, send_cqe_cnt: %d\n.", send_cqe_cnt);
            ret = -1;
            goto cleaning;
        }
    }
    if (cfg->no_peak && cfg->time_type.bs.iterations == 1) {
        run_ctx->tcompleted[0] = get_cycles();
    }

cleaning:
    if (cfg->enable_credit == true) {
        if (clean_scq_credit(tot_scredit, ctx, cfg)) {
            ret = -1;
        }
    }

    free(posted_per_jetty);
free_unused_recv_for_jetty:
    free(unused_recv_for_jetty);
free_scredit:
    free(scredit_pre_jetty);
free_rcnt:
    free(rcnt_pre_jetty);
free_cr_send:
    free(cr_send);
free_cr_recv:
    free(cr_recv);
    return ret;
}

static uint64_t calculate_opt_delta(const run_test_ctx_t *run_ctx, perftest_config_t *cfg)
{
    uint64_t i, j, t;
    uint64_t opt_delta = run_ctx->tcompleted[0] - run_ctx->tposted[0];
    if (cfg->no_peak == false) {
        for (i = 0; i < cfg->iters * cfg->jettys; i += cfg->jfs_post_list) {
            for (j = ROUND_UP(i + 1, cfg->cq_mod) - 1; j < cfg->iters * cfg->jettys; j += cfg->cq_mod) {
                t = (run_ctx->tcompleted[j] - run_ctx->tposted[i]) / (j - i + 1);
                if (t < opt_delta) {
                    opt_delta = t;
                }
            }

            if ((cfg->iters * cfg->jettys) % cfg->cq_mod != 0) {
                j = cfg->iters * cfg->jettys - 1;
                t = (run_ctx->tcompleted[j] - run_ctx->tposted[i]) / (j - i + 1);
                if (t < opt_delta) {
                    opt_delta = t;
                }
            }
        }
    }
    return opt_delta;
}

static void print_bw_report(perftest_context_t *ctx, perftest_config_t *cfg,
    bw_report_data_t *local_bw_report, uint64_t tposted_0, double cpu_mhz)
{
    double cycles_to_units, cycles_sum;
    uint64_t opt_delta;
    double peak_up, peak_down;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t num_of_cal_iters = cfg->iters;
    uint64_t inf_bi_factor;
    uint64_t size;

    if (cfg->time_type.bs.infinite == 1) {
        run_ctx->tcompleted[0] = get_cycles();
        num_of_cal_iters = cfg->iters - cfg->last_iters;
    }

    opt_delta = calculate_opt_delta(run_ctx, cfg);
    cycles_to_units = cpu_mhz * PERFTEST_M;
    if ((cycles_to_units - 0.0) <= 0.0) {
        (void)fprintf(stderr, "Can't produce a report\n");
        return;
    }
    inf_bi_factor = (cfg->bidirection && cfg->time_type.bs.infinite == 1) ?
        (cfg->api_type == PERFTEST_SEND ? INF_BI_FACTOR_SEND : INF_BI_FACTOR_OTHER) : NON_INF_BI_FACTOR;
    size = inf_bi_factor * cfg->size;
    uint64_t iters_sum = (cfg->time_type.bs.iterations == 1) ? num_of_cal_iters * cfg->jettys : num_of_cal_iters;
    /* Exception iters equals last_iters, causing iters_sum to be 0 */
    uint64_t run_ctx_iters_sum = iters_sum == 0 ? 0 : iters_sum - 1;
    cycles_sum = (double)(run_ctx->tcompleted[cfg->no_peak == true ? 0 : run_ctx_iters_sum] - tposted_0);

    double bw_avg = ((double)size * iters_sum * cycles_to_units) / (cycles_sum * PERFTEST_BW_MB);
    double msg_rate_avg = ((double)iters_sum * cycles_to_units * inf_bi_factor) / (cycles_sum * PERFTEST_M);

    peak_up = (cfg->no_peak == true ? 0 : 1) * size * cycles_to_units;
    peak_down = opt_delta * PERFTEST_MBS;

    if (local_bw_report != NULL) {
        local_bw_report->size = cfg->size;
        local_bw_report->iters = iters_sum;
        local_bw_report->bw_peak = (double)peak_up / peak_down;
        local_bw_report->bw_avg = bw_avg;
        local_bw_report->msg_rate_avg = msg_rate_avg;
    }
    // print need to be flushed from flowbuffer to output, especially for infinite mode
    (void)fflush(stdout);
    if ((!cfg->bidirection) || ((cfg->api_type == PERFTEST_SEND || cfg->enable_imm == true) &&
        cfg->time_type.bs.duration == 1) || cfg->time_type.bs.infinite == 1) {
        // " %-7u    %-10lu       %-7.3lf            %-7.3lf         %-7.6lf"
        (void)printf(REPORT_BW_FMT, cfg->size, iters_sum, (double)peak_up / peak_down, bw_avg, msg_rate_avg);
        (void)printf("\n");
    }
}

static void print_bi_bw_report(const bw_report_data_t *local_bw_report,
    const bw_report_data_t *remote_bw_report)
{
    /* local and remote bw_report can NOT be NULL */
    uint32_t size = local_bw_report->size;
    /* For bidirectional test, iters is the larger value of local and remote */
    uint64_t iters = (local_bw_report->iters > remote_bw_report->iters) ? local_bw_report->iters :
        remote_bw_report->iters;
    double bw_peak = local_bw_report->bw_peak + remote_bw_report->bw_peak;
    double bw_avg = local_bw_report->bw_avg + remote_bw_report->bw_avg;
    double msg_rate_avg = local_bw_report->msg_rate_avg + remote_bw_report->msg_rate_avg;
    // " %-7u    %-10lu       %-7.3lf            %-7.3lf         %-7.6lf"
    (void)printf(REPORT_BW_FMT, size, iters, bw_peak, bw_avg, msg_rate_avg);
    (void)printf("\n");
}

static void *infinite_print_thread(void *duration)
{
    uint32_t *inf_duration = (uint32_t *)duration;
    /* If both duration and infinite are configured, tposted[0] will be updated by catch_alarm(). */
    uint64_t tposted_0 = g_perftest_ctx->run_ctx.tposted[0];

    /* Function takes more than 200 ms to run, so it needs to be moved outside */
    double cpu_mhz = get_cpu_mhz(g_perftest_cfg->cpu_freq_f);
    if (cpu_mhz <= 0.0) {
        (void)fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
    }

    while (g_perftest_ctx->infinite_print == true) {
        (void)usleep((*inf_duration) * PERFTEST_MSEC_TO_USEC);
        print_bw_report(g_perftest_ctx, g_perftest_cfg, NULL, tposted_0, cpu_mhz);
        g_perftest_cfg->last_iters = g_perftest_cfg->iters;
        tposted_0 = get_cycles();
    }
    return NULL;
}

static int run_once_bw_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t tot_scnt = 0;
    uint64_t tot_ccnt = 0;
    uint32_t jettys = cfg->jettys;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t index;
    urma_status_t status;
    int cqe_cnt;
    int cr_id;

    /* Rate limiter */
    uint64_t gap_deadline = 0;  /* cycle */
    uint32_t burst_iter = 0;
    bool is_send_burst = false;

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        return -1;
    }
    uint64_t *scnt_for_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (scnt_for_jetty == NULL) {
        free(cr);
        return -1;
    }

    g_perftest_ctx = ctx;
    g_perftest_cfg = cfg;

    g_perftest_ctx->infinite_print = true;
    pthread_t print_thread;
    if (pthread_create(&print_thread, NULL, infinite_print_thread, (void *)&cfg->inf_period_ms) != 0) {
        (void)fprintf(stderr, "Failed to create thread.\n");
        free(cr);
        free(scnt_for_jetty);
        return -1;
    }
    cfg->iters = 0;
    cfg->last_iters = 0;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }
    run_ctx->tposted[0] = get_cycles();

    while (1) {
        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            g_perftest_ctx->infinite_print = false;
            void *thread_ret;
            (void)pthread_join(print_thread, &thread_ret);
            break;
        }
        for (index = 0; index < jettys; index++) {
            if (cfg->is_rate_limit == true && is_send_burst == false) {
                if (gap_deadline > get_cycles()) {
                    continue;
                }
                gap_deadline = get_cycles() + cfg->gap_cycles;
                is_send_burst = true;
                burst_iter = 0;
            }
            while (((run_ctx->scnt[index] - run_ctx->ccnt[index]) + cfg->jfs_post_list) <= cfg->jfs_depth &&
                !(cfg->is_rate_limit == true && is_send_burst == false)) {
                if (cfg->enable_credit == true) {
                    uint64_t swinow = (scnt_for_jetty[index] + cfg->jfs_post_list) > ctx->ctrl_buf[index][1] ?
                        (scnt_for_jetty[index] + cfg->jfs_post_list - ctx->ctrl_buf[index][1]) : 0;
                    if (swinow >= (uint64_t)cfg->credit_threshold) {
                        break;
                    }
                }
                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == 0 && cfg->cq_mod > 1)) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 0;
                }
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }
                urma_jfs_wr_t *bad_wr = NULL;
                if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                    status = urma_post_jfs_wr(ctx->jfs[index], &run_ctx->jfs_wr[index * cfg->jfs_post_list],
                        &bad_wr);
                } else {
                    status = urma_post_jetty_send_wr(ctx->jetty[index],
                        &run_ctx->jfs_wr[index * cfg->jfs_post_list], &bad_wr);
                }
                if (status != URMA_SUCCESS) {
                    (void)fprintf(stderr, "Failed to post send, status: %d, scnt: %lu, tot_scnt: %lu, ccnt: %lu, \
                        tot_ccnt: %lu.\n", (int)status, run_ctx->scnt[index], tot_scnt, run_ctx->ccnt[index], tot_ccnt);
                    goto err_exit;
                }
                run_ctx->scnt[index] += cfg->jfs_post_list;
                scnt_for_jetty[index] += cfg->jfs_post_list;
                tot_scnt += cfg->jfs_post_list;

                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == cfg->cq_mod - 1 ||
                    (cfg->time_type.bs.iterations == 1 && run_ctx->scnt[index] == cfg->iters - 1))) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 1;
                }

                if (cfg->is_rate_limit == true) {
                    burst_iter += cfg->jfs_post_list;
                    if (burst_iter >= cfg->burst_size) {
                        is_send_burst = false;
                    }
                }
            }
        }
        if (tot_ccnt < tot_scnt) {
            if (cfg->use_jfce == true) {
                if (wait_jfc_event(ctx->jfce_s[0], cfg->wait_jfc_timeout) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event.\n");
                    goto err_exit;
                }
            }
            cqe_cnt = urma_poll_jfc(ctx->jfc_s[0], PERFTEST_POLL_BATCH, cr);
            if (cqe_cnt > 0) {
                for (int i = 0; i < cqe_cnt; i++) {
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed to poll jfc, cr[%d] status: %d, tot_ccnt: %lu, tot_scnt: %lu.\n",
                            i, (int)cr[i].status, tot_ccnt, tot_scnt);
                        if (cfg->enable_err_continue == false) {
                            goto err_exit;
                        } else {
                            tot_scnt = tot_scnt - (cqe_cnt - i) * cfg->cq_mod;
                            continue;
                        }
                    }
                    cr_id = (int)cr[i].user_ctx;
                    cfg->iters += cfg->cq_mod;
                    tot_ccnt += cfg->cq_mod;
                    run_ctx->ccnt[cr_id] += cfg->cq_mod;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "Failed to poll jfc, cqe_cnt: %d.\n", cqe_cnt);
                goto err_exit;
            }
        }
    }
    free(scnt_for_jetty);
    free(cr);
    return 0;

err_exit:
    g_perftest_ctx->infinite_print = false;
    void *thread_ret;
    (void)pthread_join(print_thread, &thread_ret);
    free(scnt_for_jetty);
    free(cr);
    return -1;
}

static int run_once_bw_recv_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = 0;
    int cqe_cnt;
    uint32_t cr_id;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    int first_rx = 1;
    urma_status_t status;
    urma_jfr_wr_t *bad_wr = NULL;

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        return -1;
    }
    urma_cr_t *scr = calloc(1, sizeof(urma_cr_t) * cfg->jfs_depth);
    if (scr == NULL) {
        ret = -1;
        goto free_cr;
    }
    uint64_t *rcnt_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (rcnt_pre_jetty == NULL) {
        ret = -1;
        goto free_scr;
    }
    uint64_t *ccnt_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (ccnt_pre_jetty == NULL) {
        ret = -1;
        goto free_rcnt;
    }

    uint64_t *unused_recv_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (unused_recv_pre_jetty == NULL) {
        ret = -1;
        goto free_ccnt;
    }
    uint64_t *scredit_pre_jetty = calloc(1, sizeof(uint64_t) * cfg->jettys);
    if (scredit_pre_jetty == NULL) {
        ret = -1;
        goto free_unused_recv;
    }

    g_perftest_ctx = ctx;
    g_perftest_cfg = cfg;

    g_perftest_ctx->infinite_print = true;
    pthread_t print_thread;
    if (pthread_create(&print_thread, NULL, infinite_print_thread, (void *)&cfg->inf_period_ms) != 0) {
        (void)fprintf(stderr, "Failed to create thread in server.\n");
        ret = -1;
        goto free_scredit;
    }

    cfg->iters = 0;
    cfg->last_iters = 0;
    run_ctx->tposted[0] = get_cycles();

    while (1) {
        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            g_perftest_ctx->infinite_print = false;
            void *thread_ret;
            (void)pthread_join(print_thread, &thread_ret);
            break;
        }
        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_r[0], cfg->wait_jfc_timeout) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfc event.\n");
                ret = -1;
                goto err_exit;
            }
        }
        cqe_cnt = urma_poll_jfc(ctx->jfc_r[0], PERFTEST_POLL_BATCH, cr);
        if (cqe_cnt > 0) {
            if (first_rx) {
                set_on_first_rx(ctx, cfg);
                first_rx = 0;
            }

            for (int i = 0; i < cqe_cnt; i++) {
                cr_id = (uint32_t)cr[i].user_ctx;
                if (cr[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed to poll jfc in server, cr[%d] status: %d.\n",
                        i, (int)cr[i].status);
                    if (cfg->enable_err_continue == false) {
                        ret = -1;
                        goto err_exit;
                    } else {
                        if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                            status = urma_post_jfr_wr(ctx->jfr[cr_id],
                                &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                        } else {
                            status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                                &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                        }
                        if (status != URMA_SUCCESS) {
                            (void)fprintf(stderr, "Failed to post recv, status: %d.\n", (int)status);
                            ret = -1;
                            goto err_exit;
                        }
                        continue;
                    }
                }
                cfg->iters++;
                unused_recv_pre_jetty[cr_id]++;
                if (unused_recv_pre_jetty[cr_id] >= cfg->jfr_post_list) {
                    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                        status = urma_post_jfr_wr(ctx->jfr[cr_id],
                            &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                    } else {
                        status = urma_post_jetty_recv_wr(ctx->jetty[cr_id],
                            &run_ctx->jfr_wr[cr_id * cfg->jfr_post_list], &bad_wr);
                    }
                    if (status != URMA_SUCCESS) {
                        (void)fprintf(stderr, "Failed to post recv, status: %d.\n", (int)status);
                        ret = -1;
                        goto err_exit;
                    }
                    unused_recv_pre_jetty[cr_id] -= cfg->jfr_post_list;
                }
                if (cfg->enable_credit == true) {
                    rcnt_pre_jetty[cr_id]++;
                    scredit_pre_jetty[cr_id]++;
                    if (scredit_pre_jetty[cr_id] == cfg->credit_notify_cnt) {
                        urma_jfs_wr_t *bad_send_wr = NULL;
                        ctx->ctrl_buf[cr_id][0] = rcnt_pre_jetty[cr_id];

                        while (ccnt_pre_jetty[cr_id] == cfg->jfs_depth) {
                            int sne, j = 0;
                            sne = urma_poll_jfc(ctx->jfc_s[0], cfg->jfs_depth, scr);
                            if (sne > 0) {
                                for (j = 0; j < sne; j++) {
                                    if (scr[j].status != URMA_CR_SUCCESS) {
                                        (void)fprintf(stderr, "Poll send CQ error status=%u jetty %d",
                                            scr[j].status, (int)scr[j].user_ctx);
                                        (void)fprintf(stderr, "credit=%lu scredit=%lu\n",
                                            rcnt_pre_jetty[scr[j].user_ctx], ccnt_pre_jetty[scr[j].user_ctx]);
                                        ret = -1;
                                        goto err_exit;
                                    }
                                    ccnt_pre_jetty[scr[j].user_ctx]--;
                                }
                            } else if (sne < 0) {
                                    (void)fprintf(stderr, "Poll send cr failed ne=%d\n", sne);
                                    ret = -1;
                                    goto err_exit;
                            }
                        }
                        if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
                            status = urma_post_jfs_wr(ctx->jfs[cr_id], &run_ctx->credit_wr[cr_id],
                                &bad_send_wr);
                        } else {
                            status = urma_post_jetty_send_wr(ctx->jetty[cr_id], &run_ctx->credit_wr[cr_id],
                                &bad_send_wr);
                        }
                        if (status != URMA_SUCCESS) {
                            (void)fprintf(stderr, "Couldn't post send jetty %d credit = %lu\n",
                                cr_id, rcnt_pre_jetty[cr_id]);
                                ret = -1;
                                goto err_exit;
                        }
                        ccnt_pre_jetty[cr_id]++;
                        scredit_pre_jetty[cr_id] = 0;
                    }
                }
            }
        } else if (cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc in server, cqe_cnt: %d.\n", cqe_cnt);
            ret = -1;
            goto err_exit;
        }
    }

err_exit:
    g_perftest_ctx->infinite_print = false;
    void *thread_ret;
    (void)pthread_join(print_thread, &thread_ret);
free_scredit:
    free(scredit_pre_jetty);
free_unused_recv:
    free(unused_recv_pre_jetty);
free_ccnt:
    free(ccnt_pre_jetty);
free_rcnt:
    free(rcnt_pre_jetty);
free_scr:
    free(scr);
free_cr:
    free(cr);
    return ret;
}

static int prepare_run_bw_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_once_bw_infinite(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run_once_bw_infinite, aborting...\n");
        destroy_jfs_wr(ctx);
        return ret;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int prepare_run_bw_once(perftest_context_t *ctx, perftest_config_t *cfg,
    bw_report_data_t *local_bw_report, bw_report_data_t *remote_bw_report)
{
    uint32_t i;
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    if (cfg->warm_up && perform_warm_up(ctx, cfg) != 0) {
        (void)fprintf(stderr, "Failed to perform warm_up, api_type: %d.\n", (int)cfg->api_type);
        goto err_dest_jfs_wr;
    }
    if (cfg->bidirection) {
        for (i = 0; i < cfg->pair_num; i++) {
            ret = sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].before);
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to sync time before bw test.\n");
                goto err_dest_jfs_wr;
            }
        }
    }
    ret = run_once_bw(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run once bw, size: %u, ret: %d, api_type: %d.\n",
            cfg->size, ret, (int)cfg->api_type);
        goto err_dest_jfs_wr;
    }
    if (cfg->bidirection) {
        for (i = 0; i < cfg->pair_num; i++) {
            ret = sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].after);
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to sync time after bw test.\n");
                goto err_dest_jfs_wr;
            }
        }
    }
    double cpu_mhz = get_cpu_mhz(false);
    if (cpu_mhz <= 0.0) {
        (void)fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
    }
    print_bw_report(ctx, cfg, local_bw_report, ctx->run_ctx.tposted[0], cpu_mhz);
    if (cfg->bidirection) {
        for (i = 0; i < cfg->pair_num; i++) {
            if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(bw_report_data_t), (char *)(local_bw_report),
                (char *)(remote_bw_report)) != 0) {
                (void)fprintf(stderr, "Failed to exchange local and remote report data.\n");
                goto err_dest_jfs_wr;
            }
            print_bi_bw_report(local_bw_report, remote_bw_report);
        }
    }
    destroy_jfs_wr(ctx);
    return 0;

err_dest_jfs_wr:
    destroy_jfs_wr(ctx);
    return -1;
}

/* at the end of the measurement period, server reports the result to the client */
/* CLIENT gives the concrete bw result */
static int run_bw_once(perftest_context_t *ctx, perftest_config_t *cfg)
{
    bw_report_data_t local_bw_report = {0};
    bw_report_data_t remote_bw_report = {0};
    uint32_t i = 0;
    /* Handle half bidirectional test */
    if (cfg->comm.server_ip == NULL && !cfg->bidirection) {
        for (i = 0; i < cfg->pair_num; i++) {
            if (sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].before) != 0 ||
                sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].after) != 0) {
                (void)fprintf(stderr, "Failed to sync time in bw test in server.\n");
                return -1;
            }
            /* Size and iterations of local READ/WRITE/ATOMIC bw test should be filled before sync data */
            local_bw_report.size = cfg->size;
            local_bw_report.iters = cfg->iters;
            if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(bw_report_data_t), (char *)(&local_bw_report),
                (char *)(&remote_bw_report)) != 0) {
                (void)fprintf(stderr, "Failed to exchange local and remote data in server.\n");
                return -1;
            }
            print_bi_bw_report(&local_bw_report, &remote_bw_report);
        }
        return 0;
    }

    if (cfg->time_type.bs.infinite == 1) {
        if (prepare_run_bw_infinite(ctx, cfg) != 0) {
            (void)fprintf(stderr, "Failed to prepare and run infinite, api_type: %d.\n",
                (int)cfg->api_type);
            return -1;
        }
    } else {
        if (prepare_run_bw_once(ctx, cfg, &local_bw_report, &remote_bw_report) != 0) {
            (void)fprintf(stderr, "Failed to prepare and run bw, api_type: %d.\n", (int)cfg->api_type);
            return -1;
        }
    }

    /* Handle half bidirectional test */
    if (cfg->comm.server_ip != NULL && !cfg->bidirection) {
        for (i = 0; i < cfg->pair_num; i++) {
            if (sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].before) != 0 ||
                sync_time(cfg->comm.sock_fd[i], g_bi_exchange_info[cfg->api_type].after) != 0) {
                (void)fprintf(stderr, "Failed to sync time in bw test in client.\n");
                return -1;
            }
            if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(bw_report_data_t), (char *)(&local_bw_report),
                (char *)(&remote_bw_report)) != 0) {
                (void)fprintf(stderr, "Failed to exchange local and remote data in client.\n");
                return -1;
            }
        }
    }
    return 0;
}

int run_read_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)printf("%s\n", RESULT_BW_FMT);

    /* WRITE BW test run in both sides */
    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_bw_once(ctx, cfg) != 0) {
                return -1;
            }
        }
    } else {
        if (run_bw_once(ctx, cfg) != 0) {
            return -1;
        }
    }
    return 0;
}

/* CLIENT gives the concrete bw result */
int run_send_bw(perftest_context_t *ctx, perftest_config_t *cfg);
int run_write_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->enable_imm == true) {
        return run_send_bw(ctx, cfg);
    }
    /* WRITE BW test run in both sides */
    (void)printf("%s\n", RESULT_BW_FMT);
    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_bw_once(ctx, cfg) != 0) {
                return -1;
            }
        }
    } else {
        if (run_bw_once(ctx, cfg) != 0) {
            return -1;
        }
    }
    return 0;
}

static int run_send_bw_once(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i;
    int ret;

    for (i = 0; i < cfg->pair_num; i++) {
        ret = sync_time(cfg->comm.sock_fd[i], "send_bw_post_recv");
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to sync time, send_recv test.\n");
            return -1;
        }
    }

    if (cfg->bidirection &&
        (cfg->api_type == PERFTEST_SEND || (cfg->api_type == PERFTEST_WRITE && cfg->enable_imm))) {
        ret = run_once_bi_bw(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once bi bw, size: %u.\n", cfg->size);
            return -1;
        }
    } else if (cfg->comm.server_ip != NULL) {
        ret = run_once_bw(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once send bw, size: %u.\n", cfg->size);
            return -1;
        }
    } else {
        ret = run_once_bw_recv(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once recv bw, size: %u.\n", cfg->size);
            return -1;
        }
    }
    bw_report_data_t local_bw_report = {0};
    bw_report_data_t remote_bw_report = {0};
    double cpu_mhz = get_cpu_mhz(false);
    if (cpu_mhz <= 0.0) {
        (void)fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
    }
    print_bw_report(ctx, cfg, &local_bw_report, ctx->run_ctx.tposted[0], cpu_mhz);

    if (cfg->bidirection && cfg->time_type.bs.duration == 0) {
        for (i = 0; i < cfg->pair_num; i++) {
            if (sock_sync_data(cfg->comm.sock_fd[i], sizeof(bw_report_data_t), (char *)(&local_bw_report),
                (char *)(&remote_bw_report)) != 0) {
                (void)fprintf(stderr, "Failed to exchange local and remote data.\n");
                return -1;
            }
            print_bi_bw_report(&local_bw_report, &remote_bw_report);
        }
    }
    return 0;
}

static int run_send_bw_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    uint32_t i;

    for (i = 0; i < cfg->pair_num; i++) {
        ret = sync_time(cfg->comm.sock_fd[i], "run_send_bw_infinite");
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to sync time, run_send_bw_infinite, ret: %d.\n", ret);
            return -1;
        }
    }

    if (cfg->comm.server_ip != NULL) {
        ret = run_once_bw_infinite(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run run_once_bw_infinite in client, ret: %d.\n", ret);
            return -1;
        }
    } else {
        ret = run_once_bw_recv_infinite(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run run_once_bw_recv_infinite in server, ret: %d.\n", ret);
            return -1;
        }
    }

    return 0;
}

static int run_send_bw_one_size(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = 0;
    if (cfg->comm.server_ip != NULL || cfg->bidirection) {
        ret = prepare_jfs_wr(ctx, cfg);
        if (ret != 0) {
            return -1;
        }
    }
    if (cfg->comm.server_ip == NULL || cfg->bidirection) {
        ret = prepare_jfr_wr(ctx, cfg);
        if (ret != 0) {
            goto err_destroy_jfs_wr;
        }
    }

    if (cfg->enable_credit) {
        ret = prepare_credit_wr(ctx, cfg);
        if (ret != 0) {
            goto err_destroy_jfr_wr;
        }
    }

    if (cfg->time_type.bs.infinite == 1) {
        ret = run_send_bw_infinite(ctx, cfg);
    } else {
        ret = run_send_bw_once(ctx, cfg);
    }
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run_send_bw_once, ret: %d.\n", ret);
        goto err_destroy_credit_wr;
    }
err_destroy_credit_wr:
    if (cfg->enable_credit) {
        destroy_credit_wr(ctx);
    }
err_destroy_jfr_wr:
    if (cfg->bidirection || cfg->comm.server_ip == NULL) {
        destroy_jfr_wr(ctx);
    }
err_destroy_jfs_wr:
    if (cfg->bidirection || cfg->comm.server_ip != NULL) {
        destroy_jfs_wr(ctx);
    }
    return ret;
}

int run_send_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)printf("%s\n", RESULT_BW_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (run_send_bw_one_size(ctx, cfg) != 0) {
                return -1;
            }
        }
    } else {
        if (run_send_bw_one_size(ctx, cfg) != 0) {
            return -1;
        }
    }
    return 0;
}

int run_atomic_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    (void)printf("%s\n", RESULT_BW_FMT);

    int ret = run_bw_once(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run once bw in atomic test.\n");
        return -1;
    }

    return 0;
}
