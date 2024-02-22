/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
#define PERFTEST_M (1000000)
#define PERFTEST_MBS (0x100000)
#define PERFTEST_WAIT_JFC_TIME  (1000)  // 1s
#define PERFTEST_BW_MB 0x100000 // 2^20

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

static int wait_jfc_event(urma_jfce_t *jfce)
{
    urma_jfc_t *jfc;
    if (urma_wait_jfc(jfce, 1, PERFTEST_WAIT_JFC_TIME, &jfc) != 1) {
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

static inline void set_complete_flag(urma_jfs_wr_flag_t *flag, urma_jfs_wr_t *wr, bool use_flat_api, uint32_t value)
{
    if (use_flat_api) {
        flag->bs.complete_enable = value;
    } else {
        wr->flag.bs.complete_enable = value;
    }
}

static inline void update_duration_state(perftest_context_t *ctx, perftest_config_t *cfg)
{
    g_duration_ctx = &ctx->run_ctx;
    g_duration_ctx->state = WARMUP_STATE;
    (void)signal(SIGALRM, catch_alarm);
    cfg->iters = 0;
    (void)alarm(g_duration_ctx->duration / PERFTEST_DEF_WARMUP_TIME);
}

static int run_once_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t lva = (uint64_t)ctx->local_buf[0] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (uint64_t)ctx->remote_seg[0]->ubva.va;
    urma_jfs_wr_flag_t flag = {0};

    set_complete_flag(&flag, &run_ctx->jfs_wr[0], cfg->use_flat_api, URMA_COMPLETE_ENABLE);
    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[scnt] = get_cycles();
        }

        if (cfg->use_flat_api) {
            status = urma_read(ctx->jfs[0], ctx->import_tjfr[0], ctx->local_tseg[0], ctx->import_tseg[0], lva,
                rva, cfg->size, flag, (uintptr_t)run_ctx->rid++);
        } else {
            urma_jfs_wr_t *bad_wr = NULL;
            run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
            status = urma_post_jfs_wr(ctx->jfs[0], &run_ctx->jfs_wr[0], &bad_wr);
        }

        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Couldn't urma read status: %d, scnt: %lu\n", (int)status, scnt);
            return -1;
        }
        scnt++;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_s) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfce event\n");
                return -1;
            }
        }

        do {
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu.\n", (int)cr.status, scnt);
                    return -1;
                }

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        } while (cfg->use_jfce == false && cqe_cnt == 0);
    }

    return 0;
}

static void init_jfs_wr_flag(urma_jfs_wr_flag_t *flag, perftest_config_t *cfg, urma_jfs_wr_t *jfs_wr)
{
    if (cfg->use_flat_api) {
        flag->bs.complete_enable = 1;
        flag->bs.inline_flag = (cfg->size < cfg->inline_size) ? 1 : 0;
    } else {
        jfs_wr->flag.bs.complete_enable = 1;
        jfs_wr->flag.bs.inline_flag = (cfg->size < cfg->inline_size) ? 1 : 0;
    }
}

static int run_once_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    uint64_t ccnt = 0;
    uint64_t rcnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t lva = (uint64_t)ctx->local_buf[0] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (uint64_t)ctx->remote_seg[0]->ubva.va;
    urma_jfs_wr_flag_t flag = {0};
    init_jfs_wr_flag(&flag, cfg, &run_ctx->jfs_wr[0]);

    char *server_ip = cfg->comm.server_ip;

    volatile char *post_buf = (char *)ctx->local_buf[0] + ctx->buf_size + cfg->size - 1;
    volatile char *poll_buf = (char *)ctx->local_buf[0] + cfg->size - 1;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || ccnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && server_ip == NULL)) {
            rcnt++;
            while (*poll_buf != (char)rcnt && run_ctx->state != END_STATE);
        }

        if (scnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[scnt] = get_cycles();
            }

            *post_buf = (char)++scnt;

            if (cfg->use_flat_api) {
                status = urma_write(ctx->jfs[0], ctx->import_tjfr[0], ctx->import_tseg[0], ctx->local_tseg[0],
                    rva, lva, cfg->size, flag, (uintptr_t)run_ctx->rid++);
            } else {
                urma_jfs_wr_t *bad_wr = NULL;
                run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
                status = urma_post_jfs_wr(ctx->jfs[0], &run_ctx->jfs_wr[0], &bad_wr);
            }
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Couldn't urma write status: %d, scnt: %lu, ccnt: %lu, rcnt: %lu\n",
                    (int)status, scnt, ccnt, rcnt);
                return -1;
            }
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }
        if (ccnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            do {
                cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            } while (cqe_cnt == 0);

            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, ccnt: %lu, rcnt: %lu.\n",
                        (int)cr.status, scnt, ccnt, rcnt);
                    return -1;
                }
                ccnt++;
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        }
    }

    return 0;
}

static int send_lat_post_recv(perftest_context_t *ctx, perftest_config_t *cfg, int cnt)
{
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfr_wr_t *jfr_wr = run_ctx->jfr_wr;
    urma_jfr_wr_t *jfr_bad_wr = NULL;
    uint64_t recv_va = (uint64_t)ctx->local_buf[0];    // first half for recv

    for (int i = 0; i < cnt; i++) {
        if (cfg->use_flat_api) {
            status = urma_recv(ctx->jfr[0], ctx->local_tseg[0], recv_va, cfg->size, (uintptr_t)run_ctx->rid++);
        } else {
            status = urma_post_jfr_wr(ctx->jfr[0], jfr_wr, &jfr_bad_wr);
        }
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to urma_recv, loop:%d, status: %d\n", i, (int)status);
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

static int run_once_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    uint64_t rcnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    int first_rx = 1;
    int poll = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t size_of_jfr = cfg->jfr_depth / cfg->jfr_post_list;
    uint64_t send_va = (uint64_t)ctx->local_buf[0] + ctx->buf_size;    // Second half for send
    urma_jfs_wr_flag_t flag = {0};

    // set inline
    flag.bs.inline_flag = (cfg->size <= cfg->inline_size) ? 1 : 0;
    char *server_ip = cfg->comm.server_ip;

    urma_jfs_wr_t *wr = run_ctx->jfs_wr;

    while (scnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        /*
         * Get the recv packet. make sure that the client won't enter here until he sends his first packet (scnt < 1)
         * server will enter here first and wait for a packet to arrive (from the client)
         */
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && server_ip != NULL)) {
            if (cfg->use_jfce == true) {
                if (wait_jfc_event(ctx->jfce_r) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event\n");
                    return -1;
                }
            }
            do {
                cqe_cnt = urma_poll_jfc(ctx->jfc_r, 1, &cr);
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }

                if (cqe_cnt > 0) {
                    if (first_rx != 0) {
                        set_on_first_rx(ctx, cfg);
                        first_rx = 0;
                    }

                    if (cr.status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, rcnt: %lu", (int)cr.status, scnt, rcnt);
                        return -1;
                    }

                    rcnt++;

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters++;
                    }

                    /* if we're in duration mode or there is enough space in the rx_depth,
                    * post that you received a packet.
                    */
                    if (cfg->time_type.bs.duration == 1 || (rcnt + size_of_jfr <= cfg->iters)) {
                        if (send_lat_post_recv(ctx, cfg, 1) != 0) {
                            return -1;
                        }
                    }
                } else if (cqe_cnt < 0) {
                    (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                    return -1;
                }
            } while (cfg->use_jfce == false && cqe_cnt == 0);
        }

        if (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[scnt] = get_cycles();
            }

            scnt++;

            if (scnt % cfg->cq_mod == 0) {
                set_complete_flag(&flag, wr, cfg->use_flat_api, URMA_COMPLETE_ENABLE);
                poll = 1;
            }
            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }
            if (cfg->use_flat_api) {
                status = urma_send(ctx->jfs[0], ctx->import_tjfr[0], ctx->local_tseg[0], send_va, cfg->size,
                    flag, (uintptr_t)run_ctx->rid++);
            } else {
                urma_jfs_wr_t *bad_wr = NULL;
                wr->user_ctx = (uintptr_t)run_ctx->rid++;
                status = urma_post_jfs_wr(ctx->jfs[0], wr, &bad_wr);
            }

            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Couldn't urma send status: %d, scnt: %lu, rcnt: %lu\n", (int)status, scnt, rcnt);
                return -1;
            }
            if (poll == 1) {
                int poll_cnt;
                if (cfg->use_jfce == true) {
                    if (wait_jfc_event(ctx->jfce_s) != 0) {
                        (void)fprintf(stderr, "Couldn't wait jfce event\n");
                        return -1;
                    }
                }

                do {
                    poll_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
                } while (cfg->use_jfce == false && poll_cnt == 0);
                if (poll_cnt < 0) {
                    (void)fprintf(stderr, "poll jfc failed %d\n", poll_cnt);
                    return -1;
                }
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, rcnt: %lu", (int)cr.status, scnt, rcnt);
                    return -1;
                }

                poll = 0;
                set_complete_flag(&flag, wr, cfg->use_flat_api, URMA_COMPLETE_DISABLE);
            }
        }
    }

    return 0;
}

static urma_status_t send_cas_test(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfs_wr_flag_t flag = {0};

    set_complete_flag(&flag, &run_ctx->jfs_wr[0], cfg->use_flat_api, URMA_COMPLETE_ENABLE);

    urma_jfs_wr_t *bad_wr = NULL;
    run_ctx->jfs_wr[0].tjetty = ctx->import_tjfr[0];
    run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
    return urma_post_jfs_wr(ctx->jfs[0], &run_ctx->jfs_wr[0], &bad_wr);
}

static urma_status_t send_faa_test(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfs_wr_flag_t flag = {0};

    set_complete_flag(&flag, &run_ctx->jfs_wr[0], cfg->use_flat_api, URMA_COMPLETE_ENABLE);

    urma_jfs_wr_t *bad_wr = NULL;
    run_ctx->jfs_wr[0].tjetty = ctx->import_tjfr[0];
    run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
    return urma_post_jfs_wr(ctx->jfs[0], &run_ctx->jfs_wr[0], &bad_wr);
}

static int run_once_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[scnt] = get_cycles();
        }

        status = (cfg->atomic_type == PERFTEST_CAS) ? send_cas_test(ctx, cfg) : send_faa_test(ctx, cfg);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Couldn't urma atomic status: %d, scnt: %lu\n", (int)status, scnt);
            return -1;
        }
        scnt++;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_s) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfce event\n");
                return -1;
            }
        }

        do {
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu.\n", (int)cr.status, scnt);
                    return -1;
                }

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        } while (cfg->use_jfce == false && cqe_cnt == 0);
    }

    return 0;
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

static void print_lat_report(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    uint64_t i;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    int rtt_factor = (cfg->cmd == PERFTEST_READ_LAT || cfg->cmd == PERFTEST_ATOMIC_LAT) ? 1 : 2;
    double cycles_to_units = get_cpu_mhz(cfg->cpu_freq_f);
    double cycles_rtt_quotient = cycles_to_units * rtt_factor;

    uint64_t measure_cnt = cfg->iters - 1;
    uint64_t *delta = calloc(1, sizeof(uint64_t) * (uint32_t)measure_cnt);
    if (delta == NULL) {
        return;
    }

    // Get the cycle of a test
    for (i = 0; i < measure_cnt; i++) {
        delta[i] = run_ctx->tposted[i + 1] - run_ctx->tposted[i];
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

static void print_lat_duration_report(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    int rtt_factor = (cfg->cmd == PERFTEST_READ_LAT || cfg->cmd == PERFTEST_ATOMIC_LAT) ? 1 : 2;
    double cycles_to_units = get_cpu_mhz(cfg->cpu_freq_f);
    double cycles_rtt_quotient = cycles_to_units * rtt_factor;

    uint64_t test_time = run_ctx->tcompleted[0] - run_ctx->tposted[0];
    double avg_lat = (test_time / cycles_rtt_quotient) / cfg->iters;
    double tps = cfg->iters / (test_time / (cycles_to_units * 1000000));

    (void)printf(REPORT_LAT_DUR_FMT, cfg->size, cfg->iters, avg_lat, tps);
    (void)printf("\n");
}

static int run_jfs_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            uint32_t size_of_jfr = cfg->jfr_depth / cfg->jfr_post_list;
            if (send_lat_post_recv(ctx, cfg, (int)size_of_jfr) != 0) {
                (void)fprintf(stderr, "Failed to post recv, size: %u.\n", cfg->size);
                return -1;
            }
            /* Sync between the client and server so the client won't send packets
             * Before the server has posted his receive wqes.
             */
            ret = sync_time(cfg->comm.sock_fd, "send_lat_post_recv");
            if (ret != 0) {
                return -1;
            }
            ret = run_once_send_lat(ctx, cfg);
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to run once send lat, size: %u.\n", cfg->size);
                return -1;
            }
            cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
        }
    } else {
        uint32_t size_of_jfr = cfg->jfr_depth / cfg->jfr_post_list;
        if (send_lat_post_recv(ctx, cfg, (int)size_of_jfr) != 0) {
            (void)fprintf(stderr, "Failed to post recv, size: %u.\n", cfg->size);
            return -1;
        }
        ret = sync_time(cfg->comm.sock_fd, "send_lat_post_recv");
        if (ret != 0) {
            return -1;
        }
        ret = run_once_send_lat(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once send lat, size: %u.\n", cfg->size);
            return -1;
        }
        cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    }
    return 0;
}

static void init_jfs_wr_base(urma_jfs_wr_t *wr, perftest_context_t *ctx,
    const perftest_config_t *cfg, uint32_t jetty_index, uint32_t jfs_wr_index)
{
    switch (cfg->cmd) {
        case PERFTEST_READ_LAT:
            wr->opcode = URMA_OPC_READ;
            break;
        case PERFTEST_WRITE_LAT:
            wr->opcode = URMA_OPC_WRITE;
            break;
        case PERFTEST_SEND_LAT:
            wr->opcode = URMA_OPC_SEND;
            break;
        case PERFTEST_ATOMIC_LAT:
            wr->opcode = (cfg->atomic_type == PERFTEST_CAS ? URMA_OPC_CAS : URMA_OPC_FADD);
            break;
        case PERFTEST_READ_BW:
            wr->opcode = URMA_OPC_READ;
            break;
        case PERFTEST_WRITE_BW:
            wr->opcode = URMA_OPC_WRITE;
            break;
        case PERFTEST_SEND_BW:
            wr->opcode = URMA_OPC_SEND;
            break;
        case PERFTEST_ATOMIC_BW:
            wr->opcode = (cfg->atomic_type == PERFTEST_CAS ? URMA_OPC_CAS : URMA_OPC_FADD);
            break;
        default:
            (void)fprintf(stderr, "invalid opcode.\n");
            break;
    }
    wr->flag.bs.complete_enable = ((jfs_wr_index + 1) % cfg->cq_mod == 0) ? 1 : 0;
    wr->flag.bs.solicited_enable = 0;
    // set inline
    wr->flag.bs.inline_flag = (cfg->size <= cfg->inline_size) ? 1 : 0;
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

static void init_send_jetty_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_sge_t *local_sge = &run_ctx->jfs_sge[0];
    local_sge->addr = (uint64_t)ctx->local_buf[0] + ctx->buf_size;
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[0];

    wr->tjetty = ctx->import_tjetty[0];
    wr->send.src.sge = local_sge;
    wr->send.src.num_sge = 1;
}

// this init function is only suitable for LAT test.
static void init_post_send_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_sge_t *local_sge = &run_ctx->jfs_sge[0];
    local_sge->addr = (uint64_t)ctx->local_buf[0] + ctx->buf_size;
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[0];

    wr->tjetty = ctx->import_tjfr[0];
    wr->send.src.sge = local_sge;
    wr->send.src.num_sge = 1;
}

static void init_read_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t lva = (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (uint64_t)ctx->remote_seg[i]->ubva.va;
    urma_sge_t *local_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR + 1];
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR];

    // Step increased value
    local_sge->addr = lva;
    if (j > 0) {
        local_sge->addr = run_ctx->jfs_sge[(i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR + 1].addr;
        if (cfg->cmd == PERFTEST_READ_BW && cfg->size <= ctx->page_size / PERFTEST_BUF_NUM) {
            increase_loc_addr(local_sge, cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
        }
    }
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[i];

    remote_sge->addr = rva;
    // it is only need to calculate sge addr offset when j > 0, for the offset is 0 when j == 0.
    if (j > 0) {
        remote_sge->addr = run_ctx->jfs_sge[(i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR].addr;
        if (cfg->cmd == PERFTEST_READ_BW && cfg->size <= ctx->page_size / PERFTEST_BUF_NUM) {
            increase_loc_addr(remote_sge, cfg->size, j - 1, rva, cfg->cache_line_size, ctx->page_size);
        }
    }
    remote_sge->len = cfg->size;
    remote_sge->tseg = ctx->import_tseg[i];

    wr->rw.src.sge = remote_sge;
    wr->rw.src.num_sge = 1;

    wr->rw.dst.sge = local_sge;
    wr->rw.dst.num_sge = 1;

    wr->rw.notify_data = 0;
}

static void init_write_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t lva = (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    uint64_t rva = (uint64_t)ctx->remote_seg[i]->ubva.va;
    urma_sge_t *local_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR + 1];
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR];

    // Step increased value
    local_sge->addr = lva;
    // it is only need to calculate sge addr offset when j > 0, for the offset is 0 when j == 0.
    // the following remote_sge addr judgement is the same.
    if (j > 0) {
        local_sge->addr = run_ctx->jfs_sge[(i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR + 1].addr;
        if (cfg->cmd == PERFTEST_WRITE_BW && cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
            increase_loc_addr(local_sge, cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
        }
    }
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[i];

    remote_sge->addr = rva;
    if (j > 0) {
        remote_sge->addr = run_ctx->jfs_sge[(i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR].addr;
        if (cfg->cmd == PERFTEST_WRITE_BW && cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM)) {
            increase_loc_addr(remote_sge, cfg->size, j - 1, rva, cfg->cache_line_size, ctx->page_size);
        }
    }

    remote_sge->len = cfg->size;
    remote_sge->tseg = ctx->import_tseg[i];

    wr->rw.src.sge = local_sge;
    wr->rw.src.num_sge = 1;
    wr->rw.dst.sge = remote_sge;
    wr->rw.dst.num_sge = 1;

    wr->rw.notify_data = 0;
}

static void init_send_jfs_wr_sg(urma_jfs_wr_t *wr, perftest_context_t *ctx, perftest_config_t *cfg,
    uint32_t i, uint32_t j)
{
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint64_t lva = (uint64_t)ctx->local_buf[i] + ctx->buf_size;    // Second half for local memory
    urma_sge_t *local_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR + 1];

    // Step increased value
    local_sge->addr = lva;
    if (j > 0) {
        local_sge->addr =
            run_ctx->jfs_sge[(i * cfg->jfs_post_list + j - 1) * PERFTEST_SGE_NUM_PRE_WR + 1].addr;
        if (cfg->size <= ctx->page_size / PERFTEST_BUF_NUM) {
            increase_loc_addr(local_sge, cfg->size, j - 1, lva, cfg->cache_line_size, ctx->page_size);
        }
    }
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[i];

    wr->send.src.sge = local_sge;
    wr->send.src.num_sge = 1;

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

    uint8_t *lva = (uint8_t *)ctx->local_buf[i] + ctx->buf_size + remainder * align_size;
    uint8_t *rva = (uint8_t *)ctx->remote_seg[i]->ubva.va + remainder * align_size;

    urma_sge_t *local_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR + 1];
    urma_sge_t *remote_sge = &run_ctx->jfs_sge[(i * cfg->jfs_post_list + j) * PERFTEST_SGE_NUM_PRE_WR];
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
            if (cfg->jetty_mode == PERFTEST_JETTY_DUPLEX) {
                init_send_jetty_wr_sg(wr, ctx, cfg, i, j);
            } else {
                init_post_send_wr_sg(wr, ctx, cfg, i, j);
            }
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

static int prepare_jfs_wr(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t i, j;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    urma_jfs_wr_t *wr;

    run_ctx->jfs_wr = calloc(1, sizeof(urma_jfs_wr_t) * cfg->jettys * cfg->jfs_post_list);
    if (run_ctx->jfs_wr == NULL) {
        return -1;
    }
    run_ctx->jfs_sge = calloc(1, sizeof(urma_sge_t) * cfg->jettys * cfg->jfs_post_list * PERFTEST_SGE_NUM_PRE_WR);
    if (run_ctx->jfs_sge == NULL) {
        goto free_wr;
    }

    for (i = 0; i < cfg->jettys; i++) {
        if (cfg->type == PERFTEST_BW) {
            run_ctx->scnt[i] = 0;
            run_ctx->ccnt[i] = 0;
        }
        for (j = 0; j < cfg->jfs_post_list; j++) {
            wr = &run_ctx->jfs_wr[i * cfg->jfs_post_list + j];
            init_jfs_wr_base(wr, ctx, cfg, i, j);
            // init wr sg
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

    urma_sge_t *local_sge = &run_ctx->jfr_sge[(i * cfg->jfr_post_list + j) * PERFTEST_SGE_NUM_PRE_WR + 1];
    local_sge->addr = (uint64_t)ctx->local_buf[i];
    local_sge->len = cfg->size;
    local_sge->tseg = ctx->local_tseg[i];

    wr->src.sge = local_sge;
    wr->src.num_sge = 1;
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
    run_ctx->jfr_sge = calloc(1, sizeof(urma_sge_t) * cfg->jettys * cfg->jfr_post_list * PERFTEST_SGE_NUM_PRE_WR);
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

        run_ctx->rx_buf_addr[i] = run_ctx->jfr_sge[(i * cfg->jfr_post_list) * PERFTEST_SGE_NUM_PRE_WR + 1].addr;
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
                increase_loc_addr(&run_ctx->jfr_sge[(i * cfg->jfr_post_list) * PERFTEST_SGE_NUM_PRE_WR + 1],
                    cfg->size, j, run_ctx->rx_buf_addr[i], cfg->cache_line_size, ctx->page_size);
            }
        }
        run_ctx->jfr_sge[(i * cfg->jfr_post_list) * PERFTEST_SGE_NUM_PRE_WR + 1].addr =
            run_ctx->rx_buf_addr[i];
    }
    return 0;

free_jfr:
    destroy_jfr_wr(ctx);
    return -1;
}

static int run_once_post_read(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_once_read_lat(ctx, cfg);
    if (ret != 0) {
        destroy_jfs_wr(ctx);
        return -1;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int run_simplex_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    /* Only Client read test. */
    if (cfg->comm.server_ip == NULL) {
        return 0;
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (cfg->use_flat_api) {
                ret = run_once_read_lat(ctx, cfg);
            } else {
                ret = run_once_post_read(ctx, cfg);
            }
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to run once read lat, size: %u.\n", cfg->size);
                return -1;
            }
            cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
        }
    } else {
        if (cfg->use_flat_api) {
            ret = run_once_read_lat(ctx, cfg);
        } else {
            ret = run_once_post_read(ctx, cfg);
        }
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once read lat, size: %u.\n", cfg->size);
            return -1;
        }
        cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    }
    return 0;
}

static int run_one_jetty_read(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    run_ctx->jfs_wr[0].flag.bs.complete_enable = 1;
    run_ctx->jfs_wr[0].tjetty = ctx->import_tjetty[0];

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[scnt] = get_cycles();
        }
        urma_jfs_wr_t *bad_wr = NULL;
        run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
        urma_status_t status = urma_post_jetty_send_wr(ctx->jetty[0], &run_ctx->jfs_wr[0], &bad_wr);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Couldn't urma read status: %d, scnt: %lu\n", (int)status, scnt);
            return -1;
        }
        scnt++;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_s) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfce event\n");
                return -1;
            }
        }

        do {
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu.\n", (int)cr.status, scnt);
                    return -1;
                }

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        } while (cfg->use_jfce == false && cqe_cnt == 0);
    }

    return 0;
}

static int run_one_jetty_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_one_jetty_read(ctx, cfg);
    if (ret != 0) {
        destroy_jfs_wr(ctx);
        return -1;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int run_duplex_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    /* Only Client read test. */
    if (cfg->comm.server_ip == NULL) {
        return 0;
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            ret = run_one_jetty_read_lat(ctx, cfg);
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to run once jetty read lat, size: %u.\n", cfg->size);
                return -1;
            }
            cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
        }
    } else {
        ret = run_one_jetty_read_lat(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once jetty read lat, size: %u.\n", cfg->size);
            return -1;
        }
        cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    }
    return 0;
}

int run_read_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return run_simplex_read_lat(ctx, cfg);
    }
    return run_duplex_read_lat(ctx, cfg);
}

static int run_once_post_write(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_once_write_lat(ctx, cfg);
    if (ret != 0) {
        destroy_jfs_wr(ctx);
        return -1;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int run_simplex_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            if (cfg->use_flat_api) {
                ret = run_once_write_lat(ctx, cfg);
            } else {
                ret = run_once_post_write(ctx, cfg);
            }

            if (ret != 0) {
                (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
                return -1;
            }
            cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
        }
    } else {
        if (cfg->use_flat_api) {
            ret = run_once_write_lat(ctx, cfg);
        } else {
            ret = run_once_post_write(ctx, cfg);
        }
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
            return -1;
        }
        cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    }
    return 0;
}

static int run_one_jetty_write(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    uint64_t ccnt = 0;
    uint64_t rcnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    run_ctx->jfs_wr[0].flag.bs.complete_enable = 1;
    run_ctx->jfs_wr[0].flag.bs.inline_flag = (cfg->size < cfg->inline_size) ? 1 : 0;
    run_ctx->jfs_wr[0].tjetty = ctx->import_tjetty[0];

    volatile char *post_buf = (char *)ctx->local_buf[0] + ctx->buf_size + cfg->size - 1;
    volatile char *poll_buf = (char *)ctx->local_buf[0] + cfg->size - 1;
    char *server_ip = cfg->comm.server_ip;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || ccnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && server_ip == NULL)) {
            rcnt++;
            while (*poll_buf != (char)rcnt && run_ctx->state != END_STATE) {};
        }

        if (scnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[scnt] = get_cycles();
            }

            *post_buf = (char)++scnt;
            urma_jfs_wr_t *bad_wr = NULL;
            run_ctx->jfs_wr[0].user_ctx = (uintptr_t)++run_ctx->rid;
            status = urma_post_jetty_send_wr(ctx->jetty[0], &run_ctx->jfs_wr[0], &bad_wr);
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Couldn't urma write status: %d, scnt: %lu, ccnt: %lu, rcnt: %lu\n",
                    (int)status, scnt, ccnt, rcnt);
                return -1;
            }
        }

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }
        if (ccnt < cfg->iters || cfg->time_type.bs.duration == 1) {
            do {
                cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            } while (cqe_cnt == 0);

            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, ccnt %lu, rcnt: %lu.\n",
                        (int)cr.status, scnt, rcnt, ccnt);
                    return -1;
                }
                ccnt++;
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        }
    }

    return 0;
}

static int run_one_jetty_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_one_jetty_write(ctx, cfg);
    if (ret != 0) {
        destroy_jfs_wr(ctx);
        return -1;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int run_duplex_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            ret = run_one_jetty_write_lat(ctx, cfg);
            if (ret != 0) {
                (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
                return -1;
            }
            cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
        }
    } else {
        ret = run_one_jetty_write_lat(ctx, cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to run once write lat, size: %u.\n", cfg->size);
            return -1;
        }
        cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    }
    return 0;
}

int run_write_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return run_simplex_write_lat(ctx, cfg);
    }
    return run_duplex_write_lat(ctx, cfg);
}

static int send_lat_post_jetty_recv(perftest_context_t *ctx, perftest_config_t *cfg, int cnt)
{
    urma_status_t status;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;

    urma_jfr_wr_t *jfr_bad_wr = NULL;
    urma_jfr_wr_t *jfr_wr = run_ctx->jfr_wr;
    for (int i = 0; i < cnt; i++) {
        jfr_wr->user_ctx = (uintptr_t)run_ctx->rid++;
        status = urma_post_jetty_recv_wr(ctx->jetty[0], jfr_wr, &jfr_bad_wr);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Failed to urma_post_jetty_recv_wr, loop:%d, status: %d\n", i, (int)status);
            return -1;
        }
    }

    return 0;
}

static int run_once_jetty_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    uint64_t rcnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    urma_status_t status;
    int first_rx = 1;
    int poll = 0;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    uint32_t size_of_jetty = cfg->jfr_depth / cfg->jfr_post_list;

    urma_jfs_wr_t *wr = run_ctx->jfs_wr;
    wr->tjetty = ctx->import_tjetty[0];
    char *server_ip = cfg->comm.server_ip;

    while (scnt < cfg->iters || rcnt < cfg->iters ||
        (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        /*
         * Get the recv packet. make sure that the client won't enter here until he sends his first packet (scnt < 1)
         * server will enter here first and wait for a packet to arrive (from the client)
         */
        if ((rcnt < cfg->iters || cfg->time_type.bs.duration == 1) && !(scnt < 1 && server_ip != NULL)) {
            if (cfg->use_jfce == true) {
                if (wait_jfc_event(ctx->jfce_r) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event\n");
                    return -1;
                }
            }
            do {
                cqe_cnt = urma_poll_jfc(ctx->jfc_r, 1, &cr);
                if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                    break;
                }

                if (cqe_cnt > 0) {
                    if (first_rx != 0) {
                        set_on_first_rx(ctx, cfg);
                        first_rx = 0;
                    }

                    if (cr.status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, rcnt: %lu.\n",
                            (int)cr.status, scnt, rcnt);
                        return -1;
                    }

                    rcnt++;

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters++;
                    }

                    /* if we're in duration mode or there is enough space in the rx_depth,
                    * post that you received a packet.
                    */
                    if (cfg->time_type.bs.duration == 1 || (rcnt + size_of_jetty <= cfg->iters)) {
                        if (send_lat_post_jetty_recv(ctx, cfg, 1) != 0) {
                            return -1;
                        }
                    }
                } else if (cqe_cnt < 0) {
                    (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                    return -1;
                }
            } while (cfg->use_jfce == false && cqe_cnt == 0);
        }

        if (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
            if (cfg->time_type.bs.iterations == 1) {
                run_ctx->tposted[scnt] = get_cycles();
            }

            scnt++;

            if (scnt % cfg->cq_mod == 0 || (cfg->time_type.bs.iterations == 1 && scnt == cfg->iters)) {
                wr->flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
                poll = 1;
            }

            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }
            urma_jfs_wr_t *bad_wr = NULL;
            wr->user_ctx = (uintptr_t)run_ctx->rid++;
            status = urma_post_jetty_send_wr(ctx->jetty[0], wr, &bad_wr);
            if (status != URMA_SUCCESS) {
                (void)fprintf(stderr, "Couldn't urma send status: %d, scnt: %lu, rcnt: %lu\n",
                    (int)status, scnt, rcnt);
                return -1;
            }
            if (poll == 1) {
                if (cfg->use_jfce == true) {
                    if (wait_jfc_event(ctx->jfce_s) != 0) {
                        (void)fprintf(stderr, "Couldn't wait jfce event\n");
                        return -1;
                    }
                }

                do {
                    cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
                } while (cfg->use_jfce == false && cqe_cnt == 0);
                if (cqe_cnt < 0) {
                    (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                    return -1;
                }
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu, rcnt: %lu", (int)cr.status, scnt, rcnt);
                    return -1;
                }

                poll = 0;
                wr->flag.bs.complete_enable = URMA_COMPLETE_DISABLE;
            }
        }
    }

    return 0;
}

static int run_one_post_send(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint32_t size_of_jetty = cfg->jfr_depth / cfg->jfr_post_list;
    int ret;
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        ret = send_lat_post_recv(ctx, cfg, (int)size_of_jetty);
    } else {
        ret = send_lat_post_jetty_recv(ctx, cfg, (int)size_of_jetty);
    }
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to post recv, size: %u.\n", cfg->size);
        return -1;
    }
    /* Sync between the client and server so the client won't send packets
     * Before the server has posted his receive wqes.
     */
    ret = sync_time(cfg->comm.sock_fd, "send_lat_post_recv");
    if (ret != 0) {
        return -1;
    }
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        ret = run_once_send_lat(ctx, cfg);
    } else {
        ret = run_once_jetty_send_lat(ctx, cfg);
    }
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run_once_post_send_lat, size: %u.\n", cfg->size);
        return -1;
    }
    cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    return 0;
}

static int run_one_post_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = prepare_jfr_wr(ctx, cfg);
    if (ret != 0) {
        goto destroy_post_jfs;
    }
    ret = run_one_post_send(ctx, cfg);
    if (ret != 0) {
        goto destroy_post_jfr;
    }
    destroy_jfs_wr(ctx);
    destroy_jfr_wr(ctx);
    return 0;

destroy_post_jfr:
    destroy_jfr_wr(ctx);
destroy_post_jfs:
    destroy_jfs_wr(ctx);
    return -1;
}

static int run_post_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    if (cfg->all == true) {
        for (uint32_t i = 1; i <= cfg->order; i++) {
            cfg->size = (1U << i);
            ret = run_one_post_send_lat(ctx, cfg);
            if (ret != 0) {
                return -1;
            }
        }
    } else {
        ret = run_one_post_send_lat(ctx, cfg);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

int run_send_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        if (cfg->use_flat_api) {
            return run_jfs_send_lat(ctx, cfg);
        }
        return run_post_send_lat(ctx, cfg);
    }
    return run_post_send_lat(ctx, cfg);
}

static int run_once_post_atomic(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    ret = run_once_atomic_lat(ctx, cfg);
    if (ret != 0) {
        destroy_jfs_wr(ctx);
        return -1;
    }
    destroy_jfs_wr(ctx);
    return 0;
}

static int run_simplex_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    /* Only Client atomic test. */
    if (cfg->comm.server_ip == NULL) {
        return 0;
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    ret = run_once_post_atomic(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run once atomic lat, size: %u.\n", cfg->size);
        return -1;
    }
    cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);

    return 0;
}

static int run_one_jetty_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t scnt = 0;
    urma_cr_t cr;
    int cqe_cnt;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    run_ctx->jfs_wr[0].tjetty = ctx->import_tjetty[0];
    run_ctx->jfs_wr[0].flag.bs.complete_enable = 1;

    if (cfg->time_type.bs.duration == 1) {
        update_duration_state(ctx, cfg);
    }

    while (scnt < cfg->iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->time_type.bs.iterations == 1) {
            run_ctx->tposted[scnt] = get_cycles();
        }
        urma_jfs_wr_t *bad_wr = NULL;
        run_ctx->jfs_wr[0].user_ctx = (uintptr_t)run_ctx->rid++;
        urma_status_t status = urma_post_jetty_send_wr(ctx->jetty[0], &run_ctx->jfs_wr[0], &bad_wr);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Couldn't urma atomic status: %d, scnt: %lu\n", (int)status, scnt);
            return -1;
        }
        scnt++;

        if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
            break;
        }

        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_s) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfce event\n");
                return -1;
            }
        }

        do {
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, 1, &cr);
            if (cqe_cnt > 0) {
                if (cr.status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status %d, scnt: %lu.\n", (int)cr.status, scnt);
                    return -1;
                }

                if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                    cfg->iters++;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "poll jfc failed %d\n", cqe_cnt);
                return -1;
            }
        } while (cfg->use_jfce == false && cqe_cnt == 0);
    }

    return 0;
}

static int run_duplex_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret;
    /* Only Client atomic test. */
    if (cfg->comm.server_ip == NULL) {
        return 0;
    }

    (void)printf("%s\n", cfg->time_type.bs.iterations == 1 ? RESULT_LAT_FMT : RESULT_LAT_DUR_FMT);

    ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }

    ret = run_one_jetty_atomic_lat(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run once atomic lat, size: %u.\n", cfg->size);
        destroy_jfs_wr(ctx);
        return -1;
    }

    cfg->time_type.bs.iterations == 1 ? print_lat_report(ctx, cfg) : print_lat_duration_report(ctx, cfg);
    destroy_jfs_wr(ctx);
    return 0;
}

int run_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg)
{
    if (cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        return run_simplex_atomic_lat(ctx, cfg);
    }
    return run_duplex_atomic_lat(ctx, cfg);
}

static int run_once_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
    uint64_t tot_scnt = 0;
    uint64_t tot_ccnt = 0;
    uint32_t index;
    int cqe_cnt = 0;
    int cr_id;    // completion_record_data

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
            while ((run_ctx->scnt[index] < cfg->iters || cfg->time_type.bs.duration == 1) &&
                (run_ctx->scnt[index] - run_ctx->ccnt[index] + cfg->jfs_post_list) <= cfg->jfs_depth) {
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
                    // Step increased value
                    urma_sge_t *local_sge = &run_ctx->jfs_sge[(index * cfg->jfs_post_list) *
                        PERFTEST_SGE_NUM_PRE_WR + 1];
                    increase_loc_addr(local_sge, cfg->size, run_ctx->scnt[index],
                        (uint64_t)ctx->local_buf[index] + ctx->buf_size, cfg->cache_line_size, ctx->page_size);

                    if (cfg->api_type != PERFTEST_SEND) {
                        urma_sge_t *remote_sge =
                            &run_ctx->jfs_sge[(index * cfg->jfs_post_list) * PERFTEST_SGE_NUM_PRE_WR];
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
            }
        }

        if (tot_ccnt < tot_iters || (cfg->time_type.bs.duration == 1 && tot_ccnt < tot_scnt)) {
            if (cfg->use_jfce == true && cqe_cnt == 0) {
                if (wait_jfc_event(ctx->jfce_s) != 0) {
                    (void)fprintf(stderr, "Couldn't wait jfce event\n");
                    goto free_cr;
                }
            }
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, PERFTEST_POLL_BATCH, cr);
            if (cqe_cnt > 0) {
                for (int i = 0; i < cqe_cnt; i++) {
                    cr_id = (int)cr[i].user_ctx; // todo jfs_id
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, tot_scnt: %lu, tot_ccnt: %lu",
                            (int)cr[i].status, tot_scnt, tot_ccnt);
                        goto free_cr;
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
    uint32_t *posted_per_jetty = calloc(1, sizeof(uint32_t) * cfg->jettys);
    if (posted_per_jetty == NULL) {
        return -1;
    }
    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        ret = -1;
        goto free_recv_jetty;
    }
    uint32_t *unused_recv_for_jetty = calloc(1, sizeof(uint32_t) * cfg->jettys);
    if (unused_recv_for_jetty == NULL) {
        ret = -1;
        goto free_recv_cr;
    }

    for (i = 0; i < cfg->jettys; i++) {
        posted_per_jetty[i] = (uint32_t)run_ctx->rposted;
    }
    uint64_t tot_iters = cfg->iters * cfg->jettys;

    while (rcnt < tot_iters || (cfg->time_type.bs.duration == 1 && run_ctx->state != END_STATE)) {
        if (cfg->use_jfce == true) {
            if (wait_jfc_event(ctx->jfce_r) != 0) {
                (void)fprintf(stderr, "Couldn't wait jfc event.\n");
                ret = -1;
                goto free_u_recv_jetty;
            }
        }

        do {
            if (cfg->time_type.bs.duration == 1 && run_ctx->state == END_STATE) {
                break;
            }
            cqe_cnt = urma_poll_jfc(ctx->jfc_r, PERFTEST_POLL_BATCH, &cr[0]);
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
                        goto free_u_recv_jetty;
                    }
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed CR status %d, rcnt: %lu\n", (int)cr[i].status, rcnt);
                        ret = -1;
                        goto free_u_recv_jetty;
                    }
                    rcnt++;
                    unused_recv_for_jetty[cr_id]++;

                    if (cfg->time_type.bs.duration == 1 && run_ctx->state == START_STATE) {
                        cfg->iters++;
                    }
                    if ((cfg->time_type.bs.duration == 1 ||
                        posted_per_jetty[cr_id] + cfg->jfr_post_list <= cfg->iters) &&
                        unused_recv_for_jetty[cr_id] >= cfg->jfr_post_list) {
                        urma_status_t status;
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
                            goto free_u_recv_jetty;
                        }
                        unused_recv_for_jetty[cr_id] -= cfg->jfr_post_list;
                        posted_per_jetty[cr_id] += cfg->jfr_post_list;

                        if (cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM) && cfg->jfr_post_list == 1) {
                            urma_sge_t *local_sge = &run_ctx->jfr_sge[(cr_id * cfg->jfr_post_list) *
                                PERFTEST_SGE_NUM_PRE_WR + 1];

                            increase_loc_addr(local_sge, cfg->size, posted_per_jetty[cr_id],
                                (uint64_t)ctx->local_buf[cr_id], cfg->cache_line_size, ctx->page_size);
                        }
                    }
                }
            }
        } while (cqe_cnt > 0);

        if (cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc, cqe_cnt %d\n", cqe_cnt);
            ret = -1;
            goto free_u_recv_jetty;
        }
    }
    if (cfg->time_type.bs.iterations == 1) {
        run_ctx->tcompleted[0] = get_cycles();
    }
    ret = 0;
free_u_recv_jetty:
    free(unused_recv_for_jetty);
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
    uint32_t *posted_per_jetty = (uint32_t *)calloc(1, sizeof(uint32_t) * jettys);
    if (posted_per_jetty == NULL) {
        ret = -1;
        goto free_cr_send;
    }

    for (uint32_t i = 0; i < jettys; i++) {
        posted_per_jetty[i] = (uint32_t)run_ctx->rposted;
    }
    uint32_t *unused_recv_for_jetty = (uint32_t *)calloc(1, sizeof(uint32_t) * cfg->jettys);
    if (unused_recv_for_jetty == NULL) {
        ret = -1;
        goto free_posted_per_jetty;
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
                (((run_ctx->scnt[index] - run_ctx->ccnt[index]) + cfg->jfs_post_list) <= cfg->jfs_depth)) {
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
                    goto free_unused_recv_for_jetty;
                }

                if (cfg->jfs_post_list == 1 && cfg->size <= (cfg->page_size / PERFTEST_BUF_NUM)) {
                    urma_sge_t *local_sge = &run_ctx->jfs_sge[(index * cfg->jfs_post_list) *
                        PERFTEST_SGE_NUM_PRE_WR + 1];
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
            if (wait_jfc_event(ctx->jfce_r) != 0 && wait_jfc_event(ctx->jfce_s) != 0) {
                (void)fprintf(stderr, "Failed to wait jfce event.\n");
                ret = -1;
                goto free_unused_recv_for_jetty;
            }
        }

        recv_cqe_cnt = urma_poll_jfc(ctx->jfc_r, (int)cfg->jfr_depth, cr_recv);
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
                    goto free_unused_recv_for_jetty;
                }
                if (cr_recv[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed CR status: %d, tot_scnt: %lu, tot_ccnt: %lu, tot_rcnt: %lu\n.",
                        (int)cr_recv[i].status, tot_scnt, tot_ccnt, tot_rcnt);
                    ret = -1;
                    goto free_unused_recv_for_jetty;
                }

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
                        goto free_unused_recv_for_jetty;
                    }
                    unused_recv_for_jetty[cr_id] -= cfg->jfr_post_list;
                    posted_per_jetty[cr_id] += cfg->jfr_post_list;
                    if (cfg->size <= (ctx->page_size / PERFTEST_BUF_NUM) && cfg->jfr_post_list == 1) {
                        urma_sge_t *local_sge = &run_ctx->jfr_sge[(cr_id * cfg->jfr_post_list) *
                            PERFTEST_SGE_NUM_PRE_WR + 1];
                        increase_loc_addr(local_sge, cfg->size, posted_per_jetty[cr_id],
                            (uint64_t)ctx->local_buf[cr_id], cfg->cache_line_size, ctx->page_size);
                    }
                }
            }
        } else if (recv_cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc, recv_cqe_cnt: %d.\n", recv_cqe_cnt);
            ret = -1;
            goto free_unused_recv_for_jetty;
        }

        send_cqe_cnt = urma_poll_jfc(ctx->jfc_s, PERFTEST_POLL_BATCH, cr_send);
        if (send_cqe_cnt > 0) {
            for (int i = 0; i < send_cqe_cnt; i++) {
                cr_id = (uint32_t)cr_send[i].user_ctx;
                if (cr_id > cfg->jettys) {
                    ret = -1;
                    goto free_unused_recv_for_jetty;
                }
                if (cr_send[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed cr_send, status: %d, i: %d, tot_ccnt: %lu\n.",
                        (int)cr_send[i].status, i, tot_ccnt);
                    ret = -1;
                    goto free_unused_recv_for_jetty;
                }

                if (cr_send[i].flag.bs.s_r == 0) {
                    tot_ccnt += cfg->cq_mod;
                    run_ctx->ccnt[cr_id] += cfg->cq_mod;

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
            goto free_unused_recv_for_jetty;
        }
    }
    if (cfg->no_peak && cfg->time_type.bs.iterations == 1) {
        run_ctx->tcompleted[0] = get_cycles();
    }

free_unused_recv_for_jetty:
    free(unused_recv_for_jetty);
free_posted_per_jetty:
    free(posted_per_jetty);
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
    bw_report_data_t *local_bw_report)
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

    cycles_to_units = get_cpu_mhz(cfg->cpu_freq_f) * PERFTEST_M;
    if ((cycles_to_units - 0.0) <= 0.0) {
        (void)fprintf(stderr, "Can't produce a report\n");
        return;
    }
    inf_bi_factor = (cfg->bidirection && cfg->time_type.bs.infinite == 1) ?
        (cfg->api_type == PERFTEST_SEND ? INF_BI_FACTOR_SEND : INF_BI_FACTOR_OTHER) : NON_INF_BI_FACTOR;
    size = inf_bi_factor * cfg->size;
    uint64_t iters_sum = (cfg->time_type.bs.iterations == 1) ? num_of_cal_iters * cfg->jettys : num_of_cal_iters;
    cycles_sum = (double)(run_ctx->tcompleted[cfg->no_peak == true ? 0 : iters_sum - 1] - run_ctx->tposted[0]);

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
    if ((!cfg->bidirection) || (cfg->api_type == PERFTEST_SEND && cfg->time_type.bs.duration == 1) ||
        cfg->time_type.bs.infinite == 1) {
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
    uint64_t iters = local_bw_report->iters;
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
    while (g_perftest_ctx->infinite_print == true) {
        (void)sleep(*inf_duration);
        print_bw_report(g_perftest_ctx, g_perftest_cfg, NULL);
        g_perftest_cfg->last_iters = g_perftest_cfg->iters;
        g_perftest_ctx->run_ctx.tposted[0] = get_cycles();
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

    urma_cr_t *cr = calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        return -1;
    }

    g_perftest_ctx = ctx;
    g_perftest_cfg = cfg;

    g_perftest_ctx->infinite_print = true;
    pthread_t print_thread;
    if (pthread_create(&print_thread, NULL, infinite_print_thread, (void *)&cfg->inf_period) != 0) {
        (void)fprintf(stderr, "Failed to create thread.\n");
        free(cr);
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
            while (((run_ctx->scnt[index] - run_ctx->ccnt[index]) + cfg->jfs_post_list) <= cfg->jfs_depth) {
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
                    free(cr);
                    return -1;
                }
                run_ctx->scnt[index] += cfg->jfs_post_list;
                tot_scnt += cfg->jfs_post_list;

                if (cfg->jfs_post_list == 1 && (run_ctx->scnt[index] % cfg->cq_mod == cfg->cq_mod - 1 ||
                    (cfg->time_type.bs.iterations == 1 && run_ctx->scnt[index] == cfg->iters - 1))) {
                    run_ctx->jfs_wr[index].flag.bs.complete_enable = 1;
                }
            }
        }
        if (tot_ccnt < tot_scnt) {
            cqe_cnt = urma_poll_jfc(ctx->jfc_s, PERFTEST_POLL_BATCH, cr);
            if (cqe_cnt > 0) {
                for (int i = 0; i < cqe_cnt; i++) {
                    if (cr[i].status != URMA_CR_SUCCESS) {
                        (void)fprintf(stderr, "Failed to poll jfc, cr[%d] status: %d, tot_ccnt: %lu, tot_scnt: %lu.\n",
                            i, (int)cr[i].status, tot_ccnt, tot_scnt);
                        free(cr);
                        return -1;
                    }
                    cr_id = (int)cr[i].user_ctx;
                    cfg->iters += cfg->cq_mod;
                    tot_ccnt += cfg->cq_mod;
                    run_ctx->ccnt[cr_id] += cfg->cq_mod;
                }
            } else if (cqe_cnt < 0) {
                (void)fprintf(stderr, "Failed to poll jfc, cqe_cnt: %d.\n", cqe_cnt);
                free(cr);
                return -1;
            }
        }
    }
    free(cr);
    return 0;
}

static int run_once_bw_recv_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = 0;
    int cqe_cnt;
    uint32_t cr_id;
    run_test_ctx_t *run_ctx = &ctx->run_ctx;
    int first_rx = 1;

    urma_cr_t *cr = (urma_cr_t *)calloc(1, sizeof(urma_cr_t) * PERFTEST_POLL_BATCH);
    if (cr == NULL) {
        return -1;
    }
    uint32_t *unused_recv_for_jetty = (uint32_t *)calloc(1, sizeof(uint32_t) * cfg->jettys);
    if (unused_recv_for_jetty == NULL) {
        ret = -1;
        goto inf_recv_free_cr;
    }

    g_perftest_ctx = ctx;
    g_perftest_cfg = cfg;

    g_perftest_ctx->infinite_print = true;
    pthread_t print_thread;
    if (pthread_create(&print_thread, NULL, infinite_print_thread, (void *)&cfg->inf_period) != 0) {
        (void)fprintf(stderr, "Failed to create thread in server.\n");
        ret = -1;
        goto inf_recv_free_ur_jetty;
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
        cqe_cnt = urma_poll_jfc(ctx->jfc_r, PERFTEST_POLL_BATCH, cr);
        if (cqe_cnt > 0) {
            if (first_rx) {
                set_on_first_rx(ctx, cfg);
                first_rx = 0;
            }
            for (int i = 0; i < cqe_cnt; i++) {
                if (cr[i].status != URMA_CR_SUCCESS) {
                    (void)fprintf(stderr, "Failed to poll jfc in server, cr[%d] status: %d.\n",
                        i, (int)cr[i].status);
                    ret = -1;
                    goto inf_recv_free_ur_jetty;
                }
                cfg->iters++;
                cr_id = (uint32_t)cr[i].user_ctx;
                unused_recv_for_jetty[cr_id]++;
                if (unused_recv_for_jetty[cr_id] >= cfg->jfr_post_list) {
                    urma_status_t status;
                    urma_jfr_wr_t *bad_wr = NULL;
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
                        goto inf_recv_free_ur_jetty;
                    }
                    unused_recv_for_jetty[cr_id] -= cfg->jfr_post_list;
                }
            }
        } else if (cqe_cnt < 0) {
            (void)fprintf(stderr, "Failed to poll jfc in server, cqe_cnt: %d.\n", cqe_cnt);
            ret = -1;
            goto inf_recv_free_ur_jetty;
        }
    }

inf_recv_free_ur_jetty:
    free(unused_recv_for_jetty);
inf_recv_free_cr:
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
    int ret = prepare_jfs_wr(ctx, cfg);
    if (ret != 0) {
        return -1;
    }
    if (cfg->warm_up && perform_warm_up(ctx, cfg) != 0) {
        (void)fprintf(stderr, "Failed to perform warm_up, api_type: %d.\n", (int)cfg->api_type);
        goto err_dest_jfs_wr;
    }
    if (cfg->bidirection &&
        (sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].before) != 0)) {
        (void)fprintf(stderr, "Failed to sync time before bw test.\n");
        goto err_dest_jfs_wr;
    }
    ret = run_once_bw(ctx, cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run once bw, size: %u, ret: %d, api_type: %d.\n",
            cfg->size, ret, (int)cfg->api_type);
        goto err_dest_jfs_wr;
    }
    if (cfg->bidirection &&
        (sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].after) != 0)) {
        (void)fprintf(stderr, "Failed to sync time after bw test.\n");
        goto err_dest_jfs_wr;
    }
    print_bw_report(ctx, cfg, local_bw_report);
    if (cfg->bidirection) {
        if (sock_sync_data(cfg->comm.sock_fd, sizeof(bw_report_data_t), (char *)(local_bw_report),
            (char *)(remote_bw_report)) != 0) {
            (void)fprintf(stderr, "Failed to exchange local and remote report data.\n");
            goto err_dest_jfs_wr;
        }
        print_bi_bw_report(local_bw_report, remote_bw_report);
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
    /* Handle half bidirectional test */
    if (cfg->comm.server_ip == NULL && !cfg->bidirection) {
        if (sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].before) != 0 ||
            sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].after) != 0) {
            (void)fprintf(stderr, "Failed to sync time in bw test in server.\n");
            return -1;
        }
        if (sock_sync_data(cfg->comm.sock_fd, sizeof(bw_report_data_t), (char *)(&local_bw_report),
            (char *)(&remote_bw_report)) != 0) {
            (void)fprintf(stderr, "Failed to exchange local and remote data in server.\n");
            return -1;
        }
        print_bi_bw_report(&local_bw_report, &remote_bw_report);
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
        if (sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].before) != 0 ||
            sync_time(cfg->comm.sock_fd, g_bi_exchange_info[cfg->api_type].after) != 0) {
            (void)fprintf(stderr, "Failed to sync time in bw test in client.\n");
            return -1;
        }
        if (sock_sync_data(cfg->comm.sock_fd, sizeof(bw_report_data_t), (char *)(&local_bw_report),
            (char *)(&remote_bw_report)) != 0) {
            (void)fprintf(stderr, "Failed to exchange local and remote data in client.\n");
            return -1;
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
int run_write_bw(perftest_context_t *ctx, perftest_config_t *cfg)
{
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
    int ret = sync_time(cfg->comm.sock_fd, "send_bw_post_recv");
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to sync time, send_recv test.\n");
        return -1;
    }
    if (cfg->bidirection) {
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
    print_bw_report(ctx, cfg, &local_bw_report);

    if (cfg->bidirection && cfg->time_type.bs.duration == 0) {
        if (sock_sync_data(cfg->comm.sock_fd, sizeof(bw_report_data_t), (char *)(&local_bw_report),
            (char *)(&remote_bw_report)) != 0) {
            (void)fprintf(stderr, "Failed to exchange local and remote data.\n");
            return -1;
        }
        print_bi_bw_report(&local_bw_report, &remote_bw_report);
    }
    return 0;
}

static int run_send_bw_infinite(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = sync_time(cfg->comm.sock_fd, "run_send_bw_infinite");
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to sync time, run_send_bw_infinite, ret: %d.\n", ret);
        return -1;
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

    if (cfg->time_type.bs.infinite == 1) {
        ret = run_send_bw_infinite(ctx, cfg);
    } else {
        ret = run_send_bw_once(ctx, cfg);
    }
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run_send_bw_once, ret: %d.\n", ret);
        goto err_destroy_jfr_wr;
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
