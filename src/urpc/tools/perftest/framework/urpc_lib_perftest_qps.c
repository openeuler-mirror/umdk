/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest qps test case
 * Create: 2024-3-6
 */

#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "perftest_util.h"
#include "perftest_qps.h"
#include "ub_get_clock.h"
#include "urpc_framework_api.h"
#include "urpc_lib_perftest_allocator.h"
#include "urpc_lib_perftest_param.h"
#include "urpc_lib_perftest_util.h"
#include "urpc_framework_types.h"
#include "urpc_framework_errno.h"

#include "urpc_lib_perftest_qps.h"

#define DEFAULT_FUNCTION_ID 0
#define NS_PER_US 1000.0
#define POLL_PATCH 16
#define QPS_MESSAGE_SIZE 4096
#define QPS_HEAD_ROOM_SIZE 64
#define QPS_HEAD_TOTAL_SIZE 64
#define QPS_THREAD_FORMAT "       %-7.3lf"
#define QPS_FIRST_THREAD_FORMAT "     %-7.3lf"
#define URPC_POST_RECV_WR_NUM 32

static perftest_qps_ctx_t g_urpc_perftest_qps_ctx;

perftest_qps_ctx_t *get_perftest_qps_ctx(void)
{
    return &g_urpc_perftest_qps_ctx;
}

static inline void busy_wait(double cycles_to_units, uint32_t func_period)
{
    uint64_t start_cycle = get_cycles();
    while (((get_cycles() - start_cycle) * NS_PER_US / cycles_to_units) < func_period) {
    }
}
void urpc_perftest_server_run_qps(perftest_thread_arg_t *args, urpc_lib_perftest_qps_arg_t *qps_arg, uint64_t qh)
{
    struct urpc_poll_msg *msgs = (struct urpc_poll_msg *)calloc(POLL_PATCH, sizeof(struct urpc_poll_msg));
    if (msgs == NULL) {
        LOG_PRINT("fail to malloc urpc_poll_msg\n");
        goto ERROR;
    }

    struct urpc_poll_option poll_opt = {.urpc_qh = qh};
    uint32_t thread_index = perftest_thread_index();
    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    int poll_num;
    uint32_t post_num = 0;
    uint32_t posted_num = 0;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        goto ERROR;
    }

    while (args->state == PERFTEST_THREAD_RUNNING) {
        poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt, msgs, POLL_PATCH);
        if (poll_num < 0) {
            LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
            goto ERROR;
        }

        if (poll_num == 0) {
            continue;
        }

        for (int i = 0; i < poll_num; i++) {
            if (msgs[i].event != POLL_EVENT_REQ_RECVED) {
                LOG_PRINT("urpc_func_poll get bad event %d\n", (int)msgs[i].event);
                continue;
            }
            post_num++;
            allocator->put(msgs[i].req_recved.args, msgs[i].req_recved.args_sge_num, NULL);
        }

        if (post_num > URPC_POST_RECV_WR_NUM || cfg_get.rx_depth < URPC_POST_RECV_WR_NUM) {
            posted_num = perftest_post_rx_buff(qh, post_num, cfg_get.rx_buf_size);
            if (posted_num == URPC_U32_FAIL) {
                LOG_PRINT("post rx buff faile\n");
                goto ERROR;
            }
            post_num -= posted_num;
        }

        (void)atomic_fetch_add(&g_urpc_perftest_qps_ctx.reqs[thread_index], poll_num);
    }

    free(msgs);

    return;

ERROR:
    perftest_force_quit();
    args->state = PERFTEST_THREAD_ERROR;
    free(msgs);
}

static inline int urpc_perftest_init_wr(uint32_t size, urpc_call_wr_t *wr)
{
    urpc_allocator_t *allocator = urpc_perftest_allocator_get();

    if (allocator->get(&wr->args, &wr->args_num, size, NULL) != URPC_SUCCESS) {
        LOG_PRINT("allocator get wr args failed\n");
        return -1;
    }

    wr->func_id = DEFAULT_FUNCTION_ID;

    return 0;
}

void urpc_perftest_client_run_qps(perftest_thread_arg_t *args, urpc_lib_perftest_qps_arg_t *qps_arg, uint64_t qh)
{
    struct urpc_poll_msg *msgs = (struct urpc_poll_msg *)calloc(POLL_PATCH, sizeof(struct urpc_poll_msg));
    if (msgs == NULL) {
        LOG_PRINT("fail to malloc urpc_poll_msg\n");
        goto ERROR;
    }

    urpc_call_option_t option = {
        .option_flag = FUNC_CALL_FLAG_FUNC_DEFINED | FUNC_CALL_FLAG_CALL_MODE,
        .call_mode = FUNC_CALL_MODE_EARLY_RSP,
        .func_defined = FUNC_DEF_NULL,
    };

    uint32_t thread_index = perftest_thread_index();
    struct urpc_poll_option poll_opt = {.urpc_qh = qh};
    uint32_t can_send_num = qps_arg->cfg->tx_depth;
    int poll_num;
    urpc_call_wr_t wr;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        goto ERROR;
    }

    if (urpc_perftest_init_wr(qps_arg->cfg->size_total, &wr) != 0) {
        goto ERROR;
    }

    while (args->state == PERFTEST_THREAD_RUNNING) {
        if (can_send_num > 0) {
            wr.args[0].length = get_set_sge_size(0);
            if (urpc_func_call(qps_arg->chid, &wr, &option) == URPC_U64_FAIL) {
                LOG_PRINT("urpc_func_call failed\n");
                goto ERROR;
            }
            can_send_num--;
        }
        wr.args[0].length = get_recv_max_sge_size(wr.args_num, 0);

        poll_num = urpc_func_poll(qps_arg->chid, &poll_opt, msgs, POLL_PATCH);
        if (poll_num < 0) {
            LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
            goto ERROR;
        }

        if (poll_num == 0) {
            continue;
        }

        for (int i = 0; i < poll_num; i++) {
            if (msgs[i].event != POLL_EVENT_REQ_RSPED) {
                LOG_PRINT("urpc_func_poll get bad event %d\n", (int)msgs[i].event);
                continue;
            }
        }
        (void)atomic_fetch_add(&g_urpc_perftest_qps_ctx.reqs[thread_index], poll_num);
        can_send_num += (uint32_t)poll_num;
    }

    free(msgs);

    return;

ERROR:
    perftest_force_quit();
    args->state = PERFTEST_THREAD_ERROR;
    free(msgs);
}

static inline uint64_t urpc_perftest_reqs_sum(uint32_t worker_num)
{
    uint64_t sum = 0;
    for (uint32_t i = 1; i < worker_num + 1; i++) {
        sum += atomic_load(&g_urpc_perftest_qps_ctx.reqs[i]);
    }

    return sum;
}

static inline void urpc_perftest_reqs_get(uint64_t *reqs, uint32_t size, uint32_t worker_num)
{
    for (uint32_t i = 1; i < worker_num + 1 && i < size; i++) {
        reqs[i] = atomic_load(&g_urpc_perftest_qps_ctx.reqs[i]);
    }
}

static inline uint64_t urpc_perftest_reqs_sum_get(uint64_t *reqs, uint32_t size, uint32_t worker_num)
{
    uint64_t total = 0;
    for (uint32_t i = 1; i < worker_num + 1 && i < size; i++) {
        total += reqs[i];
    }

    return total;
}

static void urpc_perftest_print_qps_title(perftest_framework_config_t *cfg)
{
    int s = 0;
    int ret;
    char title[QPS_MESSAGE_SIZE];

    if (!cfg->show_thread_qps) {
        (void)printf("  qps[Mpps]    BW[MB/Sec]\n");
        return;
    }

    ret = sprintf(title, "  qps[Mpps]    BW[MB/Sec]");
    if (ret < 0) {
        LOG_PRINT("fail to get qps title string\n");
        ret = 0;
    }

    s += ret;
    for (uint32_t i = 1; i < cfg->thread_num + 1; i++) {
        ret = sprintf(title + s, "  %02u-qps[Mpps]", i);
        if (ret < 0) {
            LOG_PRINT("fail to get qps title string\n");
            ret = 0;
        }

        s += ret;
    }

    (void)printf("%s\n", title);
}

// 用cycle计算qps的精确时间, sleep仅用于定时输出结果
void urpc_perftest_print_qps(perftest_framework_config_t *cfg)
{
    char result[QPS_MESSAGE_SIZE];
    uint64_t reqs[PERFTEST_THREAD_MAX_NUM] = {0};
    uint64_t reqs_old[PERFTEST_THREAD_MAX_NUM] = {0};
    uint64_t cur_sum, end;
    double cycles_to_units = get_cpu_mhz(true);
    double qps;
    int ret;

    urpc_perftest_reqs_get(reqs_old, PERFTEST_THREAD_MAX_NUM, cfg->thread_num);
    uint64_t reqs_num = urpc_perftest_reqs_sum_get(reqs_old, PERFTEST_THREAD_MAX_NUM, cfg->thread_num);
    uint64_t begin = get_cycles();

    urpc_perftest_print_qps_title(cfg);
    while (!is_perftest_force_quit()) {
        (void)sleep(1);

        urpc_perftest_reqs_get(reqs, PERFTEST_THREAD_MAX_NUM, cfg->thread_num);
        cur_sum = urpc_perftest_reqs_sum_get(reqs, PERFTEST_THREAD_MAX_NUM, cfg->thread_num);
        end = get_cycles();

        // show qps
        qps = (double)(cur_sum - reqs_num) * cycles_to_units / (double)(end - begin);

        int s = 0;
        ret = sprintf(result, "  %-7.6lf     %-7.3lf", qps,
            qps * URPC_PERFTEST_1M * cfg->size_total / URPC_PERFTEST_1MB);
        if (ret < 0) {
            LOG_PRINT("fail to get qps string\n");
            ret = 0;
        }

        s += ret;
        if (!cfg->show_thread_qps) {
            goto OUTPUT;
        }

        for (uint32_t i = 1; i < cfg->thread_num + 1; i++) {
            ret = sprintf(result + s, i == 1 ? QPS_FIRST_THREAD_FORMAT : QPS_THREAD_FORMAT,
                (double)(reqs[i] - reqs_old[i]) * cycles_to_units / (double)(end - begin));
            if (ret < 0) {
                LOG_PRINT("fail to get worker thread qps string\n");
                ret = 0;
            }

            s += ret;
            reqs_old[i] = reqs[i];
        }

OUTPUT:
        (void)fflush(stdout);
        (void)printf("%s\n", result);
        reqs_num = cur_sum;
        begin = end;
    }
}
