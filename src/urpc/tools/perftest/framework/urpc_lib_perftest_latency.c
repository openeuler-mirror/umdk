/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest latency test case, both side use server_client and early rsp mode
 *   testcase: latency = t3 -t0, expect latency = urma_send_latency + 0.5us
 *      server and client only need one queue for each process
 *      server_client1: t0 urpc_func_call (send 4KB or 64B request), t3 urpc_func_poll (recv response success)
 *      server_client2: t1 urpc_func_poll (recv request success),    t2 urpc_func_call (send 4KB or 64B request)
 * Create: 2024-3-29
 */

#include <math.h>
#include <stdlib.h>
#include <unistd.h>

#include "perftest_thread.h"
#include "ub_get_clock.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_perftest_allocator.h"
#include "urpc_lib_perftest_util.h"
#include "urpc_framework_types.h"
#include "urpc_util.h"
#include "protocol.h"
#include "perftest_latency.h"

#include "urpc_lib_perftest_latency.h"

#define LATENCY_MEASURE_TAIL 2
#define LATENCY_HEAD_ROOM_SIZE 64
#define LATENCY_HEAD_TOTAL_SIZE 64
#define POLL_BATCH 8
#define MAX_WR_NUM 8
#define SIGN_LEN (DEFAULT_REQUEST_SIZE64 - 8)

#define SIMULATE_USER_HDR_SIZE  192
#define SERVER_USE_SGE_SIZE 256
#define URPC_POST_RECV_WR_NUM 32

static perftest_latency_ctx_t g_urpc_perftest_latency_ctx;

perftest_latency_ctx_t *get_perftest_latency_ctx(void)
{
    return &g_urpc_perftest_latency_ctx;
}

static void call_option_set(urpc_call_option_t *opt, urpc_lib_perftest_latency_arg_t *arg)
{
    opt->option_flag =
        FUNC_CALL_FLAG_FUNC_DEFINED | FUNC_CALL_FLAG_CALL_MODE | FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH;
    opt->call_mode = FUNC_CALL_MODE_EARLY_RSP;
    opt->l_qh = arg->l_qhs[0];
    opt->r_qh = arg->r_qhs[0];
    opt->func_defined = FUNC_DEF_NULL;
    if (arg->cfg->data_trans_mode == DATA_TRANS_MODE_READ) {
        opt->call_mode = FUNC_CALL_MODE_EARLY_RSP;
    }
}

static void server_run_latency_with_one_queue(
    perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh)
{
    struct urpc_poll_msg msgs[POLL_BATCH];
    struct urpc_poll_option poll_opt = {.urpc_qh = lat_arg->l_qhs[0]};
    uint32_t i;
    urpc_call_wr_t wr[MAX_WR_NUM] = {0};
    urpc_call_option_t option;
    call_option_set(&option, lat_arg);

    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    int poll_num;
    uint64_t *dptr = NULL;
    uint32_t post_num = 0;
    uint32_t posted_num = 0;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        return;
    }

    // 1. client/server need to process recv 4K, and server use recv first
    // 2. before urpc_func_call, set wr.args[0].length to lat_arg->cfg->size.
    // 3. after urpc_func_call, to ensure recv buffer size is valid, set wr.args[0].length to 4K
    for (i = 0 ; (i < MAX_WR_NUM) && (lat_arg->cfg->data_trans_mode != DATA_TRANS_MODE_READ); i++) {
        if (allocator->get(&wr[i].args, &wr[i].args_num, lat_arg->cfg->size_total, NULL) != URPC_SUCCESS) {
            LOG_PRINT("g_allocator.get failed\n");
            goto FINISH;
        }
    }

    while (g_urpc_perftest_latency_ctx.iters < DEFAULT_LAT_TEST_ROUND && args->state == PERFTEST_THREAD_RUNNING) {
        uint32_t req_recvd = 0;
        // Round 0, no req sent, no tx_rsp.
        uint32_t tx_sent = g_urpc_perftest_latency_ctx.iters == 0 ? lat_arg->cfg->con_num : 0;
        do {
            // early-rsp sent and request recv may be disorder
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt, msgs, POLL_BATCH);
            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RECVED) {
                    // recv request and server need to respond
                    post_num++;
                    req_recvd++;
                    if (lat_arg->cfg->data_trans_mode == DATA_TRANS_MODE_READ) {
                        tx_sent++;
                    }
                    allocator->put(msgs[j].req_recved.args, msgs[j].req_recved.args_sge_num, NULL);
                } else if (msgs[j].event == POLL_EVENT_REQ_RSPED) {
                    // early-rsp send successful, continue to wait for next request
                    tx_sent++;
                    continue;
                } else {
                    LOG_PRINT("urpc_func_poll %u get bad event %d, err:%u\n",
                              g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event,  msgs[j].req_err.err_code);
                    goto FINISH;
                }
            }

            if (post_num > URPC_POST_RECV_WR_NUM || cfg_get.rx_depth < URPC_POST_RECV_WR_NUM) {
                posted_num = perftest_post_rx_buff(qh, post_num, cfg_get.rx_buf_size);
                if (posted_num == URPC_U32_FAIL) {
                    LOG_PRINT("post rx buff faile\n");
                    goto FINISH;
                }
                post_num -= posted_num;
            }

            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (!((req_recvd >= lat_arg->cfg->con_num) && (tx_sent >= lat_arg->cfg->con_num)));

        // server send request as soon as possible
        for (i = 0; (i < lat_arg->cfg->con_num) && (lat_arg->cfg->data_trans_mode != DATA_TRANS_MODE_READ); i++) {
            wr[i].args[0].length = get_set_sge_size(0);
            dptr = (uint64_t*)(uintptr_t)(wr[i].args->addr + SIGN_LEN);
            *dptr = i;
            if (urpc_func_call(lat_arg->chid, &wr[i], &option) == URPC_U64_FAIL) {
                LOG_PRINT("urpc_func_call failed\n");
                goto FINISH;
            }
            wr[i].args[0].length = get_recv_max_sge_size(wr[i].args_num, 0);
        }

        g_urpc_perftest_latency_ctx.iters++;
    }

FINISH:
    for (i = 0; (i < MAX_WR_NUM) && (lat_arg->cfg->data_trans_mode != DATA_TRANS_MODE_READ); i++) {
        if (wr[i].args_num != 0) {
            allocator->put(wr[i].args, wr[i].args_num, NULL);
        }
    }
    perftest_force_quit();
}

static void urpc_perftest_server_run_latency(
    perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh)
{
    struct urpc_poll_msg msgs[POLL_BATCH];
    struct urpc_poll_option poll_opt1 = {.urpc_qh = lat_arg->l_qhs[Q_FOR_SEND]};
    struct urpc_poll_option poll_opt2 = {.urpc_qh = lat_arg->l_qhs[Q_FOR_RECV]};
    uint32_t i;
    urpc_call_wr_t wr[MAX_WR_NUM] = {0};
    uint64_t *dptr = NULL;
    urpc_call_option_t option = {
        .option_flag =
            FUNC_CALL_FLAG_FUNC_DEFINED | FUNC_CALL_FLAG_CALL_MODE | FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH,
        .call_mode = FUNC_CALL_MODE_EARLY_RSP,
        .l_qh = lat_arg->l_qhs[Q_FOR_SEND],
        .r_qh = lat_arg->r_qhs[Q_FOR_RECV],
        .func_defined = FUNC_DEF_NULL,
    };

    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    int poll_num;
    uint32_t post_num = 0;
    uint32_t posted_num = 0;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        return;
    }

    for (i = 0 ; i < MAX_WR_NUM; i++) {
        if (allocator->get(&wr[i].args, &wr[i].args_num, lat_arg->cfg->size_total, NULL) != URPC_SUCCESS) {
            LOG_PRINT("g_allocator.get failed\n");
            goto FINISH;
        }
    }

    while (g_urpc_perftest_latency_ctx.iters < DEFAULT_LAT_TEST_ROUND && args->state == PERFTEST_THREAD_RUNNING) {
        uint32_t req_recvd = 0;
        do {
            // early-rsp sent and request recv may be disorder
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt2, msgs, POLL_BATCH);
            if (URPC_LIKELY(poll_num == 0)) {
                poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt2, msgs, POLL_BATCH);
            }

            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RECVED) {
                    // recv request and server need to respond
                    post_num++;
                    req_recvd++;
                    allocator->put(msgs[j].req_recved.args, msgs[j].req_recved.args_sge_num, NULL);
                } else {
                    LOG_PRINT(
                        "urpc_func_poll %u get bad event %d\n", g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event);
                    goto FINISH;
                }
            }

            if (post_num > URPC_POST_RECV_WR_NUM || cfg_get.rx_depth < URPC_POST_RECV_WR_NUM) {
                posted_num = perftest_post_rx_buff(lat_arg->l_qhs[Q_FOR_RECV], post_num, cfg_get.rx_buf_size);
                if (posted_num == URPC_U32_FAIL) {
                    LOG_PRINT("post rx buff faile\n");
                    goto FINISH;
                }
                post_num -= posted_num;
            }

            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (req_recvd != lat_arg->cfg->con_num);

        // server send request as soon as possible
        for (i = 0 ; i < lat_arg->cfg->con_num; i++) {
            wr[i].args[0].length = get_set_sge_size(0);
            dptr = (uint64_t*)(uintptr_t)(wr[i].args->addr + SIGN_LEN);
            *dptr = i;
            if (urpc_func_call(lat_arg->chid, &wr[i], &option) == URPC_U64_FAIL) {
                LOG_PRINT("urpc_func_call failed\n");
                goto FINISH;
            }
            wr[i].args[0].length = get_recv_max_sge_size(wr[i].args_num, 0);
        }

        req_recvd = 0;
        do {
            // early-rsp sent and request recv may be disorder
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt1, msgs, POLL_BATCH);
            if (URPC_LIKELY(poll_num == 0)) {
                poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt1, msgs, POLL_BATCH);
            }

            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RSPED) {
                    // early-rsp send successful, continue to wait for next request
                    req_recvd++;
                    continue;
                } else {
                    LOG_PRINT(
                        "urpc_func_poll %u get bad event %d\n", g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event);
                    goto FINISH;
                }
            }

            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (req_recvd != lat_arg->cfg->con_num);

        g_urpc_perftest_latency_ctx.iters++;
    }

FINISH:
    for (i = 0; i < MAX_WR_NUM; i++) {
        if (wr[i].args_num != 0) {
            allocator->put(wr[i].args, wr[i].args_num, NULL);
        }
    }
    perftest_force_quit();
}


static void urpc_perftest_client_run_latency_finish(urpc_lib_perftest_latency_arg_t *lat_arg)
{
    LOG_PRINT("--------------------------------first wqe latency info---------------------------------\n");
    perftest_calculate_latency(
        g_urpc_perftest_latency_ctx.first_cycles, g_urpc_perftest_latency_ctx.iters, lat_arg->cfg->size_total,
        SEND_LATENCY_MODE);
    if (lat_arg->cfg->con_num > 1) {
        LOG_PRINT("--------------------------------left wqe latency info---------------------------------\n");
        perftest_calculate_latency(
            g_urpc_perftest_latency_ctx.cycles, g_urpc_perftest_latency_ctx.iters, lat_arg->cfg->size_total,
            SEND_LATENCY_MODE);
    }

    free(g_urpc_perftest_latency_ctx.cycles);
    free(g_urpc_perftest_latency_ctx.first_cycles);
    g_urpc_perftest_latency_ctx.cycles = NULL;
    g_urpc_perftest_latency_ctx.first_cycles = NULL;

    perftest_force_quit();
}

static void client_run_latency_with_one_queue(
    perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh)
{
    struct urpc_poll_msg msgs[POLL_BATCH];
    struct urpc_poll_option poll_opt = {.urpc_qh = lat_arg->l_qhs[0]};
    uint32_t i;
    urpc_call_option_t option;
    call_option_set(&option, lat_arg);

    urpc_allocator_option_t allocator_option = {0};
    uint32_t length  = lat_arg->cfg->size_total;
    if (lat_arg->cfg->data_trans_mode == DATA_TRANS_MODE_READ) {
        allocator_option.qcustom_flag = 0x123;
        length = URPC_PERFTEST_PAGE_SIZE * ((uint8_t)lat_arg->cfg->size_len - PLOG_HEADER_SGE_NUM);
    }
    urpc_call_wr_t wr[MAX_WR_NUM] = {0};
    uint64_t cycles[MAX_WR_NUM] = {0};
    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    int poll_num;
    uint32_t post_num = 0;
    uint32_t posted_num = 0;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        return;
    }

    g_urpc_perftest_latency_ctx.cycles = (uint64_t *)calloc(DEFAULT_LAT_TEST_ROUND, sizeof(uint64_t));
    if (g_urpc_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("malloc latency failed\n");
        goto FINISH;
    }
    g_urpc_perftest_latency_ctx.first_cycles = (uint64_t *)calloc(DEFAULT_LAT_TEST_ROUND, sizeof(uint64_t));
    if (g_urpc_perftest_latency_ctx.first_cycles == NULL) {
        LOG_PRINT("malloc latency failed\n");
        goto FINISH;
    }

    for (i = 0; (i < MAX_WR_NUM); i++) {
        if (allocator->get(&wr[i].args, &wr[i].args_num, length, &allocator_option) != URPC_SUCCESS) {
            LOG_PRINT("g_allocator.get failed\n");
            goto FINISH;
        }
    }
    uint64_t *dptr = NULL;
    while (g_urpc_perftest_latency_ctx.iters < DEFAULT_LAT_TEST_ROUND && args->state == PERFTEST_THREAD_RUNNING) {
        for (i = 0; i < lat_arg->cfg->con_num; i++) {
            if (false) {
                // to do READ
                if (allocator->get(&wr[i].args, &wr[i].args_num, length, &allocator_option) != URPC_SUCCESS) {
                    LOG_PRINT("g_allocator.get failed\n");
                    goto FINISH;
                }
                for (uint32_t j = PLOG_HEADER_SGE_NUM; j < wr[i].args_num - 1; j++) {
                    wr[i].args[j].flag = SGE_FLAG_DATA_ZONE;
                }
                wr[i].args[wr[i].args_num - 1].flag = SGE_FLAG_NO_MEM;
                wr[i].args[wr[i].args_num - 1].addr = 0;
            } else {
                wr[i].args[0].length = get_set_sge_size(0);
                dptr = (uint64_t*)(uintptr_t)(wr[i].args->addr + SIGN_LEN);
                *dptr = i;
            }
            cycles[i] = get_cycles();
            if (urpc_func_call(lat_arg->chid, &wr[i], &option) == URPC_U64_FAIL) {
                LOG_PRINT("urpc_func_call failed\n");
                goto FINISH;
            }
            if (lat_arg->cfg->data_trans_mode != DATA_TRANS_MODE_READ) {
                wr[i].args[0].length = get_recv_max_sge_size(wr[i].args_num, 0);
            }
        }

        // client report early_rsp request sent
        uint32_t req_recvd = 0;
        uint32_t tx_sent = 0;
        do {
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt, msgs, POLL_BATCH);
            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RSPED) {
                    // early-rsp send successful, continue to wait for server respond
                    tx_sent++;
                    continue;
                } else if (msgs[j].event == POLL_EVENT_REQ_RECVED) {
                    // client report request received
                    dptr = (uint64_t*)(uintptr_t)(msgs[j].req_recved.args->addr + SIGN_LEN);
                    cycles[*dptr] = get_cycles() - cycles[*dptr];
                    post_num++;
                    req_recvd++;
                    allocator->put(msgs[j].req_recved.args, msgs[j].req_recved.args_sge_num, NULL);
                } else if (msgs[j].event == POLL_EVENT_REQ_ACKED_RSPED) {
                    post_num++;
                    req_recvd++;
                    tx_sent++;
                    cycles[0] = get_cycles() - cycles[0];
                    allocator->put(msgs[j].req_acked_rsped.args, msgs[j].req_acked_rsped.args_sge_num, NULL);
                } else {
                    LOG_PRINT("urpc_func_poll %u get bad event %d, err:%u\n",
                              g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event, msgs[j].req_err.err_code);
                    goto FINISH;
                }
            }

            if (post_num > URPC_POST_RECV_WR_NUM || cfg_get.rx_depth < URPC_POST_RECV_WR_NUM) {
                posted_num = perftest_post_rx_buff(qh, post_num, cfg_get.rx_buf_size);
                if (posted_num == URPC_U32_FAIL) {
                    LOG_PRINT("post rx buff faile\n");
                    goto FINISH;
                }
                post_num -= posted_num;
            }

            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (!((req_recvd == lat_arg->cfg->con_num) && (tx_sent == lat_arg->cfg->con_num)));

        uint64_t total = get_total_cycle(lat_arg->cfg->con_num, &cycles[0]);
        g_urpc_perftest_latency_ctx.first_cycles[g_urpc_perftest_latency_ctx.iters] = cycles[0];
        if (lat_arg->cfg->con_num > 1) {
            g_urpc_perftest_latency_ctx.cycles[g_urpc_perftest_latency_ctx.iters] = total / (lat_arg->cfg->con_num - 1);
        }

        g_urpc_perftest_latency_ctx.iters++;
    }

FINISH:
    for (i = 0; i < MAX_WR_NUM; i++) {
        if (wr[i].args_num != 0) {
            allocator->put(wr[i].args, wr[i].args_num, NULL);
        }
    }
    urpc_perftest_client_run_latency_finish(lat_arg);
}

static void urpc_perftest_client_run_latency(
    perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh)
{
    struct urpc_poll_msg msgs[POLL_BATCH];
    struct urpc_poll_option poll_opt1 = {.urpc_qh = lat_arg->l_qhs[Q_FOR_SEND]};
    struct urpc_poll_option poll_opt2 = {.urpc_qh = lat_arg->l_qhs[Q_FOR_RECV]};
    uint32_t i;
    urpc_call_option_t option = {
        .option_flag =
            FUNC_CALL_FLAG_FUNC_DEFINED | FUNC_CALL_FLAG_CALL_MODE | FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH,
        .call_mode = FUNC_CALL_MODE_EARLY_RSP,
        .l_qh = lat_arg->l_qhs[Q_FOR_SEND],
        .r_qh = lat_arg->r_qhs[Q_FOR_RECV],
        .func_defined = FUNC_DEF_NULL,
    };

    urpc_call_wr_t wr[MAX_WR_NUM] = {0};
    uint64_t cycles[MAX_WR_NUM] = {0};
    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    int poll_num;
    uint32_t post_num = 0;
    uint32_t posted_num = 0;
    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        return;
    }

    g_urpc_perftest_latency_ctx.cycles = (uint64_t *)calloc(DEFAULT_LAT_TEST_ROUND, sizeof(uint64_t));
    if (g_urpc_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("malloc latency failed\n");
        goto FINISH;
    }
    g_urpc_perftest_latency_ctx.first_cycles = (uint64_t *)calloc(DEFAULT_LAT_TEST_ROUND, sizeof(uint64_t));
    if (g_urpc_perftest_latency_ctx.first_cycles == NULL) {
        LOG_PRINT("malloc first  latency failed\n");
        goto FINISH;
    }

    for (i = 0; i < MAX_WR_NUM; i++) {
        if (allocator->get(&wr[i].args, &wr[i].args_num, lat_arg->cfg->size_total, NULL) != URPC_SUCCESS) {
            LOG_PRINT("g_allocator.get failed\n");
            goto FINISH;
        }
    }

    uint64_t *dptr = NULL;
    while (g_urpc_perftest_latency_ctx.iters < DEFAULT_LAT_TEST_ROUND && args->state == PERFTEST_THREAD_RUNNING) {
        for (i = 0; i < lat_arg->cfg->con_num; i++) {
            wr[i].args[0].length = get_set_sge_size(0);
            dptr = (uint64_t*)(uintptr_t)(wr[i].args->addr + SIGN_LEN);
            *dptr = i;
            cycles[i] = get_cycles();
            if (urpc_func_call(lat_arg->chid, &wr[i], &option) == URPC_U64_FAIL) {
                LOG_PRINT("urpc_func_call failed\n");
                goto FINISH;
            }
            wr[i].args[0].length = get_recv_max_sge_size(wr[i].args_num, 0);
        }

        // client report early_rsp request sent
        uint32_t req_recvd = 0;
        do {
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt1, msgs, POLL_BATCH);
            if (URPC_LIKELY(poll_num == 0)) {
                poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt1, msgs, POLL_BATCH);
            }

            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RSPED) {
                    // early-rsp send successful, continue to wait for server respond
                    req_recvd++;
                    continue;
                } else {
                    LOG_PRINT(
                        "urpc_func_poll %u get bad event %d\n", g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event);
                    goto FINISH;
                }
            }
            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (req_recvd != lat_arg->cfg->con_num);

        req_recvd = 0;
        do {
            poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt2, msgs, POLL_BATCH);
            if (URPC_LIKELY(poll_num == 0)) {
                poll_num = urpc_func_poll(URPC_INVALID_ID_U32, &poll_opt2, msgs, POLL_BATCH);
            }

            if (URPC_UNLIKELY(poll_num < 0)) {
                LOG_PRINT("urpc_func_poll return error %d\n", poll_num);
                goto FINISH;
            }

            for (int j = 0; j < poll_num; j++) {
                if (msgs[j].event == POLL_EVENT_REQ_RECVED) {
                    // client report request received
                    dptr = (uint64_t*)(uintptr_t)(msgs[j].req_recved.args->addr + SIGN_LEN);
                    cycles[*dptr] = get_cycles() - cycles[*dptr];
                    post_num++;
                    req_recvd++;
                    allocator->put(msgs[j].req_recved.args, msgs[j].req_recved.args_sge_num, NULL);
                } else {
                    LOG_PRINT("urpc_func_poll %u get bad event %d, err:%u\n",
                              g_urpc_perftest_latency_ctx.iters, (int)msgs[j].event, msgs[j].req_err.err_code);
                    goto FINISH;
                }
            }

            if (post_num > URPC_POST_RECV_WR_NUM || cfg_get.rx_depth < URPC_POST_RECV_WR_NUM) {
                posted_num = perftest_post_rx_buff(lat_arg->l_qhs[Q_FOR_RECV], post_num, cfg_get.rx_buf_size);
                if (posted_num == URPC_U32_FAIL) {
                    LOG_PRINT("post rx buff faile\n");
                    goto FINISH;
                }
                post_num -= posted_num;
            }

            if (args->state != PERFTEST_THREAD_RUNNING) {
                goto FINISH;
            }
        } while (req_recvd != lat_arg->cfg->con_num);

        uint64_t avg = 0;
        if (lat_arg->cfg->con_num > 1) {
            for (i = 0; i < lat_arg->cfg->con_num; i++) {
                avg += cycles[i];
            }
        }
        uint64_t total = get_total_cycle(lat_arg->cfg->con_num, &cycles[0]);
        g_urpc_perftest_latency_ctx.first_cycles[g_urpc_perftest_latency_ctx.iters] = cycles[0];
        if (lat_arg->cfg->con_num > 1) {
            g_urpc_perftest_latency_ctx.cycles[g_urpc_perftest_latency_ctx.iters] = total / (lat_arg->cfg->con_num - 1);
        }

        g_urpc_perftest_latency_ctx.iters++;
    }

FINISH:
    for (i = 0; i < MAX_WR_NUM; i++) {
        if (wr[i].args_num != 0) {
            allocator->put(wr[i].args, wr[i].args_num, NULL);
        }
    }
    urpc_perftest_client_run_latency_finish(lat_arg);
}

void urpc_perftest_run_latency(perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh)
{
    if (lat_arg->cfg->use_one_q) {
        if (lat_arg->cfg->instance_mode == SERVER) {
            server_run_latency_with_one_queue(args, lat_arg, qh);
        } else {
            client_run_latency_with_one_queue(args, lat_arg, qh);
        }

        return;
    }

    if (lat_arg->cfg->instance_mode == SERVER) {
        urpc_perftest_server_run_latency(args, lat_arg, qh);
    } else {
        urpc_perftest_client_run_latency(args, lat_arg, qh);
    }
}

void urpc_perftest_print_latency(perftest_framework_config_t *cfg)
{
    // fake print func
    while (!is_perftest_force_quit()) {
        (void)sleep(1);
    }
}
