/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perftest qps test case
 * Create: 2025-8-27
 */

#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "ub_get_clock.h"
#include "umq_api.h"
#include "umq_pro_api.h"
#include "perftest_util.h"
#include "perftest_qps.h"
#include "umq_perftest_qps.h"

#define QPS_PRINT_STR_LEN   (4096)
#define UMQ_PERFTEST_1M     (1000000)
#define UMQ_PERFTEST_1MB    (0x100000)

static perftest_qps_ctx_t g_umq_perftest_qps_ctx = {0};

perftest_qps_ctx_t *get_perftest_qps_ctx(void)
{
    return &g_umq_perftest_qps_ctx;
}

static void set_pro_data(umq_buf_t *tmp, umq_perftest_qps_arg_t *qps_arg)
{
    while (tmp) {
        umq_buf_pro_t *pro = (umq_buf_pro_t *)tmp->qbuf_ext;
        pro->flag.value = 0;
        pro->flag.bs.solicited_enable = 1;
        pro->flag.bs.complete_enable = 1;
        pro->opcode = UMQ_OPC_SEND;
        if (qps_arg->cfg->config.size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        tmp = tmp->qbuf_next;
    }
}

static void umq_perftest_server_run_qps_base_interrupt(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    umq_buf_t *recv_buf = NULL;
    umq_buf_t *tmp_buf = NULL;
    uint32_t poll_num = 0;
    uint32_t thread_inx = perftest_thread_index();
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
    }
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            continue;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            continue;
        }

        // recv req, release req buf after counting
        recv_buf = umq_dequeue(umqh);
        if (recv_buf == NULL) {
            continue;
        }

        tmp_buf = recv_buf;
        poll_num = 0;
        uint32_t rest_data_size = 0;
        while (tmp_buf) {
            rest_data_size = tmp_buf->total_data_size;
            poll_num++;
            while (tmp_buf && rest_data_size > 0) {
                if (rest_data_size < tmp_buf->data_size) { // if cannot add up to total_size, return fail
                    LOG_PRINT("rest size is negative\n");
                    return;
                }
                rest_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }

        umq_buf_free(recv_buf);
        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], poll_num);
    }
}

static void umq_perftest_server_run_qps_base_polling(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    umq_buf_t *recv_buf = NULL;
    umq_buf_t *tmp_buf = NULL;
    uint32_t poll_num = 0;
    uint32_t thread_inx = perftest_thread_index();
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        // recv req, release req buf after counting
        recv_buf = umq_dequeue(umqh);
        if (recv_buf == NULL) {
            continue;
        }

        tmp_buf = recv_buf;
        poll_num = 0;
        uint32_t rest_data_size = 0;
        while (tmp_buf) {
            rest_data_size = tmp_buf->total_data_size;
            poll_num++;
            while (tmp_buf && rest_data_size > 0) {
                if (rest_data_size < tmp_buf->data_size) { // if cannot add up to total_size, return fail
                    LOG_PRINT("rest size is negative\n");
                    return;
                }
                rest_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }

        umq_buf_free(recv_buf);
        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], poll_num);
    }
}

static void umq_perftest_server_run_qps_base(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    if (qps_arg->cfg->config.interrupt) {
        umq_perftest_server_run_qps_base_interrupt(umqh, qps_arg);
    } else {
        umq_perftest_server_run_qps_base_polling(umqh, qps_arg);
    }
}

static void umq_perftest_client_run_qps_base(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    umq_buf_t *bad_buf = NULL;
    uint32_t thread_inx = perftest_thread_index();
    uint32_t size = qps_arg->cfg->config.size;
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        /* alloc buf, send req, send 64 wr each time.
        it will attempt to poll tx during the next enqueue and then release the buffer. */
        umq_buf_t *req_buf = umq_buf_alloc(size, UMQ_BATCH_SIZE, umqh, NULL);
        if (req_buf == NULL) {
            continue;
        }

        // send req
        int32_t ret = -1;
        do {
            bad_buf = NULL;
            ret = umq_enqueue(umqh, req_buf, &bad_buf);
            if (is_perftest_force_quit()) {
                return;
            }
            if (ret == -EAGAIN) {
                continue;
            }
            if (ret == UMQ_FAIL) {
                umq_buf_free(req_buf);
                return;
            }
        } while (ret != UMQ_SUCCESS && !is_perftest_force_quit());
        umq_notify(umqh);

        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], UMQ_BATCH_SIZE);
    }
    perftest_force_quit();
}

static void umq_perftest_server_run_qps_pro_interrupt(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    umq_buf_t *bad_buf = NULL;
    uint32_t require_rx_cnt = 0;
    int32_t poll_num = 0;
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    uint32_t thread_inx = perftest_thread_index();

    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("server umq_rearm_interrupt failed\n");
    }
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            return;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("server umq_rearm_interrupt failed\n");
            return;
        }
        // recv req, release req buf after counting
        do {
            poll_num = umq_poll(umqh, UMQ_IO_ALL, polled_buf, UMQ_BATCH_SIZE);
            if (poll_num < 0) {
                LOG_PRINT("poll rx failed\n");
                return;
            }
        } while (poll_num == 0 && !is_perftest_force_quit());

        require_rx_cnt += (uint32_t)poll_num;
        for (int i = 0; i < poll_num; ++i) {
            umq_buf_free(polled_buf[i]);
        }
        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], poll_num);

        // batch fill rx
        if (require_rx_cnt >= UMQ_BATCH_SIZE) {
            umq_buf_t *rx_buf = umq_buf_alloc(qps_arg->cfg->config.size, UMQ_BATCH_SIZE, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                return;
            }

            if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
                LOG_PRINT("post rx failed\n");
                umq_buf_free(bad_buf);
                bad_buf = NULL;
                return;
            }
            require_rx_cnt -= UMQ_BATCH_SIZE;
        }
    }
}

static void umq_perftest_server_run_qps_pro_polling(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    umq_buf_t *bad_buf = NULL;
    uint32_t require_rx_cnt = 0;
    int32_t poll_num = 0;
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    uint32_t thread_inx = perftest_thread_index();
    uint32_t size = qps_arg->cfg->config.size;
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        // recv req，release req buf after counting
        poll_num = umq_poll(umqh, UMQ_IO_ALL, polled_buf, UMQ_BATCH_SIZE);
        if (poll_num < 0) {
            LOG_PRINT("poll rx failed\n");
            return;
        }

        require_rx_cnt += (uint32_t)poll_num;
        for (int i = 0; i < poll_num; ++i) {
            umq_buf_free(polled_buf[i]);
        }
        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], poll_num);

        // batch fill rx
        if (require_rx_cnt >= UMQ_BATCH_SIZE) {
            umq_buf_t *rx_buf = umq_buf_alloc(size, UMQ_BATCH_SIZE, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                return;
            }

            if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
                LOG_PRINT("post rx failed\n");
                umq_buf_free(bad_buf);
                bad_buf = NULL;
                return;
            }
            require_rx_cnt -= UMQ_BATCH_SIZE;
        }
    }
}

static void umq_perftest_server_run_qps_pro(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    if (qps_arg->cfg->config.interrupt) {
        umq_perftest_server_run_qps_pro_interrupt(umqh, qps_arg);
    } else {
        umq_perftest_server_run_qps_pro_polling(umqh, qps_arg);
    }
}

static inline uint32_t get_actual_send_num(umq_buf_t *req_buf, umq_buf_t *bad)
{
    uint32_t num = 0;
    umq_buf_t *tmp = req_buf;
    while (tmp) {
        if (tmp == bad) {
            break;
        }

        num++;
        tmp = tmp->qbuf_next;
    }

    return num;
}

static void umq_perftest_client_run_qps_pro_interrupt(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    // preparing req data, req data reuse
    umq_buf_t *req_buf = umq_buf_alloc(qps_arg->cfg->config.size, UMQ_BATCH_SIZE, umqh, NULL);
    if (req_buf == NULL) {
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    umq_buf_t *tmp = req_buf;
    set_pro_data(tmp, qps_arg);

    int ret;
    umq_buf_t *bad_buf = NULL;
    uint32_t can_send_num = qps_arg->cfg->config.tx_depth;
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    uint32_t thread_inx = perftest_thread_index();
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto ERROR;
    }
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        if (can_send_num >= UMQ_BATCH_SIZE) {
            // send req when tx depth is not fully utilized
            ret = umq_post(umqh, req_buf, UMQ_IO_TX, &bad_buf);
            if (ret != UMQ_SUCCESS) {
                if (ret == -UMQ_ERR_EAGAIN) {
                    if (req_buf == bad_buf) {
                        goto POLL;
                    }
                    can_send_num -= get_actual_send_num(req_buf, bad_buf);
                    umq_notify(umqh);
                    goto REARM;
                }
                LOG_PRINT("post tx failed\n");
                goto ERROR;
            }
            can_send_num -= UMQ_BATCH_SIZE;
            umq_notify(umqh);
        }
REARM:
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto ERROR;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto ERROR;
        }
POLL:
        // poll tx cqe，increase the count
        ret = umq_poll(umqh, UMQ_IO_TX, polled_buf, UMQ_BATCH_SIZE);
        if (ret < 0) {
            LOG_PRINT("poll tx failed\n");
            goto ERROR;
        } else if (ret == 0) {
            continue;
        }

        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], ret);
        can_send_num += (uint32_t)ret;
    }

    umq_buf_free(req_buf);
    return;

ERROR:
    umq_buf_free(req_buf);
    perftest_force_quit();
}

static void umq_perftest_client_run_qps_pro_polling(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    // preparing req data, req data reuse
    umq_buf_t *req_buf = umq_buf_alloc(qps_arg->cfg->config.size, UMQ_BATCH_SIZE, umqh, NULL);
    if (req_buf == NULL) {
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    umq_buf_t *tmp = req_buf;
    set_pro_data(tmp, qps_arg);

    int ret;
    umq_buf_t *bad_buf = NULL;
    uint32_t can_send_num = qps_arg->cfg->config.tx_depth;
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    uint32_t thread_inx = perftest_thread_index();
    uint64_t start_cycle = get_cycles();
    double cycles_to_units = get_cpu_mhz(false);
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        if (can_send_num >= UMQ_BATCH_SIZE) {
            // send req when tx depth is not fully utilized
            ret = umq_post(umqh, req_buf, UMQ_IO_TX, &bad_buf);
            if (ret != UMQ_SUCCESS) {
                if (ret == -UMQ_ERR_EAGAIN) {
                    can_send_num -= get_actual_send_num(req_buf, bad_buf);
                    goto POLL;
                }
                LOG_PRINT("post tx failed\n");
                goto ERROR;
            }
            can_send_num -= UMQ_BATCH_SIZE;
            umq_notify(umqh);
        }
POLL:
        // poll tx cqe, increase the count
        ret = umq_poll(umqh, UMQ_IO_ALL, polled_buf, UMQ_BATCH_SIZE);
        if (ret < 0) {
            LOG_PRINT("poll tx failed\n");
            goto ERROR;
        } else if (ret == 0) {
            continue;
        }

        (void)atomic_fetch_add(&g_umq_perftest_qps_ctx.reqs[thread_inx], ret);
        can_send_num += (uint32_t)ret;
    }

    umq_buf_free(req_buf);
    return;

ERROR:
    umq_buf_free(req_buf);
    perftest_force_quit();
}

static void umq_perftest_client_run_qps_pro(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    if (qps_arg->cfg->config.interrupt) {
        umq_perftest_client_run_qps_pro_interrupt(umqh, qps_arg);
    } else {
        umq_perftest_client_run_qps_pro_polling(umqh, qps_arg);
    }
}

void umq_perftest_run_qps(uint64_t umqh, umq_perftest_qps_arg_t *qps_arg)
{
    if (qps_arg->cfg->config.instance_mode == PERF_INSTANCE_SERVER) {
        if (qps_arg->cfg->feature & UMQ_FEATURE_API_PRO) {
            umq_perftest_server_run_qps_pro(umqh, qps_arg);
        } else {
            umq_perftest_server_run_qps_base(umqh, qps_arg);
        }
    } else {
        if (qps_arg->cfg->feature & UMQ_FEATURE_API_PRO) {
            umq_perftest_client_run_qps_pro(umqh, qps_arg);
        } else {
            umq_perftest_client_run_qps_base(umqh, qps_arg);
        }
    }
}
