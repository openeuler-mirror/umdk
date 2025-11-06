/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perftest latency test case
 * Create: 2025-8-29
 */

#include <math.h>
#include <unistd.h>

#include "ub_get_clock.h"

#include "umq_api.h"
#include "umq_pro_api.h"

#include "perftest_latency.h"
#include "umq_perftest_latency.h"

#define LATENCY_MEASURE_TAIL 2

perftest_latency_ctx_t g_perftest_latency_ctx = {0};

static void set_pro_data(umq_buf_t *tmp, umq_perftest_latency_arg_t *lat_arg)
{
    while (tmp) {
        umq_buf_pro_t *pro = (umq_buf_pro_t *)tmp->qbuf_ext;
        pro->flag.value = 0;
        pro->flag.bs.solicited_enable = 1;
        pro->flag.bs.complete_enable = 1;
        if (lat_arg->cfg->config.size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        pro->opcode = UMQ_OPC_SEND;
        tmp = tmp->qbuf_next;
    }
}

perftest_latency_ctx_t *get_perftest_latency_ctx(void)
{
    return &g_perftest_latency_ctx;
}

static void umq_perftest_client_run_latency_finish(umq_perftest_latency_arg_t *lat_arg)
{
    LOG_PRINT("--------------------------------latency info---------------------------------\n");
    perftest_calculate_latency(
        g_perftest_latency_ctx.cycles, g_perftest_latency_ctx.iters, lat_arg->cfg->config.size, SEND_LATENCY_MODE);

    free(g_perftest_latency_ctx.cycles);
    g_perftest_latency_ctx.cycles = NULL;
}

static void umq_perftest_server_run_latency_base_interrupt(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    umq_buf_t *bad_buf = NULL;
    uint32_t size = lat_arg->cfg->config.size;
    uint32_t test_round = lat_arg->cfg->test_round;
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    umq_buf_t *polled_buf = NULL;
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    while (g_perftest_latency_ctx.iters < test_round && !is_perftest_force_quit()) {
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }
        // recv req
        do {
            polled_buf = umq_dequeue(umqh);
            if (errno != 0) {
                LOG_PRINT("umq dequeue failed, errno %d\n", errno);
                goto FINISH;
            }
        } while (polled_buf == NULL && !is_perftest_force_quit());
        if (!buf_multiplex) {
            umq_buf_free(polled_buf);
            polled_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (polled_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }

        // send return
        int ret = umq_enqueue(umqh, polled_buf, &bad_buf);
        if (ret == -EAGAIN) {
            continue;
        }
        if (ret != UMQ_SUCCESS) {
            LOG_PRINT("enqueue failed\n");
            if (bad_buf != NULL) {
                umq_buf_free(bad_buf);
                bad_buf = NULL;
            }
            goto FINISH;
        }
        umq_notify(umqh);
        g_perftest_latency_ctx.iters++;
    }

FINISH:
    perftest_force_quit();
}

static void umq_perftest_server_run_latency_base_polling(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    umq_buf_t *polled_buf = NULL;
    umq_buf_t *bad_buf = NULL;
    uint32_t size = lat_arg->cfg->config.size;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    while (g_perftest_latency_ctx.iters < lat_arg->cfg->test_round && !is_perftest_force_quit()) {
        // recv req
        do {
            polled_buf = umq_dequeue(umqh);
            if (errno != 0) {
                LOG_PRINT("umq dequeue failed, errno %d\n", errno);
                goto FINISH;
            }
        } while (polled_buf == NULL && !is_perftest_force_quit());
        if (!buf_multiplex) {
            // send return
            umq_buf_free(polled_buf);
            polled_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (polled_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }
        if (umq_enqueue(umqh, polled_buf, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("enqueue failed\n");
            if (bad_buf != NULL) {
                umq_buf_free(bad_buf);
            }
            goto FINISH;
        }

        g_perftest_latency_ctx.iters++;
    }

FINISH:
    perftest_force_quit();
}

static void umq_perftest_server_run_latency_base(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    if (lat_arg->cfg->config.interrupt) {
        umq_perftest_server_run_latency_base_interrupt(umqh, lat_arg);
    } else {
        umq_perftest_server_run_latency_base_polling(umqh, lat_arg);
    }
}

static void umq_perftest_client_run_latency_base_interrupt(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    uint32_t test_round = lat_arg->cfg->test_round;
    g_perftest_latency_ctx.cycles = (uint64_t *)malloc(sizeof(uint64_t) * test_round);
    if (g_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("alloc cycles failed\n");
        return;
    }

    umq_buf_t *polled_buf;
    umq_buf_t *bad_buf = NULL;
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    uint32_t size = lat_arg->cfg->config.size;
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    while (g_perftest_latency_ctx.iters < test_round && !is_perftest_force_quit()) {
        umq_buf_t *req_buf = umq_buf_alloc(size, 1, umqh, NULL);
        if (req_buf == NULL) {
            LOG_PRINT("alloc buf failed\n");
            goto FINISH;
        }

        // send req
        start_cycle = get_cycles();
        int ret = umq_enqueue(umqh, req_buf, &bad_buf);
        if (ret == -EAGAIN) {
            continue;
        }
        if (ret != UMQ_SUCCESS) {
            umq_buf_free(bad_buf);
            bad_buf = NULL;
            LOG_PRINT("umq_enqueue failed\n");
            goto FINISH;
        }
        umq_notify(umqh);

        // recv return
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }
        do {
            polled_buf = umq_dequeue(umqh);
            if (errno != 0) {
                LOG_PRINT("umq dequeue failed, errno %d\n", errno);
                goto FINISH;
            }
        } while (polled_buf == NULL && !is_perftest_force_quit());

        end_cycle = get_cycles();

        umq_buf_free(polled_buf);
        g_perftest_latency_ctx.cycles[g_perftest_latency_ctx.iters++] = end_cycle - start_cycle;
    }

FINISH:
    umq_perftest_client_run_latency_finish(lat_arg);
    perftest_force_quit();
}

static void umq_perftest_client_run_latency_base_polling(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    g_perftest_latency_ctx.cycles = (uint64_t *)malloc(sizeof(uint64_t) * lat_arg->cfg->test_round);
    if (g_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("alloc cycles failed\n");
        return;
    }

    umq_buf_t *polled_buf = NULL;
    umq_buf_t *bad_buf = NULL;
    uint32_t size = lat_arg->cfg->config.size;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    umq_buf_t *req_buf = umq_buf_alloc(size, 1, umqh, NULL);
    if (req_buf == NULL) {
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    while (g_perftest_latency_ctx.iters < lat_arg->cfg->test_round && !is_perftest_force_quit()) {
        // send req
        start_cycle = get_cycles();
        if (umq_enqueue(umqh, req_buf, &bad_buf) != UMQ_SUCCESS) {
            umq_buf_free(bad_buf);
            bad_buf = NULL;
            LOG_PRINT("umq_enqueue failed\n");
            goto FINISH;
        }

        // recv return
        do {
            polled_buf = umq_dequeue(umqh);
            if (errno != 0) {
                LOG_PRINT("umq dequeue failed, errno %d\n", errno);
                goto FINISH;
            }
        } while (polled_buf == NULL && !is_perftest_force_quit());
        if (buf_multiplex) {
            req_buf = polled_buf;
        } else {
            umq_buf_free(polled_buf);
            req_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (req_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }
        end_cycle = get_cycles();
        g_perftest_latency_ctx.cycles[g_perftest_latency_ctx.iters++] = end_cycle - start_cycle;
    }
    if (buf_multiplex) {
        umq_buf_free(req_buf);
    }
FINISH:
    umq_perftest_client_run_latency_finish(lat_arg);
    perftest_force_quit();
}

static void umq_perftest_client_run_latency_base(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    if (lat_arg->cfg->config.interrupt) {
        umq_perftest_client_run_latency_base_interrupt(umqh, lat_arg);
    } else {
        umq_perftest_client_run_latency_base_polling(umqh, lat_arg);
    }
}

static int process_flow_control_buf(uint64_t umqh, umq_buf_t *buf)
{
    if (!(buf->io_direction == UMQ_IO_RX && buf->status == UMQ_BUF_FLOW_CONTROL_UPDATE && buf->total_data_size == 0)) {
        return 1;
    }

    if (umq_buf_reset(buf) != UMQ_SUCCESS) {
        LOG_PRINT("reset rx buf failed\n");
        return -1;
    }

    umq_buf_t *bad_buf = NULL;
    if (umq_post(umqh, buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
        LOG_PRINT("post rx failed\n");
        return -1;
    }

    // ignore flow control qbuf
    return 0;
}

static void umq_perftest_server_run_latency_pro_polling(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    // perpare to return data
    uint32_t size = lat_arg->cfg->config.size;
    umq_buf_t *resp_buf = umq_buf_alloc(size, 1, umqh, NULL);
    if (resp_buf == NULL) {
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    umq_buf_t *tmp = resp_buf;
    set_pro_data(tmp, lat_arg);
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    umq_buf_t *bad_buf = NULL;
    uint32_t send_cnt = 0;
    uint32_t recv_cnt = 0;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    umq_buf_t *rx_buf;
    while (g_perftest_latency_ctx.iters < lat_arg->cfg->test_round && !is_perftest_force_quit()) {
        recv_cnt = 0;

        // recv req, release rx
        do {
            int ret = umq_poll(umqh, UMQ_IO_ALL, &rx_buf, 1);
            if (ret < 0) {
                LOG_PRINT("poll rx failed\n");
                goto FINISH;
            }

            if (ret == 1) {
                ret = process_flow_control_buf(umqh, rx_buf);
                if (ret < 0) {
                    goto FINISH;
                }
            }

            recv_cnt += (uint32_t)ret;
        } while (recv_cnt < 1 && !is_perftest_force_quit());

        if (!buf_multiplex) {
            umq_buf_free(rx_buf);
            rx_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }

        // fill rx
        if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post rx failed\n");
            goto FINISH;
        }

        // send return
        if (umq_post(umqh, resp_buf, UMQ_IO_TX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post tx failed\n");
            goto FINISH;
        }

        // poll tx cqe. tx buffer reuse, no release
        send_cnt = 0;
        do {
            int ret = umq_poll(umqh, UMQ_IO_ALL, polled_buf, 1);
            if (ret < 0) {
                LOG_PRINT("umq_poll failed\n");
                goto FINISH;
            }

            if (ret == 1) {
                ret = process_flow_control_buf(umqh, polled_buf[0]);
                if (ret < 0) {
                    umq_buf_free(polled_buf[0]);
                    goto FINISH;
                }
            }

            send_cnt += (uint32_t)ret;
        } while (send_cnt != 1 && !is_perftest_force_quit());

        g_perftest_latency_ctx.iters++;
    }

FINISH:
    umq_buf_free(resp_buf);
    umq_buf_free(rx_buf);
    umq_buf_free(bad_buf);
    perftest_force_quit();
}

static void umq_perftest_server_run_latency_pro_interrupt(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    // perpare to return data
    uint32_t size = lat_arg->cfg->config.size;
    umq_buf_t *resp_buf = umq_buf_alloc(size, 1, umqh, NULL);
    if (resp_buf == NULL) {
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    umq_buf_t *tmp = resp_buf;
    set_pro_data(tmp, lat_arg);

    umq_buf_t *polled_buf = NULL;
    umq_buf_t *bad_buf = NULL;
    uint32_t send_cnt = 0;
    uint32_t recv_cnt = 0;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    uint32_t test_round = lat_arg->cfg->test_round;
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    umq_interrupt_option_t tx_interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    if (umq_rearm_interrupt(umqh, false, &tx_interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    umq_buf_t *rx_buf;
    int ret = 0;
    while (g_perftest_latency_ctx.iters < test_round && !is_perftest_force_quit()) {
        // recv req, release rx
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }

        recv_cnt = 0;
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, &rx_buf, 1);
            if (ret < 0) {
                LOG_PRINT("umq poll rx failed, ret %d\n", ret);
                goto FINISH;
            }

            if (ret == 1) {
                ret = process_flow_control_buf(umqh, rx_buf);
                if (ret < 0) {
                    goto FINISH;
                }
            }

            recv_cnt += (uint32_t)ret;
        } while (recv_cnt < 1 && !is_perftest_force_quit());

        if (!buf_multiplex) {
            umq_buf_free(rx_buf);
            rx_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }

        // fill rx
        if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post rx failed\n");
            umq_buf_free(bad_buf);
            bad_buf = NULL;
            goto FINISH;
        }

        // send return
        if (umq_post(umqh, resp_buf, UMQ_IO_TX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post tx failed\n");
            goto FINISH;
        }
        umq_notify(umqh);

        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &tx_interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &tx_interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &tx_interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }

        // poll tx cqe. tx buffer reuse, no release
        send_cnt = 0;
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, &polled_buf, 1);
            if (ret < 0) {
                LOG_PRINT("umq poll tx failed, ret %d\n", ret);
                goto FINISH;
            }
            if (ret == 1) {
                ret = process_flow_control_buf(umqh, polled_buf);
                if (ret < 0) {
                    goto FINISH;
                }
            }

            send_cnt += (uint32_t)ret;
        } while (send_cnt != 1 && !is_perftest_force_quit());
        g_perftest_latency_ctx.iters++;
    }

FINISH:
    umq_buf_free(rx_buf);
    umq_buf_free(resp_buf);
    umq_buf_free(bad_buf);
    perftest_force_quit();
}

static void umq_perftest_server_run_latency_pro(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    if (lat_arg->cfg->config.interrupt) {
        umq_perftest_server_run_latency_pro_interrupt(umqh, lat_arg);
    } else {
        umq_perftest_server_run_latency_pro_polling(umqh, lat_arg);
    }
}

static void umq_perftest_client_run_latency_pro_polling(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    uint64_t start_cycle = 0;
    uint32_t size = lat_arg->cfg->config.size;
    g_perftest_latency_ctx.cycles = (uint64_t *)malloc(sizeof(uint64_t) * lat_arg->cfg->test_round);
    if (g_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("alloc cycles failed\n");
        return;
    }

    // preparing req data. tx buffer reuse
    umq_buf_t *req_buf = umq_buf_alloc(size, 1, umqh, NULL);
    if (req_buf == NULL) {
        free(g_perftest_latency_ctx.cycles);
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    int ret;
    umq_buf_t *tmp = req_buf;
    set_pro_data(tmp, lat_arg);
    umq_buf_t *polled_buf[UMQ_BATCH_SIZE];
    umq_buf_t *bad_buf = NULL;
    uint32_t send_cnt = 0;
    uint32_t recv_cnt = 0;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    umq_buf_t *rx_buf;
    while (g_perftest_latency_ctx.iters < lat_arg->cfg->test_round && !is_perftest_force_quit()) {
        send_cnt = 0;
        // send req
        start_cycle = get_cycles();
        ret = umq_post(umqh, req_buf, UMQ_IO_TX, &bad_buf);
        if (ret != UMQ_SUCCESS) {
            if (ret == -UMQ_ERR_EAGAIN) {
                ret = umq_poll(umqh, UMQ_IO_ALL, polled_buf, 1);
                if (ret == 0) {
                    continue;
                } else if (ret == 1 && process_flow_control_buf(umqh, polled_buf[0]) == 0) {
                    continue;
                } else {
                    umq_buf_free(polled_buf[0]);
                    LOG_PRINT("umq_poll faield, ret %d\n", ret);
                    goto FINISH;
                }
            }
            LOG_PRINT("post tx failed\n");
            goto FINISH;
        }

        // poll tx cqe. tx buffer reuse, no release
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, polled_buf, 1);
            if (ret < 0) {
                LOG_PRINT("poll tx failed\n");
                goto FINISH;
            }
            if (ret == 1) {
                ret = process_flow_control_buf(umqh, polled_buf[0]);
                if (ret < 0) {
                    umq_buf_free(polled_buf[0]);
                    goto FINISH;
                }
            }
            send_cnt += (uint32_t)ret;
        } while (send_cnt != 1 && !is_perftest_force_quit());

        // recv return, release rx
        recv_cnt = 0;
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, &rx_buf, 1);
            if (ret < 0) {
                LOG_PRINT("poll rx failed\n");
                goto FINISH;
            }
            if (ret == 1) {
                ret = process_flow_control_buf(umqh, rx_buf);
                if (ret < 0) {
                    goto FINISH;
                }
            }
            recv_cnt += (uint32_t)ret;
        } while (recv_cnt < 1 && !is_perftest_force_quit());

        if (!buf_multiplex) {
            umq_buf_free(rx_buf);
            rx_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }

        // fill rx
        if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post rx failed\n");
            umq_buf_free(bad_buf);
            goto FINISH;
        }

        g_perftest_latency_ctx.cycles[g_perftest_latency_ctx.iters++] = get_cycles() - start_cycle;
    }

FINISH:
    umq_perftest_client_run_latency_finish(lat_arg);
    umq_buf_free(rx_buf);
    umq_buf_free(req_buf);
    perftest_force_quit();
}

static void umq_perftest_client_run_latency_pro_interrupt(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    uint64_t start_cycle = 0;
    uint32_t test_round = lat_arg->cfg->test_round;
    g_perftest_latency_ctx.cycles = (uint64_t *)malloc(sizeof(uint64_t) * test_round);
    if (g_perftest_latency_ctx.cycles == NULL) {
        LOG_PRINT("alloc cycles failed\n");
        return;
    }

    // preparing req data. tx buffer reuse
    uint32_t size = lat_arg->cfg->config.size;
    umq_buf_t *req_buf = umq_buf_alloc(size, 1, umqh, NULL);
    if (req_buf == NULL) {
        free(g_perftest_latency_ctx.cycles);
        LOG_PRINT("alloc buf failed\n");
        return;
    }

    umq_buf_t *tmp = req_buf;
    set_pro_data(tmp, lat_arg);

    umq_buf_t *polled_buf = NULL;
    umq_buf_t *bad_buf = NULL;
    umq_buf_t *rx_buf;
    uint32_t send_cnt = 0;
    uint32_t recv_cnt = 0;
    bool buf_multiplex = lat_arg->cfg->config.buf_multiplex;
    umq_interrupt_option_t interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_RX,
    };
    umq_interrupt_option_t tx_interrupt_option = {
        .flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION,
        .direction = UMQ_IO_TX,
    };
    if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    if (umq_rearm_interrupt(umqh, false, &tx_interrupt_option) != 0) {
        LOG_PRINT("umq_rearm_interrupt failed\n");
        goto FINISH;
    }
    int ret = 0;
    while (g_perftest_latency_ctx.iters < test_round && !is_perftest_force_quit()) {
        send_cnt = 0;
        // send req
        start_cycle = get_cycles();
        ret = umq_post(umqh, req_buf, UMQ_IO_TX, &bad_buf);
        if (ret != UMQ_SUCCESS) {
            if (ret == -UMQ_ERR_EAGAIN) {
                ret = umq_poll(umqh, UMQ_IO_ALL, &polled_buf, 1);
                if (ret == 0) {
                    continue;
                } else if (ret == 1 && process_flow_control_buf(umqh, polled_buf) == 0) {
                    continue;
                } else {
                    umq_buf_free(polled_buf);
                    goto FINISH;
                }
            }
            LOG_PRINT("post tx failed\n");
            goto FINISH;
        }
        umq_notify(umqh);

        // poll tx cqe. tx buffer reuse, no release
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &tx_interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &tx_interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &tx_interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, &polled_buf, 1);
            if (ret < 0) {
                LOG_PRINT("umq poll tx failed, ret %d\n", ret);
                goto FINISH;
            }
            if (ret == 1) {
                ret = process_flow_control_buf(umqh, polled_buf);
                if (ret < 0) {
                    umq_buf_free(polled_buf);
                    goto FINISH;
                }
            }
            send_cnt += (uint32_t)ret;
        } while (send_cnt != 1 && !is_perftest_force_quit());

        // recv return, release rx
        if (umq_wait_interrupt(umqh, INTERRUPT_MAX_WAIT_TIME_MS, &interrupt_option) != 1) {
            LOG_PRINT("umq_wait_interrupt failed\n");
            goto FINISH;
        }
        umq_ack_interrupt(umqh, 1, &interrupt_option);
        if (umq_rearm_interrupt(umqh, false, &interrupt_option) != 0) {
            LOG_PRINT("umq_rearm_interrupt failed\n");
            goto FINISH;
        }

        recv_cnt = 0;
        do {
            ret = umq_poll(umqh, UMQ_IO_ALL, &rx_buf, 1);
            if (ret < 0) {
                LOG_PRINT("umq poll rx failed, ret %d\n", ret);
                goto FINISH;
            }
            if (ret == 1) {
                ret = process_flow_control_buf(umqh, rx_buf);
                if (ret < 0) {
                    goto FINISH;
                }
            }
            recv_cnt += (uint32_t)ret;
        } while (recv_cnt < 1 && !is_perftest_force_quit());

        if (!buf_multiplex) {
            umq_buf_free(rx_buf);
            rx_buf = umq_buf_alloc(size, 1, umqh, NULL);
            if (rx_buf == NULL) {
                LOG_PRINT("alloc buf failed\n");
                goto FINISH;
            }
        }

        // fill rx
        if (umq_post(umqh, rx_buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post rx failed\n");
            umq_buf_free(bad_buf);
            goto FINISH;
        }

        g_perftest_latency_ctx.cycles[g_perftest_latency_ctx.iters++] = get_cycles() - start_cycle;
    }

FINISH:
    umq_perftest_client_run_latency_finish(lat_arg);
    umq_buf_free(req_buf);
    umq_buf_free(rx_buf);
    perftest_force_quit();
}

static void umq_perftest_client_run_latency_pro(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    if (lat_arg->cfg->config.interrupt) {
        umq_perftest_client_run_latency_pro_interrupt(umqh, lat_arg);
    } else {
        umq_perftest_client_run_latency_pro_polling(umqh, lat_arg);
    }
}

void umq_perftest_run_latency(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg)
{
    if (lat_arg->cfg->config.instance_mode == PERF_INSTANCE_SERVER) {
        if (lat_arg->cfg->feature & UMQ_FEATURE_API_PRO) {
            umq_perftest_server_run_latency_pro(umqh, lat_arg);
        } else {
            umq_perftest_server_run_latency_base(umqh, lat_arg);
        }
    } else {
        if (lat_arg->cfg->feature & UMQ_FEATURE_API_PRO) {
            umq_perftest_client_run_latency_pro(umqh, lat_arg);
        } else {
            umq_perftest_client_run_latency_base(umqh, lat_arg);
        }
    }
}
