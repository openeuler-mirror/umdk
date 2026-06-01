/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdio.h>

#include "urma_api.h"

#include "perftest_communication.h"
#include "perftest_parameters.h"
#include "perftest_resources.h"
#include "perftest_run_test.h"

typedef struct context_cfg {
    perftest_context_t *ctx;
    perftest_config_t *cfg;
} context_cfg_t;

static int run_test(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = 0;
    uint32_t i = 0;

    for (i = 0; i < cfg->pair_num; i++) {
        ret = sync_time(cfg->comm.sock_fd[i], "Start test");
        if (ret != 0) {
            LOG_ERROR("Failed to sync time, start test.\n");
            return ret;
        }
    }

    switch (cfg->cmd) {
        case PERFTEST_READ_LAT:
            ret = run_read_lat(ctx, cfg);
            break;
        case PERFTEST_WRITE_LAT:
            ret = run_write_lat(ctx, cfg);
            break;
        case PERFTEST_SEND_LAT:
            ret = run_send_lat(ctx, cfg);
            break;
        case PERFTEST_ATOMIC_LAT:
            ret = run_atomic_lat(ctx, cfg);
            break;
        case PERFTEST_READ_BW:
            ret = run_read_bw(ctx, cfg);
            break;
        case PERFTEST_WRITE_BW:
            ret = run_write_bw(ctx, cfg);
            break;
        case PERFTEST_SEND_BW:
            ret = run_send_bw(ctx, cfg);
            break;
        case PERFTEST_ATOMIC_BW:
            ret = run_atomic_bw(ctx, cfg);
            break;
        default:
            break;
    }

    if (cfg->type == PERFTEST_BW && cfg->enable_write_dirty == true) {
        cfg->enable_write_dirty = false; /* close the write dirty thread. */
        (void)pthread_join(ctx->write_dirty_thread_id, NULL);
    }

    if (ret != 0) {
        LOG_ERROR("Failed to run test: %d.\n", (int)cfg->cmd);
        return ret;
    }

    for (i = 0; i < cfg->pair_num; i++) {
        ret = sync_time(cfg->comm.sock_fd[i], "End test");
        if (ret != 0) {
            LOG_ERROR("Failed to sync time, End test.\n");
            return ret;
        }
    }
    return ret;
}

static int rearm_jfc(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    urma_status_t status;
    if (cfg->api_type == PERFTEST_WRITE) {
        return -1;
    }
    for (uint32_t i = 0; i < cfg->jettys; i++) {
        status = urma_rearm_jfc(ctx->jfc_s[i], false);
        if (status != URMA_SUCCESS) {
            LOG_ERROR("Couldn't rearm jfc_s %u\n", i);
            return -1;
        }
        if (cfg->api_type == PERFTEST_SEND) {
            status = urma_rearm_jfc(ctx->jfc_r[i], false);
            if (status != URMA_SUCCESS) {
                LOG_ERROR("Couldn't rearm jfc_r %u\n", i);
                return -1;
            }
        }
        if (cfg->pair_flag == false || cfg->type == PERFTEST_BW) {
            break;
        }
    }
    return 0;
}

static void *write_dirty_thread(void *args)
{
    context_cfg_t *ctx_cfg = (context_cfg_t *)args;
    perftest_context_t *ctx = ctx_cfg->ctx;
    perftest_config_t *cfg = ctx_cfg->cfg;

    while (cfg->enable_write_dirty == true && cfg->write_dirty_period >= PERFTEST_DEF_INF_PERIOD_MS) {
        int rand_num = rand() % PERFTEST_CHAR_MAX_VALUE;
        if (cfg->seg_pre_jetty == false) {
            char *str = (char *)ctx->local_buf[0] + ctx->buf_size * cfg->jettys;
            for (size_t i = 0; i < ctx->buf_size * cfg->jettys; i++) {
                str[i] = rand_num;
            }
        } else {
            for (uint32_t jetty = 0; jetty < cfg->jettys; jetty++) {
                char *str = (char *)ctx->local_buf[jetty] + ctx->buf_size;
                for (size_t i = 0; i < ctx->buf_size; i++) {
                    str[i] = rand_num;
                }
            }
        }
        usleep(cfg->write_dirty_period * PERFTEST_MSEC_TO_USEC);
    }
    return NULL;
}

static int prepare_test(perftest_context_t *ctx, perftest_config_t *cfg, context_cfg_t *args)
{
    print_cfg(cfg);
    if (cfg->use_jfce == true) {
        if (rearm_jfc(ctx, cfg) != 0) {
            return -1;
        }
    }

    if (cfg->type == PERFTEST_BW && cfg->enable_write_dirty == true) {
        if (pthread_create(&ctx->write_dirty_thread_id, NULL, write_dirty_thread, args) != 0) {
            LOG_ERROR("Failed to create write_dirty_thread.\n");
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    perftest_config_t cfg = {0}; /* cfg.server_ip shoule be initialized as NULL to avoid core dump */
    perftest_context_t ctx;
    context_cfg_t args;

    args.cfg = &cfg;
    args.ctx = &ctx;
    // Parse parameters and check for conflicts
    ret = perftest_parse_args(argc, argv, &cfg);
    if (ret != 0) {
        goto clean_cfg;
    }

    ret = check_local_cfg(&cfg);
    if (ret != 0) {
        goto clean_cfg;
    }

    // Establish connection between client and server
    ret = establish_connection(&cfg);
    if (ret != 0) {
        goto clean_cfg;
    }

    // Exchange configuration information and check
    ret = check_remote_cfg(&cfg);
    if (ret != 0) {
        goto close_connect;
    }

    // Create resource for test
    ret = create_ctx(&ctx, &cfg);
    if (ret != 0) {
        goto close_connect;
    }

    // Prepare the operation before the test. For example: print test information, create wr_ list.
    ret = prepare_test(&ctx, &cfg, &args);
    if (ret != 0) {
        goto destroy_ctx;
    }
    // Flush print from flowbuffer to output before starting test
    (void)fflush(stdout);

    // Run test for each cmd
    ret = run_test(&ctx, &cfg);
    if (ret != 0) {
        goto destroy_ctx;
    }

destroy_ctx:
    destroy_ctx(&ctx, &cfg);
close_connect:
    close_connection(&cfg);
clean_cfg:
    destroy_cfg(&cfg);
    return ret;
}
