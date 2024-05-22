/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdio.h>
#include <sys/socket.h>

#include "urma_api.h"

#include "perftest_parameters.h"
#include "perftest_communication.h"
#include "perftest_resources.h"
#include "perftest_run_test.h"

static int run_test(perftest_context_t *ctx, perftest_config_t *cfg)
{
    int ret = 0;
    ret = sync_time(cfg->comm.sock_fd, "Start test");
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to sync time, start test.\n");
        return ret;
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

    if (ret != 0) {
        (void)fprintf(stderr, "Failed to run test: %d.\n", (int)cfg->cmd);
        return ret;
    }

    ret = sync_time(cfg->comm.sock_fd, "End test");
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to sync time, End test.\n");
        return ret;
    }
    return ret;
}

static int rearm_jfc(perftest_context_t *ctx, const perftest_config_t *cfg)
{
    urma_status_t status;
    if (cfg->api_type == PERFTEST_WRITE) {
        return -1;
    }
    status = urma_rearm_jfc(ctx->jfc_s, false);
    if (status != URMA_SUCCESS) {
        (void)fprintf(stderr, "Couldn't rearm jfc_s\n");
        return -1;
    }
    if (cfg->api_type == PERFTEST_SEND) {
        status = urma_rearm_jfc(ctx->jfc_r, false);
        if (status != URMA_SUCCESS) {
            (void)fprintf(stderr, "Couldn't rearm jfc_r\n");
            return -1;
        }
    }
    return 0;
}

static int prepare_test(perftest_context_t *ctx, perftest_config_t *cfg)
{
    print_cfg(cfg);
    if (cfg->use_jfce == true) {
        if (rearm_jfc(ctx, cfg) != 0) {
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
    ret = establish_connection(&cfg.comm);
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
    ret = prepare_test(&ctx, &cfg);
    if (ret != 0) {
        goto destroy_ctx;
    }

    // Run test for each cmd
    ret = run_test(&ctx, &cfg);
    if (ret != 0) {
        goto destroy_ctx;
    }

destroy_ctx:
    destroy_ctx(&ctx, &cfg);
close_connect:
    if (cfg.check_alive_exited == 1) {
        /* Inform client if server failed due to timeout in send_bw test */
        ret = write_sync_data(cfg.comm.sock_fd, "Check alive exited");
        (void)shutdown(cfg.comm.sock_fd, SHUT_RDWR);
    }
    close_connection(&cfg.comm);
clean_cfg:
    destroy_cfg(&cfg);
    return ret;
}