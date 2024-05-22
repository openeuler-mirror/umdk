/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urma performance test for establish TP link
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2024-01-31   create file
 */

#include <stdio.h>
#include "urma_api.h"

#include "tp_test_para.h"
#include "tp_test_comm.h"
#include "tp_test_res.h"
#include "run_test.h"

static int prepare_test(tp_test_context_t *ctx, tp_test_config_t *cfg)
{
    print_cfg(cfg);
    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    tp_test_config_t *cfg = calloc(1, sizeof(tp_test_config_t));
    if (cfg == NULL) {
        return -1;
    }
    tp_test_context_t *ctx = calloc(1, sizeof(tp_test_context_t));
    if (ctx == NULL) {
        ret = -1;
        goto free_cfg;
    }

    // Parse parameters and check for conflicts
    ret = parse_args(argc, argv, cfg);
    if (ret != 0) {
        goto free_ctx;
    }

    ret = check_local_cfg(cfg);
    if (ret != 0) {
        goto free_ctx;
    }

    // Establish connection between client and server
    ret = establish_connection(cfg);
    if (ret != 0) {
        goto free_ctx;
    }

        // Exchange configuration information and check
    ret = check_remote_cfg(cfg);
    if (ret != 0) {
        goto close_connect;
    }

    // Create resource for test
    ret = create_ctx(ctx, cfg);
    if (ret != 0) {
        goto close_connect;
    }

    ret = prepare_test(ctx, cfg);
    if (ret != 0) {
        goto destroy_ctx;
    }

    ret = run_test(ctx, cfg);
    if (ret != 0) {
        goto destroy_ctx;
    }
destroy_ctx:
    destroy_ctx(ctx, cfg);
close_connect:
    close_connection(cfg);
free_ctx:
    free(ctx);
free_cfg:
    destroy_cfg(cfg);
    free(cfg);
    return ret;
}