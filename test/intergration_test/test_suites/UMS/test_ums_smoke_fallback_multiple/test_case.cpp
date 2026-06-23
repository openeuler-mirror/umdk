/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
 */

#include "../public.h"
#include <set>
#include <string>

using namespace std;

static int run_test(test_ums_ctx_t *ctx)
{
    int ret = 0;
    int rc = TEST_FAILED;
    int check_num;
    char setup_env[MAX_EXEC_CMD_RET_LEN];
    char test_ip_str[128]={0};
    char close_qperf[MAX_EXEC_CMD_RET_LEN];

    exec_cmd(setup_env, MAX_EXEC_CMD_RET_LEN, "rmmod ums; modprobe ums; service ums_agent restart");

    sync_time("----------------------------0");

    if (ctx->app_id == PROC_1) {
        char serv_cmd[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(serv_cmd, MAX_EXEC_CMD_RET_LEN, "for i in $(seq %d %d); do nohup qperf -lp ${i} & done", ctx->test_port, ctx->test_port + 10);
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_2) {
        char clnt_cmd[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(clnt_cmd, MAX_EXEC_CMD_RET_LEN, "for i in $(seq %d %d); do nohup ums_run qperf %s -lp ${i} -m 8192 -t 0 tcp_bw 2>&1 & done", ctx->test_port, ctx->test_port + 10, ctx->test_ip);
    }
    sync_time("----------------------------2");
    
    // 校验流量走ums
    if (ctx->app_id == PROC_2) {
        sprintf(test_ip_str, "%d", ctx->test_ip);
        check_num = query_proc_net_ums_detail_stream_num("True", test_ip_str);
        if (check_num != 20) {
            ret = -1;
        }
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "fallback multiple connect failed", EXIT);

    exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
    rc = TEST_SUCCESS;
EXIT:
    sync_time("----------------------------3");
    return rc;
}

int main(int argc, char *argv[]) {
    int ret;
    test_ums_ctx_t *ctx = test_ums_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    destroy_test_ums_ctx(ctx);
    return ret;
}