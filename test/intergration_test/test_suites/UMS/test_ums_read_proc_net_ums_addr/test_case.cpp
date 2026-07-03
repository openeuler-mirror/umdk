/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
 */

#include "../public.h"
#include <string>

using namespace std;

static int run_test(test_ums_ctx_t *ctx)
{
    int ret = 0;
    int rc = TEST_FAILED;
    // char setup_env[MAX_EXEC_CMD_RET_LEN];
    int check_num_ums;
    int check_num_fallback;
    char test_ip_str[128]={0};
    char proc_net_ums6[MAX_EXEC_CMD_RET_LEN];
    char proc_net_ums[MAX_EXEC_CMD_RET_LEN];
    char close_qperf[MAX_EXEC_CMD_RET_LEN];
    char recover_env[MAX_EXEC_CMD_RET_LEN];
    char check_perf[MAX_EXEC_CMD_RET_LEN];

    exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
    // exec_cmd(setup_env, MAX_EXEC_CMD_RET_LEN, "rmmod ums; modprobe ums; service ums_agent restart");
    sleep(3);
    sync_time("----------------------------0");

    if (ctx->app_id == PROC_1) {
        char buf0[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf0, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf -lp %d > /tmp/qperf_server0.log 2>&1 &", ctx->test_port + 1);
        char buf1[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf1, MAX_EXEC_CMD_RET_LEN, "nohup qperf -lp %d > /tmp/qperf_server1.log 2>&1 &", ctx->test_port + 2);
        sleep(3);
        exec_cmd(proc_net_ums6, MAX_EXEC_CMD_RET_LEN, "cat /proc/net/ums6");
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_2) {
        char buf2[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf2, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf %s -lp %d -t 0 -m 8192 tcp_lat > /tmp/qperf_client0.log 2>&1 &", ctx->test_ip, ctx->test_port + 1);
        char buf3[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf3, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf %s -lp %d -t 0 -m 8192 tcp_lat > /tmp/qperf_client1.log 2>&1 &", ctx->test_ip, ctx->test_port + 2);
        sleep(3);
        exec_cmd(proc_net_ums, MAX_EXEC_CMD_RET_LEN, "cat /proc/net/ums");
    }
    sleep(10);
    sync_time("----------------------------2");
    sprintf(test_ip_str, "%s", ctx->test_ip_host2);
    check_num_ums = query_proc_net_ums_detail_stream_num("False", test_ip_str);
    if (ctx->app_id == PROC_2 && check_num_ums < 1) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "ums connection error", EXIT);
    // check_num_fallback = query_proc_net_ums_detail_stream_num("True", test_ip_str);
    // if (ctx->app_id == PROC_2 && check_num_fallback != 2) {
    //     ret = -1;
    // }
    // CHKERR_JUMP(ret != TEST_SUCCESS, "fallback connection error", EXIT);

    sync_time("----------------------------3");
    exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
    sleep(2);
    exec_cmd(check_perf, MAX_EXEC_CMD_RET_LEN, "ps -ef|grep qperf");
    rc = TEST_SUCCESS;
EXIT:
    sync_time("----------------------------4");
    return rc;
}

int main(int argc, char *argv[]) {
    int ret;
    test_ums_ctx_t *ctx = test_ums_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    destroy_test_ums_ctx(ctx);
    return ret;
}