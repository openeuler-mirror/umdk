/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
 */

#include "../public.h"
#include <vector>
#include <string>

using namespace std;

static int run_test(test_ums_ctx_t *ctx)
{
    char clnt_buf[2097152] = {0}, serv_buf[2097152] = {0};
    vector<int> vec_random = {131072, 262144, 524288, 1048576, 2097152, 4194304};
    int ret = 0;
    int rc = TEST_FAILED;
    char test_ip_str[128]={0};
    char setup_env[MAX_EXEC_CMD_RET_LEN];
    char close_qperf[MAX_EXEC_CMD_RET_LEN];

    exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
    exec_cmd(setup_env, MAX_EXEC_CMD_RET_LEN, "rmmod ums; modprobe ums; service ums_agent restart");

    sync_time("----------------------------0");

    for (int i=0; i<vec_random.size(); i++) {
        char cmd_revise_snd[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(cmd_revise_snd, MAX_EXEC_CMD_RET_LEN, "echo %d > /proc/sys/net/ums/snd_buf", vec_random[i]);
        char cmd_revise_rcv[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(cmd_revise_rcv, MAX_EXEC_CMD_RET_LEN, "echo %d > /proc/sys/net/ums/rcv_buf", vec_random[i]);

        if (ctx->app_id == PROC_1) {
            char cmd0[MAX_EXEC_CMD_RET_LEN];
            exec_cmd(cmd0, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf -lp %d > /tmp/qperf_server.log 2>&1 &", ctx->test_port + 1);

        }
        sync_time("----------------------------1");
        if (ctx->app_id == PROC_2) {
            char cmd1[MAX_EXEC_CMD_RET_LEN];
            exec_cmd(cmd1, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf %s -lp %d -t 0 -m 8192 tcp_lat > /tmp/qperf_client.log 2>&1 &", ctx->test_ip, ctx->test_port + 1);
        }
        sleep(2);
        sync_time("----------------------------2");
        sprintf(test_ip_str, "%s", ctx->test_ip_host2);
        int check_num = query_proc_net_ums_detail_stream_num("False", test_ip_str);
        if (ctx->app_id == PROC_2 && check_num < 1) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "ums connection error", EXIT);
        exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
        sleep(2);
    }

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