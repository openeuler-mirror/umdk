/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: ums app
*/
#include "ums_atom.h"
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>

test_ums_ctx_t g_test_ums_ctx;

test_ums_ctx_t *test_ums_ctx_init(int argc, char *argv[], int thread_num)
{
    (void)memset(&g_test_ums_ctx, 0, sizeof(test_ums_ctx_t));
    pid_t pid = getpid();
    g_test_ums_ctx.pid = (uint64_t)pid;
    test_context *ctx = create_test_ctx(argc, argv, thread_num);
    if (ctx == nullptr) {
        TEST_LOG_ERROR("create_test_ctx failed\n");
        return nullptr;
    }
    g_test_ums_ctx.ctx = ctx;
    g_test_ums_ctx.app_id = ctx->app_id;
    g_test_ums_ctx.app_num = ctx->app_num;
    g_test_ums_ctx.test_port = ctx->test_port;
    g_test_ums_ctx.test_ip = ctx->test_ip[0];
    g_test_ums_ctx.test_ip_host2 = ctx->test_ip[1];
    g_test_ums_ctx.log_level = 4;
    g_test_ums_ctx.ssl_enable = false;
    g_test_ums_ctx.client_num = 1;
    return &g_test_ums_ctx;
}


int query_proc_net_ums_detail_stream_num(const char *fbk, const char *msg)
{
    char cmd[1024];
    exec_cmd(cmd, MAX_EXEC_CMD_RET_LEN, "cat /proc/net/ums | awk '/%s/ {if ($5==\"%s\") print $0}' | wc -l 2>&1", msg, fbk);

    return atoi(cmd);
}

void destroy_test_ums_ctx(test_ums_ctx_t *ctx)
{
    sock_disconnect();
    free_config();
    test_common_deinit();
}

int query_ums_reference_count()
{
    char cmd[1024];
    exec_cmd(cmd, MAX_EXEC_CMD_RET_LEN, "lsmod | grep ums | awk '{print $3}' | head -n 1");

    return atoi(cmd);
}

void exec_deploy_ums_agent(const char *host2ip)
{
    char getpath[1024];
    char execscript[1024];
    char cmd[1024];
    exec_cmd(getpath, MAX_EXEC_CMD_RET_LEN, "find / -name 'master_deploy_ums_agent.sh' | head -n 1");
    snprintf(execscript, "sudo sh -c 'chcon -t bin_t' %s 2>/dev/null; sh %s %s", getpath, getpath, host2ip);
    exec_cmd(cmd, MAX_EXEC_CMD_RET_LEN, execscript);
    sleep(5);
}

int is_ums_agent_running()
{
    char cmd[1024];
    char result[MAX_EXEC_CMD_RET_LEN] = {0};
    exec_cmd(cmd, MAX_EXEC_CMD_RET_LEN, "systemctl is-active ums_agent 2>/dev/null");
    std::string trimmed = cmd;
    size_t start = trimmed.find_first_not_of(" \t\r\n");
    size_t end = trimmed.find_last_not_of(" \t\r\n");
    trimmed = trimmed.substr(start, end - start + 1);
    if (trimmed.compare("active") != 0) {
        return -1;
    }
    return 0;
}