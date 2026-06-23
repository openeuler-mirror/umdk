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
    char ret_buf_0[128];
    char ret_buf_1[128];

    if (ctx->app_id == PROC_1) {
        char buf0[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf0, MAX_EXEC_CMD_RET_LEN, "service ums_agent restart");
        strcpy(ret_buf_0, buf0);
        if (strcmp(ret_buf_0, "Redirecting to /bin/systemctl restart ums_agent.service") != 0) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "para num name error", EXIT);
    }
    if (ctx->app_id == PROC_2) {
        char buf1[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf1, MAX_EXEC_CMD_RET_LEN, "service ums_agent restart");
        strcpy(ret_buf_1, buf1);
        if (strcmp(ret_buf_1, "Redirecting to /bin/systemctl restart ums_agent.service") != 0) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "para num name error", EXIT);
    }
    sync_time("----------------------------1");

    rc = TEST_SUCCESS;
EXIT:
    sync_time("----------------------------2");
    return rc;
}

int main(int argc, char *argv[]) {
    int ret;
    test_ums_ctx_t *ctx = test_ums_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    destroy_test_ums_ctx(ctx);
    return ret;
}