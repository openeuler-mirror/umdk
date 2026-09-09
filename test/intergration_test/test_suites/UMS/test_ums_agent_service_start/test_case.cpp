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
    int ums_refer_cnt_before = 0;
    int ums_refer_cnt_after = 0;
    int ums_refer_cnt_diff = 0;
    ums_refer_cnt_before = query_ums_reference_count();
    if (ctx->app_id == PROC_1) {
        char buf0[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf0, MAX_EXEC_CMD_RET_LEN, "service ums_agent restart 2>&1");
        if (strcmp(buf0, "Redirecting to /bin/systemctl restart ums_agent.service\n") != NULL) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "para num name error", EXIT);
    }
    if (ctx->app_id == PROC_2) {
        char buf1[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf1, MAX_EXEC_CMD_RET_LEN, "service ums_agent restart 2>&1");
        if (strcmp(buf1, "Redirecting to /bin/systemctl restart ums_agent.service\n") != NULL) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "para num name error", EXIT);
    }
    ums_refer_cnt_after = query_ums_reference_count();
    ums_refer_cnt_diff = ums_refer_cnt_after - ums_refer_cnt_before;
    if (ums_refer_cnt_diff != 0) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "reference count didn't return to 0", EXIT);
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