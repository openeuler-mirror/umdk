/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: dlock example
 */

#include "../public.h"
using namespace dlock;
#define TEST_NUM 1000

static int run_test(test_dlock_ctx_t *ctx)
{
    int ret, rc = TEST_FAILED;
    int lock_id = 0;
    atomic_state lock_state = {0};
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, nullptr);
    int p_desc = ctx->app_id;
    struct lock_desc lock = {0};
    struct lock_request lock_req = {0};
    ret = test_server_prepare(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    sync_time("-------------------------- 1");
    ret = test_client_prepare(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_prepare", EXIT);
    sync_time("-------------------------- 2");
    lock.lock_type = DLOCK_ATOMIC;
    lock.lease_time = tv_start.tv_sec + 60000;
    lock.p_desc = (char *)(&p_desc);
    lock.len = 4;
    ret = test_get_lock(ctx->client_ids[0], &lock, &lock_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_get_lock", EXIT);
    sync_time("-------------------------- 3");
    for (int i = 0; i < TEST_NUM; i++) {
        TEST_LOG_INFO("[i:%d] start\n",i);
        lock_req.lock_id = lock_id;
        lock_req.lock_op = LOCK_EXCLUSIVE;
        lock_req.expire_time  = DLOCK_MAX_EXPIRE_TIMEOUT;
        ret = test_trylock(ctx->client_ids[0], &lock_req, (void *)&lock_state);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_trylock", EXIT);
        lock_req.lock_id = lock_id;
        lock_req.lock_op = EXTEND_LOCK_EXCLUSIVE;
        lock_req.expire_time  = 0;
        ret = test_extend(ctx->client_ids[0], &lock_req, (void *)&lock_state);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_extend", EXIT);
        ret = test_unlock(ctx->client_ids[0], lock_id, (void *)&lock_state);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_unlock", EXIT);
        TEST_LOG_INFO("[i:%d] end\n",i);
    }
    ret = release_lock(ctx->client_ids[0], lock_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "release_lock", EXIT);
    rc = TEST_SUCCESS;
EXIT:
    sync_time("-------------------------- 4");
    return rc;
}


int main(int argc, char *argv[])
{
    int ret;
    test_dlock_ctx_t *ctx = test_dlock_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    ret += test_dlock_ctx_uninit(ctx);
    return ret;
}