/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: dlock app
*/
#include "dlock_atom.h"
using namespace dlock;
test_dlock_ctx_t g_test_dlock_ctx;
bool g_is_qemu = false;

test_dlock_ctx_t *test_dlock_ctx_init(int argc, char *argv[], int thread_num)
{
    (void)memset(&g_test_dlock_ctx, 0, sizeof(test_dlock_ctx_t));
    pid_t pid = getpid();
    g_test_dlock_ctx.pid = (uint64_t)pid;
    test_context *ctx = create_test_ctx(argc, argv, thread_num);
    if (ctx == nullptr) {
        TEST_LOG_ERROR("create_test_ctx failed\n");
        return nullptr;
    }
    g_test_dlock_ctx.ctx = ctx;
    g_test_dlock_ctx.app_id = ctx->app_id;
    g_test_dlock_ctx.app_num = ctx->app_num;
    g_test_dlock_ctx.test_port = ctx->test_port;
    g_test_dlock_ctx.trans_mode = static_cast<trans_mode_t>(ctx->mode);
    if (ctx->mode == 0) {
        TEST_LOG_INFO("test_case trans_mode_t=%d is SEPERATE_CONN\n", ctx->mode);
    } else if (ctx->mode == 1) {
        TEST_LOG_INFO("test_case trans_mode_t=%d is UNI_CONN\n", ctx->mode);
    }
    g_test_dlock_ctx.log_level = 4;
    g_test_dlock_ctx.ssl_enable = false;
    g_test_dlock_ctx.client_num = 1;
    if (strncmp(ctx->test_ip[0], "192.168.100", 11) == 0) {
        g_is_qemu = true;
    }
    return &g_test_dlock_ctx;
}

int test_str_to_u32(const char*buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = nullptr;

    if (buf == nullptr || *buf == '-') {
        return TEST_FAILED;
    }
    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == EAGAIN && ret == ULONG_MAX) {
        return TEST_FAILED;
    }
    if (end == nullptr || *end != '\0' || end == buf) {
        return TEST_FAILED;
    }
    if (ret > UINT_MAX) {
        return TEST_FAILED;
    }
    *u32 = (uint32_t)ret;
    return TEST_SUCCESS;
}

void test_dlock_u32_to_eid(uint32_t ipv4, dlock_eid_t *eid) 
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(DLOCK_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int test_dlock_str_to_eid(const char *buf, dlock_eid_t *eid)
{
    int ret;
    uint32_t ipv4;
    TEST_LOG_INFO("dlock init eid=%s\n", buf);
    if (buf == nullptr || strlen(buf) < DLOCK_EID_STR_MIN_LEN || eid == nullptr) {
        TEST_LOG_ERROR("Invalid argument.\n");
        return TEST_FAILED;
    }

    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return TEST_SUCCESS;
    }

    if (inet_pton(AF_INET, buf, &ipv4) >0) {
        test_dlock_u32_to_eid(be32toh(ipv4), eid);
        return TEST_SUCCESS;
    }

    ret = test_str_to_u32(buf, &ipv4);
    if (ret == TEST_SUCCESS) {
        test_dlock_u32_to_eid(ipv4, eid);
        return TEST_SUCCESS;
    }

    TEST_LOG_ERROR("format error: %d.\n", buf);
    return TEST_FAILED;
}

void set_trans_eid(struct server_cfg *server_cfg, struct client_cfg *client_cfg, char *eid) 
{
    dlock_eid_t dlock_eid = {0};
    test_dlock_str_to_eid(eid, &dlock_eid);
    if (server_cfg) {
        (void)memcpy(&server_cfg->eid, &dlock_eid, sizeof(dlock_eid));
    }
    if (client_cfg) {
        (void)memcpy(&client_cfg->eid, &dlock_eid, sizeof(dlock_eid));
    }
}

void get_default_server_config(test_dlock_ctx_t *ctx, struct server_cfg *config)
{
    config->tp_mode = ctx->trans_mode;
    config->type = SERVER_PRIMARY;
    config->dev_name = ctx->ctx->device_name;
    config->primary.num_of_replica = 0;
    config->primary.replica_port = 0;
    config->primary.replica_enable = false;
    config->primary.server_port = ctx->test_port;
    config->log_level = ctx->log_level;
    set_trans_eid(config, nullptr, ctx->ctx->eid);
    config->ssl.ssl_enable = ctx->ssl_enable;
}

void get_default_client_config(test_dlock_ctx_t *ctx, struct client_cfg *config)
{
    config->tp_mode = ctx->trans_mode;
    config->dev_name = ctx->ctx->device_name;
    config->primary_port = ctx->test_port;
    set_trans_eid(nullptr, config, ctx->ctx->eid);
    config->log_level = ctx->log_level;
    config->ssl.ssl_enable = ctx->ssl_enable;
}

int test_dlock_server_init(test_dlock_ctx_t *ctx) 
{
    int ret = 0;
    unsigned int max_server_num = 10;
    struct server_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    get_default_server_config(ctx, &cfg);
    // It must be ensured that the passed CPU core exists in the environment; this can be checked with lscpu.
    char ctrl_cpuset[] = "0-2";
    char cmd_cpuset[] = "0-2";
    cfg.primary.ctrl_cpuset = ctrl_cpuset;
    cfg.primary.cmd_cpuset = cmd_cpuset;
    sync_time("-------------------------- 0");
    if (ctx->app_id == PROC_1) {
        ret = dserver_lib_init(max_server_num);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("dserver_lib_init ret = %d\n", ret);
            return TEST_FAILED;
        }
        cfg.primary.recovery_client_num = 0;
        TEST_LOG_INFO("ctx->ctx->test_ip[0] = %s\n", ctx->ctx->test_ip[0]);
        cfg.primary.server_ip_str = ctx->ctx->test_ip[0];
        ret = server_start(cfg, ctx->server_id);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("server start ret = %d\n", ret);
            dserver_lib_deinit();
            return TEST_FAILED;
        }
    }
    if (ctx->recovery_client_num) {
        if (ctx->app_id == PROC_2) {
            ret = dserver_lib_init(max_server_num);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("dserver_lib_init ret = %d\n", ret);
                return TEST_FAILED;
            }
        }
        TEST_LOG_INFO("ctx->ctx->test_ip[1] = %s\n", ctx->ctx->test_ip[1]);
        cfg.primary.server_ip_str = ctx->ctx->test_ip[1];
        cfg.primary.recovery_client_num = ctx->recovery_client_num;
        TEST_LOG_INFO("cfg.primary.recovery_client_num = %d\n", cfg.primary.recovery_client_num);
        ret = server_start(cfg, ctx->server_id);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("server start ret = %d\n", ret);
            dserver_lib_deinit();
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int test_dlock_server_uninit(test_dlock_ctx_t *ctx) 
{
    int ret = 0;
    if(ctx->app_id <= PROC_2) {
        if (ctx->server_id == 0) {
            return TEST_SUCCESS;
        }
        ret = server_stop(ctx->server_id);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("server stop ret = %d\n", ret);
            return TEST_FAILED;
        }
        dserver_lib_deinit();
    }
    return TEST_SUCCESS;
}

int test_dlock_client_init(test_dlock_ctx_t *ctx) 
{
    int ret;
    struct client_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    get_default_client_config(ctx, &cfg);
    ret = dclient_lib_init(&cfg);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("dclient_lib_init failed ret = %d\n", ret);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_client_init(test_dlock_ctx_t *ctx) 
{
    int ret;
    TEST_LOG_INFO("ctx->client_num=%u\n", ctx->client_num);
    if (ctx->client_num == 0) {
        return TEST_SUCCESS;
    }
    ctx->client_ids = (int *)calloc(ctx->client_num, sizeof(int));
    if (ctx->client_ids == nullptr) {
        TEST_LOG_ERROR("client_ids calloc failed\n");
        return TEST_FAILED;
    }
    uint32_t client_num = ctx->client_num;
    ctx->client_num = 0;
    for(int i = 0; i < client_num; i++) {
        ret = client_init(&ctx->client_ids[i], ctx->ctx->test_ip[0]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("client_id idx=%u failed\n", i);
        } else {
            ctx->client_num++;
        }
    }
    if (ctx->client_num == client_num) {
        return TEST_SUCCESS;
    }
    return TEST_FAILED;
}

int test_client_uninit(test_dlock_ctx_t *ctx)
{
    int ret;
    if (ctx->client_ids == nullptr) {
        return TEST_SUCCESS;
    }
    for(int i = 0; i < ctx->client_num; i++) {
        if (ctx->client_ids[i] == 0) {
            TEST_LOG_WARN("client_id %d is null\n", i);
            continue;
        }
        ret = client_deinit(ctx->client_ids[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("client_deinit ctx->ids[%d] %lu ret=%d\n", i, ctx->client_ids[i], ret);
            CHECK_FREE(ctx->client_ids);
            dclient_lib_deinit();
            return TEST_FAILED;
        }
    }
    CHECK_FREE(ctx->client_ids);
    dclient_lib_deinit();
    return TEST_SUCCESS;
}

int test_server_prepare(test_dlock_ctx_t *ctx) 
{
    int ret = 0, rc = TEST_FAILED;
    ret = test_dlock_server_init(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_dlock_client_init", EXIT);
    rc = TEST_SUCCESS;
EXIT:
    return rc;
}

int test_client_prepare(test_dlock_ctx_t *ctx)
{
    int ret = 0, rc = TEST_FAILED;
    ret = test_dlock_client_init(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_dlock_client_init", EXIT);
    ret = test_client_init(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_init", EXIT);
    rc = TEST_SUCCESS;
EXIT:
    return rc;
}

int test_dlock_client_uninit(test_dlock_ctx_t *ctx)
{
    if (!g_is_qemu) {
        return test_client_uninit(ctx);
    } else {
        test_client_uninit(ctx);
        return TEST_SUCCESS;
    }
}

int test_dlock_ctx_uninit(test_dlock_ctx_t *ctx) 
{
    int ret = 0;
    ret += test_dlock_client_uninit(ctx);
    sync_time("-------------------------- end");
    ret += test_dlock_server_uninit(ctx);
    CHECK_FREE(ctx->client_ids);
    destroy_test_ctx(g_test_dlock_ctx.ctx);
    return ret;
}

int test_dlock_atomic64_create_get(int client_id, struct umo_atomic64_desc *desc, uint64_t init_val, int *obj_id)
{
    int ret = 0, rc = TEST_FAILED;
    ret = umo_atomic64_create(client_id, desc, init_val, obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_create", EXIT);
    ret = umo_atomic64_get(client_id, desc, obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_get", EXIT);
    rc = TEST_SUCCESS;
EXIT:
    return rc;
}

int test_dlock_atomic64_release_destroy(int client_id, int obj_id)
{
    int ret = 0, rc = TEST_FAILED;
    ret = umo_atomic64_release(client_id, obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_release", EXIT);
    ret = umo_atomic64_destroy(client_id,  obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_destroy", EXIT);
    rc = TEST_SUCCESS;
EXIT:
    return rc;
}

int test_trylock(int client_id, const struct lock_request *req, void *result) 
{
    int ret;
    if (rand_r(&g_test_dlock_ctx.ctx->seed) % 2 == 0 || (req != nullptr && req->expire_time == 0)) {
        ret = trylock(client_id, req, result);
    } else {
        ret = lock_request_async(client_id, req);
        if (ret != 0) {
            goto EXIT;
        }
        do {
            ret = lock_result_check(client_id, result);
            usleep(1000);
        } while (ret == DLOCK_ASYNC_AGAIN);
    }
EXIT:
    TEST_LOG_INFO("[test_trylock] ret=%d\n", ret);
    return ret;
}

int test_extend(int client_id, const struct lock_request *req, void *result) 
{
    int ret;
    if (rand_r(&g_test_dlock_ctx.ctx->seed) % 2 == 0 || result == nullptr) {
        ret = lock_extend(client_id, req, result);
    } else {
        ret = lock_request_async(client_id, req);
        if (ret != 0) {
            goto EXIT;
        }
        do {
            ret = lock_result_check(client_id, result);
            usleep(1000);
        } while (ret == DLOCK_ASYNC_AGAIN);
    }
EXIT:
    TEST_LOG_INFO("[lock_extend] ret=%d\n", ret);
    return ret;
}

int test_unlock(int client_id, int lock_id, void *result) 
{
    int ret, ret2;
    if (rand_r(&g_test_dlock_ctx.ctx->seed) % 2 == 0 || result == nullptr) {
        ret = unlock(client_id, lock_id, result);
    } else {
        struct lock_request req = {0};
        req.lock_id = lock_id;
        req.lock_op = UNLOCK;
        ret = lock_request_async(client_id, &req);
        if (ret != 0) {
            goto EXIT;
        }
        ret2 = lock_result_check(client_id, result);
        if (ret2 == DLOCK_NO_ASYNC) {
            goto EXIT;
        }
        ret = ret2;
        while (ret == DLOCK_ASYNC_AGAIN) {
            ret = lock_result_check(client_id, result);
            usleep(1000);
        }
    }
EXIT:
    TEST_LOG_INFO("[unlock] ret=%d\n", ret);
    return ret;
}

int test_get_lock(int client_id, struct lock_desc *p_lock, int *p_lock_id)
{
    int ret = 0;
    ret = get_lock(client_id, p_lock, p_lock_id);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("client_id:%d get_lock failed\n", client_id);
    }
    return ret;
}