/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: dlock unit test cases for dlock API
 * Author: wangyue
 * Create: 2022-7-18
 * Note:
 * History:
 */
#include <linux/limits.h>
#include <sys/time.h>

#include "gtest/gtest.h"

#include "utils.h"
#include "test_dlock_comm.h"

static int g_atomic_lock_ids[BATCH_SIZE];
static int g_rw_lock_ids[BATCH_SIZE];
static int g_fair_lock_ids[BATCH_SIZE];

static inline void construct_lock_desc(struct lock_desc &lock_desc, char *p_desc, unsigned int len,
    unsigned int lock_type, unsigned int lease_time)
{
    lock_desc.p_desc = p_desc;
    lock_desc.len = len;
    lock_desc.lock_type = lock_type;
    lock_desc.lease_time = lease_time;
}

static inline void construct_lock_request(struct lock_request &lock_req, int lock_id,
    int lock_op, unsigned int expire_time)
{
    lock_req.lock_id = lock_id;
    lock_req.lock_op = lock_op;
    lock_req.expire_time = expire_time;
}

static void test_dclient_lib_init(trans_mode_t tp_mode)
{
    int ret;
    struct client_cfg cfg_c;

    cfg_c.dev_name = nullptr;
    memset_s(&cfg_c.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_c.log_level = LOG_WARNING;
    cfg_c.tp_mode = tp_mode;
    cfg_c.ub_token_disable = false;
    cfg_c.primary_port = PRIMARY1_CONTROL_PORT_CLIENT;
    cfg_c.ssl.ssl_enable = false;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;

    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "dlock client lib already inited, ret: " << ret;
    dclient_lib_deinit();

    ret = dclient_lib_init(nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "p_client_cfg is nullptr, ret: " << ret;

    cfg_c.dev_name = strdup("xxxx");
    ret = dclient_lib_init(&cfg_c);
    free(cfg_c.dev_name);
    ASSERT_TRUE(ret == -1) << "invalid dev_name, ret: " << ret;

    cfg_c.dev_name = nullptr;
    cfg_c.log_level = 10;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "invalid log_level, ret: " << ret;
    dclient_lib_deinit();

    cfg_c.log_level = LOG_WARNING;
    cfg_c.primary_port = -1;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "invalid primary_port, ret: " << ret;
    dclient_lib_deinit();

    cfg_c.primary_port = 65536;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "need to add port range check, ret: " << ret;
    dclient_lib_deinit();
}

static void test_dclient_lib_deinit(trans_mode_t tp_mode)
{
    int ret;
    struct client_cfg cfg_c;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    cfg_c.dev_name = nullptr;
    memset_s(&cfg_c.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_c.log_level = LOG_WARNING;
    cfg_c.tp_mode = tp_mode;
    cfg_c.ub_token_disable = false;
    cfg_c.primary_port = PRIMARY1_CONTROL_PORT_CLIENT;
    cfg_c.ssl.ssl_enable = false;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    free(server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    dclient_lib_deinit();
    dclient_lib_deinit();
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    dclient_lib_deinit();
}

static void test_client_init_and_deinit(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    char *invalid_ip_str = strdup(INVALID_IP_STR);
    int client_id = 100;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = client_init(nullptr, server_ip);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "client_id is nullptr, ret: " << ret;

    ret = client_init(&client_id, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "ip_str is nullptr, ret: " << ret;

    ret = client_init(&client_id, invalid_ip_str);
    ASSERT_TRUE(ret == -1) << "invalid ip str, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == -1) << "client has not been inited, ret: " << ret;

    dclient_lib_deinit();
    free(server_ip);
    free(invalid_ip_str);
}

static void test_client_reinit_and_reinit_done(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    char *invalid_ip_str = strdup(INVALID_IP_STR);
    int client_id = 100;

    ret = client_reinit(client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    ret = client_reinit_done(client_id);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = client_reinit(client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit failed, ret: " << ret;
    ret = client_reinit_done(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit done failed, ret: " << ret;
    ret = client_reinit_done(client_id);
    ASSERT_TRUE(ret == -1) << "client has not been reinited, ret: " << ret;

    ret = client_reinit(client_id, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "ip str is nullptr, ret: " << ret;

    ret = client_reinit(100, server_ip);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "client has not been inited, ret: " << ret;

    ret = client_reinit_done(100);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_reinit(client_id, invalid_ip_str);
    ASSERT_TRUE(ret == -1) << "invalid ip str, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();

    free(server_ip);
    free(invalid_ip_str);
}

static void test_update_all_locks(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    fairlock_state lock_state1 = {0};
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    ret = update_client_locks(client_id);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = update_client_locks(client_id);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = update_client_locks(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "no locks to be updated, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    ret = update_client_locks(client_id);
    ASSERT_TRUE(ret == -1) << "server is in the normal working process, "
        "update_all_locks request is invalid, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();

    free(server_ip);
}

static void test_client_heartbeat(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    ret = client_heartbeat(client_id, 5);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = client_heartbeat(client_id, 5);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client heartbeat failed, ret: " << ret;

    ret = client_heartbeat(100, 5);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid client_id, ret: " << ret;

    ret = client_heartbeat(client_id, 0);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid timeout, ret: " << ret;

    stop_primary_server1();
    ret = client_heartbeat(client_id, 2);
    ASSERT_TRUE(ret == DLOCK_BAD_RESPONSE) << "primary server has been stopped, ret: " << ret;

    /* Recovery the server and client status to avoid affecting subsequent test cases. */
    startup_primary_server1(1, 0, false, false, tp_mode);
    ret = client_reinit(client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit failed, ret: " << ret;
    ret = update_client_locks(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "no locks to be updated, ret: " << ret;
    ret = client_reinit_done(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit done failed, ret: " << ret;
    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();

    free(server_ip);
}

static void test_lock_limit(int client_id, int lock_num, unsigned int lease_time)
{
    // To avoid memory leak after assert, we allocate lock_id statically instead of malloc
    int lock_id[LOCK_NUM_LIMIT << 1];
    struct lock_desc lock_desc;
    int i = 0;
    int ret;

    if (lock_num > (LOCK_NUM_LIMIT << 1)) {
        return;
    }
    for (; i < lock_num; i++) {
        char *lock_desc_str = (char *)(&i);
        construct_lock_desc(lock_desc, lock_desc_str, sizeof(int), DLOCK_ATOMIC, lease_time);
        ret = get_lock(client_id, &lock_desc, &lock_id[i]);
        if (i >= LOCK_NUM_LIMIT) {
            ASSERT_TRUE(ret == static_cast<int>(DLOCK_SERVER_NO_RESOURCE)) <<
                "get more than LOCK_NUM_LIMIT locks, but no DLOCK_SERVER_NO_RESOURCE err, ret: " << ret;
        } else {
            ASSERT_TRUE(ret == 0) <<
                "get less than LOCK_NUM_LIMIT locks, but ret: " << ret;
        }
    }
    for (i = 0; (i < lock_num) && (i < LOCK_NUM_LIMIT); i++) {
        ret = release_lock(client_id, lock_id[i]);
        ASSERT_TRUE(ret == 0) << "release_lock failed, ret: " << ret;
    }
}

static void test_get_lock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;
    int client_id2 = 101;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == -1) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;
    ret = client_init(&client_id2, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = get_lock(client_id, nullptr, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "desc is nullptr, ret: " << ret;

    ret = get_lock(client_id, &lock_desc1, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_id is nullptr, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, 0, DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid desc len, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, (MAX_LOCK_DESC_LEN + 1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid desc len, ret: " << ret;

    construct_lock_desc(lock_desc1, nullptr, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "p_desc is nullptr, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_MAX, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_type, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == 0) << "get_lock failed, ret: " << ret;
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == -1) << "lock has already been got, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    ret = get_lock(client_id2, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == -1) << "lock already exists, and the lock_type is not DLOCK_FAIR, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == 0) << "release_lock failed, ret: " << ret;

    test_lock_limit(client_id, LOCK_NUM_LIMIT, tv_start.tv_sec + 60000);
    test_lock_limit(client_id, LOCK_NUM_LIMIT + 1, tv_start.tv_sec + 60000);

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_release_lock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    ret = release_lock(client_id, 1);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = release_lock(client_id, 1);
    ASSERT_TRUE(ret == -1) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = release_lock(client_id, 1);
    ASSERT_TRUE(ret == -1) << "lock has not been got, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == -1) << "should unlock first, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == 0) << "release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_trylock_and_lock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    construct_lock_request(lock_req1, 1, LOCK_EXCLUSIVE, 5);
    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_LOCK_NOT_GET) << "lock has not been got, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;
    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = trylock(client_id, nullptr, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "req is nullptr, ret: " << ret;

    ret = trylock(client_id, &lock_req1, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "result is nullptr, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_OPS_MAX, 5);
    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    ret = lock(client_id, nullptr, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "req is nullptr, ret: " << ret;

    ret = lock(client_id, &lock_req1, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "result is nullptr, ret: " << ret;

    ret = lock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock failed, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_unlock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    ret = unlock(client_id, 1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = unlock(client_id, 1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = unlock(client_id, 1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_LOCK_NOT_GET) << "client has not been inited, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_UNLOCKED) << "lock has not been locked, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;

    ret = unlock(client_id, lock_id_1, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "result is nullptr, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_lock_extend(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    construct_lock_request(lock_req1, 1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_LOCK_NOT_GET) << "lock has not been got, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has not been locked, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = lock_extend(client_id, nullptr, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "req is nullptr, ret: " << ret;

    ret = lock_extend(client_id, &lock_req1, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "result is nullptr, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_OPS_MAX, 70);
    ret = lock_extend(client_id, &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_batch_get_lock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;
    int client_id2 = 101;

    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    int desc_len = sizeof(int);
    struct lock_desc lock_descs[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int lock_ids2[BATCH_SIZE];
    int i;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = client_id * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == -1) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;
    ret = client_init(&client_id2, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = batch_get_lock(client_id, BATCH_SIZE, nullptr, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "descs is nullptr, ret: " << ret;

    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_ids is nullptr, ret: " << ret;

    ret = batch_get_lock(client_id, 0, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_get_lock(client_id, (MAX_LOCK_BATCH_SIZE + 1), lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    lock_descs[1].len = 0;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid desc len, ret: " << ret;

    lock_descs[1].len = MAX_LOCK_DESC_LEN + 1;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid desc len, ret: " << ret;

    lock_descs[1].len = desc_len;
    lock_descs[1].p_desc = nullptr;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "p_desc is nullptr, ret: " << ret;

    lock_descs[1].p_desc = (char *)(&(lock_desc_strs[1]));
    lock_descs[1].lock_type = DLOCK_MAX;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_type, ret: " << ret;

    lock_descs[1].lock_type = DLOCK_ATOMIC;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    lock_descs[1].lock_type = DLOCK_FAIR;
    ret = batch_get_lock(client_id2, BATCH_SIZE, lock_descs, lock_ids2);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 1) {
            ASSERT_TRUE(lock_ids2[i] == -1) <<
                "lock[" << i << "] already exists, and the lock_type is not DLOCK_FAIR, ret: " << lock_ids2[i];
            continue;
        }
        ASSERT_TRUE(lock_ids2[i] == lock_ids[i]) <<
            "lock[" << i << "] get_lock failed, ret: " << lock_ids2[i];
    }

    ret = batch_release_lock(client_id, BATCH_SIZE, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    /* test client_id2 exit abnormally */
    dclient_lib_deinit();
    free(server_ip);
}

static void test_batch_release_lock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    int desc_len = sizeof(int);
    struct lock_desc lock_descs[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int temp_lock_ids[BATCH_SIZE];
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int i;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        temp_lock_ids[i] = i;
    }
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == -1) << "dlock client lib has not been inited,  " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == -1) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == -1) << "no valid lock_id for release,  " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(temp_lock_ids[i] == 0) <<
            "lock[" << i << "] has not been got, output lock_id: " << temp_lock_ids[i];
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = client_id * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_ids[2], LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "an async op is ongoing, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 2) {
            ASSERT_TRUE(temp_lock_ids[i] == 0) <<
                "an async op is ongoing, output lock_id: " << temp_lock_ids[i];
            continue;
        }
        ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
            "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
    }

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 2) {
            ASSERT_TRUE(temp_lock_ids[i] == 0) <<
                "should unlock first, output lock_id: " << temp_lock_ids[i];
            continue;
        }
        ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
            "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
    }

    ret = unlock(client_id, lock_ids[2], &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 2) {
            ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
                "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
            continue;
        }
        ASSERT_TRUE(temp_lock_ids[i] == 0) <<
            "lock[" << i << "] has not been got, output lock_id: " << temp_lock_ids[i];
    }

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, 0, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_release_lock(client_id, (MAX_LOCK_BATCH_SIZE + 1), temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_release_lock(client_id, BATCH_SIZE, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_ids is nullptr, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_batch_trylock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    int desc_len = sizeof(int);
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int temp_lock_ids[BATCH_SIZE];
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int i;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], i, LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_LOCK_NOT_GET) << "lock[" << i << "] has not been got, ret: " <<
            lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = client_id * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_ids[1], LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 1) {
            ASSERT_TRUE(lock_results[i].op_ret == DLOCK_ALREADY_LOCKED) <<
                "lock[" << i << "] has been already locked, ret: " << lock_results[i].op_ret;
            continue;
        }
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    ret = unlock(client_id, lock_ids[1], &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = batch_trylock(client_id, 0, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_trylock(client_id, (MAX_LOCK_BATCH_SIZE + 1), lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_trylock(client_id, BATCH_SIZE, nullptr, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "reqs is nullptr, ret: " << ret;

    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "results is nullptr, ret: " << ret;

    lock_reqs[1].lock_op = LOCK_OPS_MAX;
    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
            "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
    }

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_batch_unlock(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    int desc_len = sizeof(int);
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int temp_lock_ids[BATCH_SIZE];
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int i;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_ids[i] = i;
    }
    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_LOCK_NOT_GET) << "lock[" << i << "] has not been got, ret: " <<
            lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = client_id * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_ALREADY_UNLOCKED) <<
            "lock[" << i << "] has not been locked, ret: " << lock_results[i].op_ret;
    }

    construct_lock_request(lock_req1, lock_ids[1], LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        if (i == 1) {
            ASSERT_TRUE(lock_results[i].op_ret == DLOCK_ALREADY_LOCKED) <<
                "lock[" << i << "] has been locked multiple times, ret: " << lock_results[i].op_ret;
            continue;
        }
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = unlock(client_id, lock_ids[1], &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = batch_unlock(client_id, 0, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_unlock(client_id, (MAX_LOCK_BATCH_SIZE + 1), lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, nullptr, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_id is nullptr, ret: " << ret;

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "results is nullptr, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
            "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
    }

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_batch_lock_extend(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    int desc_len = sizeof(int);
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_request lock_extend_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int temp_lock_ids[BATCH_SIZE];
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int i;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_extend_reqs[i], i, EXTEND_LOCK_EXCLUSIVE, 70);
    }
    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_LOCK_NOT_GET) << "lock[" << i << "] has not been got, ret: " <<
            lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = client_id * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_extend_reqs[i], lock_ids[i], EXTEND_LOCK_EXCLUSIVE, 70);
    }
    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_EINVAL) << "lock[" << i << "] has not been locked, ret: " <<
            lock_results[i].op_ret;
    }

    construct_lock_request(lock_req1, lock_ids[1], LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;
    ret = unlock(client_id, lock_ids[1], &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(client_id, BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;

    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) <<
            "lock extend lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(client_id, BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_lock_extend(client_id, 0, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_lock_extend(client_id, (MAX_LOCK_BATCH_SIZE + 1), lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_num, ret: " << ret;

    ret = batch_lock_extend(client_id, BATCH_SIZE, nullptr, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "reqs is nullptr, ret: " << ret;

    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "results is nullptr, ret: " << ret;

    lock_extend_reqs[1].lock_op = LOCK_OPS_MAX;
    ret = batch_lock_extend(client_id, BATCH_SIZE, lock_extend_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(client_id, BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(temp_lock_ids[i] == lock_ids[i]) <<
            "release lock[" << i << "] failed, output lock_id: " << temp_lock_ids[i];
    }

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_lock_request_async(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;

    gettimeofday(&tv_start, nullptr);

    construct_lock_request(lock_req1, 1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_LOCK_NOT_GET) << "lock has not been got, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(client_id, &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EASYNC) << "an async op is ongoing, ret: " << ret;

    do {
        ret = lock_result_check(client_id, &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;
    ret = unlock(client_id, lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = lock_request_async(client_id, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "req is nullptr, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_OPS_MAX, 5);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "invalid lock_op, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 0);
    ret = lock_request_async(client_id, &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "0 expire time not supported in async lock op, ret: " << ret;

    ret = release_lock(client_id, lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_lock_result_check(trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    int client_id = 100;

    struct timeval tv_start;
    atomic_state lock_state1;

    gettimeofday(&tv_start, nullptr);

    ret = lock_result_check(client_id, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENTMGR_NOT_INIT) << "dlock client lib has not been inited, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = lock_result_check(client_id, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_CLIENT_NOT_INIT) << "client has not been inited, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = lock_result_check(client_id, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_NO_ASYNC) << "no outstanding async op, ret: " << ret;

    ret = lock_result_check(client_id, nullptr);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "result is nullptr, ret: " << ret;

    ret = client_deinit(client_id);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    dclient_lib_deinit();
    free(server_ip);
}

static void test_dserver_lib_init_and_deinit(void)
{
    int ret;

    ret = dserver_lib_init(0);
    ASSERT_TRUE(ret == -1) << "invalid max_server_num, ret: " << ret;

    ret = dserver_lib_init(33);
    ASSERT_TRUE(ret == -1) << "invalid max_server_num, ret: " << ret;

    ret = dserver_lib_init(10);
    ASSERT_TRUE(ret == 0) << "dlock server lib init failed, ret: " << ret;

    ret = dserver_lib_init(10);
    ASSERT_TRUE(ret == -1) << "dlock server lib has been inited, ret: " << ret;

    dserver_lib_deinit();
    dserver_lib_deinit();
}

static void test_server_start(void)
{
    int ret;
    int max_server_num = 2;
    char ctrl_cpuset[] = "15-20";
    char cmd_cpuset[] = "20-25";
    char invalid_cpuset[] = "-1";
    char *server_ip = strdup(PRIMARY_ADDRESS);
    char *invalid_server_ip = strdup("1.1.1");
    struct server_cfg primary_cfg_s;
    struct server_cfg replica_cfg_s;
    int server_id1;
    int server_id2;

    primary_cfg_s.type = SERVER_PRIMARY;
    primary_cfg_s.dev_name = nullptr;
    str_to_urma_eid(server_ip, &primary_cfg_s.eid);
    primary_cfg_s.log_level = LOG_WARNING;
    primary_cfg_s.tp_mode = SEPERATE_CONN;
    primary_cfg_s.ub_token_disable = false;
    primary_cfg_s.sleep_mode_enable = true;
    primary_cfg_s.primary.num_of_replica = 0;
    primary_cfg_s.primary.recovery_client_num = 0;
    primary_cfg_s.primary.ctrl_cpuset = ctrl_cpuset;
    primary_cfg_s.primary.cmd_cpuset = cmd_cpuset;
    primary_cfg_s.primary.server_ip_str = server_ip;
    primary_cfg_s.primary.server_port = PRIMARY1_CONTROL_PORT_CLIENT;
    primary_cfg_s.primary.replica_enable = false;
    primary_cfg_s.primary.replica_port = 0;
    primary_cfg_s.ssl.ssl_enable = false;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "dlock server lib has not been inited, ret: " << ret;

    ret = dserver_lib_init(max_server_num);
    ASSERT_TRUE(ret == 0) << "dlock server lib init failed, ret: " << ret;

    memset_s(&primary_cfg_s.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    primary_cfg_s.dev_name = nullptr;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == 0) << "eid is zero and dev_name is nullptr, ret: " << ret;
    ret = server_stop(server_id1);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;

    primary_cfg_s.type = SERVER_MAX;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "invalid server_type, ret: " << ret;

    primary_cfg_s.type = SERVER_PRIMARY;
    primary_cfg_s.primary.num_of_replica = 1;
    primary_cfg_s.primary.recovery_client_num = 0;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "replica is not enabled, invalid num_of_replica, ret: " << ret;

    primary_cfg_s.primary.num_of_replica = 0;
    primary_cfg_s.primary.recovery_client_num = MAX_NUM_CLIENT + 1;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "replica is not enabled, invalid recovery_client_num, ret: " << ret;

    primary_cfg_s.primary.replica_enable = true;
    primary_cfg_s.primary.num_of_replica = MAX_NUM_REPLICA + 1;
    primary_cfg_s.primary.recovery_client_num = 0;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "replica is enabled, invalid num_of_replica, ret: " << ret;

    primary_cfg_s.primary.num_of_replica = 0;
    primary_cfg_s.primary.recovery_client_num = 1;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "replica is enabled, invalid recovery_client_num, ret: " << ret;

    primary_cfg_s.primary.replica_enable = false;
    primary_cfg_s.primary.num_of_replica = 0;
    primary_cfg_s.primary.recovery_client_num = 0;
    primary_cfg_s.primary.ctrl_cpuset = invalid_cpuset;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "invalid ctrl_cpuset, ret: " << ret;

    primary_cfg_s.primary.ctrl_cpuset = ctrl_cpuset;
    primary_cfg_s.primary.cmd_cpuset = invalid_cpuset;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "invalid cmd_cpuset, ret: " << ret;

    primary_cfg_s.primary.cmd_cpuset = cmd_cpuset;
    primary_cfg_s.primary.server_port = 65536;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == -1) << "invalid server port, ret: " << ret;

    primary_cfg_s.primary.server_port = PRIMARY1_CONTROL_PORT_CLIENT;
    ret = server_start(primary_cfg_s, server_id1);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;

    replica_cfg_s.type = SERVER_REPLICA;
    replica_cfg_s.dev_name = nullptr;
    memset_s(&replica_cfg_s.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    replica_cfg_s.log_level = LOG_WARNING;
    replica_cfg_s.tp_mode = SEPERATE_CONN;
    replica_cfg_s.ub_token_disable = false;
    replica_cfg_s.sleep_mode_enable = true;
    replica_cfg_s.replica.primary_ip_str = server_ip;
    replica_cfg_s.replica.primary_port = 21615;
    replica_cfg_s.ssl.ssl_enable = false;
    ret = server_start(replica_cfg_s, server_id2);
    ASSERT_TRUE(ret == -1) << "replica server is not supported, ret: " << ret;

    dserver_lib_deinit();
    free(server_ip);
    free(invalid_server_ip);
}

static void test_server_stop(void)
{
    int ret;

    ret = server_stop(1);
    ASSERT_TRUE(ret == -1) << "dlock server lib is not inited, ret: " << ret;

    ret = dserver_lib_init(2);
    ASSERT_TRUE(ret == 0) << "dlock server lib init failed, ret: " << ret;

    ret = server_stop(1);
    ASSERT_TRUE(ret == -1) << "server has not been inited, ret: " << ret;

    ret = server_stop(0);
    ASSERT_TRUE(ret == -1) << "invalid server_id, ret: " << ret;

    ret = server_stop(0xFFFFFF);
    ASSERT_TRUE(ret == -1) << "invalid server_id, ret: " << ret;

    dserver_lib_deinit();
}

static void test_atomic_lock_op(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[0], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    ret = get_lock(g_client_id[1], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has not been locked, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;

    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "lock has already been locked by another client, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 0);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 0);
    ret = lock_extend(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 1);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    sleep(2);
    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 1);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "timeout, lock has already been locked by another client, ret: " << ret;

    sleep(2);
    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "timeout, lock has already been locked by another client, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(g_client_id[0], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    ret = release_lock(g_client_id[1], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
}

static void test_rw_lock_op(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    rw_state lock_state1 = {0};
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_RW, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[0], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    ret = get_lock(g_client_id[1], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;

    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "lock has already been locked by another client, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "lock has already been locked by another client, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 0);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_op is not supported  " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has been locked in exclusive mode, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;
    ret = unlock(g_client_id[1], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = release_lock(g_client_id[0], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    ret = release_lock(g_client_id[1], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
}

static void test_fair_lock_exclusive(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    struct lock_request lock_extend_req1 = {0};
    fairlock_state lock_state1 = {0};
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = get_lock(g_client_id[i], &lock_desc1, &lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    }

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 0);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_SHARED, 70);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock op does not match the lock status, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 0);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has been locked in exclusive mode, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[2], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock with ticket failed, ret: " << ret;

    ret = unlock(g_client_id[1], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = unlock(g_client_id[2], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock ticket failed, ret: " << ret;

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = release_lock(g_client_id[i], lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    }
}

static void test_fair_lock_shared(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    struct lock_request lock_extend_req1 = {0};
    fairlock_state lock_state1 = {0};
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = get_lock(g_client_id[i], &lock_desc1, &lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    }

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;
    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "reentrant trylock, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 0);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock op does not match the lock status, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_SHARED, 70);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    construct_lock_request(lock_extend_req1, lock_id_1, EXTEND_LOCK_SHARED, 0);
    ret = lock_extend(g_client_id[0], &lock_extend_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_extend failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has been locked in shared mode, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed " << ret;
    ret = unlock(g_client_id[1], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = trylock(g_client_id[2], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_ALREADY_LOCKED) << "lock has been locked multiple times, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock with ticket failed, ret: " << ret;

    ret = unlock(g_client_id[1], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    ret = unlock(g_client_id[2], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock ticket failed, ret: " << ret;

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = release_lock(g_client_id[i], lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    }
}

static void test_fair_lock_timeout(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    fairlock_state lock_state1 = {0};
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = get_lock(g_client_id[i], &lock_desc1, &lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    }

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 1);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 1);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    sleep(2);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) <<
        "exclusive unlock timeout, lock has been locked in shared mode by another client, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 1);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "trylock failed, ret: " << ret;

    sleep(2);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    ret = unlock(g_client_id[1], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_FAIL) <<
        "shared unlock timeout, lock has been locked in exclusive mode by another client, ret: " << ret;
    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = release_lock(g_client_id[i], lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    }
}

static void test_fair_lock_op(void)
{
    test_fair_lock_exclusive();
    test_fair_lock_shared();
    test_fair_lock_timeout();
}

static void test_batch_atomic_lock_op(void)
{
    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_request lock_extend_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    struct lock_op_res lock_extend_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int desc_len = sizeof(int);
    int i;
    int ret;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = g_client_id[0] * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_extend_reqs[i], lock_ids[i], EXTEND_LOCK_EXCLUSIVE, 70);
    }
    ret = batch_lock_extend(g_client_id[0], BATCH_SIZE, lock_extend_reqs, lock_extend_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "lock_extend lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_release_lock(g_client_id[0], BATCH_SIZE, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
}

static void test_batch_rw_lock_op(void)
{
    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int desc_len = sizeof(int);
    int i;
    int ret;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = g_client_id[0] * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_RW, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_SHARED, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_release_lock(g_client_id[0], BATCH_SIZE, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
}

static void test_batch_fair_lock_op(void)
{
    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_request lock_extend_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    struct lock_op_res lock_extend_results[BATCH_SIZE];
    int lock_ids[BATCH_SIZE];
    int desc_len = sizeof(int);
    int i;
    int ret;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = g_client_id[0] * BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_FAIR, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_extend_reqs[i], lock_ids[i], EXTEND_LOCK_EXCLUSIVE, 70);
    }
    ret = batch_lock_extend(g_client_id[0], BATCH_SIZE, lock_extend_reqs, lock_extend_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
           "lock_extend lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "unlock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], lock_ids[i], LOCK_SHARED, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "trylock lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_extend_reqs[i], lock_ids[i], EXTEND_LOCK_SHARED, 70);
    }
    ret = batch_lock_extend(g_client_id[0], BATCH_SIZE, lock_extend_reqs, lock_extend_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "lock_extend lock[" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(ret == DLOCK_SUCCESS) <<
            "unlock lock [" << i << "] failed, ret: " << lock_results[i].op_ret;
    }

    ret = batch_release_lock(g_client_id[0], BATCH_SIZE, lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_release_lock failed, ret: " << ret;
    return;
}

static void test_async_atomic_lock_op(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    atomic_state lock_state1;
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[0], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    ret = get_lock(g_client_id[1], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has not been locked, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_FAIL) << "lock has already been locked by another client, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = release_lock(g_client_id[0], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    ret = release_lock(g_client_id[1], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
}

static void test_async_rw_lock_op(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    rw_state lock_state1;
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_RW, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[0], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    ret = get_lock(g_client_id[1], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock_op is not supported  " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has been locked in exclusive mode, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    ret = release_lock(g_client_id[0], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    ret = release_lock(g_client_id[1], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
}

static void test_async_fair_lock_op(void)
{
    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1;
    struct lock_request lock_req1;
    fairlock_state lock_state1;
    int lock_id_1;
    int ret;

    gettimeofday(&tv_start, nullptr);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = get_lock(g_client_id[i], &lock_desc1, &lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    }

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_SHARED, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock op does not match the lock status, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock has been locked in exclusive mode, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[2], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[2], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_EAGAIN) << "get lock ticket failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock with ticket failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "unlock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[2], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[2], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_NO_ASYNC) << "the asynchronous lock operation request has been processed locally, " <<
        "there is no need to check the result, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_SHARED, 5);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "lock op does not match the lock status, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_SHARED, 70);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, UNLOCK, 0);
    ret = lock_request_async(g_client_id[0], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;
    do {
        ret = lock_result_check(g_client_id[0], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_result_check failed, ret: " << ret;

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = release_lock(g_client_id[i], lock_id_1);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "release_lock failed, ret: " << ret;
    }
}

static void test_dlock_basic_lock_op(void)
{
    test_atomic_lock_op();
    test_rw_lock_op();
    test_fair_lock_op();

    test_batch_atomic_lock_op();
    test_batch_rw_lock_op();
    test_batch_fair_lock_op();

    test_async_atomic_lock_op();
    test_async_rw_lock_op();
    test_async_fair_lock_op();
}

static void construct_failure_recovery_lock_state(void)
{
    struct timeval tv_start;
    int lock_desc_strs[BATCH_SIZE];
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int desc_len = sizeof(int);
    int base_lock_desc = 0;
    int i;
    int ret;

    gettimeofday(&tv_start, nullptr);

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = ++base_lock_desc;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, g_atomic_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    ret = batch_get_lock(g_client_id[1], BATCH_SIZE, lock_descs, g_atomic_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = ++base_lock_desc;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_RW, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, g_rw_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = ++base_lock_desc;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_FAIR, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, g_fair_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_atomic_lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) << "trylock lock[" << i << "] failed, ret: " <<
            lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_rw_lock_ids[i], LOCK_SHARED, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) << "trylock lock[" << i << "] failed, ret: " <<
            lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_fair_lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) << "trylock lock[" << i << "] failed, ret: " <<
            lock_results[i].op_ret;
    }
}

static void verify_failure_recovery_lock_state(void)
{
    return;
}

static void test_failure_recovery_lock_state(trans_mode_t tp_mode)
{
    startup_primary_server1(0, 0, false, true, tp_mode);
    startup_clients_of_server1(true, tp_mode);

    construct_failure_recovery_lock_state();
    stop_primary_server1();
    startup_primary_server1(CLIENT_NUM, 0, false, true, tp_mode);

    recovery_clients_of_server1();
    verify_failure_recovery_lock_state();

    stop_clients_of_server1();
    stop_primary_server1();
}

static void test_server_not_ready(trans_mode_t tp_mode)
{
    int ret;
    int client_id = 100;
    char *server_ip = strdup(PRIMARY_ADDRESS);

    struct timeval tv_start;
    char lock_desc_str1[] = "lock desc 1";
    struct lock_desc lock_desc1 = {0};
    struct lock_request lock_req1 = {0};
    fairlock_state lock_state1 = {0};
    int lock_id_1;

    int lock_desc_strs[BATCH_SIZE];
    struct lock_desc lock_descs[BATCH_SIZE];
    struct lock_request lock_reqs[BATCH_SIZE];
    struct lock_op_res lock_results[BATCH_SIZE];
    int temp_lock_ids[BATCH_SIZE];
    int desc_len = sizeof(int);
    int base_lock_desc = BATCH_SIZE * 4;
    int i;

    gettimeofday(&tv_start, nullptr);

    startup_primary_server1(0, 0, false, true, tp_mode);
    startup_clients_of_server1(true, tp_mode);

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[0], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;
    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_FAIR, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[1], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_lock failed, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "trylock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = base_lock_desc + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[0], BATCH_SIZE, lock_descs, g_atomic_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = base_lock_desc + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[1], BATCH_SIZE, lock_descs, g_atomic_lock_ids);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_atomic_lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_SUCCESS) << "trylock lock[" << i << "] failed, ret: " <<
            lock_results[i].op_ret;
    }

    stop_primary_server1();

    ret = client_reinit(g_client_id[0], server_ip);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) << "server has not been started, ret: " << ret;

    startup_primary_server1(CLIENT_NUM + 1, 0, false, true, tp_mode);
    recovery_clients_of_server1();

    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "client_init, server is in the failure recovery process, ret: " << ret;

    construct_lock_desc(lock_desc1, lock_desc_str1, strlen(lock_desc_str1), DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    ret = get_lock(g_client_id[2], &lock_desc1, &lock_id_1);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "get_lock, server is in the failure recovery process, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = trylock(g_client_id[1], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "trylock, server is in the failure recovery process, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, EXTEND_LOCK_EXCLUSIVE, 70);
    ret = lock_extend(g_client_id[0], &lock_req1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) << "dlock client lib has not been inited, ret: " << ret;

    ret = unlock(g_client_id[0], lock_id_1, &lock_state1);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "unlock, server is in the failure recovery process, ret: " << ret;

    ret = release_lock(g_client_id[1], lock_id_1);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "release_lock, server is in the failure recovery process, ret: " << ret;

    construct_lock_request(lock_req1, lock_id_1, LOCK_EXCLUSIVE, 5);
    ret = lock_request_async(g_client_id[1], &lock_req1);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "lock_request_async failed, ret: " << ret;

    do {
        ret = lock_result_check(g_client_id[1], &lock_state1);
    } while (ret == DLOCK_ASYNC_AGAIN);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "lock_result_check, server is in the failure recovery process, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_desc_strs[i] = BATCH_SIZE + i;
        construct_lock_desc(lock_descs[i], (char *)(&(lock_desc_strs[i])), desc_len,
            DLOCK_ATOMIC, tv_start.tv_sec + 60000);
    }
    ret = batch_get_lock(g_client_id[2], BATCH_SIZE, lock_descs, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) << "batch_get_lock failed, ret: " << ret;

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_atomic_lock_ids[i], LOCK_EXCLUSIVE, 5);
    }
    ret = batch_trylock(g_client_id[1], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_trylock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_NOT_READY) <<
            "trylock lock[" << i << "], server is in the failure recovery process, ret: " << lock_results[i].op_ret;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        construct_lock_request(lock_reqs[i], g_atomic_lock_ids[i], EXTEND_LOCK_EXCLUSIVE, 70);
    }
    ret = batch_lock_extend(g_client_id[0], BATCH_SIZE, lock_reqs, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_lock_extend failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_NOT_READY) <<
            "lock_extend lock[" << i << "], server is in the failure recovery process, ret: " << lock_results[i].op_ret;
    }

    ret = batch_unlock(g_client_id[0], BATCH_SIZE, g_atomic_lock_ids, lock_results);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "batch_unlock failed, ret: " << ret;
    for (i = 0; i < BATCH_SIZE; i++) {
        ASSERT_TRUE(lock_results[i].op_ret == DLOCK_NOT_READY) <<
            "unlock lock[" << i << "], server is in the failure recovery process, ret: " << lock_results[i].op_ret;
    }

    (void)memcpy_s(temp_lock_ids, (BATCH_SIZE * sizeof(int)), g_atomic_lock_ids, (BATCH_SIZE * sizeof(int)));
    ret = batch_release_lock(g_client_id[1], BATCH_SIZE, temp_lock_ids);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) << "batch_release_lock failed, ret: " << ret;

    ret = client_deinit(g_client_id[0]);
    ASSERT_TRUE(ret == DLOCK_NOT_READY) <<
        "client_deinit, server is in the failure recovery process, ret: " << ret;

    dclient_lib_deinit();
    stop_primary_server1();
    free(server_ip);
}

static void test_ssl_basic_process(trans_mode_t tp_mode)
{
    int ret;

    startup_primary_server1(0, 0, false, true, tp_mode);
    startup_clients_of_server1(true, tp_mode);

    test_dlock_basic_lock_op();

    ret = client_heartbeat(g_client_id[0], 5);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client heartbeat failed, ret: " << ret;

    stop_clients_of_server1();
    stop_primary_server1();
}

static int cert_verify_succ(void *ctx, const char *crl_path)
{
    return 0;
}

static int cert_verify_fail(void *ctx, const char *crl_path)
{
    return -1;
}

static void get_prkey_pwd_nullptr(char **prkey_pwd, int *prkey_pwd_len)
{
    *prkey_pwd = nullptr;
    *prkey_pwd_len = 6;
}

static void get_prkey_pwd_invalid(char **prkey_pwd, int *prkey_pwd_len)
{
    *prkey_pwd = strdup("222222");
    *prkey_pwd_len = 6;
}

static void test_client_ssl_cfg(void)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    struct client_cfg cfg_c;
    int client_id = 100;
    char *file_path = (char *)malloc(PATH_MAX + 2);

    memset_s(file_path, PATH_MAX + 1, '0', PATH_MAX + 1);
    memset_s(file_path + PATH_MAX + 1, 1, '\0', 1);

    startup_primary_server1(0, 0, false, true, SEPERATE_CONN);

    cfg_c.dev_name = nullptr;
    memset_s(&cfg_c.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_c.log_level = LOG_WARNING;
    cfg_c.tp_mode = SEPERATE_CONN;
    cfg_c.ub_token_disable = false;
    cfg_c.primary_port = PRIMARY1_CONTROL_PORT_CLIENT;

    default_client_ssl_cfg(cfg_c.ssl);
    char *ca_path = cfg_c.ssl.ca_path;
    char *cert_path = cfg_c.ssl.cert_path;
    char *prkey_path = cfg_c.ssl.prkey_path;

    cfg_c.ssl.ca_path = nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "ca path is nullptr, ret: " << ret;

    cfg_c.ssl.ca_path = strdup("");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "ca path is null string, ret: " << ret;
    free(cfg_c.ssl.ca_path);

    cfg_c.ssl.ca_path = file_path;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "ca path len > PATH_MAX, ret: " << ret;

    cfg_c.ssl.ca_path = strdup("&&&&&&&######");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "ca path is invalid, ret: " << ret;
    free(cfg_c.ssl.ca_path);

    cfg_c.ssl.ca_path = strdup("./tmp.crt");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "ca path does not exist, ret: " << ret;
    free(cfg_c.ssl.ca_path);
    cfg_c.ssl.ca_path = ca_path;

    cfg_c.ssl.crl_path = strdup("");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "crl path is null string, ret: " << ret;
    free(cfg_c.ssl.crl_path);

    cfg_c.ssl.crl_path = file_path;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "crl path len > PATH_MAX, ret: " << ret;

    cfg_c.ssl.crl_path = strdup("&&&&&&&######");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "crl path is invalid, ret: " << ret;
    free(cfg_c.ssl.crl_path);

    cfg_c.ssl.crl_path = strdup("./crl.pem");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "crl path does not exist, ret: " << ret;
    free(cfg_c.ssl.crl_path);
    cfg_c.ssl.crl_path = nullptr;

    cfg_c.ssl.cert_path = nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "cert path is nullptr, ret: " << ret;

    cfg_c.ssl.cert_path = strdup("");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "cert path is null string, ret: " << ret;
    free(cfg_c.ssl.cert_path);

    cfg_c.ssl.cert_path = file_path;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "cert path len > PATH_MAX, ret: " << ret;

    cfg_c.ssl.cert_path = strdup("&&&&&&&######");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "cert path is invalid, ret: " << ret;
    free(cfg_c.ssl.cert_path);

    cfg_c.ssl.cert_path = strdup("./tmp.crt");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "cert path does not exist, ret: " << ret;
    free(cfg_c.ssl.cert_path);
    cfg_c.ssl.cert_path = cert_path;

    cfg_c.ssl.prkey_path = nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "prkey path is nullptr, ret: " << ret;

    cfg_c.ssl.prkey_path = strdup("");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "prkey path is null string, ret: " << ret;
    free(cfg_c.ssl.prkey_path);

    cfg_c.ssl.prkey_path = file_path;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "prkey path len > PATH_MAX, ret: " << ret;

    cfg_c.ssl.prkey_path = strdup("&&&&&&&######");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "prkey path is invalid, ret: " << ret;
    free(cfg_c.ssl.prkey_path);

    cfg_c.ssl.prkey_path = strdup("./tmp.pem");
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == -1) << "prkey path does not exist, ret: " << ret;
    free(cfg_c.ssl.prkey_path);
    cfg_c.ssl.prkey_path = prkey_path;

    cfg_c.ssl.cert_verify_cb = &cert_verify_succ;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "cert_verify_cb return 0, ret: " << ret;
    dclient_lib_deinit();

    cfg_c.ssl.cert_verify_cb = &cert_verify_fail;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "cert_verify_cb return -1, ret: " << ret;
    cfg_c.ssl.cert_verify_cb = nullptr;
    dclient_lib_deinit();

    cfg_c.ssl.prkey_pwd_cb = nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "prkey_pwd_cb is nullptr, ret: " << ret;

    cfg_c.ssl.prkey_pwd_cb = &get_prkey_pwd_nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "private-key password is nullptr, ret: " << ret;
    dclient_lib_deinit();

    cfg_c.ssl.prkey_pwd_cb = &get_prkey_pwd_invalid;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "private-key password is invalid, ret: " << ret;
    cfg_c.ssl.prkey_pwd_cb = &client_get_prkey_pwd;
    dclient_lib_deinit();

    cfg_c.ssl.erase_prkey_cb = nullptr;
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == DLOCK_EINVAL) << "erase_prkey_cb is nullptr, ret: " << ret;
    cfg_c.ssl.erase_prkey_cb = &erase_prkey;

    cfg_c.ssl.ca_path = strdup(CA_2_PATH);
    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "ssl certificates does not match, ret: " << ret;
    dclient_lib_deinit();
    free(cfg_c.ssl.ca_path);

    stop_primary_server1();

    free(server_ip);
    free(ca_path);
    free(cert_path);
    free(prkey_path);
    free(file_path);
}

static void test_server_ssl_cfg(void)
{
    int ret;
    unsigned int max_server_num = 10;
    char ctrl_cpuset[] = "15-20";
    char cmd_cpuset[] = "15-20";
    char *server_ip = strdup(PRIMARY_ADDRESS);
    struct server_cfg cfg_s;
    int server_id;
    int client_id = 100;
    char *file_path = (char *)malloc(PATH_MAX + 2);

    memset_s(file_path, PATH_MAX + 1, '0', PATH_MAX + 1);
    memset_s(file_path + PATH_MAX + 1, 1, '\0', 1);

    init_dclient_lib_with_server1(true, SEPERATE_CONN);
    ret = dserver_lib_init(max_server_num);
    ASSERT_TRUE(ret == 0) << "dlock server lib init failed, ret: " << ret;

    cfg_s.type = SERVER_PRIMARY;
    cfg_s.dev_name = nullptr;
    memset_s(&cfg_s.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_s.log_level = LOG_WARNING;
    cfg_s.tp_mode = SEPERATE_CONN;
    cfg_s.ub_token_disable = false;
    cfg_s.sleep_mode_enable = true;
    cfg_s.primary.num_of_replica = 0;
    cfg_s.primary.replica_enable = false;
    cfg_s.primary.recovery_client_num = 0;
    cfg_s.primary.ctrl_cpuset = ctrl_cpuset;
    cfg_s.primary.cmd_cpuset = cmd_cpuset;
    cfg_s.primary.server_ip_str = server_ip;
    cfg_s.primary.server_port = PRIMARY1_CONTROL_PORT_CLIENT;

    default_server_ssl_cfg(cfg_s.ssl);
    char *ca_path = cfg_s.ssl.ca_path;
    char *cert_path = cfg_s.ssl.cert_path;
    char *prkey_path = cfg_s.ssl.prkey_path;

    cfg_s.ssl.ca_path = nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "ca path is nullptr, ret: " << ret;

    cfg_s.ssl.ca_path = strdup("");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "ca path is null string, ret: " << ret;
    free(cfg_s.ssl.ca_path);

    cfg_s.ssl.ca_path = file_path;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "ca path len > PATH_MAX, ret: " << ret;

    cfg_s.ssl.ca_path = strdup("&&&&&&&######");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "ca path is invalid, ret: " << ret;
    free(cfg_s.ssl.ca_path);

    cfg_s.ssl.ca_path = strdup("./tmp.crt");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "ca path does not exist, ret: " << ret;
    free(cfg_s.ssl.ca_path);
    cfg_s.ssl.ca_path = ca_path;

    cfg_s.ssl.crl_path = strdup("");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "crl path is null string, ret: " << ret;
    free(cfg_s.ssl.crl_path);

    cfg_s.ssl.crl_path = file_path;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "crl path len > PATH_MAX, ret: " << ret;

    cfg_s.ssl.crl_path = strdup("&&&&&&&######");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "crl path is invalid, ret: " << ret;
    free(cfg_s.ssl.crl_path);

    cfg_s.ssl.crl_path = strdup("./crl.pem");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "crl path does not exist, ret: " << ret;
    free(cfg_s.ssl.crl_path);
    cfg_s.ssl.crl_path = nullptr;

    cfg_s.ssl.cert_path = nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "cert path is nullptr, ret: " << ret;

    cfg_s.ssl.cert_path = strdup("");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "cert path is null string, ret: " << ret;
    free(cfg_s.ssl.cert_path);

    cfg_s.ssl.cert_path = file_path;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "cert path len > PATH_MAX, ret: " << ret;

    cfg_s.ssl.cert_path = strdup("&&&&&&&######");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "cert path is invalid, ret: " << ret;
    free(cfg_s.ssl.cert_path);

    cfg_s.ssl.cert_path = strdup("./tmp.crt");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "cert path does not exist, ret: " << ret;
    free(cfg_s.ssl.cert_path);
    cfg_s.ssl.cert_path = cert_path;

    cfg_s.ssl.prkey_path = nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey path is nullptr, ret: " << ret;

    cfg_s.ssl.prkey_path = strdup("");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey path is null string, ret: " << ret;
    free(cfg_s.ssl.prkey_path);

    cfg_s.ssl.prkey_path = file_path;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey path len > PATH_MAX, ret: " << ret;

    cfg_s.ssl.prkey_path = strdup("&&&&&&&######");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey path is invalid, ret: " << ret;
    free(cfg_s.ssl.prkey_path);

    cfg_s.ssl.prkey_path = strdup("./tmp.pem");
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey path does not exist, ret: " << ret;
    free(cfg_s.ssl.prkey_path);
    cfg_s.ssl.prkey_path = prkey_path;

    cfg_s.ssl.cert_verify_cb = &cert_verify_succ;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == 0) << "cert_verify_cb return 0, ret: " << ret;
    ret = server_stop(server_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;

    cfg_s.ssl.cert_verify_cb = &cert_verify_fail;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "server cert_verify_cb return -1, ret: " << ret;
    ret = server_stop(server_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;
    cfg_s.ssl.cert_verify_cb = nullptr;

    cfg_s.ssl.prkey_pwd_cb = nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "prkey_pwd_cb is nullptr, ret: " << ret;

    cfg_s.ssl.prkey_pwd_cb = &get_prkey_pwd_nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "server private-key password is nullptr, ret: " << ret;
    ret = server_stop(server_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;

    cfg_s.ssl.prkey_pwd_cb = &get_prkey_pwd_invalid;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "server private-key password is invalid, ret: " << ret;
    ret = server_stop(server_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;
    cfg_s.ssl.prkey_pwd_cb = &client_get_prkey_pwd;

    cfg_s.ssl.erase_prkey_cb = nullptr;
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == -1) << "erase_prkey_cb is nullptr, ret: " << ret;
    cfg_s.ssl.erase_prkey_cb = &erase_prkey;

    cfg_s.ssl.ca_path = strdup(CA_2_PATH);
    ret = server_start(cfg_s, server_id);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;
    ret = client_init(&client_id, server_ip);
    ASSERT_TRUE(ret == -1) << "ssl certificates does not match, ret: " << ret;
    ret = server_stop(server_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;
    free(cfg_s.ssl.ca_path);

    dclient_lib_deinit();
    dserver_lib_deinit();

    free(server_ip);
    free(ca_path);
    free(cert_path);
    free(prkey_path);
    free(file_path);
}

static void test_dlock_basic_lock_operation(trans_mode_t tp_mode)
{
    startup_primary_server1(0, 0, false, false, tp_mode);
    startup_clients_of_server1(false, tp_mode);

    test_dlock_basic_lock_op();

    stop_clients_of_server1();
    stop_primary_server1();
}

static void test_dlock_client_api(trans_mode_t tp_mode)
{
    startup_primary_server1(0, 0, false, false, tp_mode);

    test_dclient_lib_init(tp_mode);
    test_dclient_lib_deinit(tp_mode);
    test_client_init_and_deinit(tp_mode);
    test_client_reinit_and_reinit_done(tp_mode);
    test_update_all_locks(tp_mode);
    test_client_heartbeat(tp_mode);

    test_get_lock(tp_mode);
    test_release_lock(tp_mode);
    test_trylock_and_lock(tp_mode);
    test_unlock(tp_mode);
    test_lock_extend(tp_mode);

    test_batch_get_lock(tp_mode);
    test_batch_release_lock(tp_mode);
    test_batch_trylock(tp_mode);
    test_batch_unlock(tp_mode);
    test_batch_lock_extend(tp_mode);

    test_lock_request_async(tp_mode);
    test_lock_result_check(tp_mode);

    stop_primary_server1();
}

static void test_dlock_failure_recovery(trans_mode_t tp_mode)
{
    int ret;

    ret = generate_ssl_file();
    ASSERT_TRUE(ret == 0) << "generate ssl file failed, ret: " << ret;

    test_failure_recovery_lock_state(tp_mode);
    test_server_not_ready(tp_mode);

    (void)delete_ssl_file();
}

static void test_dlock_secure_transmission(trans_mode_t tp_mode)
{
    int ret;

    ret = generate_ssl_file();
    ASSERT_TRUE(ret == 0) << "generate ssl file failed, ret: " << ret;

    test_ssl_basic_process(tp_mode);
    test_server_ssl_cfg();
    test_client_ssl_cfg();

    (void)delete_ssl_file();
}

static inline void print_debug_stats(struct debug_stats *stats)
{
    char buf[MAX_BUF] = {0};
    int ret = 0;

    for (int i = 0; i < DEBUG_STATS_MAX; i++) {
        ret += sprintf_s((buf + ret), (MAX_BUF - ret), "%d:%ld ", i, stats->stats[i]);
    }
    DLOCK_LOG_WARN("debug_stats: %s", buf);
}

static void test_debug_stats()
{
    struct debug_stats stats;
    int ret;

    ret = get_client_debug_stats(g_client_id[0], &stats);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_client_debug_stats failed, ret: " << ret;
    print_debug_stats(&stats);

    ret = get_server_debug_stats(g_primary_server1_id, &stats);
    ASSERT_TRUE(ret == 0) << "get_server_debug_stats failed, ret: " << ret;
    print_debug_stats(&stats);

    ret = clear_client_debug_stats(g_client_id[0]);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "clear_client_debug_stats failed, ret: " << ret;

    ret = clear_server_debug_stats(g_primary_server1_id);
    ASSERT_TRUE(ret == 0) << "clear_server_debug_stats failed, ret: " << ret;

    ret = get_client_debug_stats(g_client_id[0], &stats);
    ASSERT_TRUE(ret == DLOCK_SUCCESS) << "get_client_debug_stats failed, ret: " << ret;
    print_debug_stats(&stats);

    ret = get_server_debug_stats(g_primary_server1_id, &stats);
    ASSERT_TRUE(ret == 0) << "get_server_debug_stats failed, ret: " << ret;
    print_debug_stats(&stats);
}

TEST(lock_operation_sepconn, test_dlock_basic_lock_operation_sep)
{
    test_dlock_basic_lock_operation(SEPERATE_CONN);
}

TEST(lock_operation_uniconn, test_dlock_basic_lock_operation_uni)
{
    test_dlock_basic_lock_operation(UNI_CONN);
}

TEST(client_api_sepconn, test_dlock_client_api_sep)
{
    test_dlock_client_api(SEPERATE_CONN);
}

TEST(client_api_uniconn, test_dlock_client_api_uni)
{
    test_dlock_client_api(UNI_CONN);
}

TEST(server_api, test_dlock_server_api)
{
    test_dserver_lib_init_and_deinit();
    test_server_start();
    test_server_stop();
}

TEST(failure_recovery_sepconn, test_dlock_failure_recovery_sep)
{
    test_dlock_failure_recovery(SEPERATE_CONN);
}

TEST(failure_recovery_uniconn, test_dlock_failure_recovery_uni)
{
    test_dlock_failure_recovery(UNI_CONN);
}

TEST(secure_transmission_sepconn, test_dlock_secure_transmission_sep)
{
    test_dlock_secure_transmission(SEPERATE_CONN);
}

TEST(secure_transmission_uniconn, test_dlock_secure_transmission_uni)
{
    test_dlock_secure_transmission(UNI_CONN);
}

TEST(debug_stats_api, test_dlock_debug_stats_api)
{
    startup_primary_server1(0, 0, false, false, SEPERATE_CONN);
    startup_clients_of_server1(false, SEPERATE_CONN);

    test_dlock_basic_lock_op();
    test_debug_stats();

    stop_clients_of_server1();
    stop_primary_server1();
}

class test_umo_atomic64_create_destroy : public ::testing::TestWithParam<trans_mode_t> {
protected:
    int client_id;
    int client_id2;
    char* server_ip;
    umo_atomic64_desc desc;
    uint64_t val;
    int object_id;

    void SetUp() override
    {
        client_id = 100;
        client_id2 = 101;
        server_ip = strdup(PRIMARY_ADDRESS);
        val = 20;

        struct timeval tv_start;
        gettimeofday(&tv_start, nullptr);
        desc = {
            .p_desc = const_cast<char*>("object desc 1"),
            .len = static_cast<uint32_t>(strlen("object desc 1")),
            .lease_time = 30,
        };
    }

    void TearDown() override
    {
        free(server_ip);
        dclient_lib_deinit();
    }
};

// Define parameterized tests
TEST_P(test_umo_atomic64_create_destroy, create_destroy_tests)
{
    trans_mode_t tp_mode = GetParam();
    int ret;

    startup_primary_server1(0, 0, false, false, tp_mode);

    ret = umo_atomic64_create(client_id, nullptr, val, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc is nullptr " << ret;

    desc.p_desc = nullptr;
    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc.p_desc is nullptr " << ret;

    desc.p_desc = const_cast<char*>("object desc 1");
    desc.lease_time = 0;
    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc.lease_time = 0 " << ret;

    desc.lease_time = 6000;
    ret = umo_atomic64_create(client_id, &desc, val, nullptr);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "object_id is nullptr " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "Client lib not initialized, ret: " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "Client lib not initialized, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "Client not initialized, ret: " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "Client not initialized, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client init failed, ret: " << ret;

    // Init another client
    ret = client_init(&client_id2, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client init failed, ret: " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_ALREADY_CREATED) << "umo_atomic64_create failed " << ret;

    // Another client creates the same object
    ret = umo_atomic64_create(client_id2, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_ALREADY_EXISTED) << "umo_atomic64_create failed " << ret;

    // Another client tries to destroy the object
    ret = umo_atomic64_destroy(client_id2, object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_INVALID_OWNER) << "umo_atomic64_destroy failed " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_CREATE) << "umo_atomic64_destroy failed " << ret;

    // Test case: Exceeding object creation limit
    int ids[102400];
    for (int i = 0; i < 102400; i++) {
        desc.p_desc = reinterpret_cast<char*>(&i);
        desc.len = sizeof(int);
        ret = umo_atomic64_create(client_id, &desc, val, &ids[i]);
        ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;
    }

    desc.p_desc = const_cast<char*>("object desc 1");
    desc.len = static_cast<uint32_t>(strlen("object desc 1"));
    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_TOO_MANY) << "umo_atomic64_create failed " << ret;

    for (int i = 0; i < 102400; i++) {
        ret = umo_atomic64_destroy(client_id, ids[i]);
        ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed " << ret;
    }

    ret = client_deinit(client_id);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    ret = client_deinit(client_id2);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    stop_primary_server1();
}

TEST_P(test_umo_atomic64_create_destroy, create_destroy_refresh_tests)
{
    trans_mode_t tp_mode = GetParam();
    int ret;

    startup_primary_server1(0, 0, false, false, tp_mode);

    init_dclient_lib_with_server1(false, tp_mode);

    ret = client_init(&client_id, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client init failed, ret: " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_get failed " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_ALREADY_DESTROYED) << "2nd umo_atomic64_destroy failed " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_ALREADY_DESTROYED) << "umo_atomic64_create failed " << ret;
    // To test refresh object lease time
    sleep(desc.lease_time + 1);
    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed " << ret;

    ret = client_deinit(client_id);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    stop_primary_server1();
}

TEST_P(test_umo_atomic64_create_destroy, create_no_destroy_tests)
{
    trans_mode_t tp_mode = GetParam();
    int ret;

    startup_primary_server1(0, 0, false, false, tp_mode);

    init_dclient_lib_with_server1(false, tp_mode);

    ret = client_init(&client_id, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client init failed, ret: " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;

    // No destroy called to test clear_m_object_map in server stop
    ret = client_deinit(client_id);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    stop_primary_server1();
}

// Instantiate parameterized tests with different `tp_mode` values
INSTANTIATE_TEST_CASE_P(
    ObjectCreateDestroyTests,
    test_umo_atomic64_create_destroy,
    ::testing::Values(SEPERATE_CONN, UNI_CONN)
);


class test_umo_atomic64_get_release : public ::testing::TestWithParam<trans_mode_t> {
protected:
    int client_id;
    char* server_ip;
    umo_atomic64_desc desc;
    uint64_t val;
    int object_id;

    void SetUp() override
    {
        client_id = 100;
        server_ip = strdup(PRIMARY_ADDRESS);
        val = 20;

        struct timeval tv_start;
        gettimeofday(&tv_start, nullptr);
        desc = {
            .p_desc = const_cast<char*>("object desc 1"),
            .len = static_cast<uint32_t>(strlen("object desc 1")),
            .lease_time = 60,
        };
    }

    void TearDown() override
    {
        free(server_ip);
        dclient_lib_deinit();
    }
};

TEST_P(test_umo_atomic64_get_release, get_release_tests)
{
    trans_mode_t tp_mode = GetParam();
    int ret;

    startup_primary_server1(0, 0, false, false, tp_mode);

    ret = umo_atomic64_get(client_id, nullptr, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc is nullptr " << ret;

    desc.p_desc = nullptr;
    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc.p_desc is nullptr " << ret;

    desc.p_desc = const_cast<char*>("object desc 1");
    desc.lease_time = 0;
    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_desc.lease_time = 0 " << ret;

    desc.lease_time = 6000;
    ret = umo_atomic64_get(client_id, &desc, nullptr);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "object_id is nullptr " << ret;

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "Client lib not initialized, ret: " << ret;

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "Client lib not initialized, ret: " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "Client not initialized, ret: " << ret;

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "Client not initialized, ret: " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client init failed, ret: " << ret;

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_CREATE) << "umo_atomic64_get failed " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed " << ret;

    // Test case: Get the object multiple times
    for (int i = 0; i < 10; i++) {
        int object_id2;
        ret = umo_atomic64_get(client_id, &desc, &object_id2);
        ASSERT_EQ(ret, 0) << "umo_atomic64_get failed [" << i << "] " << ret;
        ASSERT_EQ(object_id, object_id2) << "Object ID mismatch [" << i << "]: " << object_id << " != " << object_id2;
    }

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_release failed " << ret;

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_GET) << "umo_atomic64_release failed " << ret;

    int object_id3;
    ret = umo_atomic64_get(client_id, &desc, &object_id3);
    ASSERT_EQ(ret, 0) << "umo_atomic64_get failed " << ret;
    ASSERT_EQ(object_id, object_id3) << "Object ID mismatch: " << object_id << " != " << object_id3;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed " << ret;

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, DLOCK_OBJECT_ALREADY_DESTROYED) << "umo_atomic64_get after destroy failed " << ret;

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_release after destroy failed " << ret;

    ret = client_deinit(client_id);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "Client deinit failed, ret: " << ret;

    stop_primary_server1();
}

INSTANTIATE_TEST_CASE_P(
    ObjectGetReleaseTests,
    test_umo_atomic64_get_release,
    ::testing::Values(SEPERATE_CONN, UNI_CONN)
);

class test_umo_atomic64_ops : public ::testing::TestWithParam<trans_mode_t> {
protected:
    int client_id;
    char* server_ip;
    umo_atomic64_desc desc;
    uint64_t val;
    int object_id;

    void SetUp() override
    {
        server_ip = strdup(PRIMARY_ADDRESS);
        client_id = 102;
        object_id = 0;
        val = 20;

        desc = {
            .p_desc = const_cast<char*>("object desc 1"),
            .len = static_cast<uint32_t>(strlen("object desc 1")),
            .lease_time = 3600,
        };
    }

    void TearDown() override
    {
        free(server_ip);
        dclient_lib_deinit();
    }
};

TEST_P(test_umo_atomic64_ops, faa_cas_snapshot_tests)
{
    trans_mode_t tp_mode = GetParam();
    int ret;

    startup_primary_server1(0, 0, false, false, tp_mode);

    uint64_t a = 1;
    uint64_t b = 1;
    ret = umo_atomic64_faa(client_id, object_id, a, &b);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "umo_atomic64_faa failed " << ret;

    ret = umo_atomic64_cas(client_id, object_id, a, b);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "umo_atomic64_cas failed " << ret;

    ret = umo_atomic64_get_snapshot(client_id, object_id, &a);
    ASSERT_EQ(ret, DLOCK_CLIENTMGR_NOT_INIT) << "umo_atomic64_get_snapshot failed " << ret;

    init_dclient_lib_with_server1(false, tp_mode);

    ret = umo_atomic64_faa(client_id, object_id, a, &b);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "umo_atomic64_faa failed with " << ret;

    ret = umo_atomic64_cas(client_id, object_id, a, b);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "umo_atomic64_cas failed with " << ret;

    ret = umo_atomic64_get_snapshot(client_id, object_id, &a);
    ASSERT_EQ(ret, DLOCK_CLIENT_NOT_INIT) << "umo_atomic64_get_snapshot failed with " << ret;

    ret = umo_atomic64_faa(client_id, object_id, a, nullptr);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_faa failed with " << ret;

    ret = umo_atomic64_get_snapshot(client_id, object_id, nullptr);
    ASSERT_EQ(ret, DLOCK_EINVAL) << "umo_atomic64_get_snapshot failed with " << ret;

    ret = client_init(&client_id, server_ip);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client init failed, ret: " << ret;

    ret = umo_atomic64_faa(client_id, object_id, a, &b);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_GET) << "umo_atomic64_faa failed with " << ret;

    ret = umo_atomic64_cas(client_id, object_id, a, b);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_GET) << "umo_atomic64_cas failed with " << ret;

    ret = umo_atomic64_get_snapshot(client_id, object_id, &a);
    ASSERT_EQ(ret, DLOCK_OBJECT_NOT_GET) << "umo_atomic64_get_snapshot failed with " << ret;

    ret = umo_atomic64_create(client_id, &desc, val, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_create failed with " << ret;

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_get failed with " << ret;

    ret = umo_atomic64_get_snapshot(client_id, object_id, &a);
    ASSERT_EQ(ret, 0) << "umo_atomic64_get_snapshot failed with " << ret;
    ASSERT_EQ(a, val) << "umo_atomic64_get_snapshot returned unexpected value: " << a;

    a = 5;
    ret = umo_atomic64_faa(client_id, object_id, a, &b);
    ASSERT_EQ(ret, 0) << "umo_atomic64_faa failed with " << ret;
    ASSERT_EQ(b, val) << "umo_atomic64_faa returned unexpected value for b: " << b;

    uint64_t c = 25;
    uint64_t d = 1;
    ret = umo_atomic64_cas(client_id, object_id, c, d);
    ASSERT_EQ(ret, 0) << "umo_atomic64_cas failed with " << ret;

    ret = umo_atomic64_cas(client_id, object_id, c, d);
    ASSERT_EQ(ret, DLOCK_OBJECT_CAS_FAILED) << "umo_atomic64_cas failed with " << ret;

    ret = umo_atomic64_release(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_release failed with " << ret;

    ret = umo_atomic64_destroy(client_id, object_id);
    ASSERT_EQ(ret, 0) << "umo_atomic64_destroy failed with " << ret;

    ret = client_deinit(client_id);
    ASSERT_EQ(ret, DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;

    stop_primary_server1();
}

INSTANTIATE_TEST_CASE_P(
    ObjectOpsTests,
    test_umo_atomic64_ops,
    ::testing::Values(SEPERATE_CONN, UNI_CONN)
);