/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: dlock app
*/
#ifndef DLOCK_TEST_H_
#define DLOCK_TEST_H_

#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <climits>
#include "../common/common.h"

#include "dlock_client_api.h"
#include "dlock_server_api.h"
#include "dlock_types.h"

using namespace dlock;

#define DLOCK_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#define DLOCK_EID_STR_MIN_LEN 3
#define DLOCK_MAX_EXPIRE_TIMEOUT 20

typedef struct {
    test_context_t *ctx;
    trans_mode_t trans_mode;
    uint32_t app_num;
    uint32_t app_id;
    uint64_t pid;
    uint64_t test_port;
    int server_id;
    bool ssl_enable;
    int log_level;
    int recovery_client_num;
    int *client_ids;
    int client_num;
} test_dlock_ctx_t;

test_dlock_ctx_t *test_dlock_ctx_init(int argc, char *argv[], int thread_num);
int test_str_to_u32(const char*buf, uint32_t *u32);
void test_dlock_u32_to_eid(uint32_t ipv4, dlock_eid_t *eid);
int test_dlock_str_to_eid(const char *buf, dlock_eid_t *eid);
void set_trans_eid(struct server_cfg *server_cfg, struct client_cfg *client_cfg, char *eid);
void get_default_server_config(test_dlock_ctx_t *ctx, struct server_cfg *config);
void get_default_client_config(test_dlock_ctx_t *ctx, struct client_cfg *config);
int test_dlock_server_init(test_dlock_ctx_t *ctx);
int test_dlock_server_uninit(test_dlock_ctx_t *ctx);
int test_dlock_client_init(test_dlock_ctx_t *ctx);
int test_client_init(test_dlock_ctx_t *ctx);
int test_client_uninit(test_dlock_ctx_t *ctx);
int test_server_prepare(test_dlock_ctx_t *ctx);
int test_client_prepare(test_dlock_ctx_t *ctx);
int test_dlock_client_uninit(test_dlock_ctx_t *ctx);
int test_dlock_ctx_uninit(test_dlock_ctx_t *ctx);
int test_dlock_atomic64_create_get(int client_id, struct umo_atomic64_desc *desc, uint64_t init_val, int *obj_id);
int test_dlock_atomic64_release_destroy(int client_id, int obj_id);
int test_trylock(int client_id, const struct lock_request *req, void *result);
int test_extend(int client_id, const struct lock_request *req, void *result);
int test_unlock(int client_id, int lock_id, void *result);
int test_get_lock(int client_id, struct lock_desc *p_lock, int *p_lock_id);

#endif