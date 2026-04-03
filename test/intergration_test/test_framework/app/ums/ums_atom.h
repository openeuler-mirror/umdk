/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: ums app
*/
#ifndef UMS_TEST_H_
#define UMS_TEST_H_

#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <climits>
#include "../common/common.h"


#define UMS_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#define UMS_EID_STR_MIN_LEN 3
#define UMS_MAX_EXPIRE_TIMEOUT 20
#define UMS_IPV4_SIZE                (16)
#define UMS_IPV6_SIZE                (46)

typedef struct {
    test_context_t *ctx;
    uint32_t app_num;
    uint32_t app_id;
    uint64_t pid;
    uint64_t test_port;
    char *test_ip;
    int server_id;
    bool ssl_enable;
    int log_level;
    int recovery_client_num;
    int *client_ids;
    int client_num;
} test_ums_ctx_t;

test_ums_ctx_t *test_ums_ctx_init(int argc, char *argv[], int thread_num);
int query_proc_net_ums_detail_stream_num(const char *fbk, const char *msg);
void destroy_test_ums_ctx(test_ums_ctx_t *ctx);

#endif