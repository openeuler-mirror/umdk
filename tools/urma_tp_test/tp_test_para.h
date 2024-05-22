/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: parse parameters header file for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2024-01-31   create file
 */

#ifndef TP_TEST_PARA_H
#define TP_TEST_PARA_H

#include <stdint.h>
#include <stdbool.h>
#include "ub_list.h"
#include "urma_types.h"

#define TP_TEST_RESULT_LINE "---------------------------------------------------------------------------------------\n"
#define TP_TEST_DEFAULT_ITERS  10
#define TP_TEST_DEF_PORT (23416)

typedef struct tp_test_client_comm {
    int sock_fd;
} tp_test_client_comm_t;

typedef struct tp_test_client_node {
    struct ub_list node;
    int sock_fd;
} tp_test_client_node_t;

typedef struct tp_test_server_comm {
    int listen_fd;
    struct ub_list client_list;
    int now_num;
} tp_test_server_comm_t;

typedef enum tp_test_type {
    TP_TEST_LAT,
    TP_TEST_BW
} tp_test_type_t;

typedef struct tp_test_config {
    tp_test_type_t type;
    char dev_name[URMA_MAX_NAME];      /* The name of ubep device. */
    urma_transport_mode_t tp_mode;
    uint64_t iters;
    uint32_t thread_num;
    uint32_t eid_num;
    uint32_t ctxs_pre_eid;
    uint32_t jettys_pre_ctx;

    char *server_ip;
    uint16_t port;                          /* Server port for bind or connect, default 21115. */
    bool is_server;

    tp_test_client_comm_t client;
    uint32_t client_num;
    tp_test_server_comm_t server;
} tp_test_config_t;

enum tp_test_opts {
    TP_TEST_OPT_TYPE_NUM = 1,
    TP_TEST_OPT_DEV_NAME_NUM,
    TP_TEST_OPT_TP_MODE_NUM,
    TP_TEST_OPT_ITERS_NUM,
    TP_TEST_OPT_THREAD_NUM,
    TP_TEST_OPT_SERVER_IP_NUM,
    TP_TEST_OPT_SERVER_PORT_NUM,
    TP_TEST_OPT_CLIENT_NUM,
    TP_TEST_OPT_EID_NUM,
    TP_TEST_OPT_CTXS_PRE_EID,
    TP_TEST_OPT_JETTYS_PRE_CTX,
};

void print_cfg(const tp_test_config_t *cfg);
int parse_args(int argc, char *argv[], tp_test_config_t *cfg);
void destroy_cfg(tp_test_config_t *cfg);
int check_local_cfg(tp_test_config_t *cfg);
int check_remote_cfg(tp_test_config_t *cfg);
#endif