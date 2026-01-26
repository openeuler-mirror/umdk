/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest param process
 * Create: 2024-3-6
 */

#ifndef URPC_LIB_PERFTEST_PARAM_H
#define URPC_LIB_PERFTEST_PARAM_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#include "perftest_util.h"

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off
enum INSTANCE_MODE {
    NONE,
    SERVER,
    CLIENT
};

typedef enum data_trans_mode {
    DATA_TRANS_MODE_SEND,
    DATA_TRANS_MODE_READ,
    DATA_TRANS_MODE_MAX,
} data_trans_mode_t;

#define DEFAULT_REQUEST_SIZE64 64
#define DEFAULT_REQUEST_SIZE4K 4096
#define URPC_PERFTEST_RX_BUF_SIZE 4096
#define DEFAULT_RX_DEPTH 512
#define DEFAULT_TX_DEPTH 512
#define URPC_PERFTEST_DEV_NAME_SIZE 128
#define DEFAULT_LAT_TEST_ROUND 100000
#define DEFAULT_LISTEN_IP_ADDR "127.0.0.1"
#define MAX_SGE_SIZE     32

typedef struct perftest_framework_config {
    char path[PATH_MAX + 1];
    char dev_name[URPC_PERFTEST_DEV_NAME_SIZE];  // device name
    char local_ip[INET6_ADDRSTRLEN];            // local host IP addr
    char remote_ip[INET6_ADDRSTRLEN];            // remote host IP addr
    uint16_t tcp_port;                           // server TCP port
    perftest_case_type_t case_type;              // test case, lat or qps
    uint32_t thread_num;                         // test thread number, same as qh number
    uint32_t cpu_affinity;  // from which cpu core to set affinity for each thread, -1 by default means no affinity
    uint32_t size[MAX_SGE_SIZE];    // request size
    uint32_t size_len;
    uint32_t size_total;    // record sum of all sizes
    uint32_t func_period;
    uint32_t trans_mode;
    uint32_t rx_depth;
    uint32_t tx_depth;
    enum INSTANCE_MODE instance_mode;
    uint8_t target_queue;   // target-queue index of remote for client to send request to
    bool hwub_offlad;
    bool show_thread_qps;
    bool use_one_q;
    bool alloc_buf;
    bool align;
    bool is_ipv6_dev;
    uint32_t con_num;
    data_trans_mode_t data_trans_mode;
} perftest_framework_config_t;

int urpc_perftest_parse_arguments(int argc, char **argv, perftest_framework_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_PARAM_H
