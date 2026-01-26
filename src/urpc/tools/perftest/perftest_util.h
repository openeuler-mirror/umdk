/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: perftest utils
 * Create: 2024-3-6
 */

#ifndef PERFTEST_UTIL_H
#define PERFTEST_UTIL_H

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
#else
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PERFTEST_1M                     (1000000)
#define PERFTEST_1MB                    (0x100000)
#define DEFAULT_REQUEST_SIZE_4K         4096
#define DEFAULT_REQUEST_SIZE64          64
#define DEFAULT_DEPTH                   512
#define PERFTEST_DEV_NAME_SIZE          128
#define DEFAULT_LAT_TEST_ROUND          100000
#define DEFAULT_LISTEN_PORT             19876
#define MAX_SGE_SIZE                    32
#define DEFAULT_LISTEN_IP_ADDR          "127.0.0.1"
#define INTERRUPT_MAX_WAIT_TIME_MS      3000
#define ITER_MAX_WAIT_TIME_US           20000000

#define URPC_PERFTEST_ACCEPT_WAIT_US    (10000)     // 10ms
#define MAX_INFO_SIZE                   (512)

#define LOG_PRINT(fmt, ...) \
    (void)printf("%s|%s|%s|%d:" fmt "", __DATE__, __TIME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

typedef enum perftest_instance_mode {
    PERF_INSTANCE_NONE,
    PERF_INSTANCE_SERVER,
    PERF_INSTANCE_CLIENT,
    PERF_INSTANCE_MAX
} perftest_instance_mode_t;

typedef enum perftest_case_type {
    PERFTEST_CASE_LAT,
    PERFTEST_CASE_QPS,
    PERFTEST_CASE_MAX
} perftest_case_type_t;

typedef struct perftest_config {
    char dev_name[PERFTEST_DEV_NAME_SIZE];          // device name
    char local_ip[INET6_ADDRSTRLEN];                // local host IP addr
    char remote_ip[INET6_ADDRSTRLEN];               // remote host IP addr
    uint16_t tcp_port;                              // server TCP port

    perftest_case_type_t case_type;                 // test case, lat or qps
    perftest_instance_mode_t instance_mode;

    uint32_t size;                                  // request size
    // from which cpu core to set affinity for each thread, UINT32_MAX by default means no affinity
    uint32_t cpu_affinity;
    uint32_t thread_num;                            // worker thread number, client only support 1 for now

    uint32_t rx_depth;
    uint32_t tx_depth;

    bool interrupt;
    bool buf_multiplex;
} perftest_config_t;

typedef struct exchange_info {
    uint32_t msg_len;
    uint8_t data[MAX_INFO_SIZE];
} __attribute__((packed)) exchange_info_t;

int recv_data(int sock, uint8_t *recv_data, uint32_t recv_len);
int recv_exchange_data(int sock, exchange_info_t *info);

int send_exchange_data(int sock, exchange_info_t *info);

static inline int is_ipv4(const char *ip)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

static inline int is_ipv6(const char *ip)
{
    struct in6_addr addr6;
    return inet_pton(AF_INET6, ip, &addr6) == 1;
}

void perftest_force_quit(void);
bool is_perftest_force_quit(void);
void signal_handler(int signum);
void init_signal_handler(void);

bool perftest_get_remote_sockaddr(perftest_config_t *cfg, struct sockaddr_storage *addr, socklen_t *addr_len);
int perftest_create_socket(perftest_config_t *cfg, struct sockaddr_storage *addr, socklen_t *addr_len, bool is_server);
int perftest_create_server_socket(perftest_config_t *cfg);
int perftest_create_client_socket(perftest_config_t *cfg);

int perftest_server_do_accept(perftest_config_t *cfg, int fd, volatile bool *force_quit);

// client send "sync" and wait for "ack"
int perftest_client_sync(int fd);
// server wait for "sync" and send "ack"
int perftest_server_sync(int fd);

#ifdef __cplusplus
}
#endif

#endif  // PERFTEST_UTIL_H