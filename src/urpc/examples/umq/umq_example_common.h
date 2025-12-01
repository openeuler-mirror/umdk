/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq example common header
 * Create: 2025-8-16
 * History: 2025-8-16
 */

#ifndef UMQ_EXAMPLE_COMMON_H
#define UMQ_EXAMPLE_COMMON_H

#include <time.h>
#include <stdio.h>

#include "urpc_util.h"
#include "umq_api.h"
#include "umq_pro_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PORT_MAX                  65535
#define DEFAULT_PORT              19875
#define TIME_SIZE                 35
#define UMQ_MAX_BIND_INFO_SIZE    512

extern const uint32_t EXAMPLE_SLEEP_TIME_US;
extern const uint32_t EXAMPLE_MAX_WAIT_TIME_MS;
extern const uint32_t EXAMPLE_TEST_IMM_DATA;

enum URPC_POLL_JFC_MODE {
    URPC_POLLING_JFC,
    URPC_INTERRUPT_JFC
};

enum URPC_WORKER_THREAD_MODE {
    DYNAMIC_WORKER_MODE,
    STATIC_WORKER_MODE
};

enum INSTANCE_MODE {
    NONE,
    SERVER,
    CLIENT
};

enum MEM_MODE {
    URPC_ALLOCATER,
    USER_PRIVATE
};

enum TRANS_MODE {
    TRANS_MODE_UB = 0,              // ub, max io size 64K
    TRANS_MODE_IB,                  // ib, max io size 64K
    TRANS_MODE_UCP,                 // ub offload, max io size 64K
    TRANS_MODE_IPC,                 // local ipc, max io size 10M
    TRANS_MODE_UBMM,                // ub share memory, max io size 8K
    TRANS_MODE_UB_PLUS,             // ub, max io size 10M
    TRANS_MODE_IB_PLUS,             // ib, max io size 10M
    TRANS_MODE_UBMM_PLUS,           // ub share memory, max io size 10M
    TRANS_MODE_MAX,
};

enum UMQ_TRANS_MODE {
    UMQ_TM_RC = 0,
    UMQ_TM_RS,
    UMQ_TM_MAX,
};

struct urpc_example_config {
    bool greeter_test_mode;                         /* true: enable greeter test mode */
    char *dev_name;                                 /* device name */
    char *server_ip;                                /* server host IP addr */
    uint16_t tcp_port;                              /* server TCP port */
    int case_type;                                  /* case type */
    bool is_ipv6;                                   /* ipv6 case */
    enum MEM_MODE mem_mode;
    enum INSTANCE_MODE instance_mode;
    enum URPC_WORKER_THREAD_MODE worker_mode;       /* worker thread mode: static or dynamic */
    enum URPC_POLL_JFC_MODE poll_mode;              /* enable Interrupt */
    uint32_t feature;
    enum TRANS_MODE trans_mode;
    int16_t eid_idx;
    uint16_t cna;
    enum UMQ_TRANS_MODE sub_trans_mode;
    uint32_t deid;
};

struct req_cb_arg {
    volatile int *rsp_received;
    struct urpc_buffer_allocator *allocator;
};

uint64_t init_and_create_umq(struct urpc_example_config *cfg, uint8_t *local_bind_info, uint32_t *bind_info_size);

int client_exchange_bind_info(const char *ip, uint16_t port, uint8_t *send_data, uint32_t send_len,
    uint8_t *recv_data, uint32_t *recv_len);

int server_exchange_bind_info(const char *ip, uint16_t port, uint8_t *send_data, uint32_t send_len,
    uint8_t *recv_data, uint32_t *recv_len);

int parse_trans_info(struct urpc_example_config *cfg, umq_init_cfg_t *init_cfg);

int example_post_rx(uint64_t umqh, uint32_t depth);
int example_poll_rx(uint64_t umqh, const char *check_data, uint32_t data_size, bool with_imm_data);
int example_post_tx(uint64_t umqh, const char *data, uint32_t data_size);
int example_poll_tx(uint64_t umqh);
int example_enqueue_data(uint64_t umqh, const char *data, uint32_t data_size);
int example_dequeue_data(uint64_t umqh, const char *check_data, uint32_t data_size);

void example_flush(uint64_t umqh);

int parse_arguments(int argc, char **argv, struct urpc_example_config *cfg);
void print_config(struct urpc_example_config *cfg);

#define LOG_PRINT(fmt, ...) do {                                                                        \
    char time_buffer[TIME_SIZE];                                                                        \
    log_get_current_time(time_buffer, TIME_SIZE);                                                       \
    (void)fprintf(stdout, "%s|%s|%d:"fmt"", time_buffer, __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
} while (0)
#define LOG_PRINT_ERR(fmt, ...) do {                                                                    \
    char time_buffer[TIME_SIZE];                                                                        \
    log_get_current_time(time_buffer, TIME_SIZE);                                                       \
    (void)fprintf(stderr, "%s|%s|%d:"fmt"", time_buffer, __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
} while (0)

void log_get_current_time(char *buffer, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
