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
#define EXAMPLE_MAX_DEV_NUM       10
#define EXAMPLE_DEV_NAME_LEN      15
#define EXAMPLE_SLEEP_TIME_US     100
#define EXAMPLE_MAX_WAIT_TIME_MS  3000
#define EXAMPLE_FLUSH_TIME_MS     1000
#define EXAMPLE_TEST_IMM_DATA     1234

typedef enum instance_mode {
    NONE,
    SERVER,
    CLIENT
} instance_mode_t;

typedef enum example_case_type {
    CASE_TYPE_DEFAULT = 0,
    CASE_TYPE_CONNEXTION,
    CASE_TYPE_MAX,
} example_case_type_t;

struct urpc_example_config {
    char *dev_name;                                 /* device name */
    char *server_ip;                                /* server host IP addr */
    uint16_t tcp_port;                              /* server TCP port */
    int case_type;                                  /* case type */
    bool is_ipv6;                                   /* ipv6 case */
    instance_mode_t instance_mode;
    umq_queue_mode_t poll_mode;                     /* enable Interrupt */
    uint32_t feature;
    umq_trans_mode_t trans_mode;
    int16_t eid_idx;
    uint16_t cna;
    uint32_t deid;
    umq_tp_mode_t tp_mode;
    umq_tp_type_t tp_type;
    uint32_t queue_num;
    int thread_poll_size;
    char m_dev_name[EXAMPLE_MAX_DEV_NUM][EXAMPLE_DEV_NAME_LEN];
    uint16_t m_eid_idx[EXAMPLE_MAX_DEV_NUM];
    uint32_t m_dev_num;
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

int send_exchange_data(int sock, uint8_t *send_data, uint32_t send_len);
int recv_exchange_data(int sock, uint8_t *recv_data, uint32_t *recv_len);
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
