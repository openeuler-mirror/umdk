/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib common tools
 */

#ifndef LIB_COMMON_H
#define LIB_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include "urpc_framework_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PORT_MAX                65535
#define DEFAULT_PORT            19875
#define DEFAULT_MSG_SIZE        4096
// header sge, user header sge, save dma info sge, header dma sge, data dma sge
#define EXT_SGE_NUM             4
#define EXT_RSP_NUM             3
#define DEFAULT_EXT_MSG_SIZE    (DEFAULT_MSG_SIZE * EXT_SGE_NUM)
#define DEFAULT_EXT_RSP_SIZE    (DEFAULT_MSG_SIZE * EXT_RSP_NUM)
#define DEFAULT_RX_DEPTH        64
#define DEFAULT_TX_DEPTH        64
#define DEFAULT_FUNC_ID         8388612
#define REQ_HDR_SGE             0
#define SEND_PUSH_DATA_SGE      1          // send push scene
#define HEAD_DMA_SGE            2
#define DATA_DMA_SGE            1
#define SAVA_DMA_SGE            4
#define RSP_HDR_SGE             0
#define RSP_DATA_SGE            1
#define SIMULATE_USER_HDR_SIZE  192
// reserve space at the tail of ext_hdr for encryption fields (iv & tag)
#define CRYPTO_FIELD_SIZE       28
#define CLIENT_USE_SGE_SIZE     256
#define URPC_REQ_HEAD_LEN       20
#define URPC_EXT_HEADER_SIZE    256
#define DMA_CNT                 5
#define TIME_SIZE               35
#define TIME_US_SIZE            8
#define QCUSTOM_FLAG            0x123

#define LOG_PRINT(fmt, ...) do {                                                                        \
    char time_buffer[TIME_SIZE];                                                                        \
    get_current_time(time_buffer, TIME_SIZE);                                                           \
    (void)fprintf(stdout, "%s|%s|%d:"fmt"", time_buffer, __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
} while (0)
#define LOG_PRINT_ERR(fmt, ...) do {                                                                    \
    char time_buffer[TIME_SIZE];                                                                        \
    get_current_time(time_buffer, TIME_SIZE);                                                           \
    (void)fprintf(stderr, "%s|%s|%d:"fmt"", time_buffer, __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
} while (0)

typedef enum instance_mode {
    NONE,
    SERVER,
    CLIENT
} instance_mode_t;

typedef enum example_case_type {
    EARLY_RESPONSE,
    EXAMPLE_CASE_MAX
} example_case_type_t;

typedef struct client_test_case {
    char *name;
    uint64_t func_id;
    uint32_t hit_event_num;
    uint32_t hit_events;
    void (*func)(uint64_t qh, urpc_channel_qinfos_t *qinfos, urpc_call_option_t *option);
} client_test_case_t;

typedef struct urpc_lib_example_config {
    uint64_t qh;                                    /* server queue handle */
    char *dev_name;                                 /* device name */
    char *eid;                                      /* Eid */
    char *ip_addr;                                  /* server host IP addr */
    char *loc_ip_addr;                              /* assigned local IP addr */
    char *path;                                     /* unix domain socket file path */
    uint16_t port;                                  /* server TCP port */
    uint16_t loc_port;                              /* assigned local TCP port */
    instance_mode_t instance_mode;
    example_case_type_t example_case;
    uint32_t trans_mode;
    uint32_t dev_assign_mode;
    uint64_t func_id;
    bool enable_shared_jfr;  // share jfr+jfr_jfc
    bool enable_shared_jfs_jfc;
    bool ipv6;
    bool attach_ipv6;
    bool use_ssl;
    char *psk_id;
    char *psk_key;
    bool head_encrypt_disabled;
    bool payload_encrypt_disabled;
    bool bind_local_addr_enabled;
    bool nonblock_enabled;
    bool is_long_connect;
    bool multiplex_enabled;
    bool is_cancel;
} urpc_lib_example_config_t;

typedef enum urpc_lib_example_msg_type {
    WITHOUT_DMA,
    WITH_DMA,
} urpc_lib_example_msg_type_t;

typedef struct custom_head {
    urpc_lib_example_msg_type_t msg_type;
    uint32_t dma_num;
} custom_head_t;

typedef struct urpc_example_dma {
    uint64_t address;
    uint32_t size;
    uint32_t token_id;
    uint32_t token_value;
} urpc_example_dma_t;

void get_current_time(char* buffer, uint32_t len);

urpc_lib_example_config_t *get_example_cfg(void);
bool is_example_force_quit(void);

#ifdef __cplusplus
}
#endif

#endif /* LIB_COMMON_H */