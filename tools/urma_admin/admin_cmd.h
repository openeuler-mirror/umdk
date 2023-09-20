/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: ioctl command header file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#ifndef ADMIN_CMD_H
#define ADMIN_CMD_H

#include "admin_parameters.h"

typedef struct admin_core_cmd_set_utp {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint8_t eid[URMA_EID_SIZE];
        uint32_t transport_type;
        bool spray_en;
        uint16_t data_udp_start;
        uint8_t udp_range;
    } in;
} admin_core_cmd_set_utp_t;

typedef struct admin_core_cmd_show_utp {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint8_t eid[URMA_EID_SIZE];
        uint32_t transport_type;
    } in;
} admin_core_cmd_show_utp_t;

typedef struct admin_cmd_query_stats {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint8_t eid[URMA_EID_SIZE];
        uint32_t tp_type;
        uint32_t type;
        uint32_t key;
    } in;
    struct {
        uint64_t tx_pkt;
        uint64_t rx_pkt;
        uint64_t tx_bytes;
        uint64_t rx_bytes;
        uint64_t tx_pkt_err;
        uint64_t rx_pkt_err;
    } out;
} admin_cmd_query_stats_t;

typedef struct admin_cmd_query_res {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint8_t eid[URMA_EID_SIZE];
        uint32_t tp_type;
        uint32_t type;
        uint32_t key;
    } in;
    struct {
        uint64_t addr;
        uint32_t len;
    } out;
} admin_cmd_query_res_t;

int admin_set_utp(const tool_config_t *cfg);
int admin_show_udp(const tool_config_t *cfg);
int admin_show_stats(const tool_config_t *cfg);
int admin_show_res(const tool_config_t *cfg);

#endif