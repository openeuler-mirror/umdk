/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider datapath schedule header file
 * Author: Wang Hang
 * Create: 2026-04-06
 * Note:
 * History: 2026-04-06   Create File
 */

#ifndef BONDP_DATAPATH_SCHEDULE_H
#define BONDP_DATAPATH_SCHEDULE_H

#include <stdint.h>

#include "bondp_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BONDP_CHIP_ID_MIN      1
#define BONDP_CHIP_ID_MAX      2
#define ACTIVE_PORT_PER_CHIP   2
#define CHIP_ROUTE_NUM         3

typedef struct bondp_chip_id_info {
    uint32_t src_chip_id;
    uint32_t dst_chip_id;
} bondp_chip_id_info_t;

int schedule_send(urma_target_jetty_t *tjetty, bondp_comp_t *bdp_comp, int *send_idx, int *target_idx,
    bondp_chip_id_info_t *info);

int schedule_recv(bondp_comp_t *bdp_comp, int *recv_idx);
int schedule_recv_n(bondp_comp_t *bdp_comp, uint32_t wr_num, uint32_t recv_wr_cnt[URMA_UBAGG_DEV_MAX_NUM]);

#ifdef __cplusplus
}
#endif

#endif // BONDP_DATAPATH_SCHEDULE_H
