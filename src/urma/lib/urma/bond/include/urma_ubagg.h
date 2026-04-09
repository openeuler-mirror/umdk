/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: URMA ubagg provider private API header
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05   Create File
 */
#ifndef URMA_UBAGG_H
#define URMA_UBAGG_H

#include <stdint.h>
#include <stdbool.h>
#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URMA_UBAGG_DEV_MAX_NUM (20)
#define URMA_UBAGG_WR_BUF_SIZE (3)
#define URMA_UBAGG_HDR_BUF_SIZE (0x1000) // 4K
#define URMA_UBAGG_MAX_CR_CNT_PER_DEV (16)

typedef enum urma_bond_user_ctl_opcode {
    URMA_USER_CTL_BOND_GET_ID_INFO = 0,
    URMA_USER_CTL_BOND_ADD_RJFR_ID_INFO,
    URMA_USER_CTL_BOND_ADD_RJETTY_ID_INFO,
    URMA_USER_CTL_BOND_GET_SEG_INFO,
    URMA_USER_CTL_BOND_ADD_REMOTE_SEG_INFO,
    URMA_USER_CTL_BOND_SET_AGGR_MODE,
    URMA_USER_CTL_BOND_ENABLE_SEG_CACHE,
} urma_bond_user_ctl_opcode_t;

typedef struct urma_bond_seg_info_in {
    urma_target_seg_t *tseg;
} urma_bond_seg_info_in_t;

typedef struct urma_bond_seg_info_out {
    urma_seg_t base;
    urma_seg_t slaves[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
} urma_bond_seg_info_out_t;

typedef struct urma_bond_id_info_in {
    union {
        urma_jfr_t *jfr;
        urma_jetty_t *jetty;
    };
    urma_target_type_t type;
} urma_bond_id_info_in_t;

#define PORT_NUM (9)
#define IODIE_NUM (2)

typedef struct urma_bond_id_info_out {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    bool is_multipath;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
    uint32_t ports[IODIE_NUM][PORT_NUM];
} urma_bond_id_info_out_t;

typedef struct urma_bond_id_info_out urma_bond_add_rjfr_id_info_in_t;
typedef struct urma_bond_id_info_out urma_bond_add_rjetty_id_info_in_t;
typedef urma_bond_seg_info_out_t urma_bond_add_remote_seg_info_in_t;
#ifdef __cplusplus
}
#endif
#endif
