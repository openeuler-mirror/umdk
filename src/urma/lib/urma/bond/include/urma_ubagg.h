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

#include "urma_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URMA_UBAGG_DEV_MAX_NUM        (20)
#define URMA_UBAGG_WR_BUF_SIZE        (3)
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

#define PORT_NUM  (9)
#define IODIE_NUM (2)

typedef struct urma_bond_seg_info_out {
    urma_seg_t base;
    urma_seg_t slaves[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
} urma_bond_seg_info_out_t;

typedef struct urma_bond_id_info_out {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    bool is_multipath;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
    uint32_t ports[IODIE_NUM][PORT_NUM];
} urma_bond_id_info_out_t;

typedef union bondp_port_id {
    struct {
        uint8_t chip_id;
        uint8_t die_id;
        uint8_t port_idx; // portEID：0~8；primaryEID: UINT8_MAX
        uint8_t reserved;
    };
    uint64_t value;
} bondp_port_id_t;

typedef struct bondp_jfs_cfg {
    urma_jfs_cfg_t base;
    const bondp_port_id_t *port_ids;
    uint32_t port_count;
} bondp_jfs_cfg_t;

typedef struct bondp_jfr_cfg {
    urma_jfr_cfg_t base;
    bool multi_path;
} bondp_jfr_cfg_t;

typedef struct bondp_jetty_cfg {
    urma_jetty_cfg_t base;
    const bondp_port_id_t *port_ids;
    uint32_t port_count;
} bondp_jetty_cfg_t;

#ifdef __cplusplus
}
#endif
#endif
