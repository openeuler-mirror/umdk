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

/* For version compatibility */
#define BONDP_USER_CTL_BONDING BONDP_USER_CTL_BONDING

#define URMA_UBAGG_DEV_MAX_NUM        (20)
#define URMA_UBAGG_WR_BUF_SIZE        (3)
#define URMA_UBAGG_MAX_CR_CNT_PER_DEV (16)

typedef enum bondp_user_ctl_opcode {
    BONDP_USER_CTL_SET_BONDING_MODE_LEGACY = 4,
    BONDP_USER_CTL_ENABLE_SEG_CACHE,
    BONDP_USER_CTL_QUERY_PORT,
    BONDP_USER_CTL_SET_BONDING_MODE,
    BONDP_USER_CTL_GET_JFCE_FD_LIST,
} bondp_user_ctl_opcode_t;

// URMA_USER_CTL_BOND_SET_BONDING_MODE,
typedef enum bondp_bonding_mode {
    BONDP_BONDING_MODE_STANDALONE,
    BONDP_BONDING_MODE_ACTIVE_BACKUP,
    BONDP_BONDING_MODE_BALANCE,
    BONDP_BONDING_MODE_MAX,
} bondp_bonding_mode_t;

typedef enum bondp_bonding_level {
    BONDP_BONDING_LEVEL_IODIE,
    BONDP_BONDING_LEVEL_PORT,
    BONDP_BONDING_LEVEL_MAX,
} bondp_bonding_level_t;

typedef struct bondp_set_bonding_mode_in {
    bondp_bonding_mode_t bonding_mode;
    bondp_bonding_level_t bonding_level;
} bondp_set_bonding_mode_in_t;

// URMA_USER_CTL_BOND_QUERY_PORT
typedef struct bondp_query_port_in {
    union {
        urma_jfr_t *jfr;
        urma_jetty_t *jetty;
    };
} bondp_query_port_in_t;

typedef struct bondp_query_port_out {
    uint32_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    uint32_t active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_count;
} bondp_query_port_out_t;

typedef struct bondp_get_jfce_fd_list_in {
    urma_jfce_t *jfce;
} bondp_get_jfce_fd_list_in_t;

typedef struct bondp_get_jfce_fd_list_out {
    int fd_list[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t count;
} bondp_get_jfce_fd_list_out_t;

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

typedef struct bondp_jfc_cfg {
    urma_jfc_cfg_t base;
    const bondp_port_id_t *port_ids;
    uint32_t port_count;
} bondp_jfc_cfg_t;

typedef struct bondp_jfr_cfg {
    urma_jfr_cfg_t base;
    const bondp_port_id_t *port_ids;
    uint32_t port_count;
} bondp_jfr_cfg_t;

typedef struct bondp_jetty_cfg {
    urma_jetty_cfg_t base;
    const bondp_port_id_t *port_ids;
    uint32_t port_count;
} bondp_jetty_cfg_t;

typedef struct bondp_rjetty {
    urma_rjetty_t base;
    union {
        urma_jfs_t *jfs;
        urma_jetty_t *jetty;
    };
} bondp_rjetty_t;

typedef struct bondp_rjfr {
    urma_rjfr_t base;
    union {
        urma_jfs_t *jfs;
        urma_jetty_t *jetty;
    };
} bondp_rjfr_t;

typedef struct bondp_jfs_wr {
    urma_jfs_wr_t base;
    uint32_t src_chip_id;
    uint32_t dst_chip_id;
} bondp_jfs_wr_t;

urma_status_t urma_write_affinity(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,
                        urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
                        uint64_t dst, uint64_t src, uint32_t len,
                        urma_jfs_wr_flag_t flag, uint64_t user_ctx,
                        uint32_t src_chip_id, uint32_t dst_chip_id);

#ifdef __cplusplus
}
#endif
#endif
