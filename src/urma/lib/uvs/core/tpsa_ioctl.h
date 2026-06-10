/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: tpsa ioctl header file
 * Author: JiLei
 * Create: 2023-7-3
 * Note:
 * History: 2023-7-3 port ioctl functions from tpsa_connect and daemon here
 */

#ifndef TPSA_IOCTL_H
#define TPSA_IOCTL_H

#include <sys/ioctl.h>
#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif
#include "tpsa_log.h"
#include "ub_util.h"
#include "uvs_api.h"
#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* only for uvs ubcore device ioctl */
#define TPSA_CMD_MAGIC 'V'
#define TPSA_CMD       _IOWR(TPSA_CMD_MAGIC, 1, tpsa_cmd_hdr_t)

typedef struct tpsa_ioctl_ctx {
    int ubcore_fd;
    atomic_ulong id; /* unique for every ioctl session */
} tpsa_ioctl_ctx_t;

typedef struct tpsa_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
} tpsa_cmd_hdr_t;

typedef enum uvs_mue_cmd {
    TPSA_CMD_CHANNEL_INIT = 1,
    UVS_CMD_SET_MUE_CFG,
    TPSA_CMD_CREATE_TPG,
    TPSA_CMD_CREATE_VTP,
    TPSA_CMD_MODIFY_TPG,
    TPSA_CMD_MODIFY_TPG_MAP_VTP,
    TPSA_CMD_MODIFY_TPG_TP_CNT,
    TPSA_CMD_CREATE_TARGET_TPG,
    TPSA_CMD_MODIFY_TARGET_TPG,
    TPSA_CMD_DESTROY_VTP,
    TPSA_CMD_DESTROY_TPG,
    TPSA_CMD_ADD_SIP,
    TPSA_CMD_DEL_SIP,
    TPSA_CMD_MAP_VTP,
    TPSA_CMD_CREATE_UTP,
    TPSA_CMD_ONLY_CREATE_UTP,
    TPSA_CMD_DESTROY_UTP,
    TPSA_CMD_GET_DEV_FEATURE,
    TPSA_CMD_RESTORE_TP_ERROR_RSP,
    TPSA_CMD_RESTORE_TARGET_TP_ERROR_REQ,
    TPSA_CMD_RESTORE_TARGET_TP_ERROR_ACK,
    TPSA_CMD_RESTORE_TP_SUSPEND,
    TPSA_CMD_CHANGE_TP_TO_ERROR,
    NOUSE_1,
    NOUSE_2,
    TPSA_CMD_CONFIG_FUNCTION_MIGRATE_STATE,
    TPSA_CMD_SET_VPORT_CFG,
    TPSA_CMD_MODIFY_VTP,
    TPSA_CMD_GET_DEV_INFO,
    TPSA_CMD_CHANGE_TPG_TO_ERROR,
    TPSA_CMD_ALLOC_EID,
    TPSA_CMD_DEALLOC_EID,
    TPSA_CMD_QUERY_UE_IDX,
    TPSA_CMD_CONFIG_DSCP_VL,
    TPSA_CMD_MAP_TARGET_VTP,
    TPSA_CMD_LIST_MIGRATE_ENTRY,
    TPSA_CMD_QUERY_DSCP_VL,
    UVS_CMD_DFX_QUERY_STATS,
    UVS_CMD_DFX_QUERY_RES,
    UVS_CMD_DISCOVER_DMAC,
    UVS_CMD_CLEAR_VICE_TPG,
    UVS_CMD_USER_CTL,
    TPSA_CMD_LAST
} uvs_mue_cmd_t;

typedef enum uvs_global_cmd {
    UVS_CMD_REGISTER_UVS = 1,
    UVS_CMD_UNREGISTER_UVS,
    UVS_CMD_GET_VTP_TABLE_CNT,
    UVS_CMD_RESTORE_TABLE,
    UVS_CMD_GET_TPG_TABLE_CNT,
    UVS_CMD_RESTORE_TPG_TABLE,
    UVS_CMD_GET_UE_TABLE_CNT,
    UVS_CMD_RESTORE_UE_TABLE,
    UVS_CMD_GLOBAL_SET_UPI,
    UVS_CMD_GLOBAL_SHOW_UPI,
    UVS_CMD_LIST_MUE,
    UVS_CMD_SET_TOPO,
    UVS_CMD_GET_TOPO,
    UVS_CMD_GET_PATH_SET,
    UVS_CMD_INSERT_MAIN_UE_EID,
    UVS_CMD_DELETE_MAIN_UE_EID,
    UVS_CMD_LOOKUP_MAIN_UE_EID,
    UVS_CMD_FLUSH_MAIN_UE_EID,
    UVS_CMD_INSERT_MAIN_UE_EID_BATCH,
    UVS_CMD_INSERT_HOST_EID_BATCH,
    UVS_CMD_GLOBAL_LAST
} uvs_global_cmd_t;

typedef struct uvs_set_topo {
    struct {
        void *topo_info;
        uint32_t topo_num;
    } in;
} uvs_set_topo_t;

typedef struct uvs_get_topo {
    struct {
        void *topo_map;
    } out;
} uvs_get_topo_t;

typedef struct uvs_cmd_main_ue_eid_entry {
    struct {
        uvs_main_ue_eid_entry_t entry;
    } in;
} uvs_cmd_main_ue_eid_entry_t;

typedef struct uvs_cmd_main_ue_eid_delete {
    struct {
        uvs_eid_t eid;
    } in;
} uvs_cmd_main_ue_eid_delete_t;

typedef struct uvs_cmd_main_ue_eid_lookup {
    struct {
        uvs_eid_t eid;
    } in;
    struct {
        uvs_eid_t main_ue_eid;
    } out;
} uvs_cmd_main_ue_eid_lookup_t;

typedef struct uvs_cmd_main_ue_eid_flush {
    struct {
        int status;
    } out;
} uvs_cmd_main_ue_eid_flush_t;

typedef struct uvs_cmd_main_ue_eid_batch {
    struct {
        uvs_main_ue_eid_batch_entry_t entry;
    } in;
} uvs_cmd_main_ue_eid_batch_t;

#define UVS_HOST_EID_BATCH_EID_MAX 32U

typedef struct uvs_host_eid_batch_entry {
    uvs_eid_t host_eid;
    uint32_t eid_num;
    uvs_eid_t eids[UVS_HOST_EID_BATCH_EID_MAX];
} uvs_host_eid_batch_entry_t;

typedef struct uvs_cmd_host_eid_batch {
    struct {
        uvs_host_eid_batch_entry_t entry;
    } in;
} uvs_cmd_host_eid_batch_t;

typedef struct uvs_cmd_get_path_set {
    struct {
        uvs_eid_t src_bonding_eid;
        uvs_eid_t dst_bonding_eid;
        uvs_tp_type_t tp_type;
        bool iodie_level;
    } in;
    struct {
        uvs_path_set_t path_set;
    } out;
} uvs_cmd_get_path_set_t;

int uvs_ioctl_in_global(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_global_cmd_t cmd, void *arg, uint32_t arg_len);
int uvs_ioctl_set_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_set_topo_t *arg);
int uvs_ioctl_get_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_get_topo_t *arg);
int uvs_ioctl_get_path_set(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_cmd_get_path_set_t *arg);
int uvs_ioctl_insert_main_ue_eid(tpsa_ioctl_ctx_t *ioctl_ctx,
    uvs_cmd_main_ue_eid_entry_t *arg);
int uvs_ioctl_delete_main_ue_eid(tpsa_ioctl_ctx_t *ioctl_ctx,
    uvs_cmd_main_ue_eid_delete_t *arg);
int uvs_ioctl_lookup_main_ue_eid(tpsa_ioctl_ctx_t *ioctl_ctx,
    uvs_cmd_main_ue_eid_lookup_t *arg);
int uvs_ioctl_flush_main_ue_eid(tpsa_ioctl_ctx_t *ioctl_ctx);
int uvs_ioctl_insert_main_ue_eid_batch(tpsa_ioctl_ctx_t *ioctl_ctx,
    uvs_cmd_main_ue_eid_batch_t *arg);
int uvs_ioctl_insert_host_eid_batch(tpsa_ioctl_ctx_t *ioctl_ctx,
    uvs_cmd_host_eid_batch_t *arg);
#ifdef __cplusplus
}
#endif

#endif
