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

typedef enum uvs_global_cmd {
    UVS_CMD_SET_TOPO = 1,
    UVS_CMD_GET_TOPO_EID = 2,
    UVS_CMD_GET_TOPO = 3,
    UVS_CMD_GET_TOPO_PATH_EID = 4,
    UVS_CMD_INSERT_MAIN_UE_EID = 5,
    UVS_CMD_DELETE_MAIN_UE_EID = 6,
    UVS_CMD_LOOKUP_MAIN_UE_EID = 7,
    UVS_CMD_FLUSH_MAIN_UE_EID = 8,
    UVS_CMD_INSERT_MAIN_UE_EID_BATCH = 9,
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

typedef struct uvs_cmd_get_route_list {
    uvs_route_t in;
    uvs_route_list_t out;
} uvs_cmd_get_route_list_t;

typedef struct uvs_cmd_get_path_set {
    struct {
        uvs_eid_t src_bonding_eid;
        uvs_eid_t dst_bonding_eid;
        uvs_tp_type_t tp_type;
        bool multi_path;
    } in;
    uvs_path_set_t out;
} uvs_cmd_get_path_set_t;

int uvs_ioctl_in_global(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_global_cmd_t cmd, void *arg, uint32_t arg_len);
int uvs_ioctl_set_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_set_topo_t *arg);
int uvs_ioctl_get_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_get_topo_t *arg);
int uvs_ioctl_get_route_list(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_cmd_get_route_list_t *arg);
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
#ifdef __cplusplus
}
#endif

#endif
