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
#include "ub_util.h"
#include "uvs_types.h"
#include "tpsa_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* only for uvs ubcore device ioctl */
#define TPSA_CMD_MAGIC 'V'
#define TPSA_CMD _IOWR(TPSA_CMD_MAGIC, 1, tpsa_cmd_hdr_t)

typedef struct tpsa_ioctl_ctx {
    int ubcore_fd;
    atomic_ulong id;  /* unique for every ioctl session */
} tpsa_ioctl_ctx_t;

typedef struct tpsa_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
} tpsa_cmd_hdr_t;

typedef enum uvs_global_cmd {
    UVS_CMD_SET_TOPO = 1,
    UVS_CMD_GET_TOPO_EID = 2,
    UVS_CMD_GLOBAL_LAST
} uvs_global_cmd_t;

typedef struct uvs_set_topo {
    struct {
        void *topo_info;
        uint32_t topo_num;
    } in;
} uvs_set_topo_t;

typedef struct uvs_cmd_get_topo_eid {
    struct {
        uint32_t tp_type;
        uvs_eid_t src_v_eid;
        uvs_eid_t dst_v_eid;
    } in;
    struct {
        uvs_eid_t src_p_eid;
        uvs_eid_t dst_p_eid;
    } out;
} uvs_cmd_get_topo_eid_t;

int uvs_ioctl_in_global(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_global_cmd_t cmd, void *arg, uint32_t arg_len);
int uvs_ioctl_set_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_set_topo_t *arg);
int uvs_ioctl_get_topo_eid(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_cmd_get_topo_eid_t *arg);

#ifdef __cplusplus
}
#endif

#endif
