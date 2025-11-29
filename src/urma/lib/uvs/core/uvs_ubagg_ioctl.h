/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: uvs ubagg ioctl header file
 * Author: Jiajun Liu
 * Create: 2025-06-05
 * Note:
 * History:
 */
#ifndef UVS_UBAGG_IOCTL_H
#define UVS_UBAGG_IOCTL_H
#include <stdint.h>

typedef enum uvs_ubagg_cmd {
    UVS_UBAGG_CMD_ADD_DEV = 1,
    UVS_UBAGG_CMD_RMV_DEV,
    UVS_UBAGG_CMD_SET_TOPO,
} uvs_ubagg_cmd_t;

struct uvs_ubagg_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
};

#define UVS_UBAGG_CMD_MAGIC 'B'
#define UVS_UBAGG_CMD _IOWR(UVS_UBAGG_CMD_MAGIC, 1, struct uvs_ubagg_cmd_hdr)

struct uvs_ubagg_set_topo_info {
    struct {
        void *topo;
        uint32_t topo_num;
    } in;
};

int uvs_ubagg_ioctl_set_topo(void *topo_info, int topo_num);
int uvs_ubcore_ioctl_set_topo(void *topo_info, int topo_num);
int uvs_ubcore_ioctl_get_route_list(const uvs_route_t *route, uvs_route_list_t *route_list);

#endif // UVS_UBAGG_IOCTL_H