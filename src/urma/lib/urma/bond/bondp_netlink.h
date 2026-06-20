/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: bond provider support netlink.
 */
#ifndef BONDP_NETLINK_H
#define BONDP_NETLINK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bondp_nl_attr {
    BONDP_NL_ATTR_UNSPEC = 0,
    BONDP_NL_ATTR_EID = 5,
    BONDP_NL_ATTR_BONDING_PHYSICAL_DEVICE = 6,
    BONDP_NL_ATTR_PAYLOAD = 7,
    BONDP_NL_ATTR_MAX = 8,
} bondp_nl_attr_t;

typedef enum bondp_nl_cmd {
    BONDP_NL_CMD_UNSPEC = 0,
    BONDP_NL_CMD_GET_TOPO = 1,
    BONDP_NL_CMD_GET_SLAVE_EID = 2,
    BONDP_NL_CMD_GET_PHYSICAL_DEVICE = 4,
    BONDP_NL_CMD_GET_V2P_RES = 5,
    BONDP_NL_CMD_FAILBACK_NOTIFY = 6,
    BONDP_NL_CMD_FAILBACK_DONE = 7,
    BONDP_NL_CMD_MAX,
} bondp_nl_cmd_t;

int bondp_nl_sock_init(void);
void bondp_nl_sock_uninit(void);

int bondp_nl_worker_init(void);
void bondp_nl_worker_uninit(void);

#ifdef __cplusplus
}
#endif

#endif // BONDP_NETLINK_H
