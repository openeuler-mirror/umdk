/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond environment configuration header file
 */

#ifndef BONDP_ENV_H
#define BONDP_ENV_H

#include <stdbool.h>
#include <stdint.h>

#include "bondp_topo_info.h"
#include "urma_ubagg.h"

typedef struct bondp_env {
    bool enable_failover;
    bool enable_failback;
    bool enable_health_check;
    uint64_t health_check_interval_ms;
    uint32_t failover_route[IODIE_NUM][IODIE_NUM][URMA_ACTIVE_PORT_PER_DIE][URMA_FAILOVER_LINK_NUM];
    bondp_path_t path[IODIE_NUM * IODIE_NUM * URMA_ACTIVE_PORT_PER_DIE + 1];
} bondp_env_t;

extern bondp_env_t g_bondp_env;

void bondp_env_init(void);

#endif /* BONDP_ENV_H */
