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

int schedule_send(urma_target_jetty_t *tjetty, bondp_comp_t *bdp_comp, int *send_idx, int *target_idx);

int schedule_recv(bondp_comp_t *bdp_comp, int *recv_idx);

#endif // BONDP_DATAPATH_SCHEDULE_H
