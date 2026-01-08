/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib early response
 */

#ifndef URPC_LIB_CLIENT_H
#define URPC_LIB_CLIENT_H

#include "urpc_framework_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int client_run(
    uint32_t chid, uint64_t qh, urpc_channel_qinfos_t *qinfos, uint64_t func_id, const urpc_allocator_t *allocator);
#ifdef __cplusplus
}
#endif

#endif /* URPC_LIB_CLIENT_H */