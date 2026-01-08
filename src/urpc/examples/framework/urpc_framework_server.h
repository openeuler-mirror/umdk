/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib early response
 */

#ifndef URPC_LIB_SERVER_H
#define URPC_LIB_SERVER_H

#include "urpc_framework_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int server_run_early_response(uint64_t qh, uint64_t qh1, const urpc_allocator_t *allocator);
int server_run_timeout(uint64_t qh, urpc_allocator_t *allocator);

#ifdef __cplusplus
}
#endif

#endif /* URPC_LIB_SERVER_H */