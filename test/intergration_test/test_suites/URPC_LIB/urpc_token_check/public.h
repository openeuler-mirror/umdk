/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#ifndef PUBLIC_H
#define PUBLIC_H

#include "urpc_lib_atom.h"

#define CLIENT_NUM 6

int recalloc_ctx_queue_handles(test_urpc_ctx_t *ctx, uint64_t queue_nums);
int test_rpc_send_read(test_urpc_ctx_t *ctx);

#endif