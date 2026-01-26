/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uRPC 2.0 protocol
 */

#include "urpc_framework_types.h"
#include "urpc_framework_errno.h"
#include "protocol.h"

uint32_t urpc_hdr_size_get(urpc_hdr_type_t hdr_type, uint16_t flag __attribute__((unused)))
{
    (void)flag;
    switch (hdr_type) {
        case URPC_REQ: return sizeof(urpc_req_head_t);
        case URPC_ACK: return sizeof(urpc_ack_head_t);
        case URPC_RSP: return sizeof(urpc_rsp_head_t);
        default: break;
    }

    return URPC_U32_FAIL;
}
