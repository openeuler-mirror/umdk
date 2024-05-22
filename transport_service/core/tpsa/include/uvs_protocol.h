/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UVS protocol
 * Author: Zhao Yusu
 * Create: 2024-2-6
 * Note:
 * History: 2024-2-6 Zhao Yusu     UVS protocol wire format
 */

#ifndef UVS_PROTOCOL_H
#define UVS_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_PROTO_CUR_VERSION               0x0
#define UVS_PROTO_BASE_VERSION              0x0
#define UVS_PROTO_INVALID_VERSION           0xfffffffe      // Not used in wire format
#define UVS_PROTO_CAP                       0x0

#define UVS_PROTO_ACK_NULL                  0x0
#define UVS_PROTO_ACK_VER_NOT_SUPPORT       0x1

enum uvs_msg_type {
    UVS_CREATE_REQ = 0,             // Initiator --> target
    UVS_CREATE_RSP,                 // Target --> initiator
    UVS_CREATE_ACK_REQ,             // Target --> initiator
    UVS_CREATE_ACK_RSP,             // Initiator --> target
    UVS_DESTROY_REQ,                // Both
    UVS_DESTROY_RSP,                // Both
    UVS_GENERAL_ACK,                // Both
};

struct uvs_base_header {
    uint8_t     version;                // UVS protocol version
    uint8_t     msg_type;               // See "enum uvs_msg_type"
    uint16_t    length;                 // Total length of payload
    uint32_t    msn;                    // Message sequence number, to index message context
    uint16_t    cap;                    // Capability, currently not used
    uint16_t    flag;                   // Flag, for extention, currently not used
};

struct uvs_general_ack {
    uint32_t    code : 8;
    uint32_t    reserve : 24;
};

#ifdef __cplusplus
}
#endif

#endif /* UVS_PROTOCOL_H */