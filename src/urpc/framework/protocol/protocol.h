/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uRPC 2.0 protocol
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "protocol_utils.h"
#include "urpc_framework_types.h"
#include "urpc_framework_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_DMA_COUNT           0
#define DEFAULT_FUNCTION_DEFINED    0
#define DEFAULT_REQ_ID_RANGE        1

#define URPC_PROTO_VERSION          (1)
#define URPC_CTL_HDR_OPCODE         2

#define URPC_KEEPALIVE_FUNCTION_ID  (0x002001000005)
#define URPC_KEEPALIVE_RSVD_BYTES   9

typedef enum urpc_msg_type {
    URPC_MSG_REQ,
    URPC_MSG_ACK,
    URPC_MSG_RSP,
    URPC_MSG_ACK_AND_RSP,
    URPC_MSG_READ
} urpc_msg_type_t;

typedef enum urpc_msg_status {
    URPC_STAT_SUCCESS,              // Server success to execute function
    URPC_STAT_SERVER_DECLINE,       // Server decline to execute function
    URPC_STAT_FUNCTION_ERR,         // Function is not supported
    URPC_STAT_REMOTE_LEN_ERR,       // Argument buffer is insufficient in server
    URPC_STAT_TIMEOUT,              // Server execute timeout
    URPC_STAT_VERSION_ERR,          // Version is mismatch
    URPC_STAT_URPC_HDR_ERR          // urpc hdr error
} urpc_msg_status_t;

enum urpc_ctl_opcode {
    URPC_CTL_SESSION_UPDATE,
    URPC_CTL_WORKER_CHANGE,
    URPC_CTL_FUNCTION_CHANGE,
    URPC_CTL_TP_INFO_UPDATE,
    URPC_CTL_SERVER_READY,
    URPC_CTL_QUEUE_INFO_ATTACH,
    URPC_CTL_QUEUE_INFO_DETACH,
    URPC_CTL_QUEUE_INFO_REFRESH,
    URPC_CTL_QUEUE_INFO_BIND,
    URPC_CTL_QUEUE_INFO_UNBIND,
    URPC_CTL_QUEUE_INFO_ADD,
    URPC_CTL_QUEUE_INFO_RM,
    URPC_CTL_TASK_CANCEL,
    URPC_CTL_MAX
};

typedef struct arg_dma {
    uint32_t size;
    uint64_t address;
    uint32_t token;
} __attribute__((packed)) arg_dma_t;

/** uRPC Request Head:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Version    |Type       |Ak|Rsvd |DMA count     |Function                                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                                                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Request Total Size                                                                             |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Request ID                                                                                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Client's uRPC Channel                                                  |Function Defined       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct urpc_req_head {
#if defined(__BIG_ENDIAN_BITFIELD)
    uint64_t version : 4;           // uRPC version
    uint64_t type : 4;              // Message type, defined in 'enum urpc_msg_type'
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint64_t type : 4;
    uint64_t version : 4;
#endif
#if defined(__BIG_ENDIAN_BITFIELD)
    uint64_t ack : 1;               // Indicates whether to response ACK message
    uint64_t rsvd : 2;
    uint64_t arg_dma_count : 5;     // Size of argument DMA table('ub_dma')
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint64_t arg_dma_count : 5;
    uint64_t rsvd : 2;
    uint64_t ack : 1;
#endif
    uint64_t function : 48;
    uint32_t req_total_size;        // Size of total request, including uRPC request head & argument DMA table
    uint32_t req_id;                // Unique ID of the urpc request
    uint32_t client_channel : 24;   // Channel of the client that sends the uRPC REQ message
    uint32_t function_defined : 8;  // Customized field of the called function
    arg_dma_t ub_dma[0];            // Argument DMA table
} __attribute__((packed)) urpc_req_head_t;

/** uRPC Acknowledge Head:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Version    |Type       |Rsvd                   |Request ID Range                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Request ID                                                                                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Client's uRPC Channel                                                  |Rsvd                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct urpc_ack_head {
#if defined(__BIG_ENDIAN_BITFIELD)
    uint8_t version : 4;            // uRPC version
    uint8_t type : 4;               // Message type, defined in 'enum urpc_msg_type'
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t type : 4;
    uint8_t version : 4;
#endif
    uint8_t rsvd1;
    uint16_t req_id_range;          // Range of request id
    uint32_t req_id;                // Unique ID of the urpc request
    uint32_t client_channel : 24;   // Channel of the client that receives the uRPC ACK message
    uint32_t rsvd2 : 8;
} __attribute__((packed)) urpc_ack_head_t;

/** uRPC Response Head:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Version    |Type       |Status                 |Request ID Range                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Request ID                                                                                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Client's uRPC Channel                                                  |Rsvd                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Response total size                                                                            |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct urpc_rsp_head {
#if defined(__BIG_ENDIAN_BITFIELD)
    uint8_t version : 4;            // uRPC version
    uint8_t type : 4;               // Message type, defined in 'enum urpc_msg_type'
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t type : 4;
    uint8_t version : 4;
#endif
    uint8_t status;                 // Message status
    uint16_t req_id_range;          // Range of request id
    uint32_t req_id;                // Unique ID of the urpc request
    uint32_t client_channel : 24;   // Channel of the client that receives the uRPC RSP message
    uint32_t function_defined : 8;  // Customized field of the function return
    uint32_t response_total_size;   // Size of the response total data, excluding the return_data_offset
    uint32_t return_data_offset[0]; // Offsets of the return data
} __attribute__((packed)) urpc_rsp_head_t;

/** uRPC Keepalive Head (44 bytes): Based on urpc_req_head_t
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Version    |Rsvd1  |Rsp|Status                 |Local Queue ID                                 |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Server's Manager uRPC Channel                                          |Rsvd2                  |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Rsvd (8 + 28 Bytes)                                                                            |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct urpc_keepalive_head {
#if defined(__BIG_ENDIAN_BITFIELD)
    uint8_t version : 4;  // keepalive version
    uint8_t rsvd1 : 3;
    uint8_t is_rsp : 1;  // is keepalive response
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t is_rsp : 1;
    uint8_t rsvd1 : 3;
    uint8_t version : 4;
#endif
    uint8_t status;                // Status of keepalive message processing result
    uint16_t l_qid;                // Local queue id
    uint32_t server_channel : 24;  // Server manager channel id
    uint32_t rsvd2 : 8;
    uint32_t rsvd3[URPC_KEEPALIVE_RSVD_BYTES];  // last 28 bytes is Security Hdr when dp encrypt is enabled
} __attribute__((packed)) urpc_keepalive_head_t;

typedef struct urpc_ctl_head {
    uint8_t version;
    uint8_t opcode;
    int16_t error_code;
    uint16_t dp_encrypt : 1;
    uint16_t keepalive : 1;
    uint16_t primary_is_server : 1;             // primary keepalive task is server or client
    uint16_t detach_manage : 1;                 // detach manage channel if client has no channel
    uint16_t manage_channel_created : 1;        // client create new manage channel
    uint16_t func_info_enabled : 1;             // func info is enabled
    uint16_t is_start : 1;                      // indicates the start of a new task.
    uint16_t multiplex_enabled : 1;
    uint16_t rsvd1 : 8;
    uint16_t rsvd2;
    uint32_t channel;                           // Channel ID
    uint32_t data_size;                         // Payload size of the request/response (fragment)
    uint32_t ctl_opcode;                        // fill `enum urpc_ctl_opcode`
    int task_id;
} __attribute__((packed)) urpc_ctl_head_t;

/** uRPC Security Extension Header:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                             IV(12B)                                           |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                             TAG(16B)                                          |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct urpc_security_exthdr {
    uint8_t iv[URPC_AES_IV_LEN];
    uint8_t tag[URPC_AES_TAG_LEN];
} __attribute__((packed)) urpc_security_exthdr_t;

/**
 * Fill basic information for uRPC request head.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * @param[in] ack:                  Indicate whether to require ACK.
 * @param[in] client_channel:       Client Channel id.
 * Return: void.
 */
static inline void urpc_req_fill_basic_info(urpc_req_head_t *req_head, uint8_t ack, uint32_t client_channel)
{
    req_head->version = URPC_PROTO_VERSION;
    req_head->type = URPC_MSG_REQ;
    req_head->ack = ack;
    req_head->client_channel = proto_filed24_put(client_channel);
}

/**
 * Fill request information without dma for uRPC request head.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * @param[in] function:             The Function called in server.
 * @param[in] req_total_size:       Request total size.
 * @param[in] req_id:               Request id.
 * Return: void.
 */
static inline void urpc_req_fill_req_info_without_dma(urpc_req_head_t *req_head, uint64_t function,
    uint32_t req_total_size, uint32_t req_id, uint8_t function_defined)
{
    req_head->arg_dma_count = DEFAULT_DMA_COUNT;
    req_head->function = proto_filed48_put(function);
    req_head->req_total_size = proto_filed32_put(req_total_size);
    req_head->req_id = proto_filed32_put(req_id);
    req_head->function_defined = function_defined;
}

/**
 * Fill reply-one-request uRPC acknowledge head.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * @param[in] client_channel:       Client Channel id.
 * @param[in] req_id:               Request id.
 * Return: void.
 */
static inline void urpc_ack_fill_one_req_head(urpc_ack_head_t *ack_head, uint32_t client_channel, uint32_t req_id)
{
    ack_head->version = URPC_PROTO_VERSION;
    ack_head->type = URPC_MSG_ACK;
    ack_head->req_id_range = proto_filed16_put(DEFAULT_REQ_ID_RANGE);
    ack_head->req_id = proto_filed32_put(req_id);
    ack_head->client_channel = proto_filed24_put(client_channel);
}

/**
 * Fill basic information for uRPC response head.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * @param[in] status:               Message status.
 * @param[in] client_channel:       Client Channel id.
 * Return: void.
 */
static inline void urpc_rsp_fill_basic_info(
    urpc_rsp_head_t *rsp_head, uint8_t status, uint32_t client_channel, bool ack)
{
    rsp_head->version = URPC_PROTO_VERSION;
    rsp_head->type = ack ? URPC_MSG_ACK_AND_RSP : URPC_MSG_RSP;
    rsp_head->status = status;
    rsp_head->client_channel = proto_filed24_put(client_channel);
}

/**
 * Fill reply-one-request information for uRPC response head.
 * @param[in] rsp_head:                 Address of uRPC response head. Caller must ensure the validity of the address.
 * @param[in] req_id:                   Request id.
 * @param[in] response_total_size:      Size of the response total data, excluding the return_data_offset.
 * Return: void.
 */
static inline void urpc_rsp_fill_one_req_info(urpc_rsp_head_t *rsp_head, uint32_t req_id,
    uint32_t response_total_size, urpc_return_option_t *option)
{
    rsp_head->req_id_range = proto_filed16_put(DEFAULT_REQ_ID_RANGE);
    rsp_head->req_id = proto_filed32_put(req_id);
    rsp_head->response_total_size = proto_filed32_put(response_total_size);
    rsp_head->function_defined = (option != NULL && (bool)((option->option_flag & FUNC_RETURN_FLAG_FUNC_DEFINED)) ?
        option->func_defined : DEFAULT_FUNCTION_DEFINED);
}

/**
 * Parse version for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: version.
 */
static inline uint8_t urpc_req_parse_version(urpc_req_head_t *req_head)
{
    return req_head->version;
}

/**
 * Parse type for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: type.
 */
static inline uint8_t urpc_req_parse_type(urpc_req_head_t *req_head)
{
    return req_head->type;
}

/**
 * Parse ack for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: ack.
 */
static inline uint8_t urpc_req_parse_ack(urpc_req_head_t *req_head)
{
    return req_head->ack;
}

/**
 * Parse argument dma count for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: argument dma count.
 */
static inline uint8_t urpc_req_parse_arg_dma_count(urpc_req_head_t *req_head)
{
    return req_head->arg_dma_count;
}

/**
 * Parse function for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: function.
 */
static inline uint64_t urpc_req_parse_function(urpc_req_head_t *req_head)
{
    return proto_filed48_get(req_head->function);
}

/**
 * Parse request total size for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: request total size.
 */
static inline uint32_t urpc_req_parse_req_total_size(urpc_req_head_t *req_head)
{
    return proto_filed32_get(req_head->req_total_size);
}

/**
 * Parse request id for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: request id.
 */
static inline uint32_t urpc_req_parse_req_id(urpc_req_head_t *req_head)
{
    return proto_filed32_get(req_head->req_id);
}

/**
 * Parse client channel for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: client channel.
 */
static inline uint32_t urpc_req_parse_client_channel(urpc_req_head_t *req_head)
{
    return proto_filed24_get(req_head->client_channel);
}

/**
 * Parse function_defined for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: function_defined.
 */
static inline uint8_t urpc_req_parse_function_defined(urpc_req_head_t *req_head)
{
    return req_head->function_defined;
}

/**
 * Parse inline data for uRPC request.
 * @param[in] req_head:             Address of uRPC request head. Caller must ensure the validity of the address.
 * Return: the start address of inline data.
 */
static inline void *urpc_req_parse_inlinde_data(urpc_req_head_t *req_head)
{
    return (void *)((uint8_t *)(req_head + 1) + req_head->arg_dma_count * sizeof(arg_dma_t));
}

/**
 * Parse version for uRPC acknowledge.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * Return: version.
 */
static inline uint8_t urpc_ack_parse_version(urpc_ack_head_t *ack_head)
{
    return ack_head->version;
}

/**
 * Parse type for uRPC acknowledge.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * Return: type.
 */
static inline uint8_t urpc_ack_parse_type(urpc_ack_head_t *ack_head)
{
    return ack_head->type;
}

/**
 * Parse request id range for uRPC acknowledge.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * Return: request id range.
 */
static inline uint16_t urpc_ack_parse_req_id_range(urpc_ack_head_t *ack_head)
{
    return proto_filed16_get(ack_head->req_id_range);
}

/**
 * Parse request id for uRPC acknowledge.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * Return: request id.
 */
static inline uint32_t urpc_ack_parse_req_id(urpc_ack_head_t *ack_head)
{
    return proto_filed32_get(ack_head->req_id);
}

/**
 * Parse client channel for uRPC acknowledge.
 * @param[in] ack_head:             Address of uRPC acknowledge head. Caller must ensure the validity of the address.
 * Return: client channel.
 */
static inline uint32_t urpc_ack_parse_client_channel(urpc_ack_head_t *ack_head)
{
    return proto_filed24_get(ack_head->client_channel);
}

/**
 * Parse version for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: version.
 */
static inline uint8_t urpc_rsp_parse_version(urpc_rsp_head_t *rsp_head)
{
    return rsp_head->version;
}

/**
 * Parse type for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: type.
 */
static inline uint8_t urpc_rsp_parse_type(urpc_rsp_head_t *rsp_head)
{
    return rsp_head->type;
}

/**
 * Parse status for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: status.
 */
static inline uint8_t urpc_rsp_parse_status(urpc_rsp_head_t *rsp_head)
{
    return rsp_head->status;
}

/**
 * Parse request id range for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: request id range.
 */
static inline uint16_t urpc_rsp_parse_req_id_range(urpc_rsp_head_t *rsp_head)
{
    return proto_filed16_get(rsp_head->req_id_range);
}

/**
 * Parse request id for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: request id.
 */
static inline uint32_t urpc_rsp_parse_req_id(urpc_rsp_head_t *rsp_head)
{
    return proto_filed32_get(rsp_head->req_id);
}

/**
 * Parse client channel for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: client channel.
 */
static inline uint32_t urpc_rsp_parse_client_channel(urpc_rsp_head_t *rsp_head)
{
    return proto_filed24_get(rsp_head->client_channel);
}

/**
 * Parse function_defined for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: function_defined.
 */
static inline uint8_t urpc_rsp_parse_function_defined(urpc_rsp_head_t *rsp_head)
{
    return rsp_head->function_defined;
}

/**
 * Parse response total size for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: response total size.
 */
static inline uint32_t urpc_rsp_parse_response_total_size(urpc_rsp_head_t *rsp_head)
{
    return proto_filed32_get(rsp_head->response_total_size);
}

/**
 * Parse reply-one-request return data for uRPC response.
 * @param[in] rsp_head:             Address of uRPC response head. Caller must ensure the validity of the address.
 * Return: the start address of return data.
 */
static inline void *urpc_rsp_parse_one_return_data(urpc_rsp_head_t *rsp_head)
{
    return (void *)(rsp_head + 1);
}

/**
 * Fill information for uRPC keepalive head.
 * @param[in] head:                 Address of uRPC keepalive head. Caller must ensure the validity of the address.
 * @param[in] version:              Keepalive header version.
 * @param[in] is_rsp:               Indicate whether the keepalive packet is response.
 * @param[in] l_qid:                Local queue id.
 * @param[in] server_channel:       Server Channel id.
 * Return: void.
 */
static inline void urpc_keepalive_fill_head(
    urpc_keepalive_head_t *head, uint8_t version, uint8_t is_rsp, uint16_t l_qid, uint32_t server_channel)
{
    head->version = version;
    head->is_rsp = is_rsp;
    head->status = 0;
    head->l_qid = proto_filed16_put(l_qid);
    head->server_channel = proto_filed24_put(server_channel);
    head->rsvd1 = 0;
    head->rsvd2 = 0;
}

static inline void urpc_keepalive_fill_rsp(urpc_keepalive_head_t *head, uint8_t is_rsp)
{
    head->is_rsp = is_rsp;
}

/**
 * Parse server channel for uRPC keepalive head.
 * @param[in] head:                 Address of uRPC keepalive head. Caller must ensure the validity of the address.
 * Return: server channel.
 */
static inline uint32_t urpc_keepalive_parse_server_channel(urpc_keepalive_head_t *head)
{
    return proto_filed24_get(head->server_channel);
}

/**
 * Parse is_rsp for uRPC keepalive head.
 * @param[in] head:                 Address of uRPC keepalive head. Caller must ensure the validity of the address.
 * Return: is_rsp.
 */
static inline bool urpc_keepalive_parse_rsp(const urpc_keepalive_head_t *head)
{
    return (head->is_rsp != 0);
}

/**
 * get sge index and offset for user payload
 * @param[in] user_payload_offset:                 user payload offset from the sge start
 * @param[in] sge:                                 sge
 * @param[in] sge_num:                             sge num
 * @param[out] offset:                             offset of the sge where the user payload starts
 * Return: sge index where user payload starts
*/
static inline uint32_t urpc_ext_payload_idx_get(uint32_t user_payload_offset, urpc_sge_t *sge,
    uint32_t sge_num, uint32_t *offset)
{
    uint32_t payload_offset = user_payload_offset;
    for (uint32_t i = 0; i < sge_num; i++) {
        if (payload_offset < sge[i].length) {
            *offset = payload_offset;
            return i;
        }
        payload_offset -= sge[i].length;
    }
    return URPC_U32_FAIL;
}

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */