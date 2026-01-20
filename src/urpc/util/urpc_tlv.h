/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: uRPC tlv utils
 * Create: 2025-01-09
 */
#ifndef URPC_TLV
#define URPC_TLV

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* urpc tlv basic type ranges from 0 to 15(0xf)
 * urpc tlv complex type ranges from 16 to 65535(0xffff) */
typedef enum urpc_tlv_type {
    URPC_TLV_TYPE_ARRAY = 0xf,
    URPC_TLV_TYPE_NEG_MSG = 0x10,
    URPC_TLV_TYPE_CRYPTO_KEY,
    URPC_TLV_TYPE_ATTACH_MSG,
    URPC_TLV_TYPE_ATTACH_INFO,
    URPC_TLV_TYPE_CHANNEL_MSG,
    URPC_TLV_TYPE_CHANNEL_INFO,
    URPC_TLV_TYPE_QUEUE_INFO,
    URPC_TLV_TYPE_MEM_INFO,
    URPC_TLV_TYPE_DETACH_MSG,
    URPC_TLV_TYPE_DETACH_INFO,
    URPC_TLV_TYPE_CONNECT_MSG,
    URPC_TLV_TYPE_CONNECT_INFO,
} urpc_tlv_type_t;

/** TLV head for general type
 * +--+--+--+--+--+--+--+--+
 * |Type(4B)               |
 * +--+--+--+--+--+--+--+--+
 * |Length(4B)             |
 * +--+--+--+--+--+--+--+--+
 * |Value                  |
 * +--+--+--+--+--+--+--+--+
 */
typedef struct urpc_tlv_head {
    uint32_t type;
    uint32_t len;   // the length of 'value', not including 'urpc_tlv_head_t'
    char value[0];
} urpc_tlv_head_t;

/** TLV head for the array type(type: URPC_TLV_TYPE_ARRAY)
 * +--+--+--+--+--+--+--+--+
 * |Type(4B)               |
 * +--+--+--+--+--+--+--+--+
 * |Length(4B)             | Length: Array Num + User Data
 * +--+--+--+--+--+--+--+--+
 * |[Value] Arr Num(4B)    |
 * +--+--+--+--+--+--+--+--+
 * |[Value] User Data      |
 * +--+--+--+--+--+--+--+--+
 */
typedef struct urpc_tlv_arr_head {
    uint32_t type;
    uint32_t len;   // the length of 'value'(array num(4B) + user data), not including 'urpc_tlv_head_t'.
    struct {
        uint32_t arr_num;
        char user_data[0];
    } value;
} urpc_tlv_arr_head_t;

static inline urpc_tlv_head_t *urpc_tlv_get_next_element(urpc_tlv_head_t *head)
{
    return (urpc_tlv_head_t *)(head->value + head->len);
}

/* total length = sizeof(urpc_tlv_head_t) + value length */
static inline uint32_t urpc_tlv_get_total_len(urpc_tlv_head_t *head)
{
    return sizeof(urpc_tlv_head_t) + head->len;
}

/* Caller ensures the validity of 'type' */
urpc_tlv_head_t *urpc_tlv_search_element(char *buf, uint32_t buf_size, urpc_tlv_type_t type);
urpc_tlv_head_t *urpc_tlv_search_next_element(urpc_tlv_head_t *cur, uint32_t left_size, urpc_tlv_type_t type);

/* tlv head obtained from 'urpc_tlv_search_element' or 'urpc_tlv_search_next_element' can call this function directly.
 * these two function have checked the tlv head and assure it's within the range of provided buffer. */
static inline uint32_t urpc_tlv_get_left_len(char *buf, uint32_t buf_size, urpc_tlv_head_t *cur)
{
    return buf_size - (uint32_t)(uintptr_t)((char *)(uintptr_t)cur - buf);
}

static inline uint32_t urpc_tlv_arr_get_user_data_len(urpc_tlv_arr_head_t *head)
{
    return head->len - sizeof(head->value);
}

static inline uint32_t urpc_tlv_arr_get_value_len_by_user_data_len(uint32_t user_data_len)
{
    return user_data_len + sizeof(urpc_tlv_arr_head_t) - sizeof(urpc_tlv_head_t);
}

#ifdef __cplusplus
}
#endif

#endif