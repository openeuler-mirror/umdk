/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: functions to process control path version compatible messages
 */
#ifndef CP_VERS_COMPAT
#define CP_VERS_COMPAT

#include "crypto.h"
#include "channel.h"
#include "urpc_tlv.h"

#define CHANNEL_INFO_MAX_NUM (2)

#ifdef __cplusplus
extern "C" {
#endif

/* each version compatible message contains two parts, including 'buffer to store data' & 'user used fields'
 * 1. serialization: 'buffer to store data' stores the malloc-ed data serialized by 'user used fields'.
 * 2. deserialization: fill 'user used fields' by 'buffer to store data' after deserialization.
 */

typedef struct urpc_serialized_data {
    char *buffer;           // buffer to store serialized data
    uint32_t len;           // length of buffer
} urpc_serialized_data_t;

typedef struct urpc_neg_msg_v1 {
    /* buffer to store data */
    urpc_serialized_data_t data;
    /* user used fields */
    crypto_key_t *crypto_key;
} urpc_neg_msg_v1_t;

int urpc_neg_msg_v1_serialize(urpc_neg_msg_v1_t *data);
int urpc_neg_msg_v1_deserialize(urpc_neg_msg_v1_t *data);
void urpc_neg_msg_v1_buffer_release(urpc_neg_msg_v1_t *data);

typedef struct urpc_qinfo_arr_v1 {
    uint32_t arr_num;
    queue_info_t *qinfos[MAX_QUEUE_SIZE];
} urpc_qinfo_arr_v1_t;

typedef struct urpc_chmsg_v1 {
    urpc_chinfo_t *chinfo;
    urpc_qinfo_arr_v1_t qinfo_arr;
} urpc_chmsg_v1_t;

typedef struct urpc_chmsg_arr_v1 {
    uint32_t arr_num;
    urpc_chmsg_v1_t chmsgs[CHANNEL_INFO_MAX_NUM];
} urpc_chmsg_arr_v1_t;

typedef struct urpc_attach_info {
    uint64_t keepalive_attr;        // user defined keepalive attribution
    uint32_t server_chid;           // used for client
} urpc_attach_info_t;

typedef struct urpc_attach_msg_v1 {
    /* buffer to store data */
    urpc_serialized_data_t data;
    /* user used fields */
    urpc_attach_info_t *attach_info;
    urpc_chmsg_arr_v1_t chmsg_arr;
} urpc_attach_msg_v1_t;

typedef struct urpc_chmsg_input {
    union {
        urpc_channel_info_t *client_channel;
        uint32_t server_channel_id;
    };
    uint32_t q_num;
    uint64_t qh[MAX_QUEUE_SIZE];
} urpc_chmsg_input_t;

typedef struct urpc_attach_msg_input {
    urpc_attach_info_t attach_info;
    bool is_server;
    urpc_chmsg_input_t user;
    urpc_chmsg_input_t manage;
} urpc_attach_msg_input_t;

int urpc_attach_msg_v1_serialize(urpc_attach_msg_input_t *input, urpc_attach_msg_v1_t *data);
int urpc_attach_msg_v1_deserialize(urpc_attach_msg_v1_t *data);
void urpc_attach_msg_v1_buffer_release(urpc_attach_msg_v1_t *data);

typedef struct urpc_detach_msg_v1 {
    /* buffer to store data */
    urpc_serialized_data_t data;
    /* user used fields */
    urpc_detach_info_t *detach_info;
} urpc_detach_msg_v1_t;

int urpc_detach_msg_v1_serialize(urpc_channel_info_t *channel, uint32_t server_chid, urpc_detach_msg_v1_t *data);
int urpc_detach_msg_v1_deserialize(urpc_detach_msg_v1_t *data);
void urpc_detach_msg_v1_buffer_release(urpc_detach_msg_v1_t *data);

typedef struct urpc_connection_info {
    urpc_instance_key_t key;
} urpc_connection_info_t;

int meminfo_arr_serialize(urpc_channel_info_t *channel, urpc_tlv_arr_head_t *meminfo_arr_tlv_head, uint32_t mem_num);
int meminfo_arr_deserialize(urpc_tlv_arr_head_t *meminfo_arr_tlv_head, xchg_mem_info_t **meminfo_arr);

typedef struct urpc_chmsg_input_v2 {
    union {
        urpc_channel_info_t *client_channel;
        uint32_t server_channel_id;
    };
    uint32_t q_num;
    uint64_t qh[MAX_QUEUE_SIZE];
} urpc_chmsg_input_v2_t;

typedef struct urpc_chmsg_arr_v2 {
    uint32_t arr_num;
    urpc_chmsg_v1_t chmsgs[0];
} urpc_chmsg_arr_v2_t;

typedef struct urpc_connect_msg {
    /* buffer to store data */
    urpc_serialized_data_t data;
    /* user used fields */
    urpc_connection_info_t *connect_info;
    urpc_chmsg_arr_v2_t chmsg_arr;
} urpc_connect_msg_t;

typedef struct urpc_connect_msg_input {
    urpc_instance_key_t *key;
    urpc_chmsg_input_v2_t *chmsg_arr;
    uint32_t num;
} urpc_connect_msg_input_t;

int urpc_connect_msg_serialize(urpc_connect_msg_input_t *input, urpc_connect_msg_t *data);
int urpc_connect_msg_deserialize(urpc_connect_msg_t *data);
void urpc_connect_msg_buffer_release(urpc_connect_msg_t *data);
int urpc_connect_msg_extract_channel_count(char *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif