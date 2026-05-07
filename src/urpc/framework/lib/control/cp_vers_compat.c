/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: functions to process control path version compatibility message
 */

#include <unistd.h>
#include <string.h>

#include "cp.h"
#include "crypto.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"
#include "cp_vers_compat.h"

#define TLV_HEAD_NUM_PER_NEG_MSG (2)

#define TLV_HEAD_NUM_PER_ATTACH_MSG (2)
#define TLV_ARR_HEAD_NUM_PER_ATTACH_MSG (1)
#define TLV_HEAD_NUM_PER_CHANNEL_MSG (2)
#define TLV_ARR_HEAD_NUM_PER_CHANNEL_MSG (1)
#define TLV_HEAD_NUM_PER_MEM_INFO (1)

#define TLV_HEAD_NUM_PER_QUEUE_INFO (1)

#define TLV_HEAD_NUM_PER_DETACH_MSG (2)
#define TLV_HEAD_NUM_PER_CONNECT_MSG (2)
#define TLV_ARR_HEAD_NUM_PER_CONNECT_MSG (1)

/**
 * 1. negotiation message memory layout
 * negotiation message(TL)                                  URPC_TLV_TYPE_NEG_MSG
 * └── crypto key(TLV)                                      URPC_TLV_TYPE_CRYPTO_KEY
 *
 * 2. attach message memory layout
 * attach message(TL)                                       URPC_TLV_TYPE_ATTACH_MSG
 * ├── attach information(TLV)                              URPC_TLV_TYPE_ATTACH_INFO
 * └── array(TL)                                            URPC_TLV_TYPE_ARRAY
 *     ├── array number
 *     ├── channel message 0(TL)                            URPC_TLV_TYPE_CHANNEL_MSG
 *     │   ├── channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
 *     │   └── array(TL)                                    URPC_TLV_TYPE_ARRAY
 *     |       ├── array number
 *     │       ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       └── ...
 *     ├── channel message 1(TL)                            URPC_TLV_TYPE_CHANNEL_MSG
 *     │   ├── channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
 *     │   └── array(TL)                                    URPC_TLV_TYPE_ARRAY
 *     |       ├── array number
 *     │       ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       └── ...
 *     └── ...
 *
 * 3. detach message memory layout
 * detach message(TL)                                       URPC_TLV_TYPE_DETACH_MSG
 * └── detach information(TLV)                              URPC_TLV_TYPE_DETACH_INFO
 *
 * 4. channel resource message memory layout
 * channel resource message message(TL)                     URPC_TLV_TYPE_CONNECT_MSG
 * ├── reconnect information(TLV)                           URPC_TLV_TYPE_CONNECT_INFO
 * └── array(TL)                                            URPC_TLV_TYPE_ARRAY
 *     ├── array number
 *     ├── channel message 0(TL)                            URPC_TLV_TYPE_CHANNEL_MSG
 *     │   ├── channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
 *     │   └── array(TL)                                    URPC_TLV_TYPE_ARRAY
 *     |       ├── array number
 *     │       ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       └── ...
 *     ├── channel message 1(TL)                            URPC_TLV_TYPE_CHANNEL_MSG
 *     │   ├── channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
 *     │   └── array(TL)                                    URPC_TLV_TYPE_ARRAY
 *     |       ├── array number
 *     │       ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
 *     │       └── ...
 *     └── ...
 */

int urpc_neg_msg_v1_serialize(urpc_neg_msg_v1_t *data)
{
    if (data == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    uint32_t buf_len = (uint32_t)(TLV_HEAD_NUM_PER_NEG_MSG * sizeof(urpc_tlv_head_t) + sizeof(crypto_key_t));
    urpc_tlv_head_t *neg_msg_tlv_head = (urpc_tlv_head_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, buf_len);
    if (neg_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("malloc negotiate message failed\n");
        return URPC_FAIL;
    }

    urpc_tlv_head_t *crypto_key_tlv_head = (urpc_tlv_head_t *)(uintptr_t)neg_msg_tlv_head->value;
    crypto_key_tlv_head->type = URPC_TLV_TYPE_CRYPTO_KEY;
    crypto_key_tlv_head->len = (uint32_t)sizeof(crypto_key_t);
    if (crypto_ssl_gen_crypto_key((crypto_key_t *)(uintptr_t)crypto_key_tlv_head->value) != URPC_SUCCESS) {
        urpc_dbuf_free(neg_msg_tlv_head);
        URPC_LIB_LOG_ERR("generate crypto key failed\n");
        return URPC_FAIL;
    }

    data->crypto_key = (crypto_key_t *)(uintptr_t)crypto_key_tlv_head->value;

    neg_msg_tlv_head->type = URPC_TLV_TYPE_NEG_MSG;
    neg_msg_tlv_head->len = urpc_tlv_get_total_len(crypto_key_tlv_head);

    data->data.buffer = (char *)(uintptr_t)neg_msg_tlv_head;
    data->data.len = buf_len;

    return URPC_SUCCESS;
}

int urpc_neg_msg_v1_deserialize(urpc_neg_msg_v1_t *data)
{
    if (data == NULL || data->data.buffer == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_tlv_head_t *neg_msg_tlv_head =
        urpc_tlv_search_element(data->data.buffer, data->data.len, URPC_TLV_TYPE_NEG_MSG);
    if (neg_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find negotiate message\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_tlv_head_t *crypto_key_tlv_head =
        urpc_tlv_search_element(neg_msg_tlv_head->value, neg_msg_tlv_head->len, URPC_TLV_TYPE_CRYPTO_KEY);
    if (crypto_key_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find crypto key\n");
        return -URPC_ERR_EINVAL;
    }

    if (crypto_key_tlv_head->len < sizeof(crypto_key_t)) {
        URPC_LIB_LOG_ERR("the length of crypto key is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    data->crypto_key = (crypto_key_t *)(uintptr_t)crypto_key_tlv_head->value;

    return URPC_SUCCESS;
}

void urpc_neg_msg_v1_buffer_release(urpc_neg_msg_v1_t *data)
{
    if (data == NULL) {
        return;
    }

    urpc_dbuf_free(data->data.buffer);
    memset(data, 0, sizeof(urpc_neg_msg_v1_t));
}

static int attach_msg_v1_serialize_qinfo_arr(
    uint64_t *queue, uint32_t queue_num, urpc_qinfo_arr_v1_t *qinfo_arr, urpc_tlv_arr_head_t *qinfo_arr_tlv_head)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * └── ... */
    urpc_tlv_head_t *qinfo_tlv_head = (urpc_tlv_head_t *)(uintptr_t)qinfo_arr_tlv_head->value.user_data;
    for (uint32_t i = 0; i < queue_num; i++) {
        if (queue[i] == URPC_INVALID_HANDLE) {
            URPC_LIB_LOG_ERR("invalid queue handle\n");
            return URPC_FAIL;
        }

        // serialize queue information
        queue_info_t *qinfo = (queue_info_t *)(uintptr_t)qinfo_tlv_head->value;
        if (channel_get_local_queue_info(queue[i], qinfo) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("query queue information failed\n");
            return URPC_FAIL;
        }

        qinfo_tlv_head->type = URPC_TLV_TYPE_QUEUE_INFO;
        qinfo_tlv_head->len = (uint32_t)sizeof(queue_info_t);

        URPC_LIB_LOG_DEBUG("queue information tlv length: %u\n", qinfo_tlv_head->len);

        qinfo_arr->qinfos[i] = qinfo;

        qinfo_tlv_head = urpc_tlv_get_next_element(qinfo_tlv_head);
    }

    uint32_t value_len = queue_num * (uint32_t)(sizeof(queue_info_t) + sizeof(urpc_tlv_head_t));
    qinfo_arr->arr_num = queue_num;

    qinfo_arr_tlv_head->type = URPC_TLV_TYPE_ARRAY;
    qinfo_arr_tlv_head->len = urpc_tlv_arr_get_value_len_by_user_data_len(value_len);
    qinfo_arr_tlv_head->value.arr_num = queue_num;

    URPC_LIB_LOG_DEBUG("queue information array tlv length: %u\n", qinfo_arr_tlv_head->len);

    return URPC_SUCCESS;
}

static urpc_chinfo_t *attach_msg_v1_serialize_chinfo(
    bool is_server, bool is_manage, urpc_chmsg_input_t *chmsg_input, urpc_tlv_head_t *chinfo_tlv_head)
{
    // channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
    urpc_chinfo_t *chinfo = (urpc_chinfo_t *)(uintptr_t)chinfo_tlv_head->value;

    chinfo->cap.is_support_quik_reply = is_feature_enable(URPC_FEATURE_HWUB_OFFLOAD);
    if (is_server) {
        chinfo->attr = is_manage ? URPC_ATTR_MANAGE : 0;
        chinfo->chid = chmsg_input->server_channel_id;
        if (urpc_instance_key_fill(&chinfo->key) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("fill instance key failed\n");
            return NULL;
        }
    } else {
        chinfo->attr = chmsg_input->client_channel->attr;
        chinfo->chid = chmsg_input->client_channel->id;
        provider_t *provider = chmsg_input->client_channel->provider;
        if (provider == NULL) {
            /* Client channel should bind to a specified provider before it is in use:
            * 1. multi-eid off: use get_provider() to bind the channel to the only provider when creating a channel;
            * 2. multi-eid on: bind to the same provider as the local queue to be added to the channel; */
            URPC_LIB_LOG_ERR("get provider failed, channel[%u]\n", chmsg_input->client_channel->id);
            return NULL;
        }
        provider->ops->get_eid(provider, &chinfo->key.eid);
        chinfo->key.pid = (uint32_t)getpid();
    }

    chinfo_tlv_head->type = URPC_TLV_TYPE_CHANNEL_INFO;
    chinfo_tlv_head->len = (uint32_t)sizeof(urpc_chinfo_t);

    URPC_LIB_LOG_DEBUG("channel information tlv length: %u\n", chinfo_tlv_head->len);

    return chinfo;
}

static int attach_msg_v1_serialize_chmsg(bool is_server, bool is_manage, urpc_chmsg_input_t *chmsg_input,
    urpc_chmsg_v1_t *chmsg, urpc_tlv_head_t *chmsg_tlv_head)
{
    /* channel message 0(TL)                        URPC_TLV_TYPE_CHANNEL_MSG
     * ├── channel information(TLV)                 URPC_TLV_TYPE_CHANNEL_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. serialize channel information
    urpc_tlv_head_t *chinfo_tlv_head = (urpc_tlv_head_t *)(uintptr_t)chmsg_tlv_head->value;
    chmsg->chinfo = attach_msg_v1_serialize_chinfo(is_server, is_manage, chmsg_input, chinfo_tlv_head);
    if (chmsg->chinfo == NULL) {
        return URPC_FAIL;
    }

    // 2. serialize queue information array
    urpc_tlv_head_t *qinfo_arr_tlv_head = urpc_tlv_get_next_element(chinfo_tlv_head);
    if (attach_msg_v1_serialize_qinfo_arr(chmsg_input->qh, chmsg_input->q_num,
        &chmsg->qinfo_arr, (urpc_tlv_arr_head_t *)(uintptr_t)qinfo_arr_tlv_head) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    chmsg_tlv_head->len = urpc_tlv_get_total_len(chinfo_tlv_head) + urpc_tlv_get_total_len(qinfo_arr_tlv_head);
    chmsg_tlv_head->type = URPC_TLV_TYPE_CHANNEL_MSG;

    URPC_LIB_LOG_DEBUG("channel message tlv length: %u\n", chmsg_tlv_head->len);

    return URPC_SUCCESS;
}

static int attach_msg_v1_serialize_chmsg_arr(
    urpc_attach_msg_input_t *input, urpc_chmsg_arr_v1_t *chmsg_arr, urpc_tlv_arr_head_t *chmsg_arr_tlv_head)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── channel message 0(TL)                    URPC_TLV_TYPE_CHANNEL_MSG
     * └── channel message 1(TL)                    URPC_TLV_TYPE_CHANNEL_MSG */
    uint32_t idx = 0;
    uint32_t value_len = 0;
    urpc_tlv_head_t *chmsg_tlv_head = (urpc_tlv_head_t *)(uintptr_t)chmsg_arr_tlv_head->value.user_data;

    // 1. serialize manage channel message
    if (input->manage.q_num > 0) {
        if (attach_msg_v1_serialize_chmsg(
            input->is_server, true, &input->manage, &chmsg_arr->chmsgs[idx++], chmsg_tlv_head) != URPC_SUCCESS) {
            return URPC_FAIL;
        }

        value_len += urpc_tlv_get_total_len(chmsg_tlv_head);
        chmsg_tlv_head = urpc_tlv_get_next_element(chmsg_tlv_head);
    }

    // 2. serialize user channel message
    if (attach_msg_v1_serialize_chmsg(
        input->is_server, false, &input->user, &chmsg_arr->chmsgs[idx++], chmsg_tlv_head) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    value_len += urpc_tlv_get_total_len(chmsg_tlv_head);

    chmsg_arr->arr_num = idx;

    chmsg_arr_tlv_head->type = URPC_TLV_TYPE_ARRAY;
    chmsg_arr_tlv_head->len = urpc_tlv_arr_get_value_len_by_user_data_len(value_len);
    chmsg_arr_tlv_head->value.arr_num = chmsg_arr->arr_num;
    URPC_LIB_LOG_DEBUG("channel message array tlv length: %u\n", chmsg_arr_tlv_head->len);

    return URPC_SUCCESS;
}

static inline void attach_msg_v1_serialize_attach_info(
    urpc_attach_msg_input_t *input, urpc_attach_msg_v1_t *attach_msg, urpc_tlv_head_t *attach_info_tlv_head)
{
    // attach information(TLV)                      URPC_TLV_TYPE_ATTACH_INFO
    urpc_attach_info_t *attach_info = (urpc_attach_info_t *)(uintptr_t)attach_info_tlv_head->value;
    attach_info->keepalive_attr = input->attach_info.keepalive_attr;
    attach_info->server_chid = input->attach_info.server_chid;

    attach_msg->attach_info = attach_info;

    attach_info_tlv_head->type = URPC_TLV_TYPE_ATTACH_INFO;
    attach_info_tlv_head->len = sizeof(urpc_attach_info_t);

    URPC_LIB_LOG_DEBUG("attach information tlv length: %u\n", attach_info_tlv_head->len);
}

static int attach_msg_v1_serialize_attach_msg(
    urpc_attach_msg_input_t *input, urpc_attach_msg_v1_t *attach_msg, urpc_tlv_head_t *attach_msg_tlv_head)
{
    /* attach message(TL)                           URPC_TLV_TYPE_ATTACH_MSG
     * ├── attach information(TLV)                  URPC_TLV_TYPE_ATTACH_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. serialize attach information
    urpc_tlv_head_t *attach_info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)attach_msg_tlv_head->value;
    attach_msg_v1_serialize_attach_info(input, attach_msg, attach_info_tlv_head);

    // 2. serialize channel message array
    urpc_tlv_head_t *chmsg_arr_tlv_head = urpc_tlv_get_next_element(attach_info_tlv_head);
    if (attach_msg_v1_serialize_chmsg_arr(input, &attach_msg->chmsg_arr,
        (urpc_tlv_arr_head_t *)(uintptr_t)chmsg_arr_tlv_head) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    attach_msg_tlv_head->type = URPC_TLV_TYPE_ATTACH_MSG;
    attach_msg_tlv_head->len =
        urpc_tlv_get_total_len(attach_info_tlv_head) + urpc_tlv_get_total_len(chmsg_arr_tlv_head);

    URPC_LIB_LOG_DEBUG("attach message tlv length: %u\n", attach_msg_tlv_head->len);

    return URPC_SUCCESS;
}

static int attach_msg_input_validation(urpc_attach_msg_input_t *input)
{
    if (!input->is_server) {
        if (input->user.client_channel == NULL || input->user.q_num > MAX_QUEUE_SIZE) {
            URPC_LIB_LOG_ERR("input user information is invalid\n");
            return -URPC_ERR_EINVAL;
        }

        if ((input->manage.client_channel != NULL &&
            (input->manage.q_num == 0 || input->manage.q_num > MAX_QUEUE_SIZE)) ||
            (input->manage.client_channel == NULL && input->manage.q_num != 0)) {
            URPC_LIB_LOG_ERR("input manage information is invalid\n");
            return -URPC_ERR_EINVAL;
        }

        return URPC_SUCCESS;
    }

    if (input->user.server_channel_id != URPC_INVALID_ID_U32 && input->user.q_num > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("input user information is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    if ((input->manage.server_channel_id != URPC_INVALID_ID_U32 &&
        (input->manage.q_num == 0 || input->manage.q_num > MAX_QUEUE_SIZE)) ||
        (input->manage.server_channel_id == URPC_INVALID_ID_U32 && input->manage.q_num != 0)) {
        URPC_LIB_LOG_ERR("input manage information is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    return URPC_SUCCESS;
}

static uint32_t attach_msg_v1_get_total_len(uint32_t queue_num, uint32_t channel_num)
{
    // 1. total len for queue information
    uint32_t total_len = queue_num * ((TLV_HEAD_NUM_PER_QUEUE_INFO * sizeof(urpc_tlv_head_t)) + sizeof(queue_info_t));

    // 2. total len for channel message
    total_len += channel_num * (TLV_HEAD_NUM_PER_CHANNEL_MSG * sizeof(urpc_tlv_head_t) +
        TLV_ARR_HEAD_NUM_PER_CHANNEL_MSG * sizeof(urpc_tlv_arr_head_t) + sizeof(urpc_chinfo_t));

    // 3. total len for attach message
    total_len += TLV_HEAD_NUM_PER_ATTACH_MSG * sizeof(urpc_tlv_head_t) +
        TLV_ARR_HEAD_NUM_PER_ATTACH_MSG * sizeof(urpc_tlv_arr_head_t) + sizeof(urpc_attach_info_t);

    return total_len;
}

int urpc_attach_msg_v1_serialize(urpc_attach_msg_input_t *input, urpc_attach_msg_v1_t *data)
{
    if (input == NULL || data == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    int ret = attach_msg_input_validation(input);
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    uint32_t queue_num = input->user.q_num + input->manage.q_num;
    uint32_t channel_num = input->manage.q_num > 0 ? CHANNEL_INFO_MAX_NUM : 1;
    uint32_t buf_len = attach_msg_v1_get_total_len(queue_num, channel_num);
    urpc_tlv_head_t *attach_msg_tlv_head = (urpc_tlv_head_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, buf_len);
    if (attach_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("malloc attach message failed\n");
        return URPC_FAIL;
    }

    if (attach_msg_v1_serialize_attach_msg(input, data, attach_msg_tlv_head) != URPC_SUCCESS) {
        urpc_dbuf_free(attach_msg_tlv_head);
        URPC_LIB_LOG_ERR("serialize attach message failed\n");
        return URPC_FAIL;
    }

    data->data.buffer = (char *)(uintptr_t)attach_msg_tlv_head;
    data->data.len = buf_len;

    URPC_LIB_LOG_DEBUG("attach message buffer length: %u\n", buf_len);

    return URPC_SUCCESS;
}

static int attach_msg_v1_deserialize_qinfo_arr(urpc_tlv_arr_head_t *qinfo_arr_tlv_head, urpc_qinfo_arr_v1_t *qinfo_arr)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * └── ... */
    if (qinfo_arr_tlv_head->value.arr_num > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("the number of queue information exceeds upper limit\n");
        return -URPC_ERR_EINVAL;
    }

    // 1. search queue information
    char *qinfo_buf = qinfo_arr_tlv_head->value.user_data;
    uint32_t qinfo_len = urpc_tlv_arr_get_user_data_len(qinfo_arr_tlv_head);
    if (qinfo_len == 0 && qinfo_arr_tlv_head->value.arr_num == 0) {
        goto OUT;
    }

    urpc_tlv_head_t *qinfo_tlv_head = urpc_tlv_search_element(qinfo_buf, qinfo_len, URPC_TLV_TYPE_QUEUE_INFO);
    for (uint32_t i = 0; i < qinfo_arr_tlv_head->value.arr_num; i++) {
        // 2. deserialize queue information
        if (qinfo_tlv_head == NULL) {
            URPC_LIB_LOG_ERR("failed to find queue information\n");
            return URPC_FAIL;
        }

        if (qinfo_tlv_head->len < sizeof(queue_info_t)) {
            URPC_LIB_LOG_ERR("The size of queue information(%u) is smaller than the defined size(%u)\n",
                qinfo_tlv_head->len, sizeof(queue_info_t));
            return URPC_FAIL;
        }

        qinfo_arr->qinfos[i] = (queue_info_t *)(uintptr_t)qinfo_tlv_head->value;

        // 3. search next queue information
        uint32_t left_len = urpc_tlv_get_left_len(qinfo_buf, qinfo_len, qinfo_tlv_head);
        qinfo_tlv_head = urpc_tlv_search_next_element(qinfo_tlv_head, left_len, URPC_TLV_TYPE_QUEUE_INFO);
    }

OUT:
    qinfo_arr->arr_num = qinfo_arr_tlv_head->value.arr_num;

    return URPC_SUCCESS;
}

static int attach_msg_v1_deserialize_chmsg(char *buf, uint32_t len, urpc_chmsg_v1_t *chmsg)
{
    /* channel message 0(TL)                        URPC_TLV_TYPE_CHANNEL_MSG
     * ├── channel information(TLV)                 URPC_TLV_TYPE_CHANNEL_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. search channel information
    urpc_tlv_head_t *chinfo_tlv_head = urpc_tlv_search_element(buf, len, URPC_TLV_TYPE_CHANNEL_INFO);
    if (chinfo_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find channel information\n");
        return URPC_FAIL;
    }

    // 2. deserialize channel information
    if (chinfo_tlv_head->len < sizeof(urpc_chinfo_t)) {
        URPC_LIB_LOG_ERR("The size of channel information(%u) is smaller than the defined size(%u)\n",
            chinfo_tlv_head->len, sizeof(urpc_chinfo_t));
        return URPC_FAIL;
    }

    chmsg->chinfo = (urpc_chinfo_t *)chinfo_tlv_head->value;

    // 3. search queue information array
    uint32_t left_len = urpc_tlv_get_left_len(buf, len, chinfo_tlv_head);
    urpc_tlv_arr_head_t *qinfo_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)
        urpc_tlv_search_next_element(chinfo_tlv_head, left_len, URPC_TLV_TYPE_ARRAY);
    if (qinfo_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find queue information array\n");
        return URPC_FAIL;
    }

    // 4. deserialize queue information array
    int ret = attach_msg_v1_deserialize_qinfo_arr(qinfo_arr_tlv_head, &chmsg->qinfo_arr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to deserialize queue information array\n");
        return ret;
    }

    return URPC_SUCCESS;
}

static int attach_msg_v1_deserialize_chmsg_arr(urpc_tlv_arr_head_t *chmsg_arr_tlv_head, urpc_chmsg_arr_v1_t *chmsg_arr)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── channel message 0(TL)                    URPC_TLV_TYPE_CHANNEL_MSG
     * └── channel message 1(TL)                    URPC_TLV_TYPE_CHANNEL_MSG */
    if (chmsg_arr_tlv_head->len < (sizeof(urpc_tlv_arr_head_t) - sizeof(urpc_tlv_head_t)) ||
        chmsg_arr_tlv_head->value.arr_num > CHANNEL_INFO_MAX_NUM) {
        URPC_LIB_LOG_ERR("the number of channel message exceeds upper limit\n");
        return -URPC_ERR_EINVAL;
    }

    // 1. search channel message
    char *chmsg_buf = chmsg_arr_tlv_head->value.user_data;
    uint32_t chmsg_len = urpc_tlv_arr_get_user_data_len(chmsg_arr_tlv_head);
    urpc_tlv_head_t *chmsg_tlv_head = urpc_tlv_search_element(chmsg_buf, chmsg_len, URPC_TLV_TYPE_CHANNEL_MSG);

    for (uint32_t i = 0; i < chmsg_arr_tlv_head->value.arr_num; i++) {
        // 2. deserialize channel message
        if (chmsg_tlv_head == NULL) {
            URPC_LIB_LOG_ERR("failed to find channel message\n");
            return URPC_FAIL;
        }

        attach_msg_v1_deserialize_chmsg(chmsg_tlv_head->value, chmsg_tlv_head->len, chmsg_arr->chmsgs + i);

        // 3. search next channel message
        uint32_t left_len = urpc_tlv_get_left_len(chmsg_buf, chmsg_len, chmsg_tlv_head);
        chmsg_tlv_head = urpc_tlv_search_next_element(chmsg_tlv_head, left_len, URPC_TLV_TYPE_CHANNEL_MSG);
    }

    chmsg_arr->arr_num = chmsg_arr_tlv_head->value.arr_num;

    return URPC_SUCCESS;
}

static int attach_msg_v1_deserialize_attach_msg(char *buf, uint32_t len, urpc_attach_msg_v1_t *data)
{
    /* attach message(TL)                           URPC_TLV_TYPE_ATTACH_MSG
     * ├── attach information(TLV)                  URPC_TLV_TYPE_ATTACH_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. search attach message
    urpc_tlv_head_t *attach_msg_tlv_head = urpc_tlv_search_element(buf, len, URPC_TLV_TYPE_ATTACH_MSG);
    if (attach_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find attach message\n");
        return -URPC_ERR_EINVAL;
    }

    // 2. search attach information
    urpc_tlv_head_t *attach_info_tlv_head =
        urpc_tlv_search_element(attach_msg_tlv_head->value, attach_msg_tlv_head->len, URPC_TLV_TYPE_ATTACH_INFO);
    if (attach_info_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find attach information\n");
        return -URPC_ERR_EINVAL;
    }

    // 3. deserialize attach information
    data->attach_info = (urpc_attach_info_t *)(uintptr_t)attach_info_tlv_head->value;

    // 4. search channel message array
    uint32_t left_len = urpc_tlv_get_left_len(
        attach_msg_tlv_head->value, attach_msg_tlv_head->len, attach_info_tlv_head);
    urpc_tlv_arr_head_t *chmsg_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)
        urpc_tlv_search_next_element(attach_info_tlv_head, left_len, URPC_TLV_TYPE_ARRAY);
    if (chmsg_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find channel message array\n");
        return URPC_FAIL;
    }

    if (chmsg_arr_tlv_head->len < sizeof(urpc_tlv_arr_head_t) - sizeof(urpc_tlv_head_t)) {
        URPC_LIB_LOG_ERR("channel message array len invalid\n");
        return URPC_FAIL;
    }

    // 5. deserialize channel message array
    int ret = attach_msg_v1_deserialize_chmsg_arr(chmsg_arr_tlv_head, &data->chmsg_arr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to deserialize channel message array\n");
        return ret;
    }

    return URPC_SUCCESS;
}

int urpc_attach_msg_v1_deserialize(urpc_attach_msg_v1_t *data)
{
    if (data == NULL || data->data.buffer == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    int ret = attach_msg_v1_deserialize_attach_msg(data->data.buffer, data->data.len, data);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to deserialize attach message\n");
        return ret;
    }

    return URPC_SUCCESS;
}

void urpc_attach_msg_v1_buffer_release(urpc_attach_msg_v1_t *data)
{
    if (data == NULL) {
        return;
    }

    urpc_dbuf_free(data->data.buffer);
    memset(data, 0, sizeof(urpc_attach_msg_v1_t));
}

static int urpc_detach_msg_v1_serialize_detach_info(urpc_channel_info_t *channel, uint32_t server_chid,
    urpc_detach_msg_v1_t *data, urpc_tlv_head_t *detach_info_tlv_head)
{
    // 1. serialize detach information
    urpc_detach_info_t *detach_info = (urpc_detach_info_t *)(uintptr_t)detach_info_tlv_head->value;
    if (channel->provider == NULL) {
        /* Client channel should bind to a specified provider before it is in use:
         * 1. multi-eid off: use get_provider() to bind the channel to the only provider when creating a channel;
         * 2. multi-eid on: bind to the same provider as the local queue to be added to the channel; */
        URPC_LIB_LOG_ERR("get provider failed, channel[%u]\n", channel->id);
        return URPC_FAIL;
    }
    channel->provider->ops->get_eid(channel->provider, &detach_info->key.eid);
    detach_info->key.pid = (uint32_t)getpid();
    detach_info->server_chid = server_chid;

    data->detach_info = detach_info;

    detach_info_tlv_head->type = URPC_TLV_TYPE_DETACH_INFO;
    detach_info_tlv_head->len = (uint32_t)sizeof(urpc_detach_info_t);

    return URPC_SUCCESS;
}

int urpc_detach_msg_v1_serialize(urpc_channel_info_t *channel, uint32_t server_chid, urpc_detach_msg_v1_t *data)
{
    if (channel == NULL || server_chid == URPC_INVALID_ID_U32 || data == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    uint32_t buf_len = (uint32_t)(TLV_HEAD_NUM_PER_DETACH_MSG * sizeof(urpc_tlv_head_t) + sizeof(urpc_detach_info_t));
    urpc_tlv_head_t *detach_msg_tlv_head = (urpc_tlv_head_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, buf_len);
    if (detach_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("malloc detach message failed\n");
        return URPC_FAIL;
    }

    urpc_tlv_head_t *detach_info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)detach_msg_tlv_head->value;
    if (urpc_detach_msg_v1_serialize_detach_info(channel, server_chid, data, detach_info_tlv_head) != URPC_SUCCESS) {
        urpc_dbuf_free(detach_msg_tlv_head);
        URPC_LIB_LOG_ERR("failed to serialize detach information\n");
        return URPC_FAIL;
    }

    detach_msg_tlv_head->type = URPC_TLV_TYPE_DETACH_MSG;
    detach_msg_tlv_head->len = urpc_tlv_get_total_len(detach_info_tlv_head);

    data->data.buffer = (char *)(uintptr_t)detach_msg_tlv_head;
    data->data.len = buf_len;

    return URPC_SUCCESS;
}

int urpc_detach_msg_v1_deserialize(urpc_detach_msg_v1_t *data)
{
    if (data == NULL || data->data.buffer == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_tlv_head_t *detach_msg_tlv_head =
        urpc_tlv_search_element(data->data.buffer, data->data.len, URPC_TLV_TYPE_DETACH_MSG);
    if (detach_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find detach message\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_tlv_head_t *detach_info_tlv_head =
        urpc_tlv_search_element(detach_msg_tlv_head->value, detach_msg_tlv_head->len, URPC_TLV_TYPE_DETACH_INFO);
    if (detach_info_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find detach information\n");
        return -URPC_ERR_EINVAL;
    }

    if (detach_info_tlv_head->len < sizeof(urpc_detach_info_t)) {
        URPC_LIB_LOG_ERR("the length of detach information is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    data->detach_info = (urpc_detach_info_t *)detach_info_tlv_head->value;

    return URPC_SUCCESS;
}

void urpc_detach_msg_v1_buffer_release(urpc_detach_msg_v1_t *data)
{
    if (data == NULL) {
        return;
    }

    urpc_dbuf_free(data->data.buffer);
    memset(data, 0, sizeof(urpc_detach_msg_v1_t));
}

// lock free: The function call context must be within the scope of mem_info_lock.
int meminfo_arr_serialize(urpc_channel_info_t *channel, urpc_tlv_arr_head_t *meminfo_arr_tlv_head, uint32_t mem_num)
{
    channel_mem_info_t *cur_mem_info;
    urpc_tlv_head_t *meminfo_tlv_head = (urpc_tlv_head_t *)(uintptr_t)meminfo_arr_tlv_head->value.user_data;
    uint32_t mem_info_num = 0;

    URPC_LIST_FOR_EACH(cur_mem_info, node, &channel->mem_info_list) {
        if (channel->mem_info_num == mem_info_num) {
            break;
        }

        // serialize mem information
        xchg_mem_info_t *meminfo = (xchg_mem_info_t *)(uintptr_t)meminfo_tlv_head->value;
        *meminfo = cur_mem_info->xchg_mem_info;
        meminfo_tlv_head->type = URPC_TLV_TYPE_MEM_INFO;
        meminfo_tlv_head->len = (uint32_t)sizeof(xchg_mem_info_t);
        meminfo_tlv_head = urpc_tlv_get_next_element(meminfo_tlv_head);
        mem_info_num++;
    }
    uint32_t value_len = (uint32_t)(mem_info_num * (sizeof(xchg_mem_info_t) + sizeof(urpc_tlv_head_t)));

    meminfo_arr_tlv_head->type = URPC_TLV_TYPE_ARRAY;
    meminfo_arr_tlv_head->len = urpc_tlv_arr_get_value_len_by_user_data_len(value_len);
    meminfo_arr_tlv_head->value.arr_num = mem_info_num;

    URPC_LIB_LOG_DEBUG("mem information array tlv length: %u\n", meminfo_arr_tlv_head->len);

    return URPC_SUCCESS;
}

int meminfo_arr_deserialize(urpc_tlv_arr_head_t *meminfo_arr_tlv_head, xchg_mem_info_t **meminfo_arr)
{
    /* array(TL)                                  URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── mem information 0(TLV)                 URPC_TLV_TYPE_MEM_INFO
     * ├── mem information 1(TLV)                 URPC_TLV_TYPE_MEM_INFO
     * └── ... */
 
    // 1. search queue information
    char *meminfo_buf = meminfo_arr_tlv_head->value.user_data;
    uint32_t meminfo_len = urpc_tlv_arr_get_user_data_len(meminfo_arr_tlv_head);
    urpc_tlv_head_t *meminfo_tlv_head = urpc_tlv_search_element(meminfo_buf, meminfo_len, URPC_TLV_TYPE_MEM_INFO);
 
    for (uint32_t i = 0; i < meminfo_arr_tlv_head->value.arr_num; i++) {
        // 2. deserialize queue information
        if (meminfo_tlv_head == NULL) {
            URPC_LIB_LOG_ERR("failed to find mem information\n");
            return URPC_FAIL;
        }
 
        if (meminfo_tlv_head->len < sizeof(xchg_mem_info_t)) {
            URPC_LIB_LOG_ERR("The size of mem information(%u) is smaller than the defined size(%u)\n",
                meminfo_tlv_head->len, sizeof(xchg_mem_info_t));
            return URPC_FAIL;
        }
 
        meminfo_arr[i] = (xchg_mem_info_t *)(uintptr_t)meminfo_tlv_head->value;
 
        // 3. search next mem information
        uint32_t left_len = urpc_tlv_get_left_len(meminfo_buf, meminfo_len, meminfo_tlv_head);
        meminfo_tlv_head = urpc_tlv_search_next_element(meminfo_tlv_head, left_len, URPC_TLV_TYPE_MEM_INFO);
    }
 
    URPC_LIB_LOG_DEBUG("deserialize meminfo arr num: %u\n",  meminfo_arr_tlv_head->value.arr_num);
    return URPC_SUCCESS;
}

static inline void connect_msg_serialize_connect_info(
    urpc_instance_key_t *input, urpc_connect_msg_t *connect_msg, urpc_tlv_head_t *connect_info_tlv_head)
{
    // connect information(TLV)                      URPC_TLV_TYPE_CONNECT_INFO
    urpc_connection_info_t *connect_info = (urpc_connection_info_t *)(uintptr_t)connect_info_tlv_head->value;

    connect_info->key.eid = input->eid;
    connect_info->key.pid = input->pid;

    connect_msg->connect_info = connect_info;

    connect_info_tlv_head->type = URPC_TLV_TYPE_CONNECT_INFO;
    connect_info_tlv_head->len = (uint32_t)sizeof(urpc_connection_info_t);
}

static urpc_chinfo_t *connect_msg_serialize_chinfo(
    urpc_chmsg_input_v2_t *chmsg_input, urpc_tlv_head_t *chinfo_tlv_head)
{
    // channel information(TLV)                     URPC_TLV_TYPE_CHANNEL_INFO
    urpc_chinfo_t *chinfo = (urpc_chinfo_t *)(uintptr_t)chinfo_tlv_head->value;

    chinfo->cap.is_support_quik_reply = is_feature_enable(URPC_FEATURE_HWUB_OFFLOAD);

    chinfo->attr = chmsg_input->client_channel->attr;
    chinfo->chid = chmsg_input->client_channel->id;
    server_node_t *server_node = channel_get_server_node(chmsg_input->client_channel, NULL);
    if (server_node == NULL) {
        chinfo->server_chid = URPC_INVALID_ID_U32;
    } else {
        chinfo->server_chid = server_node->server_chid;
    }

    provider_t *provider = chmsg_input->client_channel->provider;
    if (provider == NULL) {
        /* Client channel should bind to a specified provider before it is in use:
        * 1. multi-eid off: use get_provider() to bind the channel to the only provider when creating a channel;
        * 2. multi-eid on: bind to the same provider as the local queue to be added to the channel; */
        URPC_LIB_LOG_ERR("get provider failed, channel[%u]\n", chmsg_input->client_channel->id);
        return NULL;
    }
    provider->ops->get_eid(provider, &chinfo->key.eid);
    chinfo->key.pid = (uint32_t)getpid();

    chinfo_tlv_head->type = URPC_TLV_TYPE_CHANNEL_INFO;
    chinfo_tlv_head->len = (uint32_t)sizeof(urpc_chinfo_t);

    return chinfo;
}

static int connect_msg_serialize_qinfo_arr(
    uint64_t *queue, uint32_t queue_num, urpc_qinfo_arr_v1_t *qinfo_arr, urpc_tlv_arr_head_t *qinfo_arr_tlv_head)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * └── ... */
    urpc_tlv_head_t *qinfo_tlv_head = (urpc_tlv_head_t *)(uintptr_t)qinfo_arr_tlv_head->value.user_data;
    for (uint32_t i = 0; i < queue_num; i++) {
        if (queue[i] == URPC_INVALID_HANDLE) {
            URPC_LIB_LOG_ERR("invalid queue handle\n");
            return URPC_FAIL;
        }

        // serialize queue information
        queue_info_t *qinfo = (queue_info_t *)(uintptr_t)qinfo_tlv_head->value;
        if (channel_get_local_queue_info(queue[i], qinfo) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("query queue information failed\n");
            return URPC_FAIL;
        }

        qinfo_tlv_head->type = URPC_TLV_TYPE_QUEUE_INFO;
        qinfo_tlv_head->len = (uint32_t)sizeof(queue_info_t);

        qinfo_arr->qinfos[i] = qinfo;

        qinfo_tlv_head = urpc_tlv_get_next_element(qinfo_tlv_head);
    }

    uint32_t value_len = queue_num * (uint32_t)(sizeof(queue_info_t) + sizeof(urpc_tlv_head_t));
    qinfo_arr->arr_num = queue_num;
    qinfo_arr_tlv_head->type = URPC_TLV_TYPE_ARRAY;
    qinfo_arr_tlv_head->len = urpc_tlv_arr_get_value_len_by_user_data_len(value_len);
    qinfo_arr_tlv_head->value.arr_num = queue_num;

    return URPC_SUCCESS;
}

static int connect_msg_serialize_chmsg(
    urpc_chmsg_input_v2_t *chmsg_input, urpc_chmsg_v1_t *chmsg, urpc_tlv_head_t *chmsg_tlv_head)
{
    /* channel message 0(TL)                        URPC_TLV_TYPE_CHANNEL_MSG
     * ├── channel information(TLV)                 URPC_TLV_TYPE_CHANNEL_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. serialize channel information
    urpc_tlv_head_t *chinfo_tlv_head = (urpc_tlv_head_t *)(uintptr_t)chmsg_tlv_head->value;
    chmsg->chinfo = connect_msg_serialize_chinfo(chmsg_input, chinfo_tlv_head);
    if (chmsg->chinfo == NULL) {
        return URPC_FAIL;
    }

    // 2. serialize queue information array
    urpc_tlv_head_t *qinfo_arr_tlv_head = urpc_tlv_get_next_element(chinfo_tlv_head);
    if (connect_msg_serialize_qinfo_arr(chmsg_input->qh, chmsg_input->q_num,
        &chmsg->qinfo_arr, (urpc_tlv_arr_head_t *)(uintptr_t)qinfo_arr_tlv_head) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    chmsg_tlv_head->type = URPC_TLV_TYPE_CHANNEL_MSG;
    chmsg_tlv_head->len = urpc_tlv_get_total_len(chinfo_tlv_head) + urpc_tlv_get_total_len(qinfo_arr_tlv_head);

    return URPC_SUCCESS;
}

static int connect_msg_serialize_chmsg_arr(
    struct urpc_connect_msg_input *input, urpc_chmsg_arr_v2_t *chmsg_arr, urpc_tlv_arr_head_t *chmsg_arr_tlv_head)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── channel message 0(TL)                    URPC_TLV_TYPE_CHANNEL_MSG
     * └── channel message 1(TL)                    URPC_TLV_TYPE_CHANNEL_MSG */
    uint32_t idx = 0;
    uint32_t value_len = 0;
    urpc_tlv_head_t *chmsg_tlv_head = (urpc_tlv_head_t *)(uintptr_t)chmsg_arr_tlv_head->value.user_data;

    for (uint32_t i = 0; i < input->num; i++) {
        // 1. serialize channel message
        if (connect_msg_serialize_chmsg(&input->chmsg_arr[i], &chmsg_arr->chmsgs[idx++], chmsg_tlv_head) !=
            URPC_SUCCESS) {
            return URPC_FAIL;
        }
        value_len += urpc_tlv_get_total_len(chmsg_tlv_head);
        chmsg_tlv_head = urpc_tlv_get_next_element(chmsg_tlv_head);
    }
    chmsg_arr->arr_num = idx;
    chmsg_arr_tlv_head->type = URPC_TLV_TYPE_ARRAY;
    chmsg_arr_tlv_head->len = urpc_tlv_arr_get_value_len_by_user_data_len(value_len);
    chmsg_arr_tlv_head->value.arr_num = chmsg_arr->arr_num;

    return URPC_SUCCESS;
}

static int connect_msg_serialize_connect_msg(
    struct urpc_connect_msg_input *input, urpc_connect_msg_t *connect_msg, urpc_tlv_head_t *connect_msg_tlv_head)
{
    /* connect message(TL)                          URPC_TLV_TYPE_CONNECT_MSG
     * ├── connect information(TLV)                 URPC_TLV_TYPE_CONNECT_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. serialize attach information
    urpc_tlv_head_t *connect_info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)connect_msg_tlv_head->value;
    connect_msg_serialize_connect_info(input->key, connect_msg, connect_info_tlv_head);

    // 2. serialize channel message array
    urpc_tlv_head_t *chmsg_arr_tlv_head = urpc_tlv_get_next_element(connect_info_tlv_head);
    if (connect_msg_serialize_chmsg_arr(
        input, &connect_msg->chmsg_arr, (urpc_tlv_arr_head_t *)(uintptr_t)chmsg_arr_tlv_head) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    connect_msg_tlv_head->type = URPC_TLV_TYPE_CONNECT_MSG;
    connect_msg_tlv_head->len =
        urpc_tlv_get_total_len(connect_info_tlv_head) + urpc_tlv_get_total_len(chmsg_arr_tlv_head);

    return URPC_SUCCESS;
}

static uint32_t channel_resources_msg_v1_get_total_len(urpc_chmsg_input_v2_t chmsg_arr[], uint32_t channel_num)
{
    size_t total_len = 0;
    // local queue num does not exceed MAX_QUEUE_SIZE
    for (uint32_t i = 0; i < channel_num; i++) {
        // 1. total len for queue information
        total_len +=
            chmsg_arr[i].q_num * ((TLV_HEAD_NUM_PER_QUEUE_INFO * sizeof(urpc_tlv_head_t)) + sizeof(queue_info_t));
    }
    // 2. total len for channel message
    total_len += channel_num * (TLV_HEAD_NUM_PER_CHANNEL_MSG * sizeof(urpc_tlv_head_t) +
            TLV_ARR_HEAD_NUM_PER_CHANNEL_MSG * sizeof(urpc_tlv_arr_head_t) + sizeof(urpc_chinfo_t));
    // 3. total len for reconnect channel message
    total_len += TLV_HEAD_NUM_PER_CONNECT_MSG * sizeof(urpc_tlv_head_t) +
                 TLV_ARR_HEAD_NUM_PER_CONNECT_MSG * sizeof(urpc_tlv_arr_head_t) + sizeof(urpc_connection_info_t);
    return (uint32_t)total_len;
}

static int connect_msg_input_validation(urpc_connect_msg_input_t *input)
{
    if (input->num > URPC_MAX_CLIENT_CHANNELS_PER_CLIENT) {
        URPC_LIB_LOG_ERR("the number of channels is excessively large, count: %u\n", input->num);
        return -URPC_ERR_EINVAL;
    }
    for (uint32_t i = 0; i < input->num; i++) {
        if (input->chmsg_arr[i].q_num > MAX_QUEUE_SIZE) {
            URPC_LIB_LOG_ERR("the number of queue is excessively large\n", input->chmsg_arr[i].q_num);
            return -URPC_ERR_EINVAL;
        }
    }
    return URPC_SUCCESS;
}

int urpc_connect_msg_serialize(struct urpc_connect_msg_input *input, urpc_connect_msg_t *data)
{
    if (input == NULL || data == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }
    if (connect_msg_input_validation(input) != URPC_SUCCESS) {
        return -URPC_ERR_EINVAL;
    }
    uint32_t buf_len = channel_resources_msg_v1_get_total_len(input->chmsg_arr, input->num);
    urpc_tlv_head_t *connect_msg_tlv_head = (urpc_tlv_head_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, buf_len);
    if (connect_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("malloc connect message failed\n");
        return URPC_FAIL;
    }
    if (connect_msg_serialize_connect_msg(input, data, connect_msg_tlv_head) != URPC_SUCCESS) {
        urpc_dbuf_free(connect_msg_tlv_head);
        URPC_LIB_LOG_ERR("serialize connnect message failed\n");
        return URPC_FAIL;
    }

    data->data.buffer = (char *)(uintptr_t)connect_msg_tlv_head;
    data->data.len = buf_len;
    return URPC_SUCCESS;
}

static int connect_msg_deserialize_qinfo_arr(urpc_tlv_arr_head_t *qinfo_arr_tlv_head, urpc_qinfo_arr_v1_t *qinfo_arr)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── queue information 0(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * ├── queue information 1(TLV)                 URPC_TLV_TYPE_QUEUE_INFO
     * └── ... */
    if (qinfo_arr_tlv_head->value.arr_num > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("the number of queue information exceeds upper limit\n");
        return -URPC_ERR_EINVAL;
    }

    // 1. search queue information
    char *qinfo_buf = qinfo_arr_tlv_head->value.user_data;
    uint32_t qinfo_len = urpc_tlv_arr_get_user_data_len(qinfo_arr_tlv_head);
    if (qinfo_len == 0 && qinfo_arr_tlv_head->value.arr_num == 0) {
        goto OUT;
    }

    urpc_tlv_head_t *qinfo_tlv_head = urpc_tlv_search_element(qinfo_buf, qinfo_len, URPC_TLV_TYPE_QUEUE_INFO);
    for (uint32_t i = 0; i < qinfo_arr_tlv_head->value.arr_num; i++) {
        // 2. deserialize queue information
        if (qinfo_tlv_head == NULL) {
            URPC_LIB_LOG_ERR("failed to find queue information\n");
            return URPC_FAIL;
        }

        if (qinfo_tlv_head->len < sizeof(queue_info_t)) {
            URPC_LIB_LOG_ERR("The size of queue information(%u) is smaller than the defined size(%u)\n",
                qinfo_tlv_head->len, sizeof(queue_info_t));
            return URPC_FAIL;
        }

        qinfo_arr->qinfos[i] = (queue_info_t *)(uintptr_t)qinfo_tlv_head->value;

        // 3. search next queue information
        uint32_t left_len = urpc_tlv_get_left_len(qinfo_buf, qinfo_len, qinfo_tlv_head);
        qinfo_tlv_head = urpc_tlv_search_next_element(qinfo_tlv_head, left_len, URPC_TLV_TYPE_QUEUE_INFO);
    }

OUT:
    qinfo_arr->arr_num = qinfo_arr_tlv_head->value.arr_num;

    return URPC_SUCCESS;
}

static int connect_msg_deserialize_chmsg(char *buf, uint32_t len, urpc_chmsg_v1_t *chmsg)
{
    /* channel message 0(TL)                        URPC_TLV_TYPE_CHANNEL_MSG
     * ├── channel information(TLV)                 URPC_TLV_TYPE_CHANNEL_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. search channel information
    urpc_tlv_head_t *chinfo_tlv_head = urpc_tlv_search_element(buf, len, URPC_TLV_TYPE_CHANNEL_INFO);
    if (chinfo_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find channel information\n");
        return URPC_FAIL;
    }

    // 2. deserialize channel information
    if (chinfo_tlv_head->len < sizeof(urpc_chinfo_t)) {
        URPC_LIB_LOG_ERR("The size of channel information(%u) is smaller than the defined size(%u)\n",
            chinfo_tlv_head->len, sizeof(urpc_chinfo_t));
        return URPC_FAIL;
    }

    chmsg->chinfo = (urpc_chinfo_t *)chinfo_tlv_head->value;

    // 3. search queue information array
    uint32_t left_len = urpc_tlv_get_left_len(buf, len, chinfo_tlv_head);
    urpc_tlv_arr_head_t *qinfo_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)
        urpc_tlv_search_next_element(chinfo_tlv_head, left_len, URPC_TLV_TYPE_ARRAY);
    if (qinfo_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find queue information array\n");
        return URPC_FAIL;
    }

    // 4. deserialize queue information array
    int ret = connect_msg_deserialize_qinfo_arr(qinfo_arr_tlv_head, &chmsg->qinfo_arr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to deserialize queue information array\n");
        return ret;
    }

    return URPC_SUCCESS;
}

static int connect_msg_deserialize_chmsg_arr(urpc_tlv_arr_head_t *chmsg_arr_tlv_head, urpc_chmsg_arr_v2_t *chmsg_arr)
{
    /* array(TL)                                    URPC_TLV_TYPE_ARRAY
     * ├── array number
     * ├── channel message 0(TL)                    URPC_TLV_TYPE_CHANNEL_MSG
     * └── channel message 1(TL)                    URPC_TLV_TYPE_CHANNEL_MSG */

    // 1. search channel message
    char *chmsg_buf = chmsg_arr_tlv_head->value.user_data;
    uint32_t chmsg_len = urpc_tlv_arr_get_user_data_len(chmsg_arr_tlv_head);
    urpc_tlv_head_t *chmsg_tlv_head = NULL;
    if (chmsg_arr_tlv_head->value.arr_num != 0) {
        chmsg_tlv_head = urpc_tlv_search_element(chmsg_buf, chmsg_len, URPC_TLV_TYPE_CHANNEL_MSG);
    }

    for (uint32_t i = 0; i < chmsg_arr_tlv_head->value.arr_num; i++) {
        // 2. deserialize channel message
        if (chmsg_tlv_head == NULL) {
            URPC_LIB_LOG_ERR("failed to find channel message\n");
            return URPC_FAIL;
        }

        if (connect_msg_deserialize_chmsg(
            chmsg_tlv_head->value, chmsg_tlv_head->len, chmsg_arr->chmsgs + i) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("failed to deserialize channel message\n");
            return -URPC_ERR_EINVAL;
        }

        // 3. search next channel message
        uint32_t left_len = urpc_tlv_get_left_len(chmsg_buf, chmsg_len, chmsg_tlv_head);
        chmsg_tlv_head = urpc_tlv_search_next_element(chmsg_tlv_head, left_len, URPC_TLV_TYPE_CHANNEL_MSG);
    }

    chmsg_arr->arr_num = chmsg_arr_tlv_head->value.arr_num;

    return URPC_SUCCESS;
}

static int connect_msg_deserialize_connect_msg(char *buf, uint32_t len, urpc_connect_msg_t *data)
{
    /* connect message(TL)                          URPC_TLV_TYPE_CONNECT_MSG
     * ├── attach information(TLV)                  URPC_TLV_TYPE_CONNECT_INFO
     * └── array(TL)                                URPC_TLV_TYPE_ARRAY */

    // 1. search connect message
    urpc_tlv_head_t *connect_msg_tlv_head = urpc_tlv_search_element(buf, len, URPC_TLV_TYPE_CONNECT_MSG);
    if (connect_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find connect message\n");
        return -URPC_ERR_EINVAL;
    }

    // 2. search connect information
    urpc_tlv_head_t *connect_info_tlv_head =
        urpc_tlv_search_element(connect_msg_tlv_head->value, connect_msg_tlv_head->len, URPC_TLV_TYPE_CONNECT_INFO);
    if (connect_info_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find connect information\n");
        return -URPC_ERR_EINVAL;
    }
    if (connect_info_tlv_head->len < sizeof(urpc_connection_info_t)) {
            URPC_LIB_LOG_ERR("the size of connect information(%u) is smaller than the defined size(%u)\n",
                connect_info_tlv_head->len, sizeof(urpc_connection_info_t));
            return URPC_FAIL;
    }
    // 3. deserialize connect information
    data->connect_info = (urpc_connection_info_t *)(uintptr_t)connect_info_tlv_head->value;

    // 4. search channel message array
    uint32_t left_len = urpc_tlv_get_left_len(
        connect_msg_tlv_head->value, connect_msg_tlv_head->len, connect_info_tlv_head);
    urpc_tlv_arr_head_t *chmsg_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)
        urpc_tlv_search_next_element(connect_info_tlv_head, left_len, URPC_TLV_TYPE_ARRAY);
    if (chmsg_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find channel message array\n");
        return -URPC_ERR_EINVAL;
    }

    if (chmsg_arr_tlv_head->len < sizeof(urpc_tlv_arr_head_t) - sizeof(urpc_tlv_head_t)) {
        URPC_LIB_LOG_ERR("channel message array len invalid\n");
        return URPC_FAIL;
    }

    // 5. deserialize channel message array
    int ret = connect_msg_deserialize_chmsg_arr(chmsg_arr_tlv_head, &data->chmsg_arr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to deserialize channel message array\n");
        return ret;
    }
    return URPC_SUCCESS;
}

int urpc_connect_msg_deserialize(urpc_connect_msg_t *data)
{
    if (data == NULL || data->data.buffer == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    return connect_msg_deserialize_connect_msg(data->data.buffer, data->data.len, data);
}

void urpc_connect_msg_buffer_release(urpc_connect_msg_t *data)
{
    if (data == NULL) {
        return;
    }

    urpc_dbuf_free(data->data.buffer);
}

int urpc_connect_msg_extract_channel_count(char *buf, uint32_t len)
{
    // 1. search connect message
    urpc_tlv_head_t *connect_msg_tlv_head = urpc_tlv_search_element(buf, len, URPC_TLV_TYPE_CONNECT_MSG);
    if (connect_msg_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find attach message\n");
        return -URPC_ERR_EINVAL;
    }

    // 2. search connect information
    urpc_tlv_head_t *connect_info_tlv_head =
        urpc_tlv_search_element(connect_msg_tlv_head->value, connect_msg_tlv_head->len, URPC_TLV_TYPE_CONNECT_INFO);
    if (connect_info_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find attach information\n");
        return -URPC_ERR_EINVAL;
    }

    // 4. search channel message array
    uint32_t left_len = urpc_tlv_get_left_len(
        connect_msg_tlv_head->value, connect_msg_tlv_head->len, connect_info_tlv_head);
    urpc_tlv_arr_head_t *chmsg_arr_tlv_head = (urpc_tlv_arr_head_t *)(uintptr_t)
        urpc_tlv_search_next_element(connect_info_tlv_head, left_len, URPC_TLV_TYPE_ARRAY);
    if (chmsg_arr_tlv_head == NULL) {
        URPC_LIB_LOG_ERR("failed to find channel message array\n");
        return URPC_FAIL;
    }

    if (chmsg_arr_tlv_head->len < sizeof(urpc_tlv_arr_head_t) - sizeof(urpc_tlv_head_t)) {
        URPC_LIB_LOG_ERR("channel message array len invalid\n");
        return URPC_FAIL;
    }

    if (chmsg_arr_tlv_head->value.arr_num > URPC_MAX_CLIENT_CHANNELS_PER_CLIENT) {
        URPC_LIB_LOG_ERR("the number of channels is excessively large, count: %u\n", chmsg_arr_tlv_head->value.arr_num);
        return -URPC_ERR_EINVAL;
    }
    return (int)chmsg_arr_tlv_head->value.arr_num;
}