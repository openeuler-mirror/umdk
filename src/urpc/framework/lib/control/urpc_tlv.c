/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: uRPC tlv utils
 */

#include "urpc_lib_log.h"
#include "urpc_tlv.h"

static bool urpc_tlv_buf_validation(const char *buf, uint32_t buf_size)
{
    if (buf == NULL || buf_size < sizeof(urpc_tlv_head_t)) {
        URPC_LIB_LOG_ERR("invalid arguments\n");
        return false;
    }

    if ((uint64_t)(uintptr_t)buf > UINT64_MAX - buf_size) {
        URPC_LIB_LOG_ERR("buffer range exceeds the upper limit\n");
        return false;
    }

    return true;
}

urpc_tlv_head_t *urpc_tlv_search_element(char *buf, uint32_t buf_size, urpc_tlv_type_t type)
{
    if (!urpc_tlv_buf_validation(buf, buf_size)) {
        return NULL;
    }

    uint32_t offset = 0;
    /* Assure next tlv head not exceeds buf_size */
    while (offset <= buf_size - sizeof(urpc_tlv_head_t)) {
        urpc_tlv_head_t *tlv_head = (urpc_tlv_head_t *)(uintptr_t)(buf + offset);
        /* Assure current tlv element not exceeds buf_size:
         * 1. this tlv element is valid at least in length and user can parse this tlv element safely;
         * 2. offset can move safely by adding total length of current tlv element; */
        if (urpc_tlv_get_total_len(tlv_head) > buf_size - offset) {
            return NULL;
        }

        if (tlv_head->type == (uint32_t)type) {
            return tlv_head;
        }

        offset += urpc_tlv_get_total_len(tlv_head);
    }

    return NULL;
}

urpc_tlv_head_t *urpc_tlv_search_next_element(urpc_tlv_head_t *cur, uint32_t left_size, urpc_tlv_type_t type)
{
    if (!urpc_tlv_buf_validation((char *)(uintptr_t)cur, left_size)) {
        return NULL;
    }

    /* Assure the next tlv head is within the range of provided buffer */
    uint32_t total_len = urpc_tlv_get_total_len(cur);
    if (left_size - sizeof(urpc_tlv_head_t) < total_len) {
        return NULL;
    }

    return urpc_tlv_search_element((char *)(uintptr_t)urpc_tlv_get_next_element(cur), left_size - total_len, type);
}