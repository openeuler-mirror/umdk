/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UB imm data definition
 * Create: 2025-9-16
 */

#ifndef UMQ_UB_IMM_DATA_H
#define UMQ_UB_IMM_DATA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_UB_IMM_BITS (0xFFFFFFFFFFFFFFFF)
// in host byte order and bit order
#define UMQ_UB_IMM_WITHOUT_PRIVATE_BITS (0xFFFFFFFFFFFFFFFE)
#define UMQ_UB_IMM_PRIVATE 1
#define UMQ_UB_IMM_IN_USER_BUF 1  // user buffer with umq defined imm data

typedef enum umq_ub_imm_type {
    IMM_TYPE_UB_PLUS,               // used for ub plus imm type
    IMM_TYPE_FLOW_CONTROL,          // used for flow control window exchange
    IMM_TYPE_MEM_IMPORT_DONE,       // used for import mem in ub plus mode
    IMM_TYPE_NOTIFY,                // used for notify

    IMM_TYPE_MAX,                   // max type should not exceed 32, for type is 5 bit
} umq_ub_imm_type_t;

typedef enum umq_ub_plus_imm_sub_type {
    IMM_TYPE_UB_PLUS_DEFAULT,       // used for default sub type in ub plus mode
    IMM_TYPE_REVERSE_PULL_MEM,      // used for reverse pull mem in ub plus mode
    IMM_TYPE_REVERSE_PULL_MEM_FREE, // used for free reverse pull mem in ub plus mode
    IMM_TYPE_REVERSE_PULL_MEM_DONE, // used for reverse pull mem done in ub plus mode

    IMM_TYPE_UB_PLUS_MAX,           // max type should not exceed 32, for type is 5 bit
} umq_ub_plus_imm_sub_type_t;

typedef union umq_ub_imm {
    uint64_t value;
    struct {
        uint64_t umq_private : 1;  // 0: user defined imm data, 1: umq defined imm data
        uint64_t type : 5;
        uint64_t rsvd1 : 58;
    } bs;
    struct {
        uint64_t umq_private : 1;
        uint64_t type : 5;
        uint64_t sub_type : 5;
        uint64_t rsvd1 : 5;
        uint64_t msg_id : 16;
        uint64_t msg_num : 16;
        uint64_t rsvd2 : 16;
    } ub_plus;
    struct {
        uint64_t umq_private : 1;
        uint64_t type : 5;
        uint64_t in_user_buf : 1;
        uint64_t rsvd1 : 9;
        uint64_t window : 16;
        uint64_t rsvd2 : 32;
    } flow_control;
    struct {
        uint64_t umq_private : 1;
        uint64_t type : 5;
        uint64_t rsvd1 : 10;
        uint64_t mempool_id : 16;
        uint64_t rsvd2 : 32;
    } mem_import_done;
    struct {
        uint64_t umq_private : 1;
        uint64_t type : 5;
        uint64_t rsvd1 : 58;
    } notify;
} umq_ub_imm_t;

#ifdef __cplusplus
}
#endif

#endif
