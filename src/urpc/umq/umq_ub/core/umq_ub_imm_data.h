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
    IMM_TYPE_USER,
    IMM_TYPE_UB_PLUS_DEFAULT,
    IMM_TYPE_REVERSE_PULL_MEM,
    IMM_TYPE_REVERSE_PULL_MEM_FREE,
    IMM_TYPE_REVERSE_PULL_MEM_DONE,
    IMM_TYPE_FC_CREDIT_INIT,
    IMM_TYPE_FC_CREDIT_REQ,
    IMM_TYPE_FC_CREDIT_REP,
    IMM_TYPE_FC_CREDIT_RETURN_REQ,
    IMM_TYPE_FC_CREDIT_RETURN_ACK,
    IMM_TYPE_MEM_IMPORT,
    IMM_TYPE_MEM_IMPORT_DONE,
    IMM_TYPE_NOTIFY,
    IMM_TYPE_MAX,                   // max type should not exceed 16, for type is 4 bit
} umq_ub_imm_type_t;

typedef union umq_ub_imm {
    uint16_t value;
    struct {
        uint16_t type : 4;
        uint16_t rsvd1: 12;
    } bs;
    struct {
        uint16_t type : 4;
        uint16_t msg_id : 5;
        uint16_t msg_num : 5;
        uint16_t rsvd1: 2;
    } ub_plus;
    struct {
        uint16_t type : 4;
        uint16_t window : 10;
        uint16_t ratio : 2;     // 0: 10%, 1: 30%, 2: 50%, 3: 70%, min reserved credit: modify to 70%
    } flow_control;
    struct {
        uint16_t type : 4;
        uint16_t rsvd1 : 2;
        uint16_t mempool_id : 10;
    } mem_import;
    struct {
        uint16_t type : 4;
        uint16_t rsvd1 : 12;
    } notify;
} umq_ub_imm_t;

#ifdef __cplusplus
}
#endif

#endif
