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
#define UMQ_UB_IMM_IN_USER_BUF 1  // user buffer with umq defined imm data

typedef enum umq_ub_fc_credit_type {
    IMM_TYPE_FC_CREDIT_INIT = 0,
    IMM_TYPE_FC_CREDIT_REQ,
    IMM_TYPE_FC_CREDIT_REP,
    IMM_TYPE_FC_CREDIT_RETURN_REQ,
    IMM_TYPE_FC_CREDIT_RETURN_ACK,
    IMM_TYPE_FC_CREDIT_MAX
} umq_ub_fc_credit_type_t;

/*
 * umq_ub_imm_extend_type starts from 1 since 0 is reserved in flow_control imm.
 */
typedef enum umq_ub_imm_extend_type {
    IMM_TYPE_EXTEND_UB_PLUS_DEFAULT = 1,
    IMM_TYPE_EXTEND_PULL_MEM,
    IMM_TYPE_EXTEND_PULL_MEM_FREE,
    IMM_TYPE_EXTEND_PULL_MEM_DONE,
    IMM_TYPE_EXTEND_MEM_IMPORT,
    IMM_TYPE_EXTEND_MEM_IMPORT_DONE,
    IMM_TYPE_EXTEND_NOTIFY,
    IMM_TYPE_EXTEND_MAX
} umq_ub_imm_extend_type_t;

typedef enum umq_ub_imm_type {
    IMM_TYPE_USER = 0,
    IMM_TYPE_USER_WITHOUT_IMM,
    IMM_TYPE_CONTROL_MSG,
    IMM_TYPE_RESERVER,
    IMM_TYPE_MAX,                   // max type should not exceed 4, for type is 2 bit
} umq_ub_imm_type_t;

typedef union umq_ub_imm {
    uint64_t value;
    struct {
        uint64_t type : 2;
        uint64_t rsvd1 : 62;
    } bs;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t user_data : 24;
    } io_imm;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t extend_type : 4;
        uint64_t window : 10;
        uint64_t ratio : 2;
        uint64_t seq : 8;
    } flow_control;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t extend_type : 4;
        uint64_t rsvd2 : 20;
    } bs_ext;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t extend_type : 4;
        uint64_t msg_id : 5;
        uint64_t msg_num : 5;
        uint64_t rsvd2 : 10;
    } ub_plus;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t extend_type : 4;
        uint64_t mempool_id : 10;
        uint64_t rsvd2 : 10;
    } mem_import;
    struct {
        uint64_t type : 2;
        uint64_t umq_id : 18;
        uint64_t rsvd1 : 20;
        uint64_t extend_type : 4;
        uint64_t rsvd2 : 20;
    } notify;
} umq_ub_imm_t;

#ifdef __cplusplus
}
#endif

#endif