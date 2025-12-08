/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ pro-function types
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_PRO_TYPES_H
#define UMQ_PRO_TYPES_H

#include "umq_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* opcode definition */
typedef enum umq_opcode {
    UMQ_OPC_WRITE              = 0x00,
    UMQ_OPC_WRITE_IMM          = 0x01,
    UMQ_OPC_READ               = 0x10,
    UMQ_OPC_SEND               = 0x40,
    UMQ_OPC_SEND_IMM           = 0x41,
    UMQ_OPC_NOP                = 0x51,
    UMQ_OPC_LAST
} umq_opcode_t;

typedef union umq_opcode_flag {
    struct {
        uint32_t place_order : 2;      /* 0: There is no order with other qbuf
                                          1: relax order
                                          2: strong order
                                          3: reserve */
        uint32_t comp_order : 1;       /* 0: There is no completion order with othwe qbuf.
                                          1: Completion order with previous qbuf. */
        uint32_t fence : 1;            /* 0: There is not fence.
                                          1: Fence with previous read and atomic qbuf */
        uint32_t solicited_enable : 1; /* 0: There is not solicited.
                                          1: solicited. It will trigger an event on remote side */
        uint32_t complete_enable : 1;  /* 0: Do not notify local process after the task is complete.
                                          1: Notify local process after the task is completed. */
        uint32_t inline_flag : 1;      /* 0: not inline.
                                          1: inline data. */
        uint32_t reserved : 25;
    } bs;
    uint32_t value;
} umq_opcode_flag_t;

// max size of umq_buf_pro_t is 64B
typedef struct umq_buf_pro {
    umq_opcode_t opcode;
    umq_opcode_flag_t flag;

    uint64_t user_ctx;               // completion data

    uint64_t imm_data;               // imm_data in host byte order;

    struct umq_ref_sge {
        uint64_t addr;

        uint32_t length;
        uint32_t token_id;

        uint32_t token_value;
        uint32_t mempool_id : 8;
        uint32_t rsvd0 : 24;
    } remote_sge;                   // remote sge which reference read/write

    uint64_t rsvd1[2];
} umq_buf_pro_t;

#ifdef __cplusplus
}
#endif

#endif
