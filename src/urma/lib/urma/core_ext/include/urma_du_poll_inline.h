/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2026. All rights reserved.
 * Description: Direct URMA completion primitives. Included by urma_du.h.
 *              Only status decoding is provided; the application owns the
 *              completion loop, the wrid lookup and the index advancement.
 * Create: 2026-10-08
 */

#ifndef URMA_DU_POLL_INLINE_H
#define URMA_DU_POLL_INLINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "urma_types.h"

#define URMA_DU_SRC_STATUS_NUM 7
#define URMA_DU_SUB_STATUS_NUM 5

struct urma_du_cr_status_map {
    bool is_valid;
    urma_cr_status_t cr_status;
};

static const struct urma_du_cr_status_map
    g_urma_du_cr_status_map[URMA_DU_SRC_STATUS_NUM][URMA_DU_SUB_STATUS_NUM] = {
    {{true, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
     {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
    {{true, URMA_CR_UNSUPPORTED_OPCODE_ERR}, {false, URMA_CR_SUCCESS},
     {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
    {{false, URMA_CR_SUCCESS}, {true, URMA_CR_LOC_LEN_ERR}, {true, URMA_CR_LOC_ACCESS_ERR},
     {true, URMA_CR_REM_RESP_LEN_ERR}, {true, URMA_CR_LOC_DATA_POISON}},
    {{false, URMA_CR_SUCCESS}, {true, URMA_CR_REM_UNSUPPORTED_REQ_ERR},
     {true, URMA_CR_REM_ACCESS_ABORT_ERR}, {false, URMA_CR_SUCCESS},
     {true, URMA_CR_REM_DATA_POISON}},
    {{true, URMA_CR_RNR_RETRY_CNT_EXC_ERR}, {false, URMA_CR_SUCCESS},
     {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
    {{true, URMA_CR_ACK_TIMEOUT_ERR}, {false, URMA_CR_SUCCESS},
     {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
    {{true, URMA_CR_WR_FLUSH_ERR}, {false, URMA_CR_SUCCESS},
     {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}}
};

static inline int urma_du_get_cr_status(uint8_t src_status, uint8_t substatus,
                                        urma_cr_status_t *dst_status)
{
    if (src_status < URMA_DU_SRC_STATUS_NUM && substatus < URMA_DU_SUB_STATUS_NUM &&
        g_urma_du_cr_status_map[src_status][substatus].is_valid) {
        *dst_status = g_urma_du_cr_status_map[src_status][substatus].cr_status;
        return 0;
    }

    return -1;
}

#endif /* URMA_DU_POLL_INLINE_H */
