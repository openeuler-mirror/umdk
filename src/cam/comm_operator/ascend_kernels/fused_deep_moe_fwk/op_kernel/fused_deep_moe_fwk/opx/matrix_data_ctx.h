/*
* Copyright (c) 2025 Huawei Technologies Co., Ltd.
* This file is a part of the CANN Open Software.
* Licensed under CANN Open Software License Agreement Version 1.0 (the "License").
* Please refer to the License for details. You may not use this file except in compliance with the License.
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
* INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
* See LICENSE in the root of the software repository for the full text of the License.
*/

#pragma once


#include "opx/data_looper_ctx.h"

namespace opx
{

struct MatrixDataContext
{
    /// Config variables
    uint32_t group_list_len = 1;
    uint32_t problem_shape_m = 0;
    uint32_t problem_shape_n = 0;
    uint32_t block_num = 0;
    uint32_t block_idx = 0;
    uint32_t sub_block_num = 1;
    uint32_t sub_block_idx = 0;

    MatrixCoord block_shape;
    MatrixCoord tile_shape;

    /// Status variables
    uint32_t group_m;
    uint32_t group_m_sum;
    uint32_t group_start_block_idx;
    uint32_t group_loop_i;
    uint32_t block_loop_cnt;
    uint32_t block_loop_start_i;
    uint32_t block_loop_i;
    uint32_t block_loop_times;
    uint32_t tile_loop_cnt;
    uint32_t tile_loop_i;
    uint32_t tile_loop_times;

    MatrixCoord in_group_problem_shape;
    MatrixCoord block_coord;
    MatrixCoord actual_block_shape;
    MatrixCoord block_offset;
    MatrixCoord tile_coord;
    MatrixCoord actual_tile_shape;
    MatrixCoord tile_offset_in_block;
    MatrixCoord tile_offset;

    ProcessStatusEnum process_state;

    /// Methods
    OPX_DEVICE
    MatrixDataContext()
    {
        Reset();
    }

    OPX_DEVICE
    void Reset()
    {
        group_m = 0;
        group_m_sum = 0;
        group_start_block_idx = 0;
        group_loop_i = 0;
        block_loop_cnt = 0;
        block_loop_start_i = 0;
        block_loop_i = 0;
        block_loop_times = 0;
        tile_loop_cnt = 0;
        tile_loop_i = 0;
        tile_loop_times = 0;

        in_group_problem_shape = {};
        block_coord = {};
        actual_block_shape = {};
        block_offset = {};
        tile_coord = {};
        actual_tile_shape = {};
        tile_offset_in_block = {};
        tile_offset = {};

        process_state = PROC_NOT_START;
    }
};

} // end namespace opx
