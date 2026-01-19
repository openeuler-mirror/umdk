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


#include "opx/vector_coord.h"

namespace opx
{

struct VectorIdentityTileSwizzle
{
    VectorCoord block_shape;
    VectorCoord tile_shape;
    VectorCoord loops;

    OPX_DEVICE
    VectorIdentityTileSwizzle() = default;

    OPX_DEVICE
    VectorIdentityTileSwizzle(const VectorCoord& block_shape_, const VectorCoord& tile_shape_)
        : block_shape(block_shape_), tile_shape(tile_shape_)
    {
        loops = CeilDiv(block_shape, tile_shape);
    }

    OPX_DEVICE
    uint32_t GetLoops() const
    {
        return loops.length();
    }

    OPX_DEVICE
    VectorCoord GetTileCoord(uint32_t loop_idx) const
    {
        return VectorCoord{loop_idx % loops.length()};
    }

    OPX_DEVICE
    VectorCoord GetActualTileShape(const VectorCoord& tile_coord) const
    {
        return VectorCoord::Min(tile_shape, block_shape - tile_coord * tile_shape);
    }
};

struct VectorAverageArrangementBlockSwizzle
{
    /// Data members
    VectorCoord problem_shape;
    VectorCoord block_shape;
    VectorCoord loops;

    /// Methods
    OPX_DEVICE
    VectorAverageArrangementBlockSwizzle() = default;

    OPX_DEVICE
    VectorAverageArrangementBlockSwizzle(const VectorCoord& problem_shape_, const VectorCoord& block_shape_)
        : problem_shape(problem_shape_), block_shape(block_shape_)
    {
        loops = CeilDiv(problem_shape, block_shape);
    }

    OPX_DEVICE
    void Update(const VectorCoord& problem_shape_, const VectorCoord& block_shape_)
    {
        problem_shape = problem_shape_;
        block_shape = block_shape_;
        loops = CeilDiv(problem_shape, block_shape);
    }

    OPX_DEVICE
    uint32_t GetCoreLoops() const
    {
        return loops.length();
    }

    OPX_DEVICE
    uint32_t GetBatchIdx(uint32_t task_idx) const
    {
        return task_idx / (GetCoreLoops());
    }

    OPX_DEVICE
    VectorCoord GetBlockCoord(uint32_t task_idx, uint32_t block_num) const
    {
        // task_idx = i * block_num + block_idx
        uint32_t loop_i = task_idx / block_num;
        uint32_t block_idx = task_idx % block_num;
        uint32_t loops_per_block = GetCoreLoops() / block_num;
        uint32_t remain_loops = GetCoreLoops() % block_num;
        return VectorCoord{loops_per_block * block_idx + min(block_idx, remain_loops) + loop_i};
    }

    OPX_DEVICE
    VectorCoord GetActualBlockShape(VectorCoord block_coord) const
    {
        return VectorCoord::Min(block_shape, problem_shape - block_coord * block_shape);
    }
};

} // end namespace opx
