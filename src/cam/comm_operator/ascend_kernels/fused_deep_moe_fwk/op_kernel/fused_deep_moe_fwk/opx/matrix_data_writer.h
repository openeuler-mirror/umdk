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


#include "kernel_operator.h"
#include "opx/matrix_data_ctx.h"

namespace opx
{

template <
    typename GmType,
    uint32_t BUFFER_NUM = 1
>
struct MatrixDataWriter
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t DST_PIPE = PIPE_MTE3;

public:
    /// Methods
    OPX_DEVICE
    QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return { BUFFER_NUM, tile_shape.row() * tile_shape.column() * (uint32_t)sizeof(Element) };
    }

    OPX_DEVICE
    void DoCopy(const MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ub_tile)
    {
        using CopyUb2Gm = CopyUb2Gm<Arch::AtlasA2, GmType>;

        auto gm_tile = gm[ctx.group_m_sum * ctx.problem_shape_n + layout.GetOffset(ctx.tile_offset)];
        auto gm_tile_layout = layout.GetTileLayout(ctx.actual_tile_shape);
        auto ub_layout = Layout::template MakeLayoutInUb<Element>(ctx.actual_tile_shape);

        CopyUb2Gm{}(gm_tile, ub_tile, gm_tile_layout, ub_layout);
    }

public:
    /// Data Members
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
};

template <
    typename GmType,
    typename BlockShape,
    uint32_t BUFFER_NUM = 1,
    uint32_t WORKSPACE_STAGES = 4
>
struct MatrixStackedBlockDataWriter
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t DST_PIPE = PIPE_MTE3;

public:
    /// Methods
    OPX_DEVICE
    QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return { BUFFER_NUM, tile_shape.row() * tile_shape.column() * (uint32_t)sizeof(Element) };
    }

    OPX_DEVICE
    void DoCopy(const MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ub_tile)
    {
        using CopyUb2Gm = CopyUb2Gm<Arch::AtlasA2, GmType>;

        uint32_t stage_id = ctx.block_loop_times % WORKSPACE_STAGES;

        MatrixCoord block_offset{(stage_id * ctx.block_num + ctx.block_idx) * BlockShape::ROW, 0};
        auto gm_block = gm[layout.GetOffset(block_offset)];
        auto gm_block_layout = layout.GetTileLayout(ctx.actual_block_shape);

        auto gm_tile = gm_block[gm_block_layout.GetOffset(ctx.tile_offset_in_block)];
        auto gm_tile_layout = gm_block_layout.GetTileLayout(ctx.actual_tile_shape);
        auto ub_layout = Layout::template MakeLayoutInUb<Element>(ctx.actual_tile_shape);

        CopyUb2Gm{}(gm_tile, ub_tile, gm_tile_layout, ub_layout);
    }

public:
    /// Data Members
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
};

template <typename GmType, uint32_t BUFFER_NUM = 1>
struct MatrixRowDataWriter
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t DST_PIPE = PIPE_MTE3;

public:
    /// Methods
    OPX_DEVICE
    QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return { BUFFER_NUM, tile_shape.row() * (uint32_t)sizeof(Element) };
    }

    OPX_DEVICE
    void DoCopy(const MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ub_tile)
    {
        using CopyUb2Gm = CopyUb2Gm<Arch::AtlasA2, GmType>;

        auto gm_tile = gm[ctx.group_m_sum + layout.GetOffset(ctx.tile_offset.GetCoordByAxis<0>())];
        auto gm_tile_layout = layout.GetTileLayout(ctx.actual_tile_shape.GetCoordByAxis<0>());
        auto ub_layout = Layout::template MakeLayoutInUb<Element>(ctx.actual_tile_shape.GetCoordByAxis<0>());

        CopyUb2Gm{}(gm_tile, ub_tile, gm_tile_layout, ub_layout);
    }

public:
    /// Data Members
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
};

} // end namespace opx
