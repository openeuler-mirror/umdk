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


namespace opx
{

enum class DataPipeSyncMode
{
    NO_SYNC,
    SYNC_AUTO,
    SYNC_MANUAL
};

template <
    typename GmType
>
class DataPipe
{
public:
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    OPX_DEVICE
    void Init(
        __gm__ Element* gm_addr_,
        const Layout& gm_layout_,
        uint32_t block_num_,
        uint32_t block_idx_
    )
    {
        gm.SetGlobalBuffer(gm_addr_);
        layout = gm_layout_;
        block_num = block_num_;
        block_idx = block_idx_;
    }

    OPX_DEVICE
    void Write(
        const MatrixCoord& block_offset,
        const MatrixCoord& tile_offset_in_block,
        const MatrixCoord& actual_tile_shape
    )
    {

    }

private:
    /// Data Members
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
    uint32_t block_num;
    uint32_t block_idx;

    uint32_t write_cnt = 0;
};

} // end namespace opx
