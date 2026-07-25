/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add swiglu clip quant kernel
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create file
 */

/*!
 * \file swiglu_clip_quant.cpp
 * \brief
 */
#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#if (ORIG_DTYPE_X == DT_BF16)
    #include "swiglu_clip_quant.h"
#endif

using namespace AscendC;

#define SWIGLU_CLIP_QUANT_WITH_GROUP_NO_BIAS_FP32_QS 100000000

extern "C" __global__ __aicore__ void swiglu_clip_quant(GM_ADDR xGM,  GM_ADDR groupIndex,
                                                        GM_ADDR groupAlpha, GM_ADDR yGM,
                                                        GM_ADDR scaleGM, GM_ADDR workspace,
                                                        GM_ADDR tiling)
{
    if (workspace == nullptr) {
        return;
    }

    GM_ADDR userspace = GetUserWorkspace(workspace);
    if (userspace == nullptr) {
        return;
    }
    TPipe pipe;

#if (ORIG_DTYPE_X == DT_BF16)
    if (TILING_KEY_IS(SWIGLU_CLIP_QUANT_WITH_GROUP_NO_BIAS_FP32_QS)) {
        // New tiling branch for BF16
        GET_TILING_DATA_WITH_STRUCT(SwigluClipQuantTilingData, tilingDataIn, tiling);
        const SwigluClipQuantTilingData* __restrict__ tilingData = &tilingDataIn;
        SwigluClipQuantOps::SwigluClipQuantBase<float, float, int64_t, bfloat16_t> op(&pipe);
        op.Init(xGM, groupIndex, groupAlpha, yGM, scaleGM, tilingData);
        op.Process();
    }
#endif
}