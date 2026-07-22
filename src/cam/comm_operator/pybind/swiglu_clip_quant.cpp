/**
 * This program is free software, you can redistribute it and/or modify it.
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This file is a part of the CANN Open Software.
 * Licensed under CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include <iostream>
#include <torch/library.h>


// npu tensor max size
const int SIZE = 8;
const int DIM_0 = 0;
const int DIM_1 = 1;
const int SWIGLU_FACTOR = 2;

// 工具函数，推导输出shape
std::tuple<at::Tensor, at::Tensor> construct_swiglu_clip_quant_output_tensor(const at::Tensor& x)
{
    at::SmallVector<int64_t, SIZE> y_size(x.sizes().begin(), x.sizes().end());
    for (auto i = 0; i < x.sizes().size(); i++) {
        TORCH_CHECK(x.size(i) > 0, "All values within query's shape should be greater "
            "than 0, but shape[", i, "] is ", x.size(i));
    }
    
    // Divide the last dimension by 2
    if (!y_size.empty()) {
        y_size.back() = y_size.back() / SWIGLU_FACTOR;
    }

    at::SmallVector<int64_t, SIZE> scale_size(y_size.begin(), y_size.end() - 1);
    at::Tensor y = at::empty(y_size, x.options().dtype(at::kChar));
    at::Tensor scale = at::empty(scale_size, x.options().dtype(at::kFloat));

    return std::tuple<at::Tensor, at::Tensor>(y, scale);
}

// step2, 为NPU设备实现前向接口
std::tuple<at::Tensor, at::Tensor> swiglu_clip_quant_npu(
    const at::Tensor& x, const at::Tensor& group_index, const at::Tensor& group_alpha,
    bool activate_left, int64_t quant_mode, int64_t clamp_mode)
{
    // construct the output tensor
    auto output_tensors = construct_swiglu_clip_quant_output_tensor(x);
    at::Tensor y = std::get<0>(output_tensors);
    at::Tensor scale = std::get<1>(output_tensors);

    // convert str
    std::string quant_mode_str = "dynamic";
    if (quant_mode == 0) {
        quant_mode_str = "static";
    }
    char *quant_mode_ptr = const_cast<char *>(quant_mode_str.c_str());

    EXEC_NPU_CMD_V1(aclnnSwigluClipQuant, x, group_index, group_alpha, 
                    activate_left, quant_mode_ptr, clamp_mode, y, scale);

    return std::tuple<at::Tensor, at::Tensor>(y, scale);
}

// step3, 为META设备实现前向接口
std::tuple<at::Tensor, at::Tensor> swiglu_clip_quant_meta(
    const at::Tensor& x, const at::Tensor& group_index, const at::Tensor& group_alpha,
    bool activate_left, int64_t quant_mode, int64_t clamp_mode)
{
    // construct the output tensor
    auto output_tensors = construct_swiglu_clip_quant_output_tensor(x);
    at::Tensor y = std::get<0>(output_tensors);
    at::Tensor scale = std::get<1>(output_tensors);

    return std::tuple<at::Tensor, at::Tensor>(y, scale);
}

// step4, 为NPU设备注册前向实现
TORCH_LIBRARY_IMPL(custom, PrivateUse1, m) {
    m.impl("swiglu_clip_quant", &swiglu_clip_quant_npu);
}

// step5, 为META设备注册前向实现
TORCH_LIBRARY_IMPL(custom, Meta, m) {
    m.impl("swiglu_clip_quant", &swiglu_clip_quant_meta);
}
