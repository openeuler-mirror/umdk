/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add gmm_swiglu_quant_v2_layered pybind extention file
 * Create: 2026-09-18
 * Note:
 * History: 2026-09-18
 */
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "pytorch_npu_helper.hpp"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

// quantMode == 2 selects mx-style quantization (per-64-block scale pairs).
constexpr int64_t QUANT_MODE_MX = 2;

// Output shapes follow the op infershape: m from x_scale dim0, n from the
// per-channel weight scale last dim (halved by swiglu).
static void AllocSwigluQuantOutputs(const at::Tensor &xScale, const at::TensorList &allWeightScale,
                                    const int64_t quantMode, at::Tensor &yOut, at::Tensor &yScaleOut)
{
    int64_t m = xScale.size(0);
    int64_t n = allWeightScale[0].size(-1);
    int64_t nAfterHalve = n / 2;
    yOut = at::empty({m, nAfterHalve}, xScale.options().dtype(at::kChar));
    if (quantMode == QUANT_MODE_MX) {
        // mx-style quant: per-64-block scale pairs
        int64_t nAfterSplit = (nAfterHalve + 63) / 64;
        yScaleOut = at::empty({m, nAfterSplit, 2}, xScale.options().dtype(at::kFloat));
    } else {
        yScaleOut = at::empty({m}, xScale.options().dtype(at::kFloat));
    }
}

tensor_list cam_gmm_swiglu_quant_v2_layered_impl_npu(
    const at::Tensor &x,
    const at::TensorList &allWeight,
    const at::TensorList &allWeightScale,
    const at::TensorList &allWeightAssistMatrix,
    const at::Tensor &xScale,
    const at::Tensor &groupList,
    const at::Tensor &layerIndex,
    const int64_t dequantMode,
    const int64_t quantMode,
    const int64_t groupListType,
    const c10::optional<std::vector<int64_t>> &tuningConfigOptional)
{
    at::Tensor yOut;
    at::Tensor yScaleOut;
    AllocSwigluQuantOutputs(xScale, allWeightScale, quantMode, yOut, yScaleOut);

    // bias / smoothScale are not exposed: bias must stay null on the A8W4/A8W8
    // paths and smoothScale is A4W4-only; pass empty placeholders the op_api
    // normalizes to nullptr.
    at::Tensor biasPlaceholder;
    at::Tensor smoothScalePlaceholder;

    c10::optional<at::IntArrayRef> tuningConfigRef;
    if (tuningConfigOptional.has_value() && tuningConfigOptional->size() > 0) {
        tuningConfigRef = at::IntArrayRef(tuningConfigOptional->data(), tuningConfigOptional->size());
    }

    // EXEC_NPU_CMD's parameter packing requires lvalues; materialize the derived attrs.
    // NOTE: the aclnn API has no quant_dtype argument -- the op_api derives it from
    // the output tensor's dtype via output->GetDataType(). Passing an extra int64_t
    // here shifts every subsequent argument (tuning_config -> output, y_out ->
    // output_scale, ...), which makes `output` read tuningConfigRef (nullptr when
    // tuning_config is None) and trips "Expected a proper Tensor but got null for
    // argument output.".
    int64_t dequantDtype = static_cast<int64_t>(at::kFloat);
    EXEC_NPU_CMD(aclnnGroupedMatmulSwigluQuantV2Layered,
        // input
        x, allWeight, allWeightScale, allWeightAssistMatrix, biasPlaceholder, xScale,
        smoothScalePlaceholder, groupList, layerIndex,
        // attr
        dequantMode, dequantDtype, quantMode, groupListType, tuningConfigRef,
        // output
        yOut, yScaleOut);
    return {yOut, yScaleOut};
}

tensor_list cam_gmm_swiglu_quant_v2_layered_impl_meta(
    const at::Tensor &x,
    const at::TensorList &allWeight,
    const at::TensorList &allWeightScale,
    const at::TensorList &allWeightAssistMatrix,
    const at::Tensor &xScale,
    const at::Tensor &groupList,
    const at::Tensor &layerIndex,
    const int64_t dequantMode,
    const int64_t quantMode,
    const int64_t groupListType,
    const c10::optional<std::vector<int64_t>> &tuningConfigOptional)
{
    at::Tensor yOut;
    at::Tensor yScaleOut;
    AllocSwigluQuantOutputs(xScale, allWeightScale, quantMode, yOut, yScaleOut);
    return {yOut, yScaleOut};
}

tensor_list cam_gmm_swiglu_quant_v2_layered_impl(
    const at::Tensor &x,
    const at::TensorList &allWeight,
    const at::TensorList &allWeightScale,
    const at::TensorList &allWeightAssistMatrix,
    const at::Tensor &xScale,
    const at::Tensor &groupList,
    const at::Tensor &layerIndex,
    const int64_t dequantMode,
    const int64_t quantMode,
    const int64_t groupListType,
    const c10::optional<std::vector<int64_t>> &tuningConfigOptional)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::gmm_swiglu_quant_v2_layered", "")
                         .typed<decltype(cam_gmm_swiglu_quant_v2_layered_impl)>();
    return op.call(x, allWeight, allWeightScale, allWeightAssistMatrix, xScale, groupList, layerIndex,
        dequantMode, quantMode, groupListType, tuningConfigOptional);
}

// bind forward/backward via torch::autograd::Function subclass
class ExtCamGmmSwigluQuantV2Layered : public torch::autograd::Function<ExtCamGmmSwigluQuantV2Layered> {
public:
    static tensor_list forward(AutogradContext *ctx,
                               const at::Tensor &x,
                               const at::TensorList &allWeight,
                               const at::TensorList &allWeightScale,
                               const at::TensorList &allWeightAssistMatrix,
                               const at::Tensor &xScale,
                               const at::Tensor &groupList,
                               const at::Tensor &layerIndex,
                               const int64_t dequantMode,
                               const int64_t quantMode,
                               const int64_t groupListType,
                               const c10::optional<std::vector<int64_t>> &tuningConfigOptional)
    {
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = cam_gmm_swiglu_quant_v2_layered_impl(x, allWeight, allWeightScale, allWeightAssistMatrix,
            xScale, groupList, layerIndex, dequantMode, quantMode, groupListType, tuningConfigOptional);
        return result;
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor(),
                at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

tensor_list cam_gmm_swiglu_quant_v2_layered_impl_autograd(
    const at::Tensor &x,
    const at::TensorList &allWeight,
    const at::TensorList &allWeightScale,
    const at::TensorList &allWeightAssistMatrix,
    const at::Tensor &xScale,
    const at::Tensor &groupList,
    const at::Tensor &layerIndex,
    const int64_t dequantMode,
    const int64_t quantMode,
    const int64_t groupListType,
    const c10::optional<std::vector<int64_t>> &tuningConfigOptional)
{
    auto result = ExtCamGmmSwigluQuantV2Layered::apply(x, allWeight, allWeightScale, allWeightAssistMatrix,
        xScale, groupList, layerIndex, dequantMode, quantMode, groupListType, tuningConfigOptional);
    return result;
}

// gmm_swiglu_quant_v2_layered
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("gmm_swiglu_quant_v2_layered", &cam_gmm_swiglu_quant_v2_layered_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("gmm_swiglu_quant_v2_layered", &cam_gmm_swiglu_quant_v2_layered_impl_autograd);
}

// register forward/backward impl for Meta device
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("gmm_swiglu_quant_v2_layered", &cam_gmm_swiglu_quant_v2_layered_impl_meta);
}
