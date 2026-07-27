# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/fp8.py
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Callable, Any, Dict, List, Optional, Union

import math

import torch
import torch_npu
import torch.nn.functional as F
from torch.nn import Parameter

from module.quantization import QuantizationMethods, QuantizeMethodBase, QuantizationConfig
from module.linear import LinearBase, LinearMethodBase, UnquantizedLinearMethod
from module.quantization.utils.quant_utils import is_layer_skipped, reshape_mx_scale
from module.fuse_moe_gmm import FusedMoEGMM, FusedMoeWeightScaleSupported
from module.utils import set_weight_attrs


ACTIVATION_SCHEMES = ["static", "dynamic"]
BEFORE_INIT = 0
AFTER_INIT = 1
BLOCK_K = 32


def unpack_mxfloat4_to_fp32(packed_tensor):
    # step 1
    e2m1_values = torch.tensor(
        [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, -0.0, -0.5, -1.0, -1.5, -2.0, -3.0, -4.0, -6.0],
        dtype=torch.float32,
        device=packed_tensor.device
        )

    # step 2
    low_4bits = packed_tensor & 0x0F
    high_4bits = (packed_tensor // 16) & 0x0F

    # step 3
    unpacked = torch.stack([low_4bits, high_4bits], dim=-1)

    # step 4
    fp32_tensor = e2m1_values[unpacked.long()]

    # step 5
    new_shape = list(packed_tensor.shape)
    new_shape[-1] = new_shape[-1] * 2
    return fp32_tensor.view(*new_shape)


class W4A8MxFp4MoEGMMMethod(QuantizeMethodBase):
    def __init__(self):
        super().__init__()
        STORAGE_BITS_NPU = 8
        WEIGHT_BITS = 4
        self.pack_factor = STORAGE_BITS_NPU // WEIGHT_BITS

    def create_weights(
        self,
        layer: torch.nn.Module,
        num_experts: int,
        hidden_size: int,
        intermediate_size_per_partition: int,
        params_dtype: torch.dtype,
        **extra_weight_attrs,
    ) -> None:
        weight_type = torch.uint8
        scale_dtype = torch.uint8

        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition,
                                                    hidden_size // self.pack_factor,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size,
                                                    intermediate_size_per_partition // self.pack_factor,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.BLOCK.value})

        w13_weight_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  math.ceil(hidden_size / BLOCK_K),
                                                  dtype=scale_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_weight_scale", w13_weight_scale)
        set_weight_attrs(w13_weight_scale, extra_weight_attrs)

        w2_weight_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 hidden_size,
                                                 math.ceil(intermediate_size_per_partition / BLOCK_K),
                                                 dtype=scale_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_weight_scale", w2_weight_scale)
        set_weight_attrs(w2_weight_scale, extra_weight_attrs)

    def apply(
        self,
        layer: torch.nn.Module,
        x: torch.Tensor,
        expert_tokens: torch.Tensor,
        group_list_type: int,
        pertoken_scale: torch.Tensor = None,
        final_output_dtype: torch.dtype = torch.bfloat16,
        **kwargs
    ):
        if pertoken_scale is None:
            x, pertoken_scale = torch_npu.npu_dynamic_mx_quant(x, dst_type=torch.float8_e4m3fn)
        num_tokens = x.shape[0]
        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight.transpose(1, 2)],
            antiquant_scale=[layer.w13_weight_scale],
            per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=torch.bfloat16, group_type=0,
            weight_dtype=torch_npu.float4_e2m1fn_x2,
            per_token_scale_dtype=torch_npu.float8_e8m0fnu,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        swiglu_limit = kwargs.get("swiglu_limit", None)
        enable_custom_ops = kwargs.get("enable_custom_ops", False)
        if enable_custom_ops:
            intermediate_h, pertoken_scale, _ = torch.ops.custom.npu_swiglu_group_quant(mm1_mm3,
                                                                                        dst_type=torch.float8_e4m3fn,
                                                                                        round_scale=True,
                                                                                        quant_mode=1,
                                                                                        clamp_limit=swiglu_limit,
                                                                                        group_index=expert_tokens)
        else:
            mm1_mm3 = torch_npu.npu_swiglu(mm1_mm3)
            intermediate_h, pertoken_scale = torch_npu.npu_dynamic_mx_quant(mm1_mm3, dst_type=torch.float8_e4m3fn)

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight.transpose(1, 2)], bias=None,
            antiquant_scale=[layer.w2_weight_scale],
            per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
            weight_dtype=torch_npu.float4_e2m1fn_x2,
            per_token_scale_dtype=torch_npu.float8_e8m0fnu,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        return out_hidden

    def process_weights_after_loading(
        self, layer: torch.nn.Module,
        is_transpose: bool = True,
        is_nz: bool = True,
        **kwargs,
    ) -> None:
        w13_weight = layer.w13_weight
        w2_weight = layer.w2_weight
        w13_weight_scale = layer.w13_weight_scale
        w2_weight_scale = layer.w2_weight_scale

        w13_weight = torch_npu.npu_format_cast(
            w13_weight.data.contiguous(), 29,
            customize_dtype=torch.float8_e4m3fn,
            input_dtype=torch_npu.float4_e2m1fn_x2
        )
        w2_weight = torch_npu.npu_format_cast(
            w2_weight.data.contiguous(), 29,
            customize_dtype=torch.float8_e4m3fn,
            input_dtype=torch_npu.float4_e2m1fn_x2
        )
        w13_weight_scale.data = reshape_mx_scale(w13_weight_scale.data).transpose(1, 2)
        w2_weight_scale.data = reshape_mx_scale(w2_weight_scale.data).transpose(1, 2)

        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)


class UpGateW4A4DownW4A8MxFp4MoEGMMMethod(W4A8MxFp4MoEGMMMethod):
    def __init__(self):
        super().__init__()

    def create_weights(
        self,
        layer: torch.nn.Module,
        num_experts: int,
        hidden_size: int,
        intermediate_size_per_partition: int,
        params_dtype: torch.dtype,
        **extra_weight_attrs,
    ) -> None:
        weight_type = torch.uint8
        scale_dtype = torch.uint8

        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition,
                                                    hidden_size // self.pack_factor,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size,
                                                    intermediate_size_per_partition // self.pack_factor,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.BLOCK.value})

        w13_weight_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  math.ceil(hidden_size / BLOCK_K),
                                                  dtype=scale_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_weight_scale", w13_weight_scale)
        set_weight_attrs(w13_weight_scale, extra_weight_attrs)

        w2_weight_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 hidden_size,
                                                 math.ceil(intermediate_size_per_partition / BLOCK_K),
                                                 dtype=scale_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_weight_scale", w2_weight_scale)
        set_weight_attrs(w2_weight_scale, extra_weight_attrs)

    def apply(
        self,
        layer: torch.nn.Module,
        x: torch.Tensor,
        expert_tokens: torch.Tensor,
        group_list_type: int,
        pertoken_scale: torch.Tensor = None,
        final_output_dtype: torch.dtype = torch.bfloat16,
        **kwargs
    ):
        if pertoken_scale is None:
            x, pertoken_scale = torch_npu.npu_dynamic_mx_quant(x, dst_type=torch_npu.float4_e2m1fn_x2)
        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight],
            scale=[layer.w13_weight_scale],
            per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3, group_type=0,
            output_dtype=torch.bfloat16,
            x_dtype=torch_npu.float4_e2m1fn_x2,
            weight_dtype=torch_npu.float4_e2m1fn_x2,
            scale_dtype=torch_npu.float8_e8m0fnu,
            per_token_scale_dtype=torch_npu.float8_e8m0fnu,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        swiglu_limit = kwargs.get("swiglu_limit", None)
        enable_custom_ops = kwargs.get("enable_custom_ops", False)
        if enable_custom_ops:
            intermediate_h, pertoken_scale, _ = torch.ops.custom.npu_swiglu_group_quant(mm1_mm3,
                                                                                        dst_type=torch.float8_e4m3fn,
                                                                                        round_scale=True,
                                                                                        quant_mode=1,
                                                                                        clamp_limit=swiglu_limit,
                                                                                        group_index=expert_tokens)
        else:
            mm1_mm3 = torch_npu.npu_swiglu(mm1_mm3)
            intermediate_h, pertoken_scale = torch_npu.npu_dynamic_mx_quant(mm1_mm3, dst_type=torch.float8_e4m3fn)

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight.transpose(1, 2)], bias=None,
            antiquant_scale=[layer.w2_weight_scale],
            per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
            weight_dtype=torch_npu.float4_e2m1fn_x2,
            per_token_scale_dtype=torch_npu.float8_e8m0fnu,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        return out_hidden

    def process_weights_after_loading(
        self, layer: torch.nn.Module,
        is_transpose: bool = True,
        is_nz: bool = True,
        **kwargs,
    ) -> None:
        w13_weight = layer.w13_weight
        w2_weight = layer.w2_weight
        w13_weight_scale = layer.w13_weight_scale
        w2_weight_scale = layer.w2_weight_scale

        # w13 transpose + nd; w2 nz, transpose when inference
        w13_weight.data = w13_weight.data.transpose(1, 2)
        w2_weight = torch_npu.npu_format_cast(
            w2_weight.data.contiguous(), 29,
            customize_dtype=torch.float8_e4m3fn,
            input_dtype=torch_npu.float4_e2m1fn_x2
        )
        w13_weight_scale.data = reshape_mx_scale(w13_weight_scale.data).transpose(1, 2)
        w2_weight_scale.data = reshape_mx_scale(w2_weight_scale.data).transpose(1, 2)

        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)