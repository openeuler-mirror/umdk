# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/compressed_tensors/schemes/compressed_tensors_w8a8_int8.py
# Copyright (c) 2025-2026 Huawei Technologies Co., Ltd.
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

import torch
from torch.nn import Parameter
import torch_npu

from compressed_tensors.quantization import QuantizationStrategy
from module.quantization.compressed_tensors.compressed_tensors_scheme import CompressedTensorsScheme
from module.utils import set_weight_attrs


BEFORE_INIT = 0
AFTER_INIT = 1


class CompressedTensorsW8A8Int8LinearMethod(CompressedTensorsScheme):
    _kernel_backends_being_used: set[str] = set()

    def __init__(self, strategy: str, is_static_input_scheme: bool,
                 input_symmetric: bool):
        self.strategy = strategy
        self.is_static_input_scheme = is_static_input_scheme
        self.input_symmetric = input_symmetric


    def create_weights(self, layer: torch.nn.Module,
                       output_partition_sizes: List[int],
                       input_size_per_partition: int,
                       params_dtype: torch.dtype,
                       weight_loader: Callable,
                       **kwargs):
        self.logical_widths = output_partition_sizes

        weight = Parameter(torch.empty(sum(output_partition_sizes),
                                       input_size_per_partition,
                                       dtype=torch.int8),
                           requires_grad=False)
        set_weight_attrs(weight, {"input_dim": 1, "output_dim": 0, "weight_loader": weight_loader})

        layer.register_parameter("weight", weight)
        scale_dtype = torch.float32 if params_dtype == torch.float16 else torch.bfloat16


        if self.strategy == QuantizationStrategy.TENSOR:
            weight_offset = None
            weight_scale = Parameter(torch.empty(len(output_partition_sizes), dtype=scale_dtype), requires_grad=False)
            set_weight_attrs(weight_scale, {"weight_loader": weight_loader})
        else:
            weight_scale = Parameter(torch.empty((sum(output_partition_sizes), 1), dtype=scale_dtype),
                                     requires_grad=False)
            set_weight_attrs(weight_scale, {"output_dim": 0, "weight_loader": weight_loader})

        layer.register_parameter("weight_scale", weight_scale)
        smooth_scales = Parameter(torch.ones(input_size_per_partition, dtype=scale_dtype), requires_grad=False)
        layer.register_parameter("smooth_scales", smooth_scales)

        setattr(layer, "init_state", BEFORE_INIT)

        self.empty_out = torch.empty(1, dtype=params_dtype)


    def apply_weights(self, layer: torch.nn.Module,
                    x: torch.Tensor,
                    bias: Optional[torch.Tensor],
                    dynamic_scale: Optional = None,
                    out_dtype: Optional = torch.bfloat16
                    ) -> Union[torch.Tensor, Dict[str, Any]]:
        if dynamic_scale is not None:
            x_scale = dynamic_scale
        else:
            x, x_scale = torch_npu.npu_dynamic_quant(x, smooth_scales=layer.smooth_scales)
        out_shape_dim_0 = x.size()[:-1]
        x = x.view(-1, x.size(-1))
        x_scale = x_scale.view(-1)
        x = torch_npu.npu_quant_matmul(x, layer.weight,
                                    layer.weight_scale.view(-1),
                                    pertoken_scale=None if out_dtype == torch.int32 else x_scale,
                                    bias=layer.bias,
                                    output_dtype=out_dtype)
        x = x.view(out_shape_dim_0 + (-1, ))
        if out_dtype == torch.int32:
            return x, x_scale
        else:
            return x

    def process_weights_after_loading(self, layer, is_transpose=True, is_nz=True, scales_dtype=None):
        weight = layer.weight
        weight_scale = layer.weight_scale
        smooth_scales = layer.smooth_scales
        if is_transpose:
            weight.data = weight.data.transpose(-2, -1)
        if is_nz:
            weight.data = torch_npu.npu_format_cast(weight.data.contiguous(), 29)  # 29: format nz
        if 'scale_dtype' in scales_dtype:
            weight_scale.data = weight_scale.data.to(scales_dtype.get('scale_dtype'))
        if 'smooth_scale_dtype' in scales_dtype:
            smooth_scales.data = smooth_scales.data.to(scales_dtype.get('smooth_scale_dtype'))
        layer.weight = Parameter(weight, requires_grad=False)
        layer.weight_scale = Parameter(weight_scale, requires_grad=False)
        layer.smooth_scales = Parameter(smooth_scales, requires_grad=False)
