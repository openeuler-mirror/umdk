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

import math
from typing import Callable, Any, Dict, List, Optional, Union

import torch
import torch_npu
import torch.nn.functional as F
from torch.nn import Parameter
from module.quantization import QuantizationMethods, QuantizeMethodBase, QuantizationConfig
from module.linear import LinearBase, LinearMethodBase, UnquantizedLinearMethod
from module.quantization.utils.quant_utils import is_layer_skipped
from module.fuse_moe_gmm import FusedMoEGMM, FusedMoeWeightScaleSupported
from module.utils import set_weight_attrs


ACTIVATION_SCHEMES = ["static", "dynamic"]
BEFORE_INIT = 0
AFTER_INIT = 1


class Fp8Config(QuantizationConfig):
    """Config class for FP8."""

    def __init__(
        self,
        is_checkpoint_fp8_serialized: bool = False,
        activation_scheme: str = "dynamic",
        ignored_layers: Optional[list[str]] = None,
        weight_block_size: Optional[list[int]] = None,
    ) -> None:
        super().__init__()

        self.is_checkpoint_fp8_serialized = is_checkpoint_fp8_serialized

        if activation_scheme not in ACTIVATION_SCHEMES:
            raise ValueError(
                f"Unsupported activation scheme {activation_scheme}")
        self.activation_scheme = activation_scheme
        self.ignored_layers = ignored_layers or []
        if weight_block_size is not None:
            if not is_checkpoint_fp8_serialized:
                raise ValueError(
                    "The block-wise quantization only supports fp8-serialized "
                    "checkpoint for now.")
            if len(weight_block_size) != 2:
                raise ValueError(
                    "The quantization block size of weight must have 2 "
                    f"dimensions, but got {len(weight_block_size)} dimensions")
            if activation_scheme != "dynamic":
                raise ValueError("The block-wise quantization only supports "
                                 "dynamic activation scheme for now, but got "
                                 f"{activation_scheme} activation scheme.")
        self.weight_block_size = weight_block_size

    @classmethod
    def get_name(cls) -> QuantizationMethods:
        return "fp8"

    @classmethod
    def get_supported_act_dtypes(cls) -> list[torch.dtype]:
        return [torch.bfloat16, torch.half]

    @classmethod
    def get_config_filenames(cls) -> list[str]:
        return []

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "Fp8Config":
        quant_method = cls.get_from_keys(config, ["quant_method"])
        is_checkpoint_fp8_serialized = ("fp8" in quant_method)
        activation_scheme = cls.get_from_keys(config, ["activation_scheme"])
        ignored_layers = cls.get_from_keys_or(config, ["ignored_layers", "modules_to_not_convert"], None)
        weight_block_size = cls.get_from_keys_or(config, ["weight_block_size"],
                                                 None)
        quant_config_instance = cls(
            is_checkpoint_fp8_serialized=is_checkpoint_fp8_serialized,
            activation_scheme=activation_scheme,
            ignored_layers=ignored_layers,
            weight_block_size=weight_block_size
        )
        quant_config_instance.mm_quant_mode = "w8a8float8"
        quant_config_instance.gmm_quant_mode = "w8a8float8"
        kv_cache_scheme = config.get("kv_cache_scheme")
        if kv_cache_scheme is not None:
            quant_config_instance.kv_cache_quant_mode = \
                kv_cache_scheme.get("type", "float") + str(kv_cache_scheme.get("num_bits", 8))
        return quant_config_instance

    def get_quant_method(self, layer: torch.nn.Module,
                         prefix: str) -> Optional["QuantizeMethodBase"]:

        if isinstance(layer, LinearBase):
            if is_layer_skipped(prefix=prefix,
                                ignored_layers=self.ignored_layers,
                                fused_mapping=self.packed_modules_mapping):
                return UnquantizedLinearMethod()
            return Fp8LinearMethod(self)
        elif isinstance(layer, FusedMoEGMM):
            return Fp8MoEGMMMethod(self)
        return None


class Fp8LinearMethod(LinearMethodBase):
    _kernel_backends_being_used: set[str] = set()

    def __init__(self, quant_config):
        self.out_dtype = torch.get_default_dtype()
        self.weight_block_size = quant_config.weight_block_size
        self.block_quant = self.weight_block_size is not None

    def create_weights(self,
                       layer: torch.nn.Module,
                       input_size_per_partition: int,
                       output_partition_sizes: list[int],
                       input_size: int,
                       output_size: int,
                       params_dtype: torch.dtype,
                       weight_loader: Callable,
                       **kwargs):
        weight_dtype = torch.float8_e4m3fn

        weight = Parameter(torch.empty(sum(output_partition_sizes),
                                       input_size_per_partition,
                                       dtype=weight_dtype),
                           requires_grad=False)
        set_weight_attrs(weight, {"input_dim": 1, "output_dim": 0, "weight_loader": weight_loader})
        layer.register_parameter("weight", weight)

        scale_dtype = torch.float32
        block_n, block_k = self.weight_block_size[0], self.weight_block_size[1]

        scale = Parameter(
            torch.empty(
                (math.ceil(sum(output_partition_sizes) / block_n),
                math.ceil(input_size_per_partition / block_k)),
                dtype=scale_dtype
            ),
            requires_grad=False
        )
        set_weight_attrs(
            scale, {"input_dim": 1, "output_dim": 0, "is_per_block_scale": True, "weight_loader": weight_loader})
        layer.register_parameter("scale", scale)

        setattr(layer, "init_state", BEFORE_INIT)

    def apply(self, layer: torch.nn.Module,
                    x: torch.Tensor,
                    bias: Optional[torch.Tensor],
                    dynamic_scale: Optional = None,
                    out_dtype: Optional = torch.bfloat16,
                    ) -> Union[torch.Tensor, Dict[str, Any]]:
        out_shape_dim_0 = x.size()[:-1]
        if dynamic_scale is not None:
            x_scale = dynamic_scale
        else:
            x = x.view(-1, x.size(-1))  # only len(x.shape)==2 is supported
            x, x_scale = torch_npu.npu_dynamic_block_quant(
                x,
                dst_type=torch.float8_e4m3fn,
                row_block_size=1,
                col_block_size=self.weight_block_size[1],
            )

        x = torch_npu.npu_quant_matmul(
            x, layer.weight,
            layer.scale,
            pertoken_scale=x_scale,
            bias=layer.bias,
            output_dtype=torch.bfloat16,
            group_sizes=[1, self.weight_block_size[1], self.weight_block_size[0]])
        x = x.view(out_shape_dim_0 + (-1, ))
        if out_dtype == torch.int32:
            return x, x_scale
        else:
            return x

    apply_weights = apply

    def process_weights_after_loading(self, layer, is_transpose=True, is_nz=True, scales_dtype=None):
        weight = layer.weight
        scale = layer.scale

        if is_transpose:
            weight.data = weight.data.transpose(-2, -1)
            scale.data = scale.data.view(scale.size(0), scale.size(1)).transpose(0, 1)
        else:
            scale.data = scale.data.view(scale.size(0), scale.size(1))

        if is_nz:
            weight.data = torch_npu.npu_format_cast(weight.data.contiguous(), 29)  # 29: format nz
            scale.data = scale.data.contiguous()

        if 'scale_dtype' in scales_dtype:
            scale.data = scale.data.to(scales_dtype.get('scale_dtype'))

        layer.weight = Parameter(weight, requires_grad=False)
        layer.scale = Parameter(scale, requires_grad=False)


class Fp8MoEGMMMethod(QuantizeMethodBase):
    def __init__(self, quant_config: Fp8Config):
        super().__init__()
        self.quant_config = quant_config
        self.weight_block_size = self.quant_config.weight_block_size
        self.block_quant = self.weight_block_size is not None

    def create_weights(
        self,
        layer: torch.nn.Module,
        num_experts: int,
        hidden_size: int,
        intermediate_size_per_partition: int,
        params_dtype: torch.dtype,
        **extra_weight_attrs,
    ) -> None:
        weight_type = torch.float8_e4m3fn if self.quant_config.is_checkpoint_fp8_serialized else params_dtype
        scale_dtype = torch.float32

        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition,
                                                    hidden_size,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size,
                                                    intermediate_size_per_partition,
                                                    dtype=weight_type),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.BLOCK.value})

        block_n, block_k = self.weight_block_size[0], self.weight_block_size[1]
        w13_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * math.ceil(intermediate_size_per_partition / block_n),
                                                  math.ceil(hidden_size / block_k),
                                                  dtype=scale_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_scale", w13_scale)
        set_weight_attrs(w13_scale, extra_weight_attrs)

        w2_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 math.ceil(hidden_size / block_n),
                                                 math.ceil(intermediate_size_per_partition / block_k),
                                                 dtype=scale_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_scale", w2_scale)
        set_weight_attrs(w2_scale, extra_weight_attrs)

        smooth_scale_1 = Parameter(torch.ones((num_experts, hidden_size), dtype=scale_dtype), requires_grad=False)
        smooth_scale_2 = Parameter(torch.ones((num_experts, intermediate_size_per_partition),
                                              dtype=scale_dtype),
                                   requires_grad=False)
        layer.register_parameter("smooth_scale_1", smooth_scale_1)
        layer.register_parameter("smooth_scale_2", smooth_scale_2)

    def apply(
        self,
        layer: torch.nn.Module,
        x: torch.Tensor,
        expert_tokens: torch.Tensor,
        group_list_type: int,
        pertoken_scale: torch.Tensor = None,
        final_output_dtype: torch.dtype = torch.bfloat16,
        **kwargs,
    ):
        if pertoken_scale is None:
            # only k-axis quantized; gmm supports gsM = 1, gsN = gsK = 128
            x, pertoken_scale = torch_npu.npu_dynamic_block_quant(
                x,
                dst_type=torch.float8_e4m3fn,
                row_block_size=1,
                col_block_size=self.weight_block_size[1],
            )

        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight],
            scale=[layer.w13_scale],
            per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=torch.bfloat16, group_type=0, # scale_dtype=torch.float32, pertoken_scale_dtype=torch.float32
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        swiglu_limit = kwargs.get("swiglu_limit", None)
        enable_custom_ops = kwargs.get("enable_custom_ops", False)
        if enable_custom_ops:
            intermediate_h, pertoken_scale, _ = torch.ops.custom.npu_swiglu_group_quant(mm1_mm3,
                                                                                        dst_type=torch.float8_e4m3fn,
                                                                                        quant_mode=0,
                                                                                        clamp_limit=swiglu_limit,
                                                                                        group_index=expert_tokens)
        else:
            mm1_mm3 = torch_npu.npu_swiglu(mm1_mm3)
            intermediate_h, pertoken_scale = torch_npu.npu_dynamic_block_quant(
                mm1_mm3,
                dst_type=torch.float8_e4m3fn,
                row_block_size=1,
                col_block_size=self.weight_block_size[1],
            )
        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight], bias=None,
            scale=[layer.w2_scale], per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
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
        w13_scale = layer.w13_scale
        w2_scale = layer.w2_scale
        if is_transpose:
            w13_weight.data = w13_weight.data.transpose(1, 2)
            w2_weight.data = w2_weight.data.transpose(1, 2)
            w13_scale.data = w13_scale.data.transpose(1, 2)
            w2_scale.data = w2_scale.data.transpose(1, 2)

        if is_nz:
            w13_weight.data = torch_npu.npu_format_cast(w13_weight.data.contiguous(), 29)  # 29: format nz
            w2_weight.data = torch_npu.npu_format_cast(w2_weight.data.contiguous(), 29)  # 29: format nz
            w13_scale.data = w13_scale.data.contiguous()
            w2_scale.data = w2_scale.data.contiguous()
        layer.w13_scale.data = layer.w13_scale.data.to(torch.float)
        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)