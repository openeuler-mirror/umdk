# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/compressed_tensors/compressed_tensors_moe.py
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

import torch
import torch_npu
from torch.nn import Parameter
from module.utils import set_weight_attrs
from module.fuse_moe_gmm import FusedMoeWeightScaleSupported
from module.quantization import QuantizeMethodBase
from module.quantization.mxfp4 import W4A8MxFp4MoEGMMMethod, UpGateW4A4DownW4A8MxFp4MoEGMMMethod
from .utils import get_moe_target, is_quantization_scheme_of_moe_projs_same


class CompressedTensorsMoEGMMMethod(QuantizeMethodBase):

    @staticmethod
    def get_moe_method(
        quant_config: "CompressedTensorsConfig",
        layer: torch.nn.Module,
    ) -> "CompressedTensorsMoEMethod":
        # get targets for moe in quantization
        target = get_moe_target(quant_config.target_scheme_map)

        # when target is "MoEGMMUpGate", need to check quantization scheme of moe projections is same or not
        if is_quantization_scheme_of_moe_projs_same(target, quant_config.target_scheme_map):
            # if same
            weight_quant = quant_config.target_scheme_map[target].get("weights")
            input_quant = quant_config.target_scheme_map[target].get(
                "input_activations")

            if quant_config.is_wNa16_group_channel(weight_quant, input_quant):
                if weight_quant.num_bits == 4:
                    return CompressedTensorW4A16Int4MoEGMMMethod(quant_config)
            elif quant_config.is_dynamic_token_w8a8_int8(weight_quant, input_quant):
                return CompressedTensorW8A8Int8MoEGMMMethod()
            elif quant_config.is_dynamic_token_w4a8_int8(weight_quant, input_quant):
                return CompressedTensorW4A8Int8MoEGMMMethod()
            elif quant_config.is_dynamic_token_w4a8_mxfp8(weight_quant, input_quant):
                return W4A8MxFp4MoEGMMMethod()
            else:
                raise RuntimeError(
                    f"Unsupported FusedMoe scheme: {weight_quant}, {input_quant}")
        # if different
        weight_quant_up_gate = quant_config.target_scheme_map[target].get("weights")
        input_quant_up_gate = quant_config.target_scheme_map[target].get(
            "input_activations")

        if "MoEGMMDown" in quant_config.target_scheme_map:
            weight_quant_down = quant_config.target_scheme_map["MoEGMMDown"].get("weights")
            input_quant_down = quant_config.target_scheme_map["MoEGMMDown"].get(
                "input_activations")
        else:
            raise RuntimeError(
                f"target 'MoEGMMDown' must contained in quantization config "
                "if target 'MoEGMMUpGate' in quantization config")

        if (quant_config.is_dynamic_token_w4a4_mxfp4(weight_quant_up_gate, input_quant_up_gate) and
            quant_config.is_dynamic_token_w4a8_mxfp8(weight_quant_down, input_quant_down)):
            return UpGateW4A4DownW4A8MxFp4MoEGMMMethod()
        else:
            raise RuntimeError(
                f"Unsupported FusedMoeUpgate scheme: {weight_quant_up_gate}, {input_quant_up_gate} "
                f"together with FusedMoeDown scheme: {weight_quant_down}, {input_quant_down}")



class CompressedTensorW8A8Int8MoEGMMMethod(QuantizeMethodBase):
    def create_weights(
        self,
        layer: torch.nn.Module,
        num_experts: int,
        hidden_size: int,
        intermediate_size_per_partition: int,
        params_dtype: torch.dtype,
        **extra_weight_attrs,
    ) -> None:
        scale_dtype = torch.float32 if params_dtype == torch.float16 else torch.bfloat16
        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition,
                                                    hidden_size,
                                                    dtype=torch.int8),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size,
                                                    intermediate_size_per_partition,
                                                    dtype=torch.int8),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.CHANNEL.value})

        w13_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  dtype=scale_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_weight_scale", w13_scale)
        set_weight_attrs(w13_scale, extra_weight_attrs)

        w2_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 hidden_size,
                                                 dtype=scale_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_weight_scale", w2_scale)
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
        hidden_size = x.size(-1)

        if pertoken_scale is None:
            x, pertoken_scale = torch_npu.npu_dynamic_quant(x)

        if pertoken_scale.dim() > 1:
            pertoken_scale = pertoken_scale.reshape(-1)
            x = x.view(-1, hidden_size)

        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight],
            group_list=expert_tokens, split_item=3,
            output_dtype=torch.int32, group_type=0,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        swiglu_limit = kwargs.get("swiglu_limit", None)
        enable_custom_ops = kwargs.get("enable_custom_ops", False)
        if enable_custom_ops:
            dequant_swiglu_quant_ops = torch_npu.npu_dequant_swiglu_clamp_quant
        else:
            dequant_swiglu_quant_ops = torch_npu.npu_dequant_swiglu_quant
        swiglu_limit_args = {}
        if swiglu_limit:
            swiglu_limit_args.update({
                "swiglu_mode": 1,
                "clamp_limit": swiglu_limit,
                "glu_alpha": 1,
                "glu_bias": 0
            })
        intermediate_h, pertoken_scale = dequant_swiglu_quant_ops(
            mm1_mm3, weight_scale=layer.w13_weight_scale,
            quant_scale=layer.smooth_scale_2,
            group_index=expert_tokens,
            activate_left=True,
            quant_mode=1,
            activation_scale=pertoken_scale,
            **swiglu_limit_args,
            )

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight], bias=None,
            scale=[layer.w2_weight_scale], per_token_scale=[pertoken_scale],
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
        if is_transpose:
            w13_weight.data = w13_weight.data.transpose(1, 2)
            w2_weight.data = w2_weight.data.transpose(1, 2)
        if is_nz:
            w13_weight.data = torch_npu.npu_format_cast(w13_weight.data.contiguous(), 29)  # 29: format nz
            w2_weight.data = torch_npu.npu_format_cast(w2_weight.data.contiguous(), 29)  # 29: format nz
        layer.w13_weight_scale.data = layer.w13_weight_scale.data.to(torch.float)
        layer.smooth_scale_1.data = layer.smooth_scale_1.data.to(torch.float)
        layer.smooth_scale_2.data = layer.smooth_scale_2.data.to(torch.float)
        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)


class CompressedTensorW4A16Int4MoEGMMMethod(QuantizeMethodBase):
    def __init__(
            self,
            quant_config: "CompressedTensorsConfig",
    ):
        STORAGE_BITS_NPU = 32
        WEIGHT_BITS = 4
        self.pack_factor = STORAGE_BITS_NPU // WEIGHT_BITS

        target = "MoEGMM" if "MoEGMM" in quant_config.target_scheme_map else "Linear"
        self.weight_quant = quant_config.target_scheme_map[target].get("weights")
        self.group_size = self.weight_quant.group_size if self.weight_quant.group_size is not None else 1

    def create_weights(
        self,
        layer: torch.nn.Module,
        num_experts: int,
        hidden_size: int,
        intermediate_size_per_partition: int,
        params_dtype: torch.dtype,
        **extra_weight_attrs,
    ) -> None:
        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition,
                                                    hidden_size // self.pack_factor,
                                                    dtype=torch.int32),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size,
                                                    intermediate_size_per_partition // self.pack_factor,
                                                    dtype=torch.int32),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.GROUP.value})

        w13_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  hidden_size // self.group_size,
                                                  dtype=params_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_weight_scale", w13_scale)
        set_weight_attrs(w13_scale, extra_weight_attrs)

        w2_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 hidden_size,
                                                 intermediate_size_per_partition // self.group_size,
                                                 dtype=params_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_weight_scale", w2_scale)
        set_weight_attrs(w2_scale, extra_weight_attrs)

        w13_offset = torch.nn.Parameter(torch.zeros(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  hidden_size // self.group_size,
                                                  dtype=params_dtype),
                                       requires_grad=False)
        layer.register_parameter("w13_offset", w13_offset)
        set_weight_attrs(w13_offset, extra_weight_attrs)

        w2_offset = torch.nn.Parameter(torch.zeros(num_experts,
                                                 hidden_size,
                                                 intermediate_size_per_partition // self.group_size,
                                                 dtype=params_dtype),
                                      requires_grad=False)
        layer.register_parameter("w2_offset", w2_offset)
        set_weight_attrs(w2_offset, extra_weight_attrs)

        smooth_scale_1 = Parameter(torch.ones((num_experts, hidden_size), dtype=params_dtype), requires_grad=False)
        smooth_scale_2 = Parameter(torch.ones((num_experts, intermediate_size_per_partition),
                                              dtype=params_dtype),
                                   requires_grad=False)
        layer.register_parameter("smooth_scale_1", smooth_scale_1)
        layer.register_parameter("smooth_scale_2", smooth_scale_2)

    def apply(self,
        layer: torch.nn.Module,
        x: torch.Tensor,
        expert_tokens: torch.Tensor,
        group_list_type: int,
        pertoken_scale: torch.Tensor = None,
        final_output_dtype: torch.dtype = torch.bfloat16,
        **kwargs,
    ):

        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight],
            antiquant_scale=[layer.w13_weight_scale],
            antiquant_offset=[layer.w13_offset],
            group_list=expert_tokens, split_item=3,
            output_dtype=x.dtype, group_type=0,
            group_list_type=group_list_type,
        )[0]

        intermediate_h = torch_npu.npu_swiglu(mm1_mm3)

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight],
            antiquant_scale=[layer.w2_weight_scale],
            antiquant_offset=[layer.w2_offset],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
            group_list_type=group_list_type,
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

        # GMM kernel only support Ndim packed, repack is necessary when Kdim packed
        unpacked_w13_weight = self.unpack_from_int32(layer.w13_weight.data.flatten(0, 1), 4).view(
            layer.w13_weight.data.shape[0], layer.w13_weight.data.shape[1], -1).transpose(1, 2).contiguous().int()
        unpacked_w2_weight = self.unpack_from_int32(layer.w2_weight.data.flatten(0, 1), 4).view(
            layer.w2_weight.data.shape[0], layer.w2_weight.data.shape[1], -1).transpose(1, 2).contiguous().int()
        w13_weight = self.pack_to_int32(unpacked_w13_weight)
        w2_weight = self.pack_to_int32(unpacked_w2_weight)

        layer.w13_weight_scale.data = layer.w13_weight_scale.data.transpose(1, 2).contiguous()
        layer.w13_offset.data = layer.w13_offset.data.transpose(1, 2).contiguous()
        layer.w2_weight_scale.data = layer.w2_weight_scale.data.transpose(1, 2).contiguous()
        layer.w2_offset.data = layer.w2_offset.data.transpose(1, 2).contiguous()

        layer.smooth_scale_1.data = layer.smooth_scale_1.data.to(torch.float)
        layer.smooth_scale_2.data = layer.smooth_scale_2.data.to(torch.float)
        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)

    def unpack_from_int32(
        self,
        value: torch.Tensor,
        num_bits: int,
        shape: torch.Size = None,
        packed_dim=1,
    ) -> torch.Tensor:
        """
        Unpacks a tensor of packed int32 weights into individual int8s, maintaining the
        original bit range.

        Return tensors in int8

        :param value: tensor to upack
        :param num_bits: number of bits to unpack each data point into
        :param shape: shape to unpack into, used to remove padding
        :returns: unpacked int8 tensor
        """
        if value.dtype is not torch.int32:
            raise ValueError(
                f"Expected {torch.int32} but got {value.dtype}, Aborting unpack."
            )

        if num_bits > 8:
            raise ValueError("Unpacking is only supported for less than 8 bits")

        pack_factor = 32 // num_bits

        # unpack
        mask = (1 << num_bits) - 1

        if packed_dim == 1:
            unpacked = torch.zeros(
                (value.shape[0], value.shape[1] * pack_factor),
                device=value.device,
                dtype=torch.int32,
            )
            for i in range(pack_factor):
                unpacked[:, i::pack_factor] = (value >> (num_bits * i)) & mask

            # remove padding
            if shape is not None:
                original_row_size = int(shape[1])
                unpacked = unpacked[:, :original_row_size]
        else:
            unpacked = torch.zeros(
                (value.shape[0] * pack_factor, value.shape[1]),
                device=value.device,
                dtype=torch.int32,
            )
            for i in range(pack_factor):
                unpacked[i::pack_factor, :] = (value >> (num_bits * i)) & mask

            # remove padding
            original_row_size = int(shape[0])
            unpacked = unpacked[:original_row_size, :]

        # bits are packed in unsigned format, reformat to signed
        # update the value range from unsigned to signed
        offset = pow(2, num_bits) // 2
        unpacked = (unpacked - offset).to(torch.int8)

        return unpacked

    def pack_to_int32(self, weight: torch.Tensor):
        if weight.dim() != 3:
            raise ValueError(f"weight dim must be 3, cur ={weight.dim()} is not supported !")
        if weight.dtype == torch.int32:
            # pack 8 int4 to int32, we use a int32 to represent a int4
            if weight.shape[-1] % 8 != 0:
                raise ValueError("the last dim of weight needs to be divided by 8")
            new_weight = torch_npu.npu_convert_weight_to_int4pack(weight.flatten(0, 1))
            new_weight = new_weight.view(weight.shape[0], weight.shape[1], -1)
        elif weight.dtype == torch.int8:
            # pack 4 int8(int4*2) to int32, because in pytorch, we need to use int32 to represent int4
            if weight.shape[-1] % 4 == 0:
                raise ValueError("the last dim of weight needs to be divided by 4")
            new_weight = weight.view(torch.int32).contiguous()
        else:
            raise ValueError(f"{weight.dtype=} is not supported !")
        return new_weight


class CompressedTensorW4A8Int8MoEGMMMethod(QuantizeMethodBase):
    def __init__(
            self,
    ):
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
        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    2 * intermediate_size_per_partition // self.pack_factor,
                                                    hidden_size,
                                                    dtype=torch.int8),
                                        requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(torch.empty(num_experts,
                                                    hidden_size // self.pack_factor,
                                                    intermediate_size_per_partition,
                                                    dtype=torch.int8),
                                        requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

        w13_bias = torch.nn.Parameter(torch.empty(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  dtype=torch.float),
                                       requires_grad=False)
        layer.register_parameter("w13_bias", w13_bias)
        set_weight_attrs(w13_bias, extra_weight_attrs)

        w2_bias = torch.nn.Parameter(torch.empty(num_experts,
                                                 hidden_size,
                                                 dtype=torch.float),
                                      requires_grad=False)
        layer.register_parameter("w2_bias", w2_bias)
        set_weight_attrs(w2_bias, extra_weight_attrs)

        extra_weight_attrs.update(
            {"quant_method": FusedMoeWeightScaleSupported.CHANNEL.value})

        w13_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                  2 * intermediate_size_per_partition,
                                                  dtype=torch.int64),
                                       requires_grad=False)
        layer.register_parameter("w13_weight_scale", w13_scale)
        set_weight_attrs(w13_scale, extra_weight_attrs)

        w2_scale = torch.nn.Parameter(torch.ones(num_experts,
                                                 hidden_size,
                                                 dtype=torch.int64),
                                      requires_grad=False)
        layer.register_parameter("w2_weight_scale", w2_scale)
        set_weight_attrs(w2_scale, extra_weight_attrs)
        smooth_scale_1 = Parameter(torch.ones((num_experts, hidden_size), dtype=torch.float), requires_grad=False)
        smooth_scale_2 = Parameter(torch.ones((num_experts, intermediate_size_per_partition),
                                              dtype=torch.float),
                                   requires_grad=False)
        layer.register_parameter("smooth_scale_1", smooth_scale_1)
        layer.register_parameter("smooth_scale_2", smooth_scale_2)

        # alpha is a factor for clip kernel
        w2_alpha = torch.nn.Parameter(torch.ones(num_experts, dtype=torch.float), requires_grad=False)
        layer.register_parameter("w2_alpha", w2_alpha)
        set_weight_attrs(w2_alpha, extra_weight_attrs)

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
        hidden_size = x.size(-1)

        if pertoken_scale is None:
            x, pertoken_scale = torch_npu.npu_dynamic_quant(x)

        if pertoken_scale.dim() > 1:
            pertoken_scale = pertoken_scale.reshape(-1)
            x = x.view(-1, hidden_size)

        mm1_mm3 = torch_npu.npu_grouped_matmul(
            [x], [layer.w13_weight], bias=[layer.w13_bias],
            scale=[layer.w13_weight_scale], per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
            group_list_type=group_list_type,
            act_type=0
        )[0]

        # fusion kernel: swiglu + clip + dynamic_quant
        # To enhance quantization accuracy, a clip kernel has been introduced prior to the dynamic_quant kernel
        intermediate_h, pertoken_scale = torch.ops.umdk_cam_op_lib.swiglu_clip_quant(
            mm1_mm3,
            expert_tokens,
            layer.w2_alpha,
            activate_left=True,
            quant_mode=1,
            clamp_mode=1
        )

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [layer.w2_weight], bias=[layer.w2_bias],
            scale=[layer.w2_weight_scale], per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=final_output_dtype, group_type=0,
            group_list_type=group_list_type,
            act_type=0
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
        if is_transpose:
            w13_weight.data = w13_weight.data.transpose(1, 2)
            w2_weight.data = w2_weight.data.transpose(1, 2)
        if is_nz:
            w13_weight.data = torch_npu.npu_format_cast(w13_weight.data.contiguous(), 29)  # 29: format nz
            w2_weight.data = torch_npu.npu_format_cast(w2_weight.data.contiguous(), 29)  # 29: format nz
        w13_weight.data = w13_weight.data.view(torch.int32).contiguous()
        w2_weight.data = w2_weight.data.view(torch.int32).contiguous()
        layer.smooth_scale_1.data = layer.smooth_scale_1.data.to(torch.float)
        layer.smooth_scale_2.data = layer.smooth_scale_2.data.to(torch.float)
        layer.w13_weight_scale.data = layer.w13_weight_scale.data.unsqueeze(1)
        layer.w2_weight_scale.data = layer.w2_weight_scale.data.unsqueeze(1)
        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)