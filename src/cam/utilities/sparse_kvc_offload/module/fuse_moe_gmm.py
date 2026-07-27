# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/fused_moe/layer.py
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

import os
from enum import Enum
from typing import Optional

import torch
import torch.nn as nn
from torch.nn import Parameter
import torch_npu
from module.quantization import QuantizeMethodBase
from .utils import set_weight_attrs


class UnquantizedFusedMoEGMMMethod(QuantizeMethodBase):
    LAST_SEQ_LEN = None
    BEST_EXPERT_TOKENS = None

    def create_weights(self, layer: torch.nn.Module, num_experts: int,
                       hidden_size: int, intermediate_size_per_partition: int,
                       params_dtype: torch.dtype, **extra_weight_attrs):
        # Fused gate_up_proj (column parallel)
        w13_weight = torch.nn.Parameter(
            torch.empty(
                num_experts,
                2 * intermediate_size_per_partition,
                hidden_size,
                dtype=params_dtype),
            requires_grad=False)
        layer.register_parameter("w13_weight", w13_weight)
        set_weight_attrs(w13_weight, extra_weight_attrs)

        # down_proj (row parallel)
        w2_weight = torch.nn.Parameter(
            torch.empty(
                num_experts,
                hidden_size,
                intermediate_size_per_partition,
                dtype=params_dtype),
            requires_grad=False)
        layer.register_parameter("w2_weight", w2_weight)
        set_weight_attrs(w2_weight, extra_weight_attrs)

    def apply(
            self,
            layer: torch.nn.Module,
            x: torch.Tensor,
            expert_tokens: torch.Tensor,
            group_list_type: int,
            swiglu_limit: Optional[float] = None,
            **kwargs,
    ) -> torch.Tensor:
        mm1_mm3 = torch_npu.npu_grouped_matmul([x], [layer.w13_weight],
            group_list=expert_tokens, group_type=0, group_list_type=group_list_type, split_item=3)[0]
        if swiglu_limit is None:
            # Default fast path (unchanged): fused standard SwiGLU
            # silu(gate) * up, with w13 merged as [gate_half | up_half].
            mm1_mm3 = torch_npu.npu_swiglu(mm1_mm3)
        else:
            # Clamped SwiGLU (Step-3.7-Flash routed experts L43/44). npu_swiglu
            # has no clamp/limit input, so unfuse: split w13 output into the
            # first-half (gate) and second-half (up) blocks (FusedMoEGMM merges
            # gate+up as two contiguous halves, NOT the gpt_oss interleave),
            # apply standard silu (alpha=1) then clamp AFTER silu, up clamped to
            # [-limit, limit], up has NO +1. Matches the original HF reference
            # Step3p7MoEMLP.get_expert_output.
            gate, up = mm1_mm3.chunk(2, dim=-1)
            gate = torch.nn.functional.silu(gate)
            gate = gate.clamp(min=None, max=swiglu_limit)
            up = up.clamp(min=-swiglu_limit, max=swiglu_limit)
            mm1_mm3 = gate * up
        out = torch_npu.npu_grouped_matmul(
            [mm1_mm3], [layer.w2_weight],
            group_list=expert_tokens, group_type=0, group_list_type=group_list_type, split_item=3)[0]
        return out

    def process_weights_after_loading(self, layer: torch.nn.Module,
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
        layer.w13_weight = Parameter(w13_weight, requires_grad=False)
        layer.w2_weight = Parameter(w2_weight, requires_grad=False)


class FusedMoeWeightScaleSupported(Enum):
    TENSOR = "tensor"
    CHANNEL = "channel"
    GROUP = "group"
    BLOCK = "block"


class FusedMoEGMM(torch.nn.Module):
    def __init__(
        self,
        num_experts: int,
        hidden_size: int,
        intermediate_size: int,
        bias: bool = True,
        tp_size: int = 1,
        tp_rank: int = 0,
        ep_size: int = 1,
        ep_rank: int = 0,
        gather_output: bool = False,
        skip_bias_add: bool = False,
        params_dtype: Optional[torch.dtype] = None,
        quant_config: Optional = None,
        prefix: str = "",
    ):
        super().__init__()
        self.tp_size = tp_size
        self.tp_rank = tp_rank
        self.ep_size = ep_size
        self.ep_rank = ep_rank
        self.experts_per_rank = num_experts // ep_size
        self.intermediate_size_per_partition = intermediate_size // self.tp_size
        if quant_config is None:
            self.quant_method: Optional[QuantizeMethodBase] = (
                UnquantizedFusedMoEGMMMethod())
        else:
            self.quant_method = quant_config.get_quant_method(self, prefix)

        self.quant_method.create_weights(
            layer=self,
            num_experts=self.experts_per_rank,
            hidden_size=hidden_size,
            intermediate_size_per_partition=self.intermediate_size_per_partition,
            params_dtype=params_dtype,
            weight_loader=self.weight_loader)

    def forward(self, x: torch.Tensor,
                expert_tokens: torch.Tensor,
                group_list_type: int = 0,
                pertoken_scale: torch.Tensor = None,
                final_output_dtype: torch.dtype = torch.bfloat16,
                **kwargs,
                ):
        if self.quant_method is None:
            raise RuntimeError("self.quant_method must not be None")

        # Matrix multiply.
        final_hidden_states = self.quant_method.apply(
            layer=self,
            x=x,
            expert_tokens=expert_tokens,
            group_list_type=group_list_type,
            pertoken_scale=pertoken_scale,
            final_output_dtype=final_output_dtype,
            **kwargs,
        )

        return final_hidden_states

    def weight_loader(self, param: torch.nn.Parameter,
                      loaded_weight: torch.Tensor, weight_name: str,
                      shard_id: str, expert_id: int) -> None:

        if self.ep_size > 1 and self.tp_size == 1:
            if (expert_id < self.ep_rank * self.experts_per_rank
                or expert_id >= (self.ep_rank + 1) * self.experts_per_rank):
                return
            self.tp_rank = 0
            expert_id -= self.ep_rank * self.experts_per_rank


        if shard_id not in ("w1", "w2", "w3"):
            raise ValueError(f"shard_id must be ['w1','w2','w3'] but "
                             f"got {shard_id}.")

        WEIGHT_SCALE_SUPPORTED = [
            e.value for e in FusedMoeWeightScaleSupported
        ]
        # Fetch the dim to shard the parameter/loaded weight
        # based on the shard id. This will be whatever
        # dimension intermediate_size is used.
        SHARD_ID_TO_SHARDED_DIM = {"w1": 0, "w2": 1, "w3": 0}

        expert_data = param.data[expert_id]

        # is_transposed: if the dim to shard the weight
        # should be flipped. Required by GPTQ, compressed-tensors
        # should be whatever dimension intermediate_size is
        is_transposed = getattr(param, "is_transposed", False)
        shard_dim = SHARD_ID_TO_SHARDED_DIM[shard_id]
        if is_transposed:
            shard_dim = ~shard_dim

        # Case input scale: input_scale loading is only supported for fp8
        if "input_scale" in weight_name:
            # this is needed for compressed-tensors only
            loaded_weight = loaded_weight.to(param.data.device)

            if param.data[expert_id] != 1 and (param.data[expert_id] -
                                               loaded_weight).abs() > 1e-5:
                raise ValueError(
                    "input_scales of w1 and w3 of a layer "
                    f"must be equal. But got {param.data[expert_id]} "
                    f"vs. {loaded_weight}")

            self._load_single_value(param=param,
                                    loaded_weight=loaded_weight,
                                    expert_id=expert_id)
            return

        # Case g_idx
        if "g_idx" in weight_name:
            self._load_g_idx(shard_dim=0,
                             shard_id=shard_id,
                             loaded_weight=loaded_weight,
                             expert_data=expert_data,
                             tp_rank=self.tp_rank)
            return

        # Case weight scales and zero_points
        if ("scale" in weight_name or "zero" in weight_name or "offset" in weight_name):
            # load the weight scales and zp based on the quantization scheme
            # supported weight scales/zp can be found in
            # FusedMoeWeightScaleSupported
            quant_method = getattr(param, "quant_method", None)
            if quant_method == FusedMoeWeightScaleSupported.CHANNEL.value:
                self._load_per_channel_weight_scale(
                    shard_id=shard_id,
                    shard_dim=shard_dim,
                    loaded_weight=loaded_weight,
                    expert_data=expert_data,
                    tp_rank=self.tp_rank)
            elif quant_method == FusedMoeWeightScaleSupported.GROUP.value or \
                quant_method == FusedMoeWeightScaleSupported.BLOCK.value:
                self._load_model_weight_or_group_weight_scale(
                    shard_id=shard_id,
                    shard_dim=shard_dim,
                    loaded_weight=loaded_weight,
                    expert_data=expert_data,
                    tp_rank=self.tp_rank)
            elif quant_method == FusedMoeWeightScaleSupported.TENSOR.value:
                self._load_per_tensor_weight_scale(shard_id=shard_id,
                                                   param=param,
                                                   loaded_weight=loaded_weight,
                                                   expert_id=expert_id)
            else:
                raise ValueError(
                    f"quant method must be one of {WEIGHT_SCALE_SUPPORTED}")
            return

        if "bias" in weight_name or "alpha" in weight_name:
            self._load_per_channel_weight_scale(
                shard_id=shard_id,
                shard_dim=shard_dim,
                loaded_weight=loaded_weight,
                expert_data=expert_data,
                tp_rank=self.tp_rank)

        # Case weight_shape
        if "weight_shape" in weight_name:
            # only required by compressed-tensors
            self._load_single_value(param=param,
                                    loaded_weight=loaded_weight,
                                    expert_id=expert_id)
            return

        # Case model weights
        if "weight" in weight_name:
            self._load_model_weight_or_group_weight_scale(
                shard_id=shard_id,
                shard_dim=shard_dim,
                loaded_weight=loaded_weight,
                expert_data=expert_data,
                tp_rank=self.tp_rank)
            return

    def _load_per_tensor_weight_scale(self, shard_id: str,
                                      param: torch.nn.Parameter,
                                      loaded_weight: torch.Tensor,
                                      expert_id: int):
        param_data = param.data
        # for per tensor weight quantization
        if shard_id in ("w1", "w3"):
            # We have to keep the weight scales of w1 and w3 because
            # we need to re-quantize w1/w3 weights after weight loading.
            idx = 0 if shard_id == "w1" else 1
            param_data[expert_id][idx] = loaded_weight
        # If we are in the row parallel case (down_proj)
        elif shard_id == "w2":
            param_data[expert_id] = loaded_weight

    def _load_model_weight_or_group_weight_scale(self,
                                                 shard_dim: int,
                                                 expert_data: torch.Tensor,
                                                 shard_id: str,
                                                 loaded_weight: torch.Tensor,
                                                 tp_rank: int,
                                                 load_full_w2: bool = False):
        """
        Load grouped weight scales for group quantization or model weights
            :param shard_dim: dimension to shard
            :param expert_data: parameter for a particular expert
            :param shard_id: either w1, w2, or w3
            :param loaded_weight: checkpoint weight to load into the param
            :param tp_rank: tensor parallel rank
            :param load_full_w2: whether or not the w2 loaded should be sharded.
        """
        if shard_id == "w2":
            # In the case where we have actorder/g_idx, we do not partition the
            # w2 scales, as indicated by `load_full` argument, for all tp cases
            self._load_w2(shard_dim=shard_dim,
                          loaded_weight=loaded_weight,
                          expert_data=expert_data,
                          tp_rank=self.tp_rank,
                          load_full=load_full_w2)
        elif shard_id in ("w1", "w3"):
            self._load_w13(shard_id=shard_id,
                           shard_dim=shard_dim,
                           loaded_weight=loaded_weight,
                           expert_data=expert_data,
                           tp_rank=self.tp_rank)

    def _load_per_channel_weight_scale(self, expert_data: torch.Tensor,
                                       shard_dim: int, shard_id: str,
                                       loaded_weight: torch.tensor,
                                       tp_rank: int):
        # adapt loaded_weight shape
        loaded_weight = loaded_weight.squeeze(-1)
        # adapt end
        # for per channel weight quantization
        if shard_id == "w2":
            expert_data.copy_(loaded_weight)
        elif shard_id in ("w1", "w3"):
            self._load_w13(shard_id=shard_id,
                           shard_dim=shard_dim,
                           loaded_weight=loaded_weight,
                           expert_data=expert_data,
                           tp_rank=self.tp_rank)

    def _load_w13(self, expert_data: torch.Tensor, shard_dim: int,
                  shard_id: str, loaded_weight: torch.Tensor, tp_rank: int):

        # Index the loaded weight for tp sharding.
        # gate_up_proj: "MergedColumnParallel", so tp sharding on output_dim
        shard_size = expert_data.shape[shard_dim] // 2
        loaded_weight = loaded_weight.narrow(shard_dim, shard_size * tp_rank,
                                             shard_size)
        # Narrow parameter and load.
        # w1, gate_proj: Load into first logical weight of w13.
        if shard_id == "w1":
            expert_data = expert_data.narrow(shard_dim, 0, shard_size)
        # w3, up_proj: Load into second logical weight of w13.
        else:
            if shard_id != "w3":
                raise ValueError("only support shard_id in [\"w1\", \"w3\"] when load w13")
            expert_data = expert_data.narrow(shard_dim, shard_size, shard_size)
        expert_data.copy_(loaded_weight)

    def _load_w2(self,
                 expert_data: torch.Tensor,
                 shard_dim: int,
                 loaded_weight: torch.Tensor,
                 tp_rank: int,
                 load_full: bool = False):

        # Index the loaded weight for tp sharding.
        # down_proj: "RowParallel" so tp sharding on input_dim
        # Narrow parameter and load.
        shard_size = expert_data.shape[shard_dim]
        if not load_full:
            loaded_weight = loaded_weight.narrow(shard_dim,
                                                 shard_size * tp_rank,
                                                 shard_size)
        # w2, down_proj: Load into only logical weight of w2.
        expert_data.copy_(loaded_weight)

    def _load_single_value(self, param: torch.nn.Parameter,
                           loaded_weight: torch.Tensor, expert_id: int):
        param_data = param.data

        # Input scales can be loaded directly and should be equal.
        param_data[expert_id] = loaded_weight

    def _load_g_idx(self, shard_id: str, expert_data: torch.Tensor,
                    shard_dim: int, loaded_weight: torch.Tensor, tp_rank: int):

        if shard_id == "w2":
            self._load_w2(shard_dim=shard_dim,
                          loaded_weight=loaded_weight,
                          expert_data=expert_data,
                          tp_rank=self.tp_rank)
        else:
            if shard_id not in ("w1", "w3"):
                raise ValueError("only support shard_id in [\"w1\", \"w2\", \"w3\"]")
            expert_data.copy_(loaded_weight)

    @classmethod
    def make_expert_params_mapping(
            cls, ckpt_gate_proj_name: str, ckpt_down_proj_name: str,
            ckpt_up_proj_name: str,
            num_experts: int) -> list[tuple[str, str, int, str]]:

        return [
            # (param_name, weight_name, expert_id, shard_id)
            ("experts.w13_" if weight_name
             in [ckpt_gate_proj_name, ckpt_up_proj_name] else "experts.w2_",
             f"experts.{expert_id}.{weight_name}.", expert_id, shard_id)
            for expert_id in range(num_experts) for shard_id, weight_name in [
                ("w1", ckpt_gate_proj_name),
                ("w2", ckpt_down_proj_name),
                ("w3", ckpt_up_proj_name),
            ]
        ]
