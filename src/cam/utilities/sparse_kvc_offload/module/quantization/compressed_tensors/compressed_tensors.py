# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/compressed_tensors/compressed_tensors.py
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

from typing import Any, Dict, List, Optional, cast
from pydantic import BaseModel
import torch
from compressed_tensors.quantization import QuantizationArgs, QuantizationStrategy, QuantizationType
from module.quantization import QuantizationMethods, QuantizationConfig
from module.quantization.compressed_tensors.compressed_tensors_moe_gmm import CompressedTensorsMoEGMMMethod
from module.quantization.compressed_tensors.compressed_tensors_w8a8_int8 import CompressedTensorsW8A8Int8LinearMethod
from module.quantization.compressed_tensors.compressed_tensors_w8a8_hif8 import CompressedTensorsW8A8Hif8LinearMethod
from module.linear import LinearBase, LinearMethodBase, UnquantizedLinearMethod
from module.fuse_moe_gmm import FusedMoEGMM
from module.quantization.mxfp8 import MxFp8LinearMethod
from module.quantization.fp8 import Fp8LinearMethod
from .utils import (find_matched_target, is_activation_quantization_format, should_ignore_layer, get_moe_target)

QUANTIZATION_SCHEME_MAP_TYPE = dict[str, Optional[dict[str, QuantizationArgs]]]
MX_BLOCK_K = 32


class CompressedTensorsConfig(QuantizationConfig):
    def __init__(
        self,
        target_scheme_map: dict[str, Any],
        ignore: list[str],
        quant_format: str,
        sparsity_scheme_map: Dict,
        sparsity_ignore_list: list[str],
        config: Optional[dict[str, Any]] = None,
        weight_block_size: Optional[list[int]] = None,
    ):
        super().__init__()
        self.ignore = ignore
        self.quant_format = quant_format
        # Map from [target -> scheme]
        self.target_scheme_map = target_scheme_map
        self.sparsity_scheme_map = sparsity_scheme_map
        self.sparsity_ignore_list = sparsity_ignore_list
        self.config = config
        self.weight_block_size = weight_block_size

    def get_linear_method(self) -> "CompressedTensorsLinearMethod":
        return CompressedTensorsLinearMethod(self)

    @classmethod
    def get_supported_act_dtypes(cls) -> list[torch.dtype]:
        return [torch.float16, torch.bfloat16]

    def get_name(self) -> QuantizationMethods:
        return "compressed-tensors"

    def get_quant_method(
        self,
        layer: torch.nn.Module,
        prefix: str,
    ) -> Optional["QuantizeMethodBase"]:
        if should_ignore_layer(layer_name=prefix, ignore=self.ignore):
            return UnquantizedLinearMethod()
        if isinstance(layer, LinearBase):
            scheme = self.get_scheme(layer=layer, layer_name=prefix)
            layer.scheme = scheme
            return CompressedTensorsLinearMethod(self)
        elif isinstance(layer, FusedMoEGMM):
            moe_method = CompressedTensorsMoEGMMMethod.get_moe_method(self, layer)
            return moe_method
        return None

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "CompressedTensorsConfig":
        ignore: list[str] = cast(list[str], config.get("ignore", []))
        quant_format = cast(str, config.get("format"))
        target_scheme_map = cls._quantization_scheme_map_from_config(
            config=config)
        weight_block_size = cls.get_from_keys_or(config, ["weight_block_size"],
                                                 None)
        quant_config_instance = cls(target_scheme_map=target_scheme_map,
                                    ignore=ignore,
                                    quant_format=quant_format,
                                    sparsity_scheme_map=None,
                                    sparsity_ignore_list=None,
                                    config=config,
                                    weight_block_size=weight_block_size,
        )
        quant_config_instance.mm_quant_mode = quant_config_instance._get_quant_mode(
            target_scheme_map=target_scheme_map,
            target="Linear")
        moe_target = get_moe_target(target_scheme_map)
        quant_config_instance.gmm_quant_mode = quant_config_instance._get_quant_mode(
            target_scheme_map=target_scheme_map,
            target=moe_target)

        kv_cache_scheme = config.get("kv_cache_scheme")
        if kv_cache_scheme is not None:
            quant_config_instance.kv_cache_quant_mode = \
                kv_cache_scheme.get("type", "int") + str(kv_cache_scheme.get("num_bits", 8))
        return quant_config_instance

    @classmethod
    def _quantization_scheme_map_from_config(
            cls, config: dict[str, Any]) -> QUANTIZATION_SCHEME_MAP_TYPE:
        """
        :param config: The `quantization_config` dictionary from config.json
        :return: A dictionary mapping target layer names to their corresponding
            quantization_args for weights and input activations
        """
        target_scheme_map: dict[str, Any] = dict()
        quant_format = cast(str, config.get("format"))

        # The quant_config has multiple config_groups, each containing
        # an input_activations key with details about how the activations are
        # quantized, a weights key indicating how the weights are quantized,
        # and a list of targets under the `targets` key, dictating which
        # layers are impacted by the quantization details. The quantization
        # details follow the structure defined by the QuantizationArgs
        # pydantic model, which is used to verify the structure of the
        # quant_config and also store the details for later use.

        config_groups = config.get("config_groups", dict())
        for _, quant_config in config_groups.items():
            targets = quant_config.get("targets")
            for target in targets:
                target_scheme_map[target] = {}
                target_scheme_map[target][
                    "weights"] = QuantizationArgs.model_validate(
                        quant_config.get("weights"))

                target_scheme_map[target]["input_activations"] = None
                if is_activation_quantization_format(quant_format):
                    input_activations = quant_config.get("input_activations")
                    # The only case where we have activation quant supported
                    # but no input_activations provided in the config
                    # should be w4a16int4 w4a16int4 can also run for cases where
                    # there is an input_quant but it is ignored
                    if not input_activations:
                        assert target_scheme_map[target][
                            "weights"].type == QuantizationType.INT
                    else:
                        target_scheme_map[target][
                            "input_activations"] = QuantizationArgs.model_validate(
                                quant_config.get("input_activations"))
                else:
                    raise ValueError(f"quant format {quant_format} is not valid")
        return target_scheme_map

    def _get_quant_mode(self, target_scheme_map: dict[str, Any], target: str) -> str:
        # get quant mode from quant_config
        # it's a string formed by concatenating num_bits of weights and num_bits of activations.
        weight_bits = str(
            target_scheme_map[target].get("weights").num_bits
            if target_scheme_map[target].get("weights") is not None
            else "16")
        weight_quant_mode = "w" + weight_bits
        input_quant_mode = "a" + str(
            target_scheme_map[target].get("input_activations").num_bits
            if target_scheme_map[target].get("input_activations") is not None
            else "16")
        data_type = (target_scheme_map[target].get("weights").type
            if target_scheme_map[target].get("weights") is not None
            else "float") + weight_bits
        if (self.weight_block_size is not None and self.weight_block_size[0] == 1 and
            self.weight_block_size[1] == MX_BLOCK_K and "float" in data_type):
            quant_mode = weight_quant_mode + input_quant_mode + "mx" + data_type
        elif (target_scheme_map[target].get("input_activations") is not None
              and target_scheme_map[target].get("input_activations").strategy == QuantizationStrategy.TENSOR.value
              and "float" in data_type):
            quant_mode = weight_quant_mode + input_quant_mode + "hi" + data_type
        else:
            quant_mode = weight_quant_mode + input_quant_mode + data_type
        return quant_mode

    def is_dynamic_token_w8a8_int8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        # avoid a16 none input_quant that input_quant.num_bits will be error
        if input_quant is None:
            return False
        is_8_bits = weight_quant.num_bits == input_quant.num_bits == 8 and weight_quant.type == "int"
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization are supported.
        # Only symmetric weight quantization is supported.
        return is_8_bits and is_token and weight_quant.symmetric and is_dynamic

    def is_wNa16_group_channel(self,
                            weight_quant: BaseModel,
                            input_quant: BaseModel,) -> bool:
        input_quant_none = input_quant is None
        is_symmetric = weight_quant.symmetric
        is_channel_group = (
            weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value
        )
        is_static = not weight_quant.dynamic

        return is_channel_group and input_quant_none and is_symmetric and is_static

    def is_dynamic_token_w4a8_int8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        is_w4a8_int8 = (weight_quant.num_bits == 4) and (input_quant.num_bits == 8) and weight_quant.type == "int"
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization supported.
        # Only symmetric weight quantization supported.
        return is_w4a8_int8 and is_token and weight_quant.symmetric and is_dynamic

    def is_dynamic_token_w8a8_mxfp8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        is_mxfloat = (self.weight_block_size is not None and self.weight_block_size[0] == 1 and
                      self.weight_block_size[1] == MX_BLOCK_K and weight_quant.type == "float")
        is_w8a8_mxfp8 = (weight_quant.num_bits == 8) and (input_quant.num_bits == 8) and is_mxfloat
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization supported.
        # Only symmetric weight quantization supported.
        return is_w8a8_mxfp8 and is_token and weight_quant.symmetric and is_dynamic

    def is_dynamic_token_w8a8_fp8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        is_not_mxfloat = (self.weight_block_size is not None and (self.weight_block_size[0] != 1 or
                      self.weight_block_size[1] != MX_BLOCK_K) and weight_quant.type == "float")
        is_w8a8_fp8 = (weight_quant.num_bits == 8) and (input_quant.num_bits == 8) and is_not_mxfloat
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization supported.
        # Only symmetric weight quantization supported.
        return is_w8a8_fp8 and is_token and weight_quant.symmetric and is_dynamic

    def is_dynamic_token_w4a8_mxfp8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        is_w4a8_mxfp8 = (weight_quant.num_bits == 4) and (input_quant.num_bits == 8) and weight_quant.type == "float"
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization supported.
        # Only symmetric weight quantization supported.
        return is_w4a8_mxfp8 and is_token and weight_quant.symmetric and is_dynamic

    def is_dynamic_token_w4a4_mxfp4(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        is_w4a4_mxfp4 = (weight_quant.num_bits == 4) and (input_quant.num_bits == 4) and weight_quant.type == "float"
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_token = (weight_strategy and input_quant.strategy
                    == QuantizationStrategy.TOKEN.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic

        # Both symmetric and asymmetric input quantization supported.
        # Only symmetric weight quantization supported.
        return is_w4a4_mxfp4 and is_token and weight_quant.symmetric and is_dynamic

    def is_dynamic_token_w8a8_hifloat8(self,
                               weight_quant: BaseModel,
                               input_quant: BaseModel,) -> bool:
        # avoid a16 none input_quant that input_quant.num_bits will be error
        if input_quant is None:
            return False
        is_8_bits = weight_quant.num_bits == input_quant.num_bits == 8 and weight_quant.type == "float"
        weight_strategy = (
            weight_quant.strategy == QuantizationStrategy.TENSOR.value 
            or weight_quant.strategy == QuantizationStrategy.CHANNEL.value 
            or weight_quant.strategy == QuantizationStrategy.GROUP.value)
        is_tensor = (weight_strategy and input_quant.strategy == QuantizationStrategy.TENSOR.value)
        is_dynamic = not weight_quant.dynamic and input_quant.dynamic
        
        # Both symmetric and asymmetric input quantization are supported.
        # Only symmetric weight quantization is supported.
        return is_8_bits and is_tensor and weight_quant.symmetric and is_dynamic

    def _get_scheme_from_parts(
            self,
            layer_name: str,
            weight_quant: BaseModel,
            input_quant: BaseModel) -> "CompressedTensorsScheme":

        if is_activation_quantization_format(self.quant_format):
            if self.is_dynamic_token_w8a8_int8(weight_quant, input_quant):
                return CompressedTensorsW8A8Int8LinearMethod(
                    strategy=weight_quant.strategy,
                    is_static_input_scheme=False,
                    input_symmetric=input_quant.symmetric)
            elif self.is_dynamic_token_w8a8_hifloat8(weight_quant, input_quant): 
                return CompressedTensorsW8A8Hif8LinearMethod( 
                    strategy=weight_quant.strategy, 
                    is_static_input_scheme=False, 
                    input_symmetric=input_quant.symmetric) 
            elif self.is_dynamic_token_w8a8_mxfp8(weight_quant, input_quant):
                return MxFp8LinearMethod()
            elif self.is_dynamic_token_w8a8_fp8(weight_quant, input_quant):
                return Fp8LinearMethod(self)

        raise NotImplementedError(
            "No compressed-tensors compatible scheme was found.")

    def get_scheme(self,
                   layer: torch.nn.Module,
                   layer_name: Optional[str] = None
                   ) -> Optional["CompressedTensorsScheme"]:
        """
        compressed-tensors supports non uniform in the following way:

        ignore: List of layer_names or nn.Module names to be ignored.
        targets of config_groups: There can be N config_groups which each
            have a quantization scheme. Each config_group has a list of targets
            which can be a full layer_name, a regex for a layer_name, or
            an nn.Module name.

        We first check whether a layer is in the ignore group and use
        CompressedTensorsUnquantized (i.e. fp16/bf16) scheme for the layer

        We then detect whether a layer_name is found in any target and
        use the quantization scheme corresponding to the matched target
        to select the CompressedTensorsScheme used for infernece.
        """

        # Find the "target" in the compressed-tensors config
        # that our layer conforms to.
        # so we do not have to re-write these functions
        # need to make accelerate optional in ct to do this
        matched_target = find_matched_target(
            layer_name=layer_name,
            module=layer,
            targets=self.target_scheme_map.keys())

        # Find the quant_scheme
        scheme_dict = self.target_scheme_map[matched_target]

        scheme = self._get_scheme_from_parts(
            layer_name=layer_name,
            weight_quant=scheme_dict["weights"],
            input_quant=scheme_dict["input_activations"])
        return scheme


    def get_cache_scale(self, name: str) -> Optional[str]:
        """
        Check whether the param name matches the format for k/v cache scales
        in compressed-tensors. If this is the case, return its equivalent
        param name expected by vLLM

        :param name: param name
        :return: matching param name for KV cache scale in vLLM
        """
        if name.endswith(".output_scale") and ".k_proj" in name:
            return name.replace(".k_proj.output_scale", ".attn.k_scale")
        if name.endswith(".output_scale") and ".v_proj" in name:
            return name.replace(".v_proj.output_scale", ".attn.v_scale")
        # If no matches, return None
        return None


class CompressedTensorsLinearMethod(LinearMethodBase):

    def __init__(self, quantization_config: CompressedTensorsConfig):
        self.quantization_config = quantization_config

    def create_weights(self, layer: torch.nn.Module,
                       input_size_per_partition: int,
                       output_partition_sizes: list[int],
                       input_size: int,
                       output_size: int,
                       params_dtype: torch.dtype,
                       **extra_weight_attrs):
        """
        Use the CompressedTensorsScheme associated with each layer to create
        the necessary parameters for the layer. See LinearMethodBase for param
        details
        """
        weight_loader = extra_weight_attrs.get("weight_loader")
        layer.scheme.create_weights(
            layer=layer,
            input_size=input_size,
            input_size_per_partition=input_size_per_partition,
            output_partition_sizes=output_partition_sizes,
            output_size=output_size,
            params_dtype=params_dtype,
            weight_loader=weight_loader)

    def apply(self,
              layer: torch.nn.Module,
              x: torch.Tensor,
              bias: Optional[torch.Tensor] = None,
              dynamic_scale: Optional = None,
              out_dtype: Optional = None):
        """
        Use the output of create_weights and the CompressedTensorsScheme
        associated with the layer to apply the forward pass with the
        layer input.  See LinearMethodBase for param details

        """

        scheme = layer.scheme
        if scheme is None:
            raise ValueError("A scheme must be defined for each layer")
        return scheme.apply_weights(layer, x, bias=bias, dynamic_scale=dynamic_scale, out_dtype=out_dtype)

    def process_weights_after_loading(self, layer: torch.nn.Module,
                                      is_transpose: bool = True,
                                      is_nz: bool = True,
                                      scales_dtype: torch.dtype = None,
                                      ) -> None:
        layer.scheme.process_weights_after_loading(layer,
                                                   is_transpose=is_transpose,
                                                   is_nz=is_nz,
                                                   scales_dtype=scales_dtype
                                                   )
