# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/base_config.py
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

import inspect
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional, Literal, get_args

import torch
from torch import nn

QuantizationMethods = Literal[
    "compressed-tensors",
    "fp8",
    "mxfp8"
]
QUANTIZATION_METHODS: list[str] = list(get_args(QuantizationMethods))


class QuantizeMethodBase(ABC):
    """Base class for different quantized methods."""

    @abstractmethod
    def create_weights(self, layer: torch.nn.Module, *weight_args,
                       **extra_weight_attrs):
        """
        Create weights for a layer.
        The weights will be set as attributes of the layer.
        """
        raise NotImplementedError

    @abstractmethod
    def apply(self, layer: torch.nn.Module, *args, **kwargs) -> torch.Tensor:
        """
        Apply the weights in layer to the input tensor.
        Expects create_weights to have been called before on the layer.
        """
        raise NotImplementedError

    # Not required functions
    def embedding(self, layer: torch.nn.Module, *args,
                  **kwargs) -> torch.Tensor:
        """
        Gather embeddings in the layer based on indices in the input tensor.
        Expects create_weights to have been called before on the layer.
        """
        raise NotImplementedError

    def process_weights_after_loading(self, layer: nn.Module, **kwargs) -> None:
        """
        Process the weight after loading.
        This can be used for example, to transpose weights for computation.
        """
        return


class QuantizationConfig(ABC):
    """Base class for quantization configs."""

    def __init__(self):
        super().__init__()
        # mapping is updated by models as they initialize
        self.packed_modules_mapping: dict[str, list[str]] = dict()
        # quant_mode default w16a16, will be initalized in function from_config()
        self.mm_quant_mode = "w16a16"
        self.gmm_quant_mode = "w16a16"
        self.kv_cache_quant_mode = "unquant"

    @abstractmethod
    def get_name(self) -> QuantizationMethods:
        """Name of the quantization method."""
        raise NotImplementedError

    @abstractmethod
    def get_supported_act_dtypes(self) -> list[torch.dtype]:
        """List of supported activation dtypes."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict[str, Any]) -> "QuantizationConfig":
        """Create a config class from the model's quantization config."""
        raise NotImplementedError

    @classmethod
    def override_quantization_method(
            cls, hf_quant_cfg, user_quant) -> Optional[QuantizationMethods]:
        """
           Detects if this quantization method can support a given checkpoint
           format by overriding the user specified quantization method --
           this method should only be overwritten by subclasses in exceptional
           circumstances
        """
        return None

    @staticmethod
    def get_from_keys(config: dict[str, Any], keys: list[str]) -> Any:
        """Get a value from the model's quantization config."""
        for key in keys:
            if key in config:
                return config[key]
        raise ValueError(f"Cannot find any of {keys} in the model's "
                         "quantization config.")

    @staticmethod
    def get_from_keys_or(config: dict[str, Any], keys: list[str],
                         default: Any) -> Any:
        """Get a optional value from the model's quantization config."""
        try:
            return QuantizationConfig.get_from_keys(config, keys)
        except ValueError:
            return default

    @abstractmethod
    def get_quant_method(self, layer: torch.nn.Module,
                         prefix: str) -> Optional[QuantizeMethodBase]:
        """Get the quantize method to use for the quantized layer.

        Args:
            layer: The layer for the quant method.
            prefix: The full name of the layer in the state dict
        Returns:
            The quantize method. None if the given layer doesn't support quant
            method.
        """
        raise NotImplementedError

    def get_cache_scale(self, name: str) -> Optional[str]:
        return None

    def set_quant_mode(self, name: str, value: str) -> None:
        setattr(self, name, value)


# Adapted from vllm.model_executor.layers.quantization.get_quantization_config
def get_quantization_config(quantization: str) -> type[QuantizationConfig]:
    if quantization not in QUANTIZATION_METHODS:
        raise ValueError(f"Invalid quantization method: {quantization}")

    # lazy import to avoid triggering `torch.compile` too early
    from module.quantization.compressed_tensors.compressed_tensors import CompressedTensorsConfig
    from module.quantization.fp8 import Fp8Config
    from module.quantization.mxfp8 import MxFp8Config

    method_to_config: dict[str, type[QuantizationConfig]] = {
        "compressed-tensors": CompressedTensorsConfig,
        "fp8": Fp8Config,
        "mxfp8": MxFp8Config,
    }
    # Update the `method_to_config` with customized quantization methods.

    return method_to_config[quantization]


# Adapted from vllm.model_executor.model_loader.weight_utils.get_quant_config
def get_quant_config(hf_config, quantization, model_path) -> QuantizationConfig:

    quant_cls = get_quantization_config(quantization)

    # Read the quantization config from the HF model config, if available.
    hf_quant_config = getattr(hf_config, "quantization_config",
                              None)
    # some vision model may keep quantization_config in their text_config
    hf_text_config = getattr(hf_config, "text_config", None)
    if hf_quant_config is None and hf_text_config is not None:
        hf_quant_config = getattr(hf_text_config, "quantization_config", None)
    if hf_quant_config is None:
        # compressed-tensors uses a compressions_config
        hf_quant_config = getattr(hf_config, "compression_config",
                                  None)
    if hf_quant_config is not None:
        return quant_cls.from_config(hf_quant_config)

    hf_folder = model_path

    possible_config_filenames = quant_cls.get_config_filenames()

    # If the quantization config is not found, use the default config.
    if not possible_config_filenames:
        return quant_cls()

    config_files = glob.glob(os.path.join(hf_folder, "*.json"))

    quant_config_files = [
        f for f in config_files if any(
            f.endswith(x) for x in possible_config_filenames)
    ]
    if len(quant_config_files) == 0:
        raise ValueError(
            f"Cannot find the config file for {quantization}")
    if len(quant_config_files) > 1:
        raise ValueError(
            f"Found multiple config files for {quantization}: "
            f"{quant_config_files}")

    quant_config_file = quant_config_files[0]
    with open(quant_config_file) as f:
        config = json.load(f)

        if quantization == "bitsandbytes":
            config["adapter_name_or_path"] = model_path
        elif quantization == "modelopt":
            if config["producer"]["name"] == "modelopt":
                return quant_cls.from_config(config)
            else:
                raise ValueError(
                    f"Unsupported quantization config"
                    f" found for {quantization} in {f}.")

    return quant_cls.from_config(config)
