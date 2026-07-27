# coding=utf-8
# This code is copied from vllm implementations.
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/compressed_tensors/schemes/compressed_tensors_scheme.py
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
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

from abc import ABC, abstractmethod
from typing import Optional

import torch

__all__ = ["CompressedTensorsScheme"]


class CompressedTensorsScheme(ABC):
    """
    Abstract class used to describe the weight creation and forward pass
    of different quantization schemes supported by CompressedTensors.
    """

    @abstractmethod
    def create_weights(self, *args, **kwargs):
        """
        Weight creation for the particular scheme. Inputs to this function

        """
        raise NotImplementedError

    @abstractmethod
    def apply_weights(self, layer: torch.nn.Module, x: torch.Tensor,
                      bias: Optional[torch.Tensor]):
        """
        Run the forward pass for the particular scheme. This is where
        scheme-specific dequant/quant steps/kernels should be applied.

        :param layer: torch.nn.Module with the registered weights and
            other parameters relevant to the particular scheme.
        :param x: input to the layer
        :param bias: bias parameter

        """
        raise NotImplementedError

    @abstractmethod
    def process_weights_after_loading(self, layer: torch.nn.Module,
                                      is_transpose: Optional[bool] = True,
                                      is_nz: Optional[bool] = True,
                                      scales_dtype: Optional[dict] = None,):
        """
        Called after weight loading is complete for any cleanup that
        needs to occur.
        """
        raise NotImplementedError
