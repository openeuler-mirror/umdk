# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/distributed/utils.py
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

from typing import Any, Optional

import torch
import torch_npu


def to_transpose_nz(tensor, transpose_contigous: bool = False):
    if transpose_contigous:
        tensor.data = tensor.data.transpose(-2, -1).contiguous()
    return torch_npu.npu_format_cast(tensor.data, 29)  # 29: to NZ format


def ensure_divisibility(numerator, denominator):
    """Ensure that numerator is divisible by the denominator."""
    if numerator % denominator != 0:
        raise ValueError("{} is not divisible by {}".format(
                         numerator, denominator))


def divide(numerator, denominator):
    """
    Ensure that numerator is divisible by the denominator and return
    the division value.
    """
    ensure_divisibility(numerator, denominator)
    return numerator // denominator


# Adapted from vllm.model_executor.utils.set_weight_attrs
def set_weight_attrs(
    weight: torch.Tensor,
    weight_attrs: Optional[dict[str, Any]],
):
    """Set attributes on a weight tensor.

    This method is used to set attributes on a weight tensor. This method
    will not overwrite existing attributes.

    Args:
        weight: The weight tensor.
        weight_attrs: A dictionary of attributes to set on the weight tensor.
    """
    if weight_attrs is None:
        return
    for key, value in weight_attrs.items():
        if hasattr(weight, key):
            raise RuntimeError(f"Overwriting existing tensor attribute: {key}")
        setattr(weight, key, value)
