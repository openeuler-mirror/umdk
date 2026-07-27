# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/model_loader/dummy_loader.py
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

import torch
import torch.nn as nn

from .base_loader import BaseModelLoader
from .utils import (
    set_default_torch_dtype)
from .weight_utils import (
    initialize_dummy_weights)


class DummyModelLoader(BaseModelLoader):
    """Model loader that will set model weights to random values."""

    def __init__(self):
        super().__init__()

    def load_model(self, config, model_cls, runner_settings, **kwargs) -> nn.Module:
        with set_default_torch_dtype(torch.bfloat16):
            if "comm_manager" in kwargs:
                model = model_cls(config, runner_settings, comm_manager=kwargs["comm_manager"])
            else:
                model = model_cls(config, runner_settings)
            # NOTE(woosuk): For accurate performance evaluation, we assign
            # random values to the weights.
            initialize_dummy_weights(model)

        return model.eval()
