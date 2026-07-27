# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/model_loader/base_loader.py
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

import torch.nn as nn


class BaseModelLoader(ABC):
    """Base class for model loaders."""

    def __init__(self):
        pass

    @abstractmethod
    def load_model(self, *, config, **kwargs) -> nn.Module:
        """Load a model with the given configurations.

        Args:
            config: Model configuration
            **kwargs: Additional arguments passed to model constructor
                      (e.g., infer_config, comm_manager)
        """
        raise NotImplementedError
