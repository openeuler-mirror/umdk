# coding=utf-8
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

"""
Graph compilation utilities for NPU inference.
"""

import os
import logging
import torch
from torchair.configs.compiler_config import CompilerConfig


def compile_model_forward(
    model_forward,
    exe_mode="ge_graph",
    enable_cache_compile=False,
    cache_dir=None,
    frozen_parameter=True,
    tiling_schedule_optimize=True,
    topology_sorting_strategy="StableRDFS",
    enable_static_kernel=False,
    enable_superkernel=False,
):
    """
    Compile a model.forward method for graph execution.

    Args:
        model_forward: The model.forward callable to compile.
        exe_mode: Execution mode ("ge_graph", "npugraph_ex", etc.).
        enable_cache_compile: Whether to use cache compilation.
        cache_dir: Directory for cache compilation.
        frozen_parameter: Whether to freeze parameters.
        tiling_schedule_optimize: Whether to enable tiling schedule optimization.
        topology_sorting_strategy: Strategy for topology sorting.
        enable_static_kernel: Whether to enable static kernel compile for npugraph_ex.

    Returns:
        Compiled forward function.
    """
    import torchair as tng
    import torchair.ge_concrete_graph.ge_converter.experimental.patch_for_hcom_allreduce
    tng.patch_for_hcom()
    # Compile model forward
    torch._dynamo.config.inline_inbuilt_nn_modules = False
    if exe_mode == "npugraph_ex":
        # npugraph_ex uses torch.compile or cache_compile directly with backend options.
        compile_options = {
            "frozen_parameter": True,
            "static_kernel_compile": enable_static_kernel,
            "super_kernel_optimize": enable_superkernel,
            "super_kernel_optimize_options": {"dcci_disable_on_kernel": [".*"]}
        }
        if enable_cache_compile:
            compiled = torch.npu.npugraph_ex.inference.cache_compile(model_forward, cache_dir=cache_dir,
                                                                     dynamic=True, options=compile_options)

        else:
            compiled = torch.compile(model_forward, dynamic=True, fullgraph=True, backend="npugraph_ex",
                                     options=compile_options)

        return compiled

    # Create and configure CompilerConfig
    compiler_config = CompilerConfig()
    compiler_config.experimental_config.frozen_parameter = frozen_parameter
    compiler_config.experimental_config.tiling_schedule_optimize = tiling_schedule_optimize
    compiler_config.experimental_config.topology_sorting_strategy = topology_sorting_strategy
    # Compile model forward
    if enable_cache_compile:
        if cache_dir is None:
            raise ValueError("cache_dir must be provided when enable_cache_compile=True")

        compiled = tng.inference.cache_compile(
            model_forward,
            cache_dir=cache_dir,
            config=compiler_config,
            dynamic=False,
            fullgraph=True,
            ge_cache=True
        )
    else:
        npu_backend = tng.get_npu_backend(compiler_config=compiler_config)
        compiled = torch.compile(model_forward, dynamic=False, fullgraph=True, backend=npu_backend)

    return compiled
