# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import os
import sys
import math
import time
import argparse
import logging
import copy
import gc
from operator import attrgetter
from typing import get_args
import numpy as np
import torch
import torch.distributed as dist
import torch_npu
import torch.nn as nn
from models.modeling_deepseek import DeepseekV3ForCausalLM, DeepseekV3ModelMTP
from executor.utils import override, get_init_attn_mask
from executor.model_runner import ModelRunner
from module.quantization import QuantizeMethodBase
from module.quantization.compressed_tensors.compressed_tensors_moe_gmm import (
    CompressedTensorW8A8Int8MoEGMMMethod,
    CompressedTensorW4A8Int8MoEGMMMethod
)

root_logger = logging.getLogger()
root_logger.handlers.clear()
logging.basicConfig(format='%(asctime)s - %(levelname)s - [LLM](%(filename)s:%(lineno)d): %(message)s',
                    level=logging.INFO)
logging.getLogger("paramiko").setLevel(logging.ERROR)

torch.manual_seed(42)
torch.npu.manual_seed_all(42)


class DeepSeekRunner(ModelRunner):
    def __init__(self, runner_settings):
        super().__init__(runner_settings)
        self.batch_size = runner_settings.get("data_config").get("batch_size")
        self.with_ckpt = runner_settings.get("model_config").get("with_ckpt", True)
        self.enable_weight_nz = runner_settings.get("model_config").get("enable_weight_nz", True)
        self.enable_cache_compile = runner_settings.get("model_config").get("enable_cache_compile", False)
        self.share_mask_tril = get_init_attn_mask(2048, self.device)  # 2048: fixed shape of mask, used in PFA
        self.prefill_mini_batch_size = runner_settings.get("model_config").get("prefill_mini_batch_size", 0)
        self.batch_size_per_rank = runner_settings.get("data_config").get("batch_size_per_rank", 1)
        self.cp_size = self.runner_settings.get("parallel_config").get("cp_size", 1)
        self.use_dataset = runner_settings.get("data_config").get("dataset", "default") != "default"
        self.prefill_cycles = 0
        self.query_id_list = []
        self.max_new_tokens = runner_settings.get("data_config").get("max_new_tokens", 32)
        self.enable_static_kernel = self.runner_settings.get("model_config").get("enable_static_kernel", False)

    @override
    def init_model(self, is_mtp=False):
        self.is_mtp = is_mtp
        if self.with_ckpt:
            self.use_pretrained_model = True
            config = None
        else:
            self.use_pretrained_model = False
        from models.configuration_deepseek import DeepseekV3IndexConfig as config
        logging.info(f"use_pretrained_model: {self.use_pretrained_model}")
        if is_mtp:
            model = DeepseekV3ModelMTP
            super().init_model(DeepseekV3ModelMTP, config)
        else:
            model = DeepseekV3ForCausalLM
            super().init_model(DeepseekV3ForCausalLM, config)

    @override
    def _process_weight_after_loading(self):
        '''
        Doing weight transpose, format cast to nz, and scale type cast after loading weights from files.
        '''
        self.init_splited_kv_b_weight()
        self.to_device()
        # map for scales need to cast to float when apply w8a8 quant method
        float_scales_map = [
            "gate_up_proj",
            "q_b_proj",
            "wq_b",
        ]
        # map for smooth scales need to cast to float when apply w8a8 quant method
        float_smooth_scales_map = [
            "down_proj"
        ]
        for module_name, module in self.model.named_modules():
            if "kv_b_proj" in module_name:
                continue
            quant_method = getattr(module, "quant_method", None)
            scales_dtype = {}
            for scale_name in float_scales_map:
                # if scale in module need type cast, add target dtype to dict
                if scale_name in module_name:
                    scales_dtype['scale_dtype'] = torch.float
                    break

            for smooth_scale_name in float_smooth_scales_map:
                # if smootj scale in module need type cast, add target dtype to dict
                if smooth_scale_name in module_name:
                    scales_dtype['smooth_scale_dtype'] = torch.float
                    break

            if isinstance(quant_method, QuantizeMethodBase):
                quant_method.process_weights_after_loading(
                    module, is_nz=self.enable_weight_nz, scales_dtype=scales_dtype)
            # Dynamic quant for input_avtivation of first grouped matmul requies complete smooth scale.
            # When applying expert parallel, each device only reserves smooth scales of mapping experts.
            # Need to do all gather to obtain complete smooth scale.
            if isinstance(quant_method, CompressedTensorW8A8Int8MoEGMMMethod) or \
                isinstance(quant_method, CompressedTensorW4A8Int8MoEGMMMethod):
                moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
                if moe_ep_size > 1:
                    all_experts_smooth_scale = module.smooth_scale_1.data.new_empty(
                        module.smooth_scale_1.data.shape[0] * moe_ep_size, module.smooth_scale_1.data.shape[1])
                    dist.all_gather_into_tensor(all_experts_smooth_scale, module.smooth_scale_1.data,
                                                group=self.model.hccl_comm_dict.get("moe_ep_group", None))
                    module.smooth_scale_1.data = all_experts_smooth_scale

    @override
    def graph_compile(self):
        if not self.enable_cache_compile:
            import torchair as tng
            tng.patch_for_hcom()
            from torchair.configs.compiler_config import CompilerConfig

            compiler_config = CompilerConfig()
            if self.execute_mode == "acl_graph":
                compiler_config.mode = "reduce-overhead"
                # Need to remove the config once torch_npu released at that time.
                if hasattr(compiler_config.debug.aclgraph, "clone_input"):
                    compiler_config.debug.aclgraph.clone_input = False
                if self.enable_static_kernel:
                    compiler_config.experimental_config.aclgraph._aclnn_static_shape_kernel = True
            compiler_config.experimental_config.frozen_parameter = True
            compiler_config.experimental_config.tiling_schedule_optimize = True
            compiler_config.experimental_config.topology_sorting_strategy = "StableRDFS"
            npu_backend = tng.get_npu_backend(compiler_config=compiler_config)
            self.model.decode = torch.compile(self.model.decode, dynamic=False, fullgraph=True, backend=npu_backend)

    @override
    def init_splited_kv_b_weight(self):
        def for_each_to_init_splited_k_b_weight(layer, layer_idx=""):
            try:
                data_getter = attrgetter("self_attn.kv_b_proj_w_k_data")
                data_tensor = data_getter(layer)
                layer.self_attn.kv_b_proj_w_k = nn.Parameter(data_tensor.contiguous(), requires_grad=False)
            except AttributeError:
                pass

        def for_each_to_init_splited_v_b_weight(layer, layer_idx=""):
            try:
                data_getter = attrgetter("self_attn.kv_b_proj_w_v_data")
                data_tensor = data_getter(layer)
                layer.self_attn.kv_b_proj_w_v = nn.Parameter(data_tensor.contiguous(), requires_grad=False)
            except AttributeError:
                pass

        def for_each_to_offload_kv_b_weight(layer, layer_idx=""):
            try:
                layer.self_attn.kv_b_proj.weight = None
            except AttributeError:
                pass

        if self.is_mtp:
            for _, layer in self.model.model.layers.items():
                for_each_to_init_splited_k_b_weight(layer, self.model.config.num_hidden_layers)
                for_each_to_init_splited_v_b_weight(layer, self.model.config.num_hidden_layers)
                for_each_to_offload_kv_b_weight(layer, self.model.config.num_hidden_layers)
        else:
            for layer_idx, layer in enumerate(self.model.model.layers):
                for_each_to_init_splited_k_b_weight(layer, layer_idx)
                for_each_to_init_splited_v_b_weight(layer, layer_idx)
                for_each_to_offload_kv_b_weight(layer, layer_idx)
        gc.collect()