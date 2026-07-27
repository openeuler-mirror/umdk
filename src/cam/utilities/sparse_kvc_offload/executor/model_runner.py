# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import os
import time
import argparse
import logging
import copy
import numpy as np
import torch
import torch_npu
from transformers import AutoTokenizer, AutoProcessor

from executor.utils import get_default_group, process_infer_time, remove_padding_left, detokenize_outputs
from executor.model_loader.default_loader import DefaultModelLoader
from executor.model_loader.dummy_loader import DummyModelLoader
from module.quantization import (QUANTIZATION_METHODS,
                                 QuantizationMethods,
                                 QuantizeMethodBase,
                                 get_quantization_config,
                                 get_quant_config)

from executor.utils.logging_config import setup_logging

torch.npu.config.allow_internal_format = True

setup_logging()
logger = logging.getLogger(__name__)

torch.manual_seed(42)
torch.npu.manual_seed_all(42)


class FakeContextManager:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    @staticmethod
    def step():
        return


class ModelRunner:
    def __init__(self, runner_settings):
        self.runner_settings = runner_settings
        self.model_name = runner_settings.get("model_name", "default_model_name")
        model_path = self.runner_settings.get("model_path")
        self.dtype = runner_settings.get("model_config").get("dtype", torch.bfloat16)
        self.enable_online_split_weight = runner_settings.get("model_config").get("enable_online_split_weight", False)
        self.max_position_embeddings = \
                runner_settings.get("data_config").get("max_position_embeddings", 131072)
        self.input_max_len = runner_settings.get("data_config").get("input_max_len", 1024)
        self.max_new_tokens = runner_settings.get("data_config").get("max_new_tokens", 32)
        self.batch_size = runner_settings.get("data_config").get("batch_size", 16)
        self.tokenizer = None
        self.model = None
        self.device = None
        self.local_rank = int(os.getenv("LOCAL_RANK", "0"))
        self.rank_offset = int(os.getenv("RANK_OFFSET", "0"))
        self.global_rank = self.local_rank + self.rank_offset
        self.world_size = int(os.getenv("WORLD_SIZE", "1"))
        if self.world_size == 1 or self.enable_online_split_weight:
            self.model_path = model_path
        else:
            self.model_path = os.path.join(model_path, f"rank_{self.global_rank}")
        self.res_path = os.getenv("RES_PATH", "./")
        self.enable_profiler = runner_settings.get("model_config").get("enable_profiler", False)
        self.enable_prefill_profiler = self.enable_profiler
        self.enable_decode_profiler = self.enable_profiler
        self.use_pretrained_model = True
        self.execute_mode = runner_settings.get("exe_mode", "ge_graph")
        self.tokenizer_mode = runner_settings.get("model_config").get("tokenizer_mode", "default")
        self.platform_version = runner_settings.get("model_config").get("platform_version", "A3")
        self.profiler = FakeContextManager()
        self.hf_config = None
        self.quantization = None
        self.init_device()

    @staticmethod
    def define_profiler(enable_profiler=False, profile_save_path="prof", active=10, repeat=1, skip_first=10):
        if enable_profiler:
            os.makedirs(profile_save_path, exist_ok=True)
            experimental_config = torch_npu.profiler._ExperimentalConfig(
                profiler_level=torch_npu.profiler.ProfilerLevel.Level1,
                aic_metrics=torch_npu.profiler.AiCMetrics.PipeUtilization
            )
            profiler = torch_npu.profiler.profile(
                activities=[
                    torch_npu.profiler.ProfilerActivity.NPU,
                    torch_npu.profiler.ProfilerActivity.CPU,
                ],
                with_stack=False,
                record_shapes=False,
                profile_memory=False,
                experimental_config=experimental_config,
                schedule=torch_npu.profiler.schedule(
                    wait=0,
                    warmup=0,
                    active=active,
                    repeat=repeat,
                    skip_first=skip_first
                ),
                on_trace_ready=torch_npu.profiler.tensorboard_trace_handler(profile_save_path)
            )
        else:
            profiler = FakeContextManager()

        return profiler

    def init_device(self):
        logger.info("Set execution using npu index: %s, global: %s", self.local_rank, self.global_rank)
        self.device = torch.device("%s:%s" % ("npu", self.local_rank))
        torch.npu.set_device(self.device)

        if torch.npu.is_available() and self.world_size > 1:
            default_pg = get_default_group()
            if default_pg is None:
                options = torch_npu._C._distributed_c10d.ProcessGroupHCCL.Options()
                if self.platform_version == "950": # use ccu_ms for 950
                    options.hccl_config = {"hccl_op_expansion_mode": 5}
                torch.distributed.init_process_group(
                    backend="hccl", world_size=self.world_size, rank=self.global_rank, pg_options=options)

    def init_model(self, model, config=None, **kwargs):
        if self.enable_online_split_weight:
            self._init_model_with_online_splited_weight(model, config, **kwargs)
        else:
            self._init_model_with_offline_splited_weight(model, config, **kwargs)
        self._process_weight_after_loading()
        self.compile_model()
        self.init_tokenizer()

    def _process_weight_after_loading(self):
        self.to_device()
        if self.enable_online_split_weight:
            for _, module in self.model.named_modules():
                quant_method = getattr(module, "quant_method", None)
                if isinstance(quant_method, QuantizeMethodBase):
                    quant_method.process_weights_after_loading(module)
        else:
            self.scale_dtype_adapter()
            self.cast_format()


    def _init_model_with_online_splited_weight(self, model, config, **kwargs):
        if config is None:
            raise Exception("config cannot be None")
        if self.use_pretrained_model:
            logger.info("Try to load pretrained model in path: %s", self.model_path)
            loader = DefaultModelLoader()

        else:
            loader = DummyModelLoader()
        self.hf_config = config.from_pretrained(
                self.model_path,
                low_cpu_mem_usage=True,
                ignore_mismatched_sizes=True,
                runner_settings=self.runner_settings
            )
        self._verify_quantization()
        if self.quantization is not None:
            self.hf_config.quant_config = get_quant_config(self.hf_config, self.quantization, self.model_path)
        self.check_model_cfg()
        self.update_model_cfg()
        self.model = loader.load_model(config=self.hf_config, model_cls=model,
                                       runner_settings=self.runner_settings, model_path=self.model_path, **kwargs)

    def _init_model_with_offline_splited_weight(self, model, config, **kwargs):
        if self.use_pretrained_model:
            self._load_model_with_manual_splited_weight(model, **kwargs)
        else:
            self._init_model_from_config(model, config=config, **kwargs)

    def _init_model_from_config(self, model, config, **kwargs):
        if config is None:
            raise Exception("config cannot be None")
        config_file = os.path.join(self.model_path, "config.json")
        model_config = config.from_pretrained(config_file, torch_dtype=self.dtype)
        self.model = model(model_config, runner_settings=self.runner_settings, **kwargs).to(self.dtype)

    def _load_model_with_manual_splited_weight(self, model, **kwargs):
        logger.info("Try to load pretrained model in path: %s", self.model_path)
        self.model = model.from_pretrained(self.model_path,
                                            low_cpu_mem_usage=True,
                                            ignore_mismatched_sizes=True,
                                            torch_dtype="auto", # 使用权重的默认数据类型
                                            runner_settings=self.runner_settings,
                                            **kwargs)

    def save_model(self):
        pass

    def scale_dtype_adapter(self):
        pass

    def to_device(self):
        self.model.to(self.device)
        logger.info("Model weights H2D finished.")

    def cast_format(self):
        pass

    def init_tokenizer(self):
        if "deepseek_vl2" in self.model_name:
            self.tokenizer = AutoProcessor.from_pretrained(
                self.model_path, trust_remote_code=True, use_fast=True
            )
            logging.info(f"use deepseek_vl2 tokenizer.")
            return
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path,
            padding_side="right",
            truncation_side='right',
            trust_remote_code=True
            )
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

    def tokenize_prompts(self, prompts):
        kwargs = {
            "return_tensors": "pt", "truncation": True, "padding": "max_length", "max_length": self.input_max_len
        }
        # To more intuitively demonstrate the model's performance on the LongBench dataset, we provide a fixed prompt
        # before and after the text.
        if self.runner_settings.get("data_config").get("dataset", "default") != "default":
            from executor.utils.data_utils import build_dataset_input
            prompts = build_dataset_input(self.tokenizer, prompts, self.input_max_len,
                                          self.max_new_tokens, is_chat=False)
        inputs = self.tokenizer(prompts, **kwargs).to(self.device)

        return inputs

    def compile_model(self):
        logger.info("The final model structure is: \n %s", self.model)
        if "graph" in self.execute_mode:
            logger.info("Try to compile model")
            self.graph_compile()

    def graph_compile(self):
        import torchair as tng
        import torchair.ge_concrete_graph.ge_converter.experimental.patch_for_hcom_allreduce
        from torchair.configs.compiler_config import CompilerConfig

        compiler_config = CompilerConfig()
        compiler_config.experimental_config.frozen_parameter = True
        compiler_config.experimental_config.tiling_schedule_optimize = True
        npu_backend = tng.get_npu_backend(compiler_config=compiler_config)
        self.model = torch.compile(self.model, dynamic=True, fullgraph=True, backend=npu_backend)

    @staticmethod
    def mark_detail(model_inputs, item_key, is_cache=False):
        item = model_inputs.get(item_key, None)
        if item is None:
            return
        if is_cache:
            for item_sub in item:
                for sub_item in item_sub:
                    if isinstance(sub_item, torch.Tensor):
                        torch._dynamo.mark_static(sub_item)
        elif isinstance(item, torch.Tensor):
            torch._dynamo.mark_static(item)

    def mark_inputs(self, model_inputs, loop_list=None):
        # prefill with dynamic sequence length, decode with static sequence length
        # `loop_list` refers to the list of keys corresponding to values that are tuple, e.g.
        # ['past_key_values']. And the tensor elements within the tuple are marked as static through iteration.
        if loop_list is None:
            loop_list = []
        for input_key, _ in model_inputs.items():
            is_cache = True if input_key in loop_list else False
            self.mark_detail(model_inputs, input_key, is_cache=is_cache)

    def model_input_prepare(self, input_dict):
        pass
        return None

    def model_inference(self, model_inputs, is_prefill, warm_up=False):
        torch.npu.synchronize()
        start_time = time.time()
        with torch.no_grad():
            logits = self.model(**model_inputs)
        torch.npu.synchronize()
        end_time = time.time()
        inference_time = end_time - start_time
        inference_stage = "prefill" if is_prefill else "decode"
        logger.info(f"{self.model_name} inference time cost of {inference_stage} is {(inference_time)*1000:.2f} ms")
        return (logits, inference_time)

    # Copied from vllm.config._parse_quant_hf_config
    def _parse_quant_hf_config(self):
        quant_cfg = getattr(self.hf_config, "quantization_config", None)
        if quant_cfg is None:
            # compressed-tensors uses a "compression_config" key
            quant_cfg = getattr(self.hf_config, "compression_config", None)
        return quant_cfg

    # Adapted from vllm.config._verify_quantization
    def _verify_quantization(self) -> None:
        '''
        Adapted from vllm, verify quantization configurations
        '''
        supported_quantization = QUANTIZATION_METHODS

        # Parse quantization method from the HF model config, if available.
        quant_cfg = self._parse_quant_hf_config()

        if quant_cfg is not None and quant_cfg:
            quant_method = quant_cfg.get("quant_method", "").lower()
            quant_method = quant_method.replace("compressed_tensors",
                                                "compressed-tensors")

            # Verify quantization configurations.
            self.quantization = quant_method

        if self.quantization is not None:
            if self.quantization not in supported_quantization:
                raise ValueError(
                    f"Unknown quantization method: {self.quantization}. Must "
                    f"be one of {supported_quantization}.")

    def model_generate(self, input_dict, input_lens, warm_up=False):
        logger.info("Prompt lens is : %d", input_lens)
        generate_tokens = 0
        cnt = 0
        infer_time_rec = []
        enable_profiler = self.enable_prefill_profiler and not warm_up
        self.profiler = self.define_profiler(
            enable_profiler=enable_profiler,
            profile_save_path=os.path.join(self.res_path, "prof", "prefill"),
            active=1, skip_first=0, repeat=1)

        with self.profiler:
            model_inputs = self.model_input_prepare(input_dict)
            outputs = self.model_inference(model_inputs, is_prefill=input_dict['is_prefill'], warm_up=warm_up)
            # The outputs is a tuple containing logits, inference_time and other necessary return values.
            logits = outputs[0]
            inference_time = outputs[1]
            self.model_output_process(model_inputs, logits, input_dict)
            self.profiler.step()
            generate_tokens += 1
            cnt += 1
            infer_time_rec.append(inference_time)
        enable_profiler = self.enable_decode_profiler and not warm_up
        self.profiler = self.define_profiler(
            enable_profiler=enable_profiler,
            profile_save_path=os.path.join(self.res_path, "prof", "decode"))
        with self.profiler:
            while True:
                jump_flag = self.get_jump_flag(cnt, warm_up)
                if jump_flag:
                    break

                model_inputs = self.model_input_prepare(input_dict)
                outputs = self.model_inference(model_inputs, is_prefill=input_dict['is_prefill'], warm_up=warm_up)
                # The outputs is a tuple containing logits, inference_time and other necessary return values.
                logits = outputs[0]
                inference_time = outputs[1]
                self.model_output_process(model_inputs, logits, input_dict)
                self.profiler.step()
                generate_tokens += 1
                cnt += 1
                infer_time_rec.append(inference_time)

        if not warm_up:
            avg_infer_time = process_infer_time(infer_time_rec, cnt)
            logger.info(f"{self.model_name} average inference time cost is {(avg_infer_time)*1000:.2f} ms")

        # detokenize outputs
        generate_ids = input_dict["generate_ids"].clip(0,\
                            self.model.config.vocab_size - 1)
        generate_ids_list = remove_padding_left(generate_ids, self.tokenizer.pad_token_id)
        res_list = detokenize_outputs(generate_ids_list, self.tokenizer, input_lens)
        return res_list

    def get_jump_flag(self, cnt, warm_up):
        default_decode_dump = 2
        # warm up only perform for 2 times(decode)
        jump_flag_warm = warm_up and cnt >= default_decode_dump
        # do not generate after max_token
        jump_flag_oversize = cnt >= self.max_new_tokens
        jump_flag = jump_flag_oversize or jump_flag_warm
        return jump_flag

    def model_output_process(self, model_inputs, outputs, input_dict):
        pass

    def check_model_cfg(self):
        pass

    def update_model_cfg(self):
        pass
