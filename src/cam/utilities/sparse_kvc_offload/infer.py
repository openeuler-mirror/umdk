# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import os
import argparse
import logging
import torch

from runner_deepseek import DeepSeekRunner
from models.model_infer import Infer
from executor.utils import update_settings, align_up, read_yaml
from executor.utils.data_utils import generate_prompt

root_logger = logging.getLogger()
root_logger.handlers.clear()
logging.basicConfig(format='%(asctime)s - %(levelname)s - [LLM](%(filename)s:%(lineno)d): %(message)s',
                    level=logging.INFO)
logging.getLogger("paramiko").setLevel(logging.ERROR)
torch.manual_seed(42)
torch.npu.manual_seed_all(42)


def parse_args():
    parser = argparse.ArgumentParser(description="llm run parameters")
    parser.add_argument('--yaml_file_path', type=str, help="inference configurations")
    parser.add_argument('--local_rank', type=int, default=0, help="Local rank id for torch distributed launch")
    parser_args = parser.parse_args()
    return parser_args


def run_deepseek(runner_settings):
    preset_prompts, query_id_list = generate_prompt(runner_settings)
    model_runner_main = DeepSeekRunner(runner_settings)
    # to accelerate the compiling process for torch dynamo
    torch.npu.set_compile_mode(jit_compile=False)
    model_runner_main.init_model()

    model_runner_mtp = None
    next_n = runner_settings.get("model_config").get("next_n", 0)
    if next_n > 0:
        model_runner_mtp = DeepSeekRunner(runner_settings)
        model_runner_mtp.init_model(is_mtp=True)
        # the mtp modules share embed, lm_head, rotary_emb with the main model
        model_runner_mtp.model.model.embed_tokens = model_runner_main.model.model.embed_tokens
        model_runner_mtp.model.lm_head = model_runner_main.model.lm_head
        model_runner_mtp.model.rotary_emb = model_runner_main.model.model.rotary_emb

    # init mtp infer process
    infer = Infer(runner_settings, model_runner_main, model_runner_mtp)
    # warmup
    input_dict_main, input_dict_mtp = infer.model_generate(preset_prompts, warm_up=True)
    # generate perf data
    past_key_values_mtp = input_dict_mtp['past_key_values'] if next_n > 0 else None
    past_key_values_indexer_mtp = input_dict_mtp['past_key_values_indexer'] if next_n > 0 else None
    past_key_scales_indexer = input_dict_main['past_key_scales_indexer']
    past_key_scales_indexer_mtp = input_dict_mtp['past_key_scales_indexer'] if next_n > 0 else None

    enable_offload = runner_settings.get("model_config").get("enable_offload", False)
    offload_cache = None
    offload_cache_mtp = None
    if enable_offload:
        offload_cache = input_dict_main['offload_cache']
        offload_cache_mtp = input_dict_mtp['offload_cache'] if next_n > 0 else None

    infer.model_generate(preset_prompts, past_key_values=input_dict_main['past_key_values'],
                         past_key_values_indexer=input_dict_main['past_key_values_indexer'],
                         past_key_values_mtp=past_key_values_mtp,
                         past_key_values_indexer_mtp=past_key_values_indexer_mtp,
                         past_key_scales_indexer=past_key_scales_indexer,
                         past_key_scales_indexer_mtp=past_key_scales_indexer_mtp,
                         offload_cache=offload_cache,
                         offload_cache_mtp=offload_cache_mtp
                         )


def check_parallel_settings(world_size, runner_settings):
    attn_tp_size = runner_settings.get("parallel_config").get("attn_tp_size")
    oproj_tp_size = runner_settings.get("parallel_config").get("oproj_tp_size", 1)
    moe_tp_size = runner_settings.get("parallel_config").get("moe_tp_size")
    embed_tp_size = runner_settings.get("parallel_config").get("embed_tp_size")
    lmhead_tp_size = runner_settings.get("parallel_config").get("lmhead_tp_size", embed_tp_size)
    cp_size = runner_settings.get("parallel_config").get("cp_size", 1)
    dense_tp_size = runner_settings.get("parallel_config").get("dense_tp_size", 1)
    attn_dp_size = world_size // attn_tp_size
    batch_size = runner_settings.get("data_config").get("batch_size", 1)

    if world_size <= 0:
        raise ValueError(f"{world_size=} must greater than 0")
    if world_size % attn_tp_size != 0:
        raise ValueError(f"{world_size=} is not divisible by {attn_tp_size=}")
    if world_size % oproj_tp_size != 0:
        raise ValueError(f"{world_size=} is not divisible by {oproj_tp_size=}")
    if attn_tp_size > 1 and oproj_tp_size > 1:
        raise ValueError(f"oproj_tp_size does not support when attn_tp_size is lager than 1")
    if world_size % moe_tp_size != 0:
        raise ValueError(f"{world_size=} is not divisible by {moe_tp_size=}")
    if world_size % embed_tp_size != 0 or world_size % lmhead_tp_size != 0:
        raise ValueError(f"{world_size=} is not divisible by {embed_tp_size=} or {lmhead_tp_size=}")
    if embed_tp_size < attn_tp_size:
        raise ValueError(f"{embed_tp_size=} should not be smaller than {attn_tp_size=}")
    elif embed_tp_size % attn_tp_size != 0:
        raise ValueError(f"{embed_tp_size=} should be a multiple of {attn_tp_size=}")
    if batch_size % attn_dp_size != 0:
        raise ValueError(f"{batch_size=} is not divisible by {attn_dp_size=}")
    if cp_size > 1 and world_size != cp_size:
        raise ValueError(f"when cp enabled, {world_size=} should equal to {cp_size=}")
    if world_size % dense_tp_size != 0:
        raise ValueError(f"{world_size=} is not divisible by {dense_tp_size=}")


def check_model_settings(world_size, runner_settings):
    exe_mode = runner_settings.get("exe_mode")
    enable_cache_compile = runner_settings.get("model_config").get("enable_cache_compile", False)
    enable_multi_streams = runner_settings.get("model_config").get("enable_multi_streams", False)
    enable_superkernel = runner_settings.get("model_config").get("enable_superkernel", False)
    next_n = runner_settings.get("model_config").get("next_n", 0)
    prefill_mini_batch_size = runner_settings.get("model_config").get("prefill_mini_batch_size", 0)

    if exe_mode not in ["ge_graph", "eager", "acl_graph"]:
        raise ValueError(f"{exe_mode=} does not supported!")

    dynamo_feat = (enable_cache_compile or enable_multi_streams or enable_superkernel)
    if exe_mode == "eager" and dynamo_feat:
        raise ValueError(f"{exe_mode=} does not support cache compile, multi_streams or superkernel!")
    pa_max_length = runner_settings.get("model_config").get("pa_max_length", 2048)
    block_size = runner_settings.get("model_config").get("pa_block_size", 128)
    if pa_max_length % block_size != 0:
        raise ValueError(f"{pa_max_length=} should be a multiple of {block_size=}")
    if next_n > 3:
        raise ValueError(f"{next_n=} must equal or smaller than 3")
    if prefill_mini_batch_size > 0:
        batch_size = runner_settings.get("data_config").get("batch_size", 1)
        if prefill_mini_batch_size > batch_size or batch_size % prefill_mini_batch_size != 0:
            raise ValueError(f"{batch_size=} should be divided by {prefill_mini_batch_size=}")
        attn_tp_size = runner_settings.get("parallel_config").get("attn_tp_size")
        attn_dp_size = world_size // attn_tp_size
        batch_size_per_rank = batch_size // attn_dp_size
        if prefill_mini_batch_size > batch_size_per_rank or batch_size_per_rank % prefill_mini_batch_size != 0:
            raise ValueError(f"{batch_size_per_rank=} should be divided by {prefill_mini_batch_size=}")


def check_vars(world_size, runner_settings):
    check_parallel_settings(world_size, runner_settings)
    check_model_settings(world_size, runner_settings)


def update_vars(world_size, runner_settings):
    attn_tp_size = runner_settings.get("parallel_config").get("attn_tp_size")
    attn_dp_size = world_size // attn_tp_size
    cp_size = runner_settings.get("parallel_config").get("cp_size", 1)
    moe_dp_size = world_size // runner_settings.get("parallel_config").get("moe_tp_size")
    moe_ep_size = moe_dp_size
    embed_dp_size = world_size // runner_settings.get("parallel_config").get("embed_tp_size")

    batch_size = runner_settings.get("data_config").get("batch_size", 1)
    batch_size_per_rank = batch_size // attn_dp_size
    if cp_size > 1:
        prefill_dp_size = world_size // cp_size // attn_tp_size
        bs_per_cp_group = batch_size // prefill_dp_size
        runner_settings = update_settings(runner_settings, "data_config", "bs_per_cp_group", bs_per_cp_group)

    runner_settings = update_settings(runner_settings, "data_config", "batch_size_per_rank", batch_size_per_rank)
    runner_settings = update_settings(runner_settings, "parallel_config", "attn_dp_size", attn_dp_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "moe_dp_size", moe_dp_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "moe_ep_size", moe_ep_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "embed_dp_size", embed_dp_size)

    input_max_len = runner_settings.get("data_config").get("input_max_len", 32)
    max_new_tokens = runner_settings.get("data_config").get("max_new_tokens", 32)
    if cp_size > 1:
        input_max_len = align_up(input_max_len, cp_size * 2)
        runner_settings = update_settings(runner_settings, "data_config", "input_max_len", input_max_len)
    next_n = runner_settings.get("model_config").get("next_n", 0)
    max_position_embeddings = max_new_tokens * (next_n + 1) + input_max_len
    runner_settings = update_settings(
        runner_settings, "data_config", "max_position_embeddings", max_position_embeddings)

    pa_block_size = runner_settings.get("model_config").get("pa_block_size", 128)
    pa_max_length = align_up(max_position_embeddings, pa_block_size)
    runner_settings = update_settings(runner_settings, "model_config", "pa_max_length", pa_max_length)
    return runner_settings


if __name__ == "__main__":
    args = parse_args()
    yaml_file_path = args.yaml_file_path
    runner_settings = read_yaml(yaml_file_path)
    world_size = int(os.getenv("WORLD_SIZE", "1"))
    check_vars(world_size, runner_settings)
    runner_settings = update_vars(world_size, runner_settings)
    logging.info(f"runner_settings is: {runner_settings}")

    run_deepseek(runner_settings)
    logging.info("model run success")
