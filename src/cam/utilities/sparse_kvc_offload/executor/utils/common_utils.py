# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import math

import logging
from functools import wraps
from typing import Dict
from enum import Enum
import yaml
import torch
import torch_npu
import numpy as np
import torchair as tng


logger = logging.getLogger(__name__)


def get_had_pow2(n, norm=True):
    if not ((n & (n - 1) == 0) and (n > 0)):
        raise ValueError(f"n must be a positive power of 2, got{n}")
    had = torch.ones(1, 1, dtype=torch.bfloat16).npu()
    while had.shape[0] != n:
        had = torch.cat((torch.cat([had, had], 1), torch.cat([had, -had], 1)), 0)
        if norm:
            had /= math.sqrt(2)
    return had


def read_yaml(yaml_file_path):
    try:
        with open(yaml_file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except FileNotFoundError:
        logger.error(f"No such yaml file: {yaml_file_path}")
    except yaml.YAMLError as e:
        logger.error(f"Load yaml file failed: {e}")
    return data


class FakeContextManager:
    def __init__(self) -> None:
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        pass


def superkernel_scope(enable: bool, scope: str, options: str = None):
    if enable:
        return tng.scope.super_kernel(scope, options)
    else:
        return FakeContextManager()


def align_up(a, b):
    if b <= 0:
        raise ValueError("b should be larger then zero!")
    return (a + b - 1) // b * b


def align_memory(tensor: torch.Tensor, alignment: int) -> torch.Tensor:
    """Return a view of `tensor` whose `data_ptr()` is `alignment`-byte aligned.

    `alignment` is a byte count. The caller must over-allocate `tensor` by at
    least `ceil(alignment / tensor.element_size())` elements so the returned
    view can be safely narrowed to its target size.
    """
    data_ptr = tensor.data_ptr()
    aligned_addr = (data_ptr + alignment - 1) // alignment * alignment
    offset = int((aligned_addr - data_ptr) // tensor.element_size())
    return tensor.narrow(0, offset, tensor.numel() - offset)


def ceil_div(a, b):
    return (a + b - 1) // b


def update_settings(runner_settings: Dict, module_name: str, key: str, value):
    if runner_settings.get(module_name) is None:
        raise Exception(f"runner_settings doesn't have submodule ({module_name})!")
    module = runner_settings.get(module_name)
    module.update({key: value})
    logger.info(f"add ({key}: {value}) to runner_settings.")
    return runner_settings


def override(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def get_init_attn_mask(mask_length, device, valid_len=None):
    share_mask_tril = ~torch.tril(
        torch.ones((mask_length, mask_length),
                   dtype=torch.bool, device=device))
    if valid_len is not None:
        share_mask_tril[-valid_len:, :] = torch.zeros(valid_len, mask_length)
    return share_mask_tril


def get_decode_mask(mask_length, device, position):
    decode_mask = torch.zeros((1, mask_length), device=device)
    decode_mask[0, :position] = 1
    return decode_mask


def npu_wait_tensor(switch_flag: bool, out: torch.Tensor, wait_tensor: torch.Tensor):
    if switch_flag:
        out = tng.scope.npu_wait_tensor(out, wait_tensor)
    return out


def npu_stream_switch(switch_flag: bool, stream_tag: str, stream_priority: int = 0):
    if switch_flag:
        return tng.scope.npu_stream_switch(stream_tag, stream_priority)
    else:
        return FakeContextManager()


def limit_core_num(switch_flag: bool, aic_num: str, aiv_num: str):
    if switch_flag:
        return tng.scope.limit_core_num(aic_num, aiv_num)
    else:
        return FakeContextManager()


def record_event(switch_flag: bool, events: tuple[torch.npu.Event], idx: int):
    if switch_flag:
        tng.ops.npu_tagged_event_record(events[idx])


def wait_event(switch_flag: bool, events: tuple[torch.npu.Event], idx: int):
    if switch_flag:
        tng.ops.npu_tagged_event_wait(events[idx])


def record_stream(switch_flag: bool, out: torch.Tensor, stream_id: str):
    if switch_flag:
        tng.ops.npu_record_tagged_stream(out, stream_id)


def npu_prefetch(switch_flag, weight, depend, size, offset=0):
    if switch_flag:
        return torch_npu.npu_prefetch(weight, depend, size, offset)
    else:
        return None


def process_infer_time(infer_time_rec, token_count):
    if len(infer_time_rec) == 0: # no time recorded
        logger.info(f"precoss infer time receives empty time record")
        return 0
    elif len(infer_time_rec) == 1 or (token_count <= 1): # only prefill
        return infer_time_rec[0]
    else: # obtain average time for decode
        avg_token_per_round = token_count / len(infer_time_rec) # mtp steps may take more than one token

        # skip the time cost for prefill step
        infer_time_rec = infer_time_rec[1:]
        token_count -= 1

    q1 = np.percentile(infer_time_rec, 25)
    q3 = np.percentile(infer_time_rec, 75)
    iqr_upper_threshold = q3 + 1.5 * (q3 - q1)
    total_time = 0
    for t in infer_time_rec:
        if t > iqr_upper_threshold:
            token_count -= avg_token_per_round
            continue
        total_time += t
    if token_count == 0:
        return infer_time_rec[0]
    avg_infer_time = total_time / token_count

    return avg_infer_time


class MicroBatchMode(Enum):
    DISABLE = 0
    PREFILL_MICRO_BATCH_DP_EP = 1
    PREFILL_MICRO_BATCH_SP_TP_EP = 2


def remove_padding_left(tensor, pad_id):
    # remove left padding tokens in mtp, pad_token_id may be equal to eos_token
    if tensor.shape[0] == 1:
        return [tensor[0]]
    if tensor.dim() != 2:
        raise ValueError("remove padding func input dim must be 2")
    batch_size, seq_len = tensor.shape
    output_tensorlist = []

    for i in range(batch_size):
        row = tensor[i]
        mask = (row != pad_id)
        if mask.any():
            first_valid_token = torch.argmax(mask.float())
            processed_row = row[first_valid_token:]
        else:
            processed_row = row
        output_tensorlist.append(processed_row)

    return output_tensorlist


def remove_eos_right(output_tensorlist: list[torch.Tensor], eos_id: int) -> list[list[int]]:
    res = []

    for toks in output_tensorlist:
        if eos_id in toks:
            toks = toks[:toks.index(eos_id)]
        res.append(toks.cpu().tolist().append(eos_id))
    return res


def detokenize_outputs(generate_ids_list, tokenizer, input_lens):
    res_list = []
    for generate_ids in generate_ids_list:
        res = tokenizer.decode(generate_ids[input_lens:], skip_special_tokens=False)
        if tokenizer.eos_token in res:
            res = res.split(tokenizer.eos_token)[0]
        res_list.append(res)
    if isinstance(res_list, list):
        logger.info("Inference decode result for batch 0: \n%s", res_list[0])
    else:
        logger.info("Inference decode result: \n%s", res_list)
    return res_list


def check_common_parallel_settings(world_size, runner_settings):
    if world_size <= 0:
        raise ValueError(f"{world_size=} must greater than 0")
    parallel_config = runner_settings.get("parallel_config", {})
    batch_size = runner_settings.get("data_config").get("batch_size", 1)
    target_keys = ("tp_size", "ep_size", "kvp_size")
    for key, value in parallel_config.items():
        is_target_key = any(target_key in key for target_key in target_keys)
        if is_target_key and world_size % value != 0:
            raise ValueError(f"{world_size=} is not divisible by {key}={value}")
        if "dp_size" in key and batch_size % value != 0:
            raise ValueError(f"{batch_size=} is not divisible by {key}={value}")


def update_common_vars(world_size, runner_settings):
    attn_dp_size = world_size // runner_settings.get("parallel_config").get("attn_tp_size", 1)
    moe_dp_size = world_size // runner_settings.get("parallel_config").get("moe_tp_size", 1)
    moe_ep_size = moe_dp_size
    embed_dp_size = world_size // runner_settings.get("parallel_config").get("embed_tp_size", 1)

    batch_size = runner_settings.get("data_config").get("batch_size", 1)
    batch_size_per_rank = batch_size // attn_dp_size

    runner_settings = update_settings(runner_settings, "data_config", "batch_size_per_rank", batch_size_per_rank)
    runner_settings = update_settings(runner_settings, "parallel_config", "attn_dp_size", attn_dp_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "moe_dp_size", moe_dp_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "moe_ep_size", moe_ep_size)
    runner_settings = update_settings(runner_settings, "parallel_config", "embed_dp_size", embed_dp_size)

    input_max_len = runner_settings.get("data_config").get("input_max_len", 32)
    max_new_tokens = runner_settings.get("data_config").get("max_new_tokens", 32)
    next_n = runner_settings.get("model_config").get("next_n", 0)
    max_position_embeddings = max_new_tokens * (next_n + 1) + input_max_len
    runner_settings = update_settings(runner_settings, "data_config", "max_position_embeddings",
                                      max_position_embeddings)


def obtain_mtp_stats(next_n, model_name, total_accepted_num, cnt, infer_time_rec):
    avg_accepted_num = torch.mean(total_accepted_num)
    logger.info(f"Finished inference, number of loop step is {cnt}, "
                    f"draft tokens per batch is {cnt}*{next_n}, "
                    f"average accepted number per batch is {avg_accepted_num.to(torch.int32)}")

    total_tokens = avg_accepted_num + cnt
    equivalent_infer_time = process_infer_time(infer_time_rec, total_tokens)
    avg_infer_time = process_infer_time(infer_time_rec, len(infer_time_rec))
    logger.info(
        f"{model_name} main and mtp model average inference time cost is {(avg_infer_time)*1000:.2f} ms")
    logger.info(
        f"{model_name} model average equivalent latency of MTP{next_n}"
        f" is {(equivalent_infer_time)*1000:.2f} ms")

    return avg_infer_time


# Adapted from
# https://gitee.com/ascend/ModelZoo-PyTorch/blob/master/MindIE/LLM/DeepSeek/DeepSeek-V2/NPU_inference/fp8_cast_bf16.py
def weight_dequant(weight: torch.Tensor, scale: torch.Tensor, block_size: int = 128) -> torch.Tensor:
    """
    Dequantizes the given weight tensor using the provided scale tensor, efficiently handling cases where
    `weight` is not a multiple of `block_size` by broadcasting `scale`.

    Args:
        weight (torch.Tensor): The quantized weight tensor of shape(M, N).
        scale (torch.Tensor): The scale tensor of shape (M // block_size, N // block_size).
        block_size (int, optional): The block size to use for dequantization. Defaults to 128.

    Returns:
        torch.Tensor: The dequantized weight tensor of the same shape as `weight`, converted to the default dtype.

    Raises:
        AssertionError: If `scale` dimensions do not align with `weight` shape after scaling.
    """

    # Get the original dimensions of weight
    M, N = weight.shape

    # Compute the effective block dimensions for scale
    scale_m, scale_n = scale.shape
    assert scale_m == (
        M + block_size - 1) // block_size, "Mismatch in scale rows and weight rows."
    assert scale_n == (
        N + block_size - 1) // block_size, "Mismatch in scale columns and weight columns."

    # Convert weight to float32 for calculations
    weight = weight.to(torch.float32)
    scale = scale.to(torch.float32)

    # Expand scale to match the weight tensor's shape
    scale_expanded = scale.repeat_interleave(
        block_size, dim=0).repeat_interleave(block_size, dim=1)

    # Trim scale_expanded to match weight's shape if necessary
    scale_expanded = scale_expanded[:M, :N]

    # Perform element-wise multiplication
    dequantized_weight = weight * scale_expanded

    # Convert the output to the default dtype
    dequantized_weight = dequantized_weight.to(torch.get_default_dtype())

    return dequantized_weight