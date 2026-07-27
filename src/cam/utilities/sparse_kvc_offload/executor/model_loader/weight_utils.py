# coding=utf-8
# This code is copied from vllm implementations.
# (https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/model_loader/weight_utils.py)
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
"""Utilities for downloading and initializing model weights."""
import json
import os
import time
from typing import Generator, List, Tuple
from transformers.utils import logging

import numpy as np
import torch
from safetensors.torch import load_file, safe_open, save_file
from tqdm.auto import tqdm

logger = logging.get_logger(__name__)


# For models like Mistral-7B-v0.3, there are both sharded
# safetensors files and a consolidated safetensors file.
# Passing both of these to the weight loader functionality breaks.
# So, we use the index_file to
# look up which safetensors files should be used.
def filter_duplicate_safetensors_files(hf_weights_files: List[str],
                                       hf_folder: str,
                                       index_file: str) -> List[str]:
    # model.safetensors.index.json is a mapping from keys in the
    # torch state_dict to safetensors file holding that weight.
    index_file_name = os.path.join(hf_folder, index_file)
    if not os.path.isfile(index_file_name):
        return hf_weights_files

    # Iterate through the weight_map (weight_name: safetensors files)
    # to identify weights that we should use.
    with open(index_file_name) as f:
        weight_map = json.load(f)["weight_map"]
    weight_files_in_index = set()
    for weight_name in weight_map:
        weight_files_in_index.add(
            os.path.join(hf_folder, weight_map[weight_name]))
    # Filter out any fields that are not found in the index file.
    hf_weights_files = [
        f for f in hf_weights_files if f in weight_files_in_index
    ]
    return hf_weights_files


def filter_files_not_needed_for_inference(
        hf_weights_files: List[str]) -> List[str]:
    """
    Exclude files that are not needed for inference.

    See https://github.com/huggingface/transformers/blob/v4.34.0/src/transformers/trainer.py#L227-L233
    """
    blacklist = [
        "training_args.bin",
        "optimizer.bin",
        "optimizer.pt",
        "scheduler.pt",
        "scaler.pt",
    ]
    hf_weights_files = [
        f for f in hf_weights_files
        if not any(f.endswith(x) for x in blacklist)
    ]
    return hf_weights_files


# explicitly use pure text format, with a newline at the end
# this makes it impossible to see the animation in the progress bar
# but will avoid messing up with ray or multiprocessing, which wraps
# each line of output with some prefix.
_BAR_FORMAT = \
    "{desc}: {percentage:3.0f}% Completed | {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]\n"


def enable_tqdm(use_tqdm_on_load: bool):
    return use_tqdm_on_load


def safetensors_weights_iterator(
    hf_weights_files: List[str],
    use_tqdm_on_load: bool,
) -> Generator[Tuple[str, torch.Tensor], None, None]:
    """Iterate over the weights in the model safetensor files."""
    for st_file in tqdm(
            hf_weights_files,
            desc="Loading safetensors checkpoint shards",
            disable=not enable_tqdm(use_tqdm_on_load),
            bar_format=_BAR_FORMAT,
    ):
        with safe_open(st_file, framework="pt") as f:
            for name in f.keys():
                param = f.get_tensor(name)
                yield name, param


def default_weight_loader(param: torch.Tensor,
                          loaded_weight: torch.Tensor) -> None:
    """Default weight loader."""
    try:
        if param.numel() == 1 and loaded_weight.numel() == 1:
            # Sometimes scalar values aren't considered tensors with shapes
            # so if both param and loaded_weight are a scalar,
            # "broadcast" instead of copy
            param.data.fill_(loaded_weight.item())
        else:
            if param.size() != loaded_weight.size():
                raise ValueError(
                    f"Attempted to load weight ({loaded_weight.size()}) "
                    f"into parameter ({param.size()})")

            param.data.copy_(loaded_weight)
    except Exception as e:
        # NOTE: This exception is added for the purpose of setting breakpoint to
        # debug weight loading issues.
        logger.error(f"default weight load failed {e}")


def initialize_dummy_weights(
    model: torch.nn.Module,
    low: float = -1e-3,
    high: float = 1e-3,
    seed: int = 1234,
) -> None:
    """Initialize model weights with random values.

    The model weights must be randomly initialized for accurate performance
    measurements. Additionally, the model weights should not cause NaNs in the
    forward pass. We empirically found that initializing the weights with
    values between -1e-3 and 1e-3 works well for most models.

    We use per-parameter random seed, so that dummy weights are consistent,
    even if the model is partitioned across multiple devices. When the seed
    is fixed, the random values generated by this function only depends on
    the parameter's number of elements and its data type.
    """
    for param in model.state_dict().values():
        if torch.is_floating_point(param):
            generator = torch.Generator(device=param.data.device)
            generator.manual_seed(seed)
            if torch.finfo(param.data.dtype).bits < 16:
                # uniform_ doesn't support < 16-bit datatypes (FP8)
                dtype = param.data.dtype
                tmp_param = param.data.to(torch.float16)
                tmp_param = tmp_param.uniform_(low, high,
                                               generator=generator).to(dtype)
                param.data.copy_(tmp_param)
            else:
                param.uniform_(low, high, generator=generator)
