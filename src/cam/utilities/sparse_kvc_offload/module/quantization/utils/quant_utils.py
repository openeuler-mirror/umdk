# coding=utf-8
# This code is copied from vllm implementations.
# (https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/quantization/utils/quant_utils.py)
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from types import MappingProxyType


def is_layer_skipped(
    prefix: str,
    ignored_layers: list[str],
    fused_mapping: Mapping[str, list[str]] = MappingProxyType({})
) -> bool:
    # prefix: model.layers.0.self_attn.q_proj
    # proj_name: q_proj
    proj_name = prefix.split(".")[-1]

    # Fused layers like gate_up_proj or qkv_proj will not be fused
    # in the safetensors checkpoint. So, we convert the name
    # from the fused version to unfused + check to make sure that
    # each shard of the fused layer has the same scheme.
    if proj_name in fused_mapping:
        shard_prefixes = [
            prefix.replace(proj_name, shard_proj_name)
            for shard_proj_name in fused_mapping[proj_name]
        ]

        is_skipped = None
        for shard_prefix in shard_prefixes:
            is_shard_skipped = shard_prefix in ignored_layers

            if is_skipped is None:
                is_skipped = is_shard_skipped
            elif is_shard_skipped != is_skipped:
                raise ValueError(
                    f"Detected some but not all shards of {prefix} "
                    "are quantized. Ensure all shards of fused layers "
                    "use the same precision.")
    else:
        is_skipped = prefix in ignored_layers

    assert is_skipped is not None
    return is_skipped


def reshape_mx_scale(scale_tensor):
    """
    Reshape the last dimension of 2D/3D tensor into (original_size // 2, 2) for GMM/MM operators.
    """
    # Keep all dims except last, then split last into (n // 2, 2)
    return scale_tensor.view(*scale_tensor.shape[:-1], scale_tensor.size(-1) // 2, 2)