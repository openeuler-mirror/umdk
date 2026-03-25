#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: UT for dispatch/combine prefill op
# Create: 2026-1-21
# Note:
# History: 2026-1-21 create file
#

import pytest
import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import torchair
from torchair.configs.compiler_config import CompilerConfig

import umdk_cam_op_lib

from ..util import tool

from ..util.marker import Author
from ..util.marker import MPTest
from ..util.marker import A3Test
from ..util.marker import SKIP_ENV_RANKSIZE_UNEQUAL

torch_npu.npu.config.allow_internal_format = True

class Module(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, x, topk_idx, topk_weights, group_ep, rank, num_ranks, num_experts, use_quant):
        layout_args = {
            "topk_idx": topk_idx,
            "num_experts": num_experts,
            "num_ranks": num_ranks
        }
        output_layout = torch.ops.umdk_cam_op_lib.get_dispatch_layout(**layout_args)

        num_tokens_per_expert, send_token_idx_small = output_layout[0:2]
        dispatch_args = {
            "x": x,
            "topk_idx": topk_idx,
            "topk_weights": topk_weights,
            "num_tokens_per_expert": num_tokens_per_expert,
            "send_token_idx_small": send_token_idx_small,
            "group_ep": group_ep,
            "rank": rank,
            "num_ranks": num_ranks,
            "use_quant": use_quant
        }

        output_dispatch = torch.ops.umdk_cam_op_lib.moe_dispatch_prefill(**dispatch_args)
        recv_x, dynamic_scales_out, expand_idx_out, recv_count, recv_tokens_per_expert = output_dispatch[0:5]

        recv_x = per_token_cast_back(recv_x, dynamic_scales_out) if use_quant else recv_x

        combine_args = {
            "x": recv_x,
            "topk_idx": topk_idx,
            "topk_weights": topk_weights,
            "src_idx": expand_idx_out,
            "send_head": recv_count,
            "group_ep": group_ep,
            "rank": rank,
            "num_ranks": num_ranks
        }
        combine_x = torch.ops.umdk_cam_op_lib.moe_combine_prefill(**combine_args)

        return combine_x

def per_token_cast_back(x_fp8: torch.Tensor, x_scales: torch.Tensor):
    if x_scales.dtype == torch.int:
        x_scales = x_scales.view(dtype=torch.int8).to(torch.int) << 23
        x_scales = x_scales.view(dtype=torch.float)
    x_fp32 = x_fp8.to(torch.float32).view(x_fp8.size(0), -1, 128)
    x_scales = x_scales.view(x_fp8.size(0), -1, 1)
    return (x_fp32 * x_scales).view(x_fp8.shape).to(torch.bfloat16)

def calc_diff(x, y):
    x, y = x.astype(np.float64) + 1, y.astype(np.float64) + 1
    denominator = (x * x + y * y).sum()
    sim = 2 * (x * y).sum() / denominator
    return 1 - sim

def gen_x(rank, num_tokens, hidden_size):
    x = np.ones((num_tokens, hidden_size), dtype=np.float32) * rank
    return x

def gen_topk_idx(num_experts, num_tokens, num_topk):
    scores = np.abs(np.random.randn(num_tokens, num_experts).astype(np.float32)) + 1
    topk_idx = np.argpartition(scores, -num_topk, axis=-1)[:, -num_topk:]
    return topk_idx

def gen_topk_weights(rank, num_tokens, num_topk):
    topk_weights = np.ones((num_tokens, num_topk), dtype=np.float32) * rank
    return topk_weights

CASE_16RANK = {
    "num_ranks": 16,
    "num_experts": 16,
    "num_topk": 8,
    "num_tokens": 32,
    "hidden_size": 7168,
}

@MPTest
@A3Test
@SKIP_ENV_RANKSIZE_UNEQUAL(16)
@pytest.mark.parametrize("mode, use_quant", [('Eager', False), ('Eager', True)])
def test_base_test(mode, use_quant):
    if mode == "GE" and tool.is_run_for_cov():
        return

    rank = tool.get_rank()
    worldSize = tool.get_world_size()

    case = CASE_16RANK
    num_ranks = case["num_ranks"]
    num_experts = case["num_experts"]
    num_topk = case["num_topk"]
    num_tokens = case["num_tokens"]
    hidden_size = case["hidden_size"]

    ep_ranks_list = list(np.arange(0, worldSize))
    ep_group = dist.new_group(backend="hccl", ranks=ep_ranks_list)

    group_ep = ep_group._get_backend(torch.device("npu")).get_hccl_comm_name(rank)

    if mode == "Eager":
        mod = Module().npu()
    elif mode == "GE":
        torch_npu.npu.set_compile_mode(jit_compile=True)
        config = CompilerConfig()
        npu_backend = torchair.get_npu_backend(compiler_config=config)
        mod = torch.compile(Module().npu(), backend=npu_backend)

    x_np = gen_x(rank, num_tokens, hidden_size)
    topk_idx_np = gen_topk_idx(num_experts, num_tokens, num_topk)
    topk_weights_np = gen_topk_weights(rank, num_tokens, num_topk)

    x = torch.from_numpy(x_np).to(dtype=torch.bfloat16).npu()
    topk_idx = torch.from_numpy(topk_idx_np.astype(np.int64)).npu()
    topk_weights = torch.from_numpy(topk_weights_np).npu()

    out = mod(
        x=x,
        topk_idx=topk_idx,
        topk_weights=topk_weights,
        group_ep=group_ep,
        rank=rank,
        num_ranks=worldSize,
        num_experts=num_experts,
        use_quant=use_quant
    )

    torch.npu.synchronize()

    check_x = out.cpu().float().numpy()
    ref_weights = np.where(topk_idx_np == -1, np.float32(0), topk_weights_np).sum(axis=1).reshape(-1, 1)
    ref_x = x_np * ref_weights

    diff = calc_diff(check_x, ref_x)
    assert(diff < 5e-5)