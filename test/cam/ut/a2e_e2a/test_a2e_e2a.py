#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: UT for a2e and e2a ops
# Create: 2026-03-02
# Note:
# History: 2026-03-02 create file
#

import pytest
import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import torchair
from torchair.configs.compiler_config import CompilerConfig
from collections import defaultdict
import os
import math
import random
import socket

# CAM Torch package
import umdk_cam_op_lib

from ..util import tool
# Required fixtures (import to activate)
from ..util.marker import Author
from ..util.marker import MPTest
from ..util.marker import A3Test
from ..util.marker import SKIP_ENV_RANKSIZE_UNEQUAL

class A2E_E2A_Module(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, x, expert_ids, scales, batch_size, hidden_size, topk, expert_rank_size, atten_rank_size, rank, group_ep, aiv_num):
        # Determine if current rank is on MOE side or Attention side
        is_moe_side = rank < expert_rank_size
        is_attention_side = rank >= expert_rank_size
        
        # Execute different logic based on role
        if is_attention_side:
            # Attention side: Call A2E to send data to MOE side
            a2e_output = torch.ops.umdk_cam_op_lib.a2e(
                x=x,
                expert_ids=expert_ids,
                scales=scales,
                batch_size=batch_size,
                hidden_size=hidden_size,
                topk=topk,
                expert_rank_size=expert_rank_size,
                atten_rank_size=atten_rank_size,
                rank=rank,
                group_ep=group_ep,
                aiv_num=aiv_num,
                compute_gate=1
            )
            
            # Parse A2E output
            expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out = a2e_output
            
            # Attention side: Call E2A to receive data from MOE side
            e2a_output = torch.ops.umdk_cam_op_lib.e2a(
                expand_x=x,      # Original input tensor
                atten_batch_size=atten_batch_size,
                batch_size=batch_size,
                hidden_size=hidden_size,
                topk=topk,
                expert_rank_size=expert_rank_size,
                attention_rank_size=atten_rank_size,
                rank=rank,
                group_ep=group_ep,
                aiv_num=aiv_num
            )
            
            return e2a_output, expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out
        else:  # MOE side
            # MOE side: Use empty tensor as placeholder, will actually receive data from Attention side
            dummy_x = torch.empty(0, hidden_size, dtype=x.dtype, device=x.device)
            dummy_expert_ids = torch.empty(0, topk, dtype=torch.int32, device=x.device)
            dummy_scales = torch.empty(0, topk, dtype=torch.float, device=x.device)
            
            a2e_output = torch.ops.umdk_cam_op_lib.a2e(
                x=dummy_x,
                expert_ids=dummy_expert_ids,
                scales=dummy_scales,
                batch_size=batch_size,
                hidden_size=hidden_size,
                topk=topk,
                expert_rank_size=expert_rank_size,
                atten_rank_size=atten_rank_size,
                rank=rank,
                group_ep=group_ep,
                aiv_num=aiv_num,
                compute_gate=1
            )
            
            # Parse A2E output
            expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out = a2e_output
            
            # MOE side: Call E2A to send data to Attention side
            e2a_output = torch.ops.umdk_cam_op_lib.e2a(
                expand_x=expand_x,
                atten_batch_size=atten_batch_size,
                batch_size=batch_size,
                hidden_size=hidden_size,
                topk=topk,
                expert_rank_size=expert_rank_size,
                attention_rank_size=atten_rank_size,
                rank=rank,
                group_ep=group_ep,
                aiv_num=aiv_num
            )
            
            return e2a_output, expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out

def gen_x(rank, batch_size, hidden_size):
    arr = [rank * batch_size + i + 1 for i in range(batch_size) for j in range(hidden_size)]
    return arr

def gen_expert_ids(rank, batch_size, topk, expert_rank_size):
    arr = [0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = (rank + i + j) % expert_rank_size
    return arr

def gen_scales(batch_size, topk):
    arr = [0.0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = 1.0 / topk
    return arr

# Test case configuration
CASE_16RANK = {
    "batchSize": 16,
    "hiddenSize": 512,
    "topk": 2,
    "expertRankSize": 8,  # 8 ranks for MOE side
    "attentionRankSize": 8,  # 8 ranks for Attention side
    "aivNum": 4
}

@MPTest # Test case type, here represents multi-process test case
@A3Test
@SKIP_ENV_RANKSIZE_UNEQUAL(16) # Skip this test case if RankSize is not 16 as expected
@pytest.mark.parametrize("mode", [('Eager')])
def test_base_test(mode):
    os.environ["MASTER_ADDR"] = "127.0.0.1"
    os.environ["MASTER_PORT"] = "29600"
    # Exit early because graph mode cannot get operator coverage
    if mode == "GE" and tool.is_run_for_cov():
        return
    # Get rank and world_size
    rank = tool.get_rank()
    world_size = tool.get_world_size()

    case = CASE_16RANK
    batch_size = case["batchSize"]
    hidden_size = case["hiddenSize"]
    topk = case["topk"]
    expert_rank_size = case["expertRankSize"]
    atten_rank_size = case["attentionRankSize"]
    aiv_num = case["aivNum"]
    data_type = torch.bfloat16

    # Determine if current rank is on MOE side or Attention side
    is_moe_side = rank < expert_rank_size
    is_attention_side = rank >= expert_rank_size

    # Construct communication domain
    ep_ranks_list = list(np.arange(0, world_size))
    ep_group = dist.new_group(backend="hccl", ranks=ep_ranks_list)
    ep_hcomm_info = ep_group._get_backend(
        torch.device("npu")).get_hccl_comm_name(rank)
    torch_npu.npu.synchronize()
    
    # Construct input data
    # Only Attention side needs real input data
    if is_attention_side:
        # x
        x_data = np.array(gen_x(rank, batch_size, hidden_size))
        x_data = x_data.reshape(batch_size, hidden_size)
        x_tensor = torch.tensor(x_data, dtype=data_type, device='npu')

        # expert_ids
        expert_ids_data = np.array(gen_expert_ids(rank, batch_size, topk, expert_rank_size))
        expert_ids_data = expert_ids_data.reshape(batch_size, topk)
        expert_ids_tensor = torch.tensor(expert_ids_data, dtype=torch.int32, device='npu')

        # scales
        scales_data = np.array(gen_scales(batch_size, topk))
        scales_data = scales_data.reshape(batch_size, topk)
        scales_tensor = torch.tensor(scales_data, dtype=torch.float, device='npu')
    else:  # MOE side
        # MOE side uses empty tensor as placeholder
        x_tensor = torch.empty(0, hidden_size, dtype=data_type, device='npu')
        expert_ids_tensor = torch.empty(0, topk, dtype=torch.int32, device='npu')
        scales_tensor = torch.empty(0, topk, dtype=torch.float, device='npu')

    if mode == "Eager":
        mod = A2E_E2A_Module().npu()
    elif mode == "GE":
        torch_npu.npu.set_compile_mode(jit_compile=True)
        config = CompilerConfig()
        npu_backend = torchair.get_npu_backend(compiler_config=config)
        mod = torch.compile(A2E_E2A_Module().npu(), backend=npu_backend)

    # Execute forward computation
    e2a_output, expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out = mod(
        x=x_tensor,
        expert_ids=expert_ids_tensor,
        scales=scales_tensor,
        batch_size=batch_size,
        hidden_size=hidden_size,
        topk=topk,
        expert_rank_size=expert_rank_size,
        atten_rank_size=atten_rank_size,
        rank=rank,
        group_ep=ep_hcomm_info,
        aiv_num=aiv_num
    )

    torch.npu.synchronize()

    # Validate output based on role
    if is_attention_side:
        # Attention side: Validate E2A output matches input x
        assert e2a_output.shape == x_tensor.shape, f"E2A output shape mismatch: {e2a_output.shape} vs {x_tensor.shape}"
        # Check if the output is close to the input (allowing for small numerical differences)
        assert torch.allclose(e2a_output, x_tensor, atol=1e-3), "E2A output does not match input x"
        
        print(f"Attention Side Rank {rank}: A2E-E2A test passed!")
        print(f"  Input shape: {x_tensor.shape}")
        print(f"  E2A output shape: {e2a_output.shape}")
        print(f"  Input and output are consistent!")
    else:  # MOE side
        # MOE side: Validate A2E output shape
        assert expand_x.shape[1] == hidden_size, f"expand_x shape mismatch: {expand_x.shape}"

        print(f"MOE Side Rank {rank}: A2E-E2A test passed!")
        print(f"  A2E expand_x shape: {expand_x.shape}")
