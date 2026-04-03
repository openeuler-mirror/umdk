#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: A2E and E2A sample code
# Create: 2026-03-02
# Note:
# History: 2026-03-02 create file
#

import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import os
import torch.multiprocessing as mp

# CAM Torch package
import umdk_cam_op_lib

class A2E_E2A_Module(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, x, expert_ids, scales, batch_size, hidden_size, topk, expert_rank_size, atten_rank_size, rank, group_ep, aiv_num):
        # Determine if current rank is on MOE side or Attention side
        is_moe_side = rank < expert_rank_size
        is_attention_side = rank >= expert_rank_size
        
        # Execute different logic based on role
        if is_attention_side:
            # Attention side: Call A2E (Attention to Expert) to send data to MOE side
            a2e_output = torch.ops.umdk_cam_op_lib.a2e(
                x=x,                    # Input tensor [batch_size, hidden_size]
                expert_ids=expert_ids,     # Expert indices [batch_size, topk]
                scales=scales,           # Scaling factors [batch_size, topk]
                batch_size=batch_size,     # Batch size
                hidden_size=hidden_size,   # Hidden layer size
                topk=topk,              # Number of experts per token
                expert_rank_size=expert_rank_size,  # Number of expert ranks
                atten_rank_size=atten_rank_size,  # Number of attention ranks
                rank=rank,              # Current rank ID
                group_ep=group_ep,        # Communication group information
                aiv_num=aiv_num,           # AIV number
                compute_gate=1              # Compute gate flag
            )
            
            # Parse A2E output
            expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out = a2e_output
            
            # A2E output:
            # expand_x: Expanded input tensor for expert layer
            # simulate_expert_ids: Simulated expert indices
            # simulate_expert_scales: Simulated expert scaling factors
            # atten_batch_size: Attention batch size
            # x_active_mask_out: Active mask
            
            # Attention side: Call E2A (Expert to Attention) to receive data from MOE side
            e2a_output = torch.ops.umdk_cam_op_lib.e2a(
                expand_x=x,      # Original input tensor
                atten_batch_size=atten_batch_size,  # A2E output, attention batch size
                batch_size=batch_size,     # Batch size
                hidden_size=hidden_size,   # Hidden layer size
                topk=topk,              # Number of experts per token
                expert_rank_size=expert_rank_size,  # Number of expert ranks
                attention_rank_size=atten_rank_size,  # Number of attention ranks
                rank=rank,              # Current rank ID
                group_ep=group_ep,        # Communication group information
                aiv_num=aiv_num           # AIV number
            )
            
            # E2A output: Transformed output tensor with shape [batch_size, hidden_size]
            
            return e2a_output, expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out
        else:  # MOE side
            # MOE side: Use empty tensor as placeholder, will actually receive data from Attention side
            dummy_x = torch.empty(0, hidden_size, dtype=x.dtype, device=x.device)
            dummy_expert_ids = torch.empty(0, topk, dtype=torch.int32, device=x.device)
            dummy_scales = torch.empty(0, topk, dtype=torch.float, device=x.device)
            
            # A2E: Receive data from Attention side
            a2e_output = torch.ops.umdk_cam_op_lib.a2e(
                x=dummy_x,              # Empty tensor as placeholder
                expert_ids=dummy_expert_ids,  # Empty tensor as placeholder
                scales=dummy_scales,     # Empty tensor as placeholder
                batch_size=batch_size,     # Batch size
                hidden_size=hidden_size,   # Hidden layer size
                topk=topk,              # Number of experts per token
                expert_rank_size=expert_rank_size,  # Number of expert ranks
                atten_rank_size=atten_rank_size,  # Number of attention ranks
                rank=rank,              # Current rank ID
                group_ep=group_ep,        # Communication group information
                aiv_num=aiv_num,           # AIV number
                compute_gate=1              # Compute gate flag
            )
            
            # Parse A2E output
            expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out = a2e_output
            
            # MOE side: Call E2A to send data to Attention side
            e2a_output = torch.ops.umdk_cam_op_lib.e2a(
                expand_x=expand_x,      # A2E output, expanded input
                atten_batch_size=atten_batch_size,  # A2E output, attention batch size
                batch_size=batch_size,     # Batch size
                hidden_size=hidden_size,   # Hidden layer size
                topk=topk,              # Number of experts per token
                expert_rank_size=expert_rank_size,  # Number of expert ranks
                attention_rank_size=atten_rank_size,  # Number of attention ranks
                rank=rank,              # Current rank ID
                group_ep=group_ep,        # Communication group information
                aiv_num=aiv_num           # AIV number
            )
            
            return e2a_output, expand_x, simulate_expert_ids, simulate_expert_scales, atten_batch_size, x_active_mask_out

def gen_x(rank, batch_size, hidden_size):
    """Generate input tensor data"""
    arr = [rank * batch_size + i + 1 for i in range(batch_size) for j in range(hidden_size)]
    return arr

def gen_expert_ids(rank, batch_size, topk, expert_rank_size):
    """Generate expert indices data"""
    arr = [0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = (rank + i + j) % expert_rank_size
    return arr

def gen_scales(batch_size, topk):
    """Generate scaling factors data"""
    arr = [0.0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = 1.0 / topk
    return arr

def run_once(local_rank_id, ep_world_size):
    """Single run test function"""
    os.environ["MASTER_ADDR"] = "127.0.0.1"
    os.environ["MASTER_PORT"] = "29600"
    rank = local_rank_id
    world_size = ep_world_size

    # Set device
    torch.npu.set_device(rank)
    dist.init_process_group(backend="hccl", rank=rank, world_size=world_size)

    # Test parameters
    batch_size = 16
    hidden_size = 512
    topk = 2
    expert_rank_size = 8  # 8 ranks for MOE side
    atten_rank_size = 8   # 8 ranks for Attention side
    aiv_num = 4
    data_type = torch.bfloat16

    # Determine if current rank is on MOE side or Attention side
    is_moe_side = rank < expert_rank_size
    is_attention_side = rank >= expert_rank_size

    # Construct communication domain
    ep_ranks_list = list(range(0, world_size))
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

    # Create model
    mod = A2E_E2A_Module().npu()

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

    # Print results based on role
    if is_attention_side:
        # Attention side
        print(f"Attention Side Rank {rank}: A2E-E2A sample run completed!")
        print(f"  Input shape: {x_tensor.shape}")
        print(f"  E2A output shape: {e2a_output.shape}")
        
        # Validate output: Compare input x with E2A output
        assert e2a_output.shape == x_tensor.shape, f"E2A output shape mismatch: {e2a_output.shape} vs {x_tensor.shape}"
        # Check if the output is close to the input (allowing for small numerical differences)
        assert torch.allclose(e2a_output, x_tensor, atol=1e-3), "E2A output does not match input x"
        print(f"  Input and output are consistent!")
    else:  # MOE side
        # MOE side
        print(f"MOE Side Rank {rank}: A2E-E2A sample run completed!")
        print(f"  A2E expand_x shape: {expand_x.shape}")
        print(f"  A2E simulate_expert_ids shape: {simulate_expert_ids.shape}")
        print(f"  A2E simulate_expert_scales shape: {simulate_expert_scales.shape}")
        print(f"  A2E atten_batch_size shape: {atten_batch_size.shape}")
        print(f"  A2E x_active_mask_out shape: {x_active_mask_out.shape}")

    # Cleanup
    dist.destroy_process_group()

if __name__ == "__main__":
    """Main function"""
    # Test configuration
    ep_world_size = 16
    
    print("A2E-E2A sample started!")
    print(f"Running with {ep_world_size} ranks")
    
    # Run with multiple processes
    mp.spawn(run_once, args=(ep_world_size,), nprocs=ep_world_size, join=True)
    
    print("A2E-E2A sample completed successfully!")
