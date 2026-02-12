#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for dispatch/combine normal a2 operator
# Create: 2026-02-11
# Note:
# History: 2026-02-11 create dispatch/combine normal a2 example
#
import argparse
import time

# noinspection PyUnresolvedReferences
import numpy as np
import torch
import torch.distributed as dist
import torch_npu
import umdk_cam_op_lib
from utils import (
    bench,
    bench_kineto,
    calc_diff,
    diagnose_matrix,
    init_dist,
    inplace_unique,
    per_token_cast_back,
)

MAX_BATCH_SIZE = 4096
enable_a2_test = True


# noinspection PyShadowingNames
def test_main(
    args: argparse.Namespace,
    num_local_ranks: int,
    local_rank: int,
    num_ranks: int,
    rank: int,
    group: dist.ProcessGroup,
):
    # Settings
    num_tokens, hidden = args.num_tokens, args.hidden
    num_topk, num_experts = args.num_topk, args.num_experts
    num_servers = num_ranks // num_local_ranks
    num_nodes = num_servers

    print(f"{rank=}, {num_experts=}, {num_ranks=}, {num_nodes=}")
    assert num_experts % num_ranks == 0 and num_nodes >= 1
    assert num_tokens <= MAX_BATCH_SIZE
    if local_rank == 0:
        print(
            f"num_tokens={num_tokens}, hidden={hidden}, num_topk={num_topk}, active_ranks={args.active_ranks}",
            flush=True,
        )

    experts_per_rank = num_experts // num_ranks

    if args.active_ranks:
        # Only assign tokens to the specified ranks
        try:
            active_ranks = [
                int(r.strip()) for r in args.active_ranks.split(",") if r.strip()
            ]
        except ValueError:
            raise ValueError(
                f"Invalid value in --active-ranks: {args.active_ranks}. "
                f"Must be a comma-separated list of integers, e.g., '0,1,3'."
            )

        # Validate range
        if any(r < 0 or r >= num_ranks for r in active_ranks):
            raise ValueError(
                f"Invalid rank in --active-ranks: {active_ranks}. "
                f"Ranks must be in range [0, {num_ranks-1}]."
            )

        if not active_ranks:
            raise ValueError(
                "Parsed --active-ranks is empty. Provide at least one valid rank."
            )

        valid_experts = torch.cat(
            [
                torch.arange(
                    r * experts_per_rank, (r + 1) * experts_per_rank, device="npu"
                )
                for r in active_ranks
            ]
        )
        # Randomly sample experts from active ranks only
        topk_idx = valid_experts[
            torch.randint(0, len(valid_experts), (num_tokens, num_topk), device="npu")
        ]
    else:
        # Default: random over all experts (original behavior)
        scores = (
            torch.randn(
                (num_tokens, num_experts), dtype=torch.float32, device="npu"
            ).abs()
            + 1
        )
        topk_idx = torch.topk(scores, num_topk, dim=-1, largest=True, sorted=True)[1]

    rank_idx = topk_idx // (num_experts // num_ranks)
    rank_idx.masked_fill_(topk_idx == -1, -1)
    inplace_unique(rank_idx, num_ranks)

    rdma_rank_idx = rank_idx // num_local_ranks
    rdma_rank_idx.masked_fill_(rank_idx == -1, -1)
    inplace_unique(rdma_rank_idx, num_nodes)

    # RDMA dispatch counts
    rdma_idx = topk_idx // (num_experts // num_nodes)
    rdma_idx.masked_fill_(topk_idx == -1, -1)
    inplace_unique(rdma_idx, num_nodes)
    num_rdma_token_sent = rdma_idx.ne(-1).sum().item()

    # Expert meta
    num_tokens_per_expert = torch.zeros((num_experts,), dtype=torch.int, device="npu")
    for i in range(num_experts):
        num_tokens_per_expert[i] = (topk_idx == i).sum()
    gbl_num_tokens_per_expert = num_tokens_per_expert.clone()
    dist.all_reduce(gbl_num_tokens_per_expert, group=group)

    def check_layout_a2_data(notify_send_data):
        # cpu calc data
        count_num_expert = [0] * num_experts
        num_tokens_per_server_uniq = torch.zeros(
            (num_servers,), dtype=torch.int, device="npu"
        )
        num_each_token_to_server = torch.zeros(
            (num_tokens * num_servers,), dtype=torch.int, device="npu"
        )
        each_token_to_num_server = torch.zeros(
            (num_tokens,), dtype=torch.int, device="npu"
        )
        each_token_offset_to_server = torch.zeros(
            (num_tokens * num_servers,), dtype=torch.int, device="npu"
        )
        send_token_idx = torch.zeros(
            (num_tokens * num_experts,), dtype=torch.int, device="npu"
        )
        expert_rank_token_idx = torch.zeros(
            (num_experts * MAX_BATCH_SIZE,), dtype=torch.int, device="npu"
        )

        for i in range(num_tokens):
            seen_server = [0] * num_servers
            for j in range(num_topk):
                expert_id = topk_idx[i][j]
                rank_id = expert_id // experts_per_rank
                server_id = rank_id // num_local_ranks
                if seen_server[server_id] == 0:
                    num_tokens_per_server_uniq[server_id] += 1
                    each_token_offset_to_server[i * num_servers + server_id] = (
                        num_tokens_per_server_uniq[server_id]
                    )
                    each_token_to_num_server[i] += 1
                    seen_server[server_id] += 1
                num_each_token_to_server[i * num_servers + server_id] += 1
                count_num_expert[expert_id] += 1
                send_token_idx[i * num_experts + expert_id] = count_num_expert[
                    expert_id
                ]

        count_num_expert = [0] * num_experts
        for i in range(num_tokens):
            for j in range(num_topk):
                expert_id = topk_idx[i][j]
                rank_id = expert_id // experts_per_rank
                server_id = rank_id // num_local_ranks
                expert_rank_token_idx[
                    expert_id * MAX_BATCH_SIZE + count_num_expert[expert_id]
                ] = each_token_offset_to_server[i * num_servers + server_id]
                count_num_expert[expert_id] += 1

        # layout output data
        ref_num_tokens_per_server_uniq = notify_send_data[
            num_experts : num_experts + num_servers
        ]
        ref_num_each_token_to_server = notify_send_data[
            num_experts + num_servers : num_experts + num_servers * (1 + num_tokens)
        ]
        ref_each_token_to_num_server = notify_send_data[
            num_experts
            + num_servers * (1 + MAX_BATCH_SIZE) : num_experts
            + num_servers
            + MAX_BATCH_SIZE * num_servers
            + num_tokens
        ]
        ref_each_token_offset_to_server = notify_send_data[
            num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers + 1) : num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers + 1)
            + num_servers * num_tokens
        ]
        ref_send_token_idx = notify_send_data[
            num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers * 2 + 1) : num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers * 2 + 1)
            + num_tokens * num_experts
        ]
        ref_expert_rank_token_idx = notify_send_data[
            num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers * 2 + num_experts + 1) : num_experts
            + num_servers
            + MAX_BATCH_SIZE * (num_servers * 2 + num_experts + num_experts + 1)
        ]

        # check data
        try:
            assert torch.allclose(
                num_tokens_per_expert, notify_send_data[:num_experts]
            ), f"Assertion num_tokens_per_rank failed on rank {rank}: Expected {ref_num_tokens_per_expert}, Actual {notify_send_data[:num_experts]}"
            assert torch.allclose(
                num_tokens_per_server_uniq, ref_num_tokens_per_server_uniq
            ), f"Assertion num_tokens_per_server_uniq failed on rank {rank}: Expected {num_tokens_per_server_uniq}, Actual {ref_num_tokens_per_server_uniq}"
            assert torch.allclose(
                num_each_token_to_server, ref_num_each_token_to_server
            ), f"Assertion num_each_token_to_server failed on rank {rank}: Expected {num_each_token_to_server}, Actual {ref_num_each_token_to_server}"
            assert torch.allclose(
                each_token_to_num_server, ref_each_token_to_num_server
            ), f"Assertion each_token_to_num_server failed on rank {rank}: Expected {each_token_to_num_server}, Actual {ref_each_token_to_num_server}"
            assert torch.allclose(
                each_token_offset_to_server, ref_each_token_offset_to_server
            ), f"Assertion each_token_offset_to_server failed on rank {rank}: Expected {each_token_offset_to_server}, Actual {ref_each_token_offset_to_server}"
            assert torch.allclose(
                send_token_idx, ref_send_token_idx
            ), f"Assertion send_token_idx failed on rank {rank}: Expected {send_token_idx}, Actual {ref_send_token_idx}"
            assert torch.allclose(
                expert_rank_token_idx, ref_expert_rank_token_idx
            ), f"Assertion expert_rank_token_idx failed on rank {rank}: Expected {expert_rank_token_idx}, Actual {ref_expert_rank_token_idx}"
        except AssertionError as e:
            raise

    # Rank layout meta
    num_tokens_per_rank = torch.empty((num_ranks,), dtype=torch.int, device="npu")
    num_tokens_per_rdma_rank = torch.empty((num_nodes,), dtype=torch.int, device="npu")
    token_idx_in_rank = torch.full(
        (num_ranks, num_tokens), -1, dtype=torch.long, device="npu"
    )
    for i in range(num_ranks):
        num_tokens_per_rank[i] = (rank_idx == i).sum()
        token_sel = (rank_idx == i).max(dim=-1)[0]
        count = token_sel.sum().item()
        tokens = torch.sort(token_sel.to(torch.int), descending=True)[1]
        tokens[:count] = torch.sort(tokens[:count])[0]
        token_idx_in_rank[i][tokens[:count]] = torch.arange(
            count, dtype=torch.long, device="npu"
        )
    for i in range(num_nodes):
        num_tokens_per_rdma_rank[i] = (rdma_rank_idx == i).sum()
    token_idx_in_rank = token_idx_in_rank.T.contiguous().to(torch.int)
    is_token_in_rank = (token_idx_in_rank >= 0).to(torch.int)
    gbl_num_tokens_per_rank = num_tokens_per_rank.clone()
    dist.all_reduce(gbl_num_tokens_per_rank, group=group)

    time.sleep(1)

    try:
        try:
            return_values = torch.ops.umdk_cam_op_lib.get_dispatch_layout_a2(topk_idx, num_experts, num_ranks)
        except Exception as e:
            print(f"Error occurred while calling get_dispatch_layout: {e}")
            raise

        (
            ref_num_tokens_per_expert,
            ref_notify_send_data,
        ) = return_values
        try:
            assert torch.allclose(
                ref_num_tokens_per_expert, num_tokens_per_expert
            ), f"Assertion num_tokens_per_expert failed on rank {rank}: Expected {num_tokens_per_expert}, Actual {ref_num_tokens_per_expert}"
            if enable_a2_test:
                check_layout_a2_data(ref_notify_send_data)
        except AssertionError as e:
            print(e)
            raise
        print(f"#DBG0120 check layout passed {ref_num_tokens_per_expert=}, {ref_notify_send_data=}", flush=True)
    except Exception as e:
        print(f"An error occurred: {e}")

    # Config
    buffer_size = 256
    ep_hcomm_info = group._get_backend(torch.device("npu")).get_hccl_comm_name(rank)
    
    ep_hcomm_info = ep_hcomm_info.encode('utf-8')
    print(f"{rank=}, {ep_hcomm_info=}", flush=True)
    # Random data
    x = torch.ones((num_tokens, hidden), dtype=torch.bfloat16, device="npu") * rank
    x_pure_rand = torch.randn((num_tokens, hidden), dtype=torch.bfloat16, device="npu")
    topk_weights = (
        torch.ones((num_tokens, num_topk), dtype=torch.float32, device="npu") * rank
    )
    topk_weights_pure_rand = torch.randn(
        (num_tokens, num_topk), dtype=torch.float32, device="npu"
    )
    use_quant = False
    for current_x in filter(lambda elem: elem is not None, (x, x_pure_rand, )):
        if local_rank == 0:
            print(
                f'[testing] Running with {"FP8" if isinstance(current_x, tuple) else "BF16"}, with top-k {num_topk} ...',
                flush=True,
            )
    
        dispatch_args = {
                "x": current_x,
                "topk_idx": topk_idx,
                "topk_weights": (
                    topk_weights_pure_rand if current_x is x_pure_rand else topk_weights
                ),
                "num_tokens_per_expert": num_tokens_per_expert,
                "notify_send_data": ref_notify_send_data,
                "group_ep": ep_hcomm_info,
                "rank": rank,
                "num_ranks": num_ranks,
                "use_quant": use_quant
            }

        test_comm_arg = dispatch_args["group_ep"]

        print(f"{rank=}, {dispatch_args}", flush=True)
        for i, t in dispatch_args.items():
            if isinstance(t, torch.Tensor):
                print(f"{rank=}, {i} : shape={t.shape}, contiguous={t.is_contiguous()}, "
                        f"device={t.device}, dtype={t.dtype}", flush=True)
            else:
                print(f"{rank=}, {i} : {t=}", flush=True)
        (
            recv_x,
            dynamic_scales_out,
            expand_idx_out,
            recv_count,
            offset_inner,
            offset_outer,
            count_outer,
            expand_scales,
        ) = torch.ops.umdk_cam_op_lib.moe_dispatch_prefill_a2(**dispatch_args)
        recv_x = per_token_cast_back(recv_x, dynamic_scales_out) if use_quant else recv_x

    torch.npu.synchronize()
    print("after call deepep dispatch, result is:", recv_x[0], flush = True)

    def test_correctness():
        for current_x in filter(lambda elem: elem is not None, (x_pure_rand, x)):
            if local_rank == 0:
                print(
                    f'[testing] Running with {"FP8" if isinstance(current_x, tuple) else "BF16"}, with top-k {num_topk} ...',
                    flush=True,
                )
           
            dispatch_args = {
                "x": current_x,
                "topk_idx": topk_idx,
                "topk_weights": (
                    topk_weights_pure_rand if current_x is x_pure_rand else topk_weights
                ),
                "num_tokens_per_expert": num_tokens_per_expert,
                "notify_send_data": ref_notify_send_data,
                "group_ep": ep_hcomm_info,
                "rank": rank,
                "num_ranks": num_ranks,
                "use_quant": use_quant
            }

            test_comm_arg = dispatch_args["group_ep"]
            print(f"before call dispatch, {rank=}, {test_comm_arg=}", flush=True)
            (
                recv_x,
                dynamic_scales_out,
                expand_idx_out,
                recv_count,
                offset_inner,
                offset_outer,
                count_outer,
                expand_scales,
            ) = torch.ops.umdk_cam_op_lib.moe_dispatch_prefill_a2(**dispatch_args)
            recv_x = per_token_cast_back(recv_x, dynamic_scales_out) if use_quant else recv_x

            # Test combine
            combine_args = {
                "x": recv_x,
                "topk_idx": topk_idx,
                "topk_weights": (
                    topk_weights_pure_rand if current_x is x_pure_rand else topk_weights
                ),
                "src_idx": expand_idx_out,
                "send_head": recv_count,
                "expand_scales": expand_scales,
                "offset_inner": offset_inner,
                "offset_outer": offset_outer,
                "count_outer": count_outer,
                "group_ep": ep_hcomm_info,
                "rank": rank,
                "num_ranks": num_ranks,
            }
            combined_x = torch.ops.umdk_cam_op_lib.moe_combine_prefill_a2(**combine_args)
            check_x = combined_x.float()
            ref_x = x_pure_rand if current_x is x_pure_rand else x

            if current_x is x_pure_rand:
                golden = ref_x * topk_weights_pure_rand.masked_fill(topk_idx == -1, 0).sum(dim=1).view(-1, 1)
            else:
                golden = ref_x * topk_weights.masked_fill(topk_idx == -1, 0).sum(dim=1).view(-1, 1)

            print(f"{rank=}, {check_x=}, {golden=}", flush=True)
            assert (
                calc_diff(
                    check_x,
                    golden
                )
                < 5e-5
            )

            if local_rank == 0:
                print(" passed", flush=True)
        print(f"{rank=} finished correct check")
        if local_rank == 0:
            print("", flush=True)

    torch.npu.synchronize()
    dist.barrier()
    time.sleep(1)
    
    test_correctness()

import os
import sys
import time

split_log = False

def redirect_output(logfile_path):
    f = open(logfile_path, "w")
    os.dup2(f.fileno(), sys.stdout.fileno())
    os.dup2(f.fileno(), sys.stderr.fileno())
    return f


def test_loop(local_rank: int, num_local_ranks: int, args: argparse.Namespace):
    rank, num_ranks, group = init_dist(local_rank, num_local_ranks)

    if split_log:
        directory= "logs"
        if not os.path.exists(directory):
            os.makedirs(directory)  # Create the directory
            print(f"Directory '{directory}' created.")
        else:
            print(f"Directory '{directory}' already exists.", flush=True)
            log_file = redirect_output(f"{directory}/log_rank{rank}.out")

    torch.manual_seed(rank)
    print(f"{rank=} start", flush=True)
    test_main(args, num_local_ranks, local_rank, num_ranks, rank, group)
    if local_rank == 0:
        print("", flush=True)

    dist.barrier()
    dist.destroy_process_group()
    if split_log:
        log_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test intranode EP kernels")
    parser.add_argument(
        "--num-processes",
        type=int,
        default=8,
        help="Number of processes to spawn (default: 8)",
    )
    parser.add_argument(
        "--num-tokens", type=int, default=1024, help="Number of tokens (default: 1024)"
    )
    parser.add_argument(
        "--hidden", type=int, default=7168, help="Hidden dimension size (default: 7168)"
    )
    parser.add_argument(
        "--num-topk", type=int, default=8, help="Number of top-k experts (default: 8)"
    )
    parser.add_argument(
        "--num-experts", type=int, default=16, help="Number of experts (default: 16)"
    )
    parser.add_argument(
        "--active-ranks",
        type=str,
        default="",
        help="Comma-separated list of ranks that will receive tokens. "
        'Example: "0,1,3". If empty, all ranks may receive tokens.',
    )
    parser.add_argument(
        "--enable-diagnose",
        action="store_true",
        help="Whether to enable diagnose for testing",
    )
    args = parser.parse_args()

    num_processes = args.num_processes
    torch.multiprocessing.spawn(
        test_loop, args=(num_processes, args), nprocs=num_processes
    )
