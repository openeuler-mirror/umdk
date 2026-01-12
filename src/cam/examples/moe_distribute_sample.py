import argparse
import time

# noinspection PyUnresolvedReferences
import torch
import torch.distributed as dist
import torch_npu
import umdk_cam_op_lib
from utils import (
    bench,
    calc_diff,
    init_dist,
    inplace_unique,
    per_token_cast_back,
)

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

    assert num_experts % num_ranks == 0
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
        topk_idx = torch.topk(scores, num_topk, dim=-1, largest=True, sorted=False)[1]

    rank_idx = topk_idx // experts_per_rank
    rank_idx.masked_fill_(topk_idx == -1, -1)
    inplace_unique(rank_idx, num_ranks)

    # Expert meta
    num_tokens_per_expert = torch.zeros((num_experts,), dtype=torch.int, device="npu")
    for i in range(num_experts):
        num_tokens_per_expert[i] = (topk_idx == i).sum()
    gbl_num_tokens_per_expert = num_tokens_per_expert.clone()
    dist.all_reduce(gbl_num_tokens_per_expert, group=group)

    # Rank layout meta
    num_tokens_per_rank = torch.empty((num_ranks,), dtype=torch.int, device="npu")
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
    token_idx_in_rank = token_idx_in_rank.T.contiguous().to(torch.int)
    is_token_in_rank = (token_idx_in_rank >= 0).to(torch.int)
    gbl_num_tokens_per_rank = num_tokens_per_rank.clone()
    dist.all_reduce(gbl_num_tokens_per_rank, group=group)

    t = bench(lambda: torch.ops.umdk_cam_op_lib.get_dispatch_layout(topk_idx, num_experts, num_ranks))[0]
    if local_rank == 0:
        print(f"[layout] Kernel performance: {t * 1000:.3f} ms", flush=True)
        print("", flush=True)
    dist.barrier()
    time.sleep(1)

    try:
        return_values = torch.ops.umdk_cam_op_lib.get_dispatch_layout(topk_idx, num_experts, num_ranks)
        (
            ref_num_tokens_per_expert,
            ref_send_token_idx_small,
        ) = return_values
    except Exception as e:
        print(f"An error occurred: {e}")

    # Config
    buffer_size = 256
    ep_hcomm_info = group._get_backend(torch.device("npu")).get_hccl_comm_name(rank)
    ep_hcomm_info = ep_hcomm_info.encode('utf-8')

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

    # Test dispatch

    dispatch_args = {
        "x": x,
        "topk_idx": topk_idx,
        "topk_weights": topk_weights,
        "num_tokens_per_expert": num_tokens_per_expert,
        "send_token_idx_small": ref_send_token_idx_small,
        "group_ep": ep_hcomm_info,
        "rank": rank,
        "num_ranks": num_ranks,
        "use_quant": use_quant,
    }

    (
        recv_x,
        dynamic_scales_out,
        expand_idx_out,
        recv_count,
        recv_tokens_per_expert,
    ) = torch.ops.umdk_cam_op_lib.moe_dispatch_prefill(**dispatch_args)
    recv_x = per_token_cast_back(recv_x, dynamic_scales_out) if use_quant else recv_x

    # Test combine
    combine_args = {
        "x": recv_x,
        "topk_idx": topk_idx,
        "topk_weights": topk_weights,
        "src_idx": expand_idx_out,
        "send_head": recv_count,
        "group_ep": ep_hcomm_info,
        "rank": rank,
        "num_ranks": num_ranks,
    }
    combined_x = torch.ops.umdk_cam_op_lib.moe_combine_prefill(**combine_args)
    check_x = combined_x.float()
    ref_x = x
    assert (
        calc_diff(
            check_x,
            ref_x * topk_weights.masked_fill(topk_idx == -1, 0).sum(dim=1).view(-1, 1),
        )
        < 5e-5
    )
    if local_rank == 0:
        print(" passed", flush=True)
    if local_rank == 0:
        print("", flush=True)

    # Tune dispatch & combine performance
    fp8_factor = (1 + 4 / 128) / 2
    recv_bytes = recv_x.numel() * 2
    combine_bf16_send_bytes = recv_bytes
    recv_bytes = recv_bytes * fp8_factor if use_quant else recv_bytes

    t = bench(lambda: torch.ops.umdk_cam_op_lib.moe_dispatch_prefill(**dispatch_args))[0]
    if local_rank == 0:
        print(
            f'[tuning] Dispatch ({"FP8" if use_quant else "BF16"}) {recv_bytes / 1e9 / t:.2f} GB/s (HCCS), avg_t: {t * 1e6:.2f} us',
            flush=True,
        )
        print("", flush=True)
    t = bench(lambda: torch.ops.umdk_cam_op_lib.moe_combine_prefill(**combine_args))[0]
    if local_rank == 0:
        print(
            f"[tuning] Combine {combine_bf16_send_bytes / 1e9 / t:.2f} GB/s (HCCS), avg_t: {t * 1e6:.2f} us",
            flush=True,
        )
        print("", flush=True)

# noinspection PyUnboundLocalVariable,PyShadowingNames
def test_loop(local_rank: int, num_local_ranks: int, args: argparse.Namespace):
    rank, num_ranks, group = init_dist(local_rank, num_local_ranks)

    print(f"[Rank {rank} | Local rank {local_rank}] Initializing buffer...", flush=True)
    torch.manual_seed(rank)

    test_main(args, num_local_ranks, local_rank, num_ranks, rank, group)
    if local_rank == 0:
        print("", flush=True)

    dist.barrier()
    dist.destroy_process_group()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test intranode EP kernels")
    parser.add_argument(
        "--num-processes",
        type=int,
        default=16,
        help="Number of processes to spawn (default: 16)",
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