#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for ZB normal layout/dispatch/combine via ZbBuffer.
#
#   torchrun --nproc_per_node=8 src/cam/examples/moe_dispatch_combine_prefill_zb_sample.py
#
# Env: SHMEM_IP_PORT, SHMEM_MEM_SIZE, ZB_QUANT_MODE, ZB_DTYPE, ZB_EXPERTS_PER_RANK,
#      ZB_TOPK, ZB_BATCH_SIZE / ZB_BATCH_SIZE_LIST / ZB_BATCH_SIZE_MIN|MAX,
#      ZB_HIDDEN_SIZE, ZB_RANDOM_TOPK, ZB_BENCH_ITERS
#

import os
import random
import time

import numpy as np
import torch
import torch.distributed as dist
import torch_npu
import umdk_cam_op_lib


def _count_unequal_element(data_expect, data_check, rtol, atol, msg=""):
    assert data_expect.shape == data_check.shape
    total_count = len(data_expect.flatten())
    error = np.abs(data_expect - data_check)
    greater = np.greater(error, atol + np.abs(data_check) * rtol)
    loss_count = np.count_nonzero(greater)
    assert (loss_count / total_count) < rtol, (
        "\nmsg{0}_data_expect_std:{1}\ndata_check_error:{2}\nloss:{3}".format(
            msg, data_expect[greater], data_check[greater], error[greater]
        )
    )


def allclose_nparray(data_expect, data_check, rtol=1e-4, atol=1e-4, equal_nan=True, msg=""):
    if np.any(np.isnan(data_expect)):
        assert np.allclose(data_expect, data_check, rtol, atol, equal_nan=equal_nan)
    elif not np.allclose(data_expect, data_check, rtol, atol, equal_nan=equal_nan):
        _count_unequal_element(data_expect, data_check, rtol, atol, msg)


def gen_x(rank, batch_size, hidden_size):
    return [rank * batch_size + i + 11 for i in range(batch_size) for _ in range(hidden_size)]


def gen_expert_ids(rank, batch_size, topk, moe_expert_num):
    arr = [0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = (rank + i + j) % moe_expert_num
    return arr


def gen_expert_ids_random(batch_size, topk, moe_expert_num, device):
    scores = torch.rand((batch_size, moe_expert_num), dtype=torch.float32, device=device)
    _, topk_idx = torch.topk(scores, topk, dim=-1, largest=True, sorted=False)
    return topk_idx.to(torch.int32)


def gen_scales(batch_size, topk):
    arr = [0.0] * (batch_size * topk)
    for i in range(batch_size):
        sum_val = 0.0
        for j in range(topk):
            distribution = random.uniform(1, 10)
            arr[i * topk + j] = distribution
            sum_val += distribution
        for j in range(topk):
            arr[i * topk + j] /= sum_val
    return arr


def estimate_zb_shmem_bytes(
    max_tokens_per_rank: int,
    ep_world_size: int,
    topk: int,
    moe_expert_num: int,
    hidden: int,
    use_quant: bool,
):
    """Worst-case ZbBuffer SHMEM bytes: rows = max_bs*EP*min(topk, local_experts)."""
    if ep_world_size <= 0 or moe_expert_num % ep_world_size != 0:
        raise ValueError("invalid ep_world_size / moe_expert_num")
    local_experts = moe_expert_num // ep_world_size
    global_bs = max_tokens_per_rank * ep_world_size
    rows = global_bs * min(topk, local_experts)
    combine_bytes = rows * hidden * 2
    scales_bytes = rows * 4 if use_quant else 0
    meta_bytes = 2 * 1024 * 1024
    notify_bytes = ep_world_size * moe_expert_num * 4 + moe_expert_num * 4
    payload = combine_bytes + scales_bytes + meta_bytes + notify_bytes
    recommend = payload + 64 * 1024 * 1024
    return {
        "local_experts": local_experts,
        "global_bs": global_bs,
        "rows": rows,
        "combine_bytes": combine_bytes,
        "scales_bytes": scales_bytes,
        "payload_bytes": payload,
        "recommend_bytes": recommend,
    }


def _resolve_local_batch_size(rank, world_size, default_bs):
    """Per-rank token count: LIST > ZB_BATCH_SIZE > random [MIN, MAX]."""
    list_env = os.environ.get("ZB_BATCH_SIZE_LIST", "").strip()
    if list_env:
        parts = [p.strip() for p in list_env.split(",") if p.strip()]
        assert len(parts) == world_size, (
            f"ZB_BATCH_SIZE_LIST has {len(parts)} entries but world_size={world_size}: {list_env}"
        )
        bs = int(parts[rank])
        assert bs > 0, f"ZB_BATCH_SIZE_LIST[{rank}] must be > 0, got {bs}"
        return bs
    if "ZB_BATCH_SIZE" in os.environ:
        return int(os.environ["ZB_BATCH_SIZE"])
    bs_min = int(os.environ.get("ZB_BATCH_SIZE_MIN", "1"))
    bs_max = int(os.environ.get("ZB_BATCH_SIZE_MAX", str(max(default_bs, 1))))
    if bs_min > bs_max:
        raise ValueError(f"ZB_BATCH_SIZE_MIN={bs_min} > ZB_BATCH_SIZE_MAX={bs_max}")
    rng = random.Random(10007 + rank * 97 + int(os.environ.get("ZB_INPUT_SEED", "0")))
    return rng.randint(bs_min, bs_max)


def _allreduce_max_int(value, device):
    t = torch.tensor([int(value)], dtype=torch.int32, device=device)
    dist.all_reduce(t, op=dist.ReduceOp.MAX)
    return int(t.item())


def _dequant_identity(recv_x_i8, scales, data_type):
    """Host-side dequant (identity expert). combine() copies into SHMEM slot."""
    return (recv_x_i8.to(torch.float32) * scales.unsqueeze(1)).to(data_type)


CASE_8RANK = {
    "moe_expert_num": 32,
    "topk": 4,
    "batch_size": 1024,
    "hidden_size": 7168,
    "quant_mode": 0,
}

CASE_16RANK = {
    "moe_expert_num": 256,
    "topk": 8,
    "batch_size": 4096,
    "hidden_size": 7168,
    "quant_mode": 0,
}


def test_base_test(local_rank_id, ep_world_size):
    rank = local_rank_id
    world_size = ep_world_size

    case = CASE_8RANK if world_size <= 8 else CASE_16RANK
    if world_size not in (8, 16):
        case = {
            "moe_expert_num": world_size,
            "topk": min(4, world_size),
            "batch_size": 32,
            "hidden_size": 7168,
            "quant_mode": 0,
        }

    moe_expert_num = case["moe_expert_num"]
    topk = case["topk"]
    hidden_size = case["hidden_size"]
    default_bs = case["batch_size"]
    quant_mode = int(os.environ.get("ZB_QUANT_MODE", str(case["quant_mode"])))

    if "ZB_EXPERTS_PER_RANK" in os.environ:
        experts_per_rank = int(os.environ["ZB_EXPERTS_PER_RANK"])
        assert experts_per_rank > 0, "ZB_EXPERTS_PER_RANK must be > 0"
        moe_expert_num = experts_per_rank * world_size
    if "ZB_TOPK" in os.environ:
        topk = int(os.environ["ZB_TOPK"])
    if "ZB_HIDDEN_SIZE" in os.environ:
        hidden_size = int(os.environ["ZB_HIDDEN_SIZE"])

    dtype_name = os.environ.get("ZB_DTYPE", "bfloat16").lower()
    dtype_map = {
        "bfloat16": torch.bfloat16,
        "bf16": torch.bfloat16,
        "float16": torch.float16,
        "fp16": torch.float16,
        "half": torch.float16,
    }
    assert dtype_name in dtype_map, f"unsupported ZB_DTYPE={dtype_name}, expect bfloat16|float16"
    data_type = dtype_map[dtype_name]
    use_quant = quant_mode == 2
    use_random_topk = int(os.environ.get("ZB_RANDOM_TOPK", "1")) == 1

    assert moe_expert_num % world_size == 0, "moe_expert_num must be divisible by ep_world_size"
    assert world_size >= 2, "ep_world_size must be >= 2 for ZB normal ops"
    assert quant_mode in (0, 2), f"unsupported quant_mode={quant_mode}"
    assert 0 < topk <= 16, f"topk should be in (0, 16], got {topk}"
    assert topk <= moe_expert_num, f"topk={topk} must be <= moe_expert_num={moe_expert_num}"
    assert 1024 <= hidden_size <= 7168, f"hidden_size should be in [1024, 7168], got {hidden_size}"

    batch_size = _resolve_local_batch_size(rank, world_size, default_bs)
    assert batch_size > 0, f"batch_size must be > 0, got {batch_size}"
    max_bs = _allreduce_max_int(batch_size, device="npu")
    global_bs = max_bs * world_size
    shmem_est = estimate_zb_shmem_bytes(
        max_bs, world_size, topk, moe_expert_num, hidden_size, use_quant
    )

    if rank == 0:
        bs_mode = (
            "list"
            if os.environ.get("ZB_BATCH_SIZE_LIST", "").strip()
            else ("uniform" if "ZB_BATCH_SIZE" in os.environ else "random")
        )
        print(
            f"[zb sample] world={world_size} experts_per_rank={moe_expert_num // world_size} "
            f"moe_expert_num={moe_expert_num} topk={topk} max_bs={max_bs} "
            f"hidden={hidden_size} quant={quant_mode} dtype={dtype_name} "
            f"random_topk={use_random_topk} bs_mode={bs_mode}",
            flush=True,
        )
        print(
            f"[zb sample] shmem estimate: rows={shmem_est['rows']} "
            f"(=global_bs*min(topk,local_experts)={shmem_est['global_bs']}*"
            f"min({topk},{shmem_est['local_experts']})) "
            f"combine={shmem_est['combine_bytes']/1024**3:.4f}GiB "
            f"recommend={shmem_est['recommend_bytes']/1024**3:.4f}GiB",
            flush=True,
        )
    print(f"[rank {rank}] local_bs={batch_size} max_bs={max_bs} global_bs={global_bs}", flush=True)

    x_np = np.array(gen_x(rank, batch_size, hidden_size), dtype=float).reshape(batch_size, hidden_size)
    x = torch.tensor(x_np, dtype=data_type, device="npu")

    if use_random_topk:
        torch.manual_seed(10007 + rank * 97 + int(os.environ.get("ZB_INPUT_SEED", "0")))
        topk_idx = gen_expert_ids_random(batch_size, topk, moe_expert_num, device=x.device)
    else:
        expert_ids_np = np.array(gen_expert_ids(rank, batch_size, topk, moe_expert_num), dtype=np.int32).reshape(
            batch_size, topk
        )
        topk_idx = torch.tensor(expert_ids_np, dtype=torch.int32, device="npu")

    scales_np = np.array(gen_scales(batch_size, topk), dtype=np.float32).reshape(batch_size, topk)
    topk_weights = torch.tensor(scales_np, dtype=torch.float32, device="npu")

    ip_port = os.environ.get("SHMEM_IP_PORT", "tcp://127.0.0.1:8666")
    local_mem_size = int(os.environ.get("SHMEM_MEM_SIZE", str(1024**3)))
    if local_mem_size < shmem_est["recommend_bytes"]:
        if rank == 0:
            print(
                f"[zb sample] SHMEM_MEM_SIZE={local_mem_size} < recommend "
                f"{shmem_est['recommend_bytes']}; using recommend",
                flush=True,
            )
        local_mem_size = int(shmem_est["recommend_bytes"])

    buf = umdk_cam_op_lib.ZbBuffer(
        rank,
        world_size,
        local_mem_size,
        ip_port,
        hidden_size,
        moe_expert_num,
        use_quant,
        global_bs,
    )
    try:
        num_tokens_per_expert, send_token_idx = buf.get_dispatch_layout(topk_idx)
        recv_x, scales, handle = buf.dispatch(
            x, topk_idx, send_token_idx, num_tokens_per_expert, quant_mode
        )
        actual_recv = int(recv_x.size(0))

        # Quant: host dequant once; combine() copies into SHMEM (expandx aliases combine_x).
        prebuilt_expert_out = None
        if use_quant:
            assert recv_x.dtype == torch.int8, f"quant recv_x dtype={recv_x.dtype}"
            assert scales.dtype == torch.float32
            prebuilt_expert_out = _dequant_identity(recv_x, scales, data_type)
            torch.npu.synchronize()
            dist.barrier()
            expert_out = prebuilt_expert_out
        else:
            expert_out = recv_x

        combine_x = buf.combine(expert_out, topk_weights, topk_idx, handle)
        torch.npu.synchronize()

        out_cpu = combine_x.cpu().to(torch.float).numpy()
        expect_out = x_np.astype(float)
        rtol = 1e-2 if use_quant else 5e-3
        atol = 1e-2 if use_quant else 5e-3
        allclose_nparray(expect_out, out_cpu, rtol=rtol, atol=atol, msg=f"rank{rank}")

        if use_quant:
            print(
                f"[rank {rank}] zb buffer quant dispatch+prebuilt-dequant+combine passed, "
                f"actual_recv={actual_recv}, combine_shape={tuple(combine_x.shape)}",
                flush=True,
            )
        else:
            print(
                f"[rank {rank}] zb buffer sample passed, actual_recv={actual_recv}, "
                f"combine_shape={tuple(combine_x.shape)}",
                flush=True,
            )

        bench_iters = int(os.environ.get("ZB_BENCH_ITERS", "0"))
        if bench_iters > 0:
            for _ in range(min(5, bench_iters)):
                num_tokens_per_expert, send_token_idx = buf.get_dispatch_layout(topk_idx)
                recv_x, scales, handle = buf.dispatch(
                    x, topk_idx, send_token_idx, num_tokens_per_expert, quant_mode
                )
                expert_out = prebuilt_expert_out if use_quant else recv_x
                _ = buf.combine(expert_out, topk_weights, topk_idx, handle)
            torch.npu.synchronize()
            dist.barrier()

            t0 = time.perf_counter()
            for _ in range(bench_iters):
                num_tokens_per_expert, send_token_idx = buf.get_dispatch_layout(topk_idx)
                recv_x, scales, handle = buf.dispatch(
                    x, topk_idx, send_token_idx, num_tokens_per_expert, quant_mode
                )
                expert_out = prebuilt_expert_out if use_quant else recv_x
                _ = buf.combine(expert_out, topk_weights, topk_idx, handle)
            torch.npu.synchronize()
            elapsed_ms = (time.perf_counter() - t0) * 1e3
            print(
                f"[rank {rank}] zb buffer bench iters={bench_iters} "
                f"avg={(elapsed_ms / bench_iters):.3f} ms "
                f"(layout+dispatch+combine; quant host-dequant once)",
                flush=True,
            )
    finally:
        del buf


if __name__ == "__main__":
    local_rank = int(os.environ["LOCAL_RANK"])
    world_size = int(os.environ["WORLD_SIZE"])
    torch.npu.set_device(local_rank)
    dist.init_process_group(backend="hccl", rank=local_rank)
    test_base_test(local_rank, world_size)
    dist.destroy_process_group()
