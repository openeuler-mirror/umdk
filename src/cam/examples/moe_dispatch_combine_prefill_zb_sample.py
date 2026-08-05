#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for ZB normal layout/dispatch/combine via ZbBuffer.
#   Flow: ZbBuffer.get_dispatch_layout -> dispatch (fused notify+dispatch)
#         -> (identity / dequant writeback) -> combine
# Create: 2026-08-01
# Note:
# History: 2026-08-01 create normal zb dispatch/combine example file
#          2026-08-05 switch to ZbBuffer session API (SHMEM owned by Buffer)
#
# Prereq:
#   1) Install CAM run package (ZB kernels) and umdk_cam_op_lib whl with ZbBuffer
#   2) Install Ascend SHMEM and export SHMEM_HOME_PATH if needed
#   3) source CANN / CAM set_env
#
# Run (8 cards example):
#   torchrun --nproc_per_node=8 \
#     src/cam/examples/moe_dispatch_combine_prefill_zb_sample.py
#
# Optional env:
#   SHMEM_IP_PORT=tcp://127.0.0.1:8666
#   SHMEM_MEM_SIZE=4294967296
#   ZB_QUANT_MODE=0|2
#   ZB_BENCH_ITERS=N   # if >0, time N dispatch+combine rounds (quant dequant is prebuilt)
#   Empirical shmem memory size ≈ 2 × batch_size × world_size × 7168 × 2
#
# Quant / perf note:
#   Host dequant is done once after the first dispatch and cached as prebuilt_expert_out.
#   Later rounds (correctness re-run / ZB_BENCH_ITERS) reuse that tensor — combine only
#   copy_s it into the SHMEM slot. Do NOT put dequant inside a timed combine loop.
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
    # Values > 10 to meet combine precision guidance for dispatch inputs.
    return [rank * batch_size + i + 11 for i in range(batch_size) for _ in range(hidden_size)]


def gen_expert_ids(rank, batch_size, topk, moe_expert_num):
    arr = [0] * (batch_size * topk)
    for i in range(batch_size):
        for j in range(topk):
            arr[i * topk + j] = (rank + i + j) % moe_expert_num
    return arr


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
    batch_size = case["batch_size"]
    quant_mode = int(os.environ.get("ZB_QUANT_MODE", str(case["quant_mode"])))
    data_type = torch.bfloat16
    global_bs = batch_size * world_size
    use_quant = quant_mode == 2

    assert moe_expert_num % world_size == 0, "moe_expert_num must be divisible by ep_world_size"
    assert world_size >= 2, "ep_world_size must be >= 2 for ZB normal ops"
    assert quant_mode in (0, 2), f"unsupported quant_mode={quant_mode}"

    x_np = np.array(gen_x(rank, batch_size, hidden_size), dtype=float).reshape(batch_size, hidden_size)
    x = torch.tensor(x_np, dtype=data_type, device="npu")

    expert_ids_np = np.array(gen_expert_ids(rank, batch_size, topk, moe_expert_num), dtype=np.int32).reshape(
        batch_size, topk
    )
    topk_idx = torch.tensor(expert_ids_np, dtype=torch.int32, device="npu")

    scales_np = np.array(gen_scales(batch_size, topk), dtype=np.float32).reshape(batch_size, topk)
    topk_weights = torch.tensor(scales_np, dtype=torch.float32, device="npu")

    ip_port = os.environ.get("SHMEM_IP_PORT", "tcp://127.0.0.1:8666")
    local_mem_size = int(os.environ.get("SHMEM_MEM_SIZE", str(1024**3)))

    # ZbBuffer owns aclshmem_init, meta GVA, named SHMEM slots, and finalize.
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
        # ---- 1) first dispatch: build layout/handle + (quant) prebuilt expert_out ----
        num_tokens_per_expert, send_token_idx = buf.get_dispatch_layout(topk_idx)
        recv_x, scales, handle = buf.dispatch(
            x, topk_idx, send_token_idx, num_tokens_per_expert, quant_mode
        )
        actual_recv = int(recv_x.size(0))

        # Quant: dequant ONCE. Fixed inputs → same recv packing each round, so this
        # bf16 tensor can be reused for combine / bench without re-dequant.
        # Note: expandx and combine_x share SHMEM; each later dispatch overwrites that
        # block as int8, so combine still copy_s prebuilt_expert_out into the slot —
        # that copy is cheap vs host dequant and must stay outside the dequant path.
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

        # ---- 2) correctness (uses prebuilt on quant path) ----
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

        # ---- 3) optional perf loop: no dequant inside timed region ----
        bench_iters = int(os.environ.get("ZB_BENCH_ITERS", "0"))
        if bench_iters > 0:
            # warmup
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
                # quant: reuse prebuilt_expert_out — do not call _dequant_identity here
                expert_out = prebuilt_expert_out if use_quant else recv_x
                _ = buf.combine(expert_out, topk_weights, topk_idx, handle)
            torch.npu.synchronize()
            elapsed_ms = (time.perf_counter() - t0) * 1e3
            print(
                f"[rank {rank}] zb buffer bench iters={bench_iters} "
                f"avg={(elapsed_ms / bench_iters):.3f} ms "
                f"(layout+dispatch+combine; quant dequant prebuilt)",
                flush=True,
            )
    finally:
        del buf


if __name__ == "__main__":
    local_rank = int(os.environ["LOCAL_RANK"])
    world_size = int(os.environ["WORLD_SIZE"])
    # shmem init inside ZbBuffer must come after torch.npu.set_device
    torch.npu.set_device(local_rank)
    dist.init_process_group(backend="hccl", rank=local_rank)
    test_base_test(local_rank, world_size)
    dist.destroy_process_group()
