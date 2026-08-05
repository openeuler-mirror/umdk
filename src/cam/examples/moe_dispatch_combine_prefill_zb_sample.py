#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for ZB normal layout/dispatch/combine.
#   Flow: get_dispatch_layout_zb -> moe_dispatch_prefill_zb (fused notify+dispatch)
#         -> (identity expert) -> moe_combine_prefill_zb
#   moe_dispatch_prefill_zb matches master moe_dispatch_prefill wrapping style.
# Create: 2026-08-01
# Note:
# History: 2026-08-01 create normal zb dispatch/combine example file
#
# Prereq:
#   1) Install CAM run package (ZB kernels) and umdk_cam_op_lib whl with *_zb pybind
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
#   Empirical shmem memory size ≈ 2 × batch_size × world_size × 7168 × 2
#

import os
import random

import numpy as np
import shmem as shm
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


class PrefillZbModule(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(
        self,
        x,
        topk_idx,
        topk_weights,
        comm_meta_ptr,
        ep_world_size,
        ep_rank_id,
        moe_expert_num,
        quant_mode,
        global_bs,
    ):
        # topk_idx: int32 for layout / dispatch / combine.
        # 1) layout — num_tokens_per_expert is SHMEM (needed by notify AllGather).
        num_tokens_per_expert, send_token_idx = torch.ops.umdk_cam_op_lib.get_dispatch_layout_zb(
            topk_idx,
            moe_expert_num,
            ep_world_size,
        )

        # 2) fused notify + dispatch (same as master moe_dispatch_prefill / deepep).
        recv_x, dynamic_scales_out, put_offset, total_recv_tokens, _recv_per_exp = (
            torch.ops.umdk_cam_op_lib.moe_dispatch_prefill_zb(
                x,
                topk_idx,
                send_token_idx,
                num_tokens_per_expert,
                ep_world_size,
                ep_rank_id,
                moe_expert_num,
                quant_mode,
                global_bs,
                comm_meta_ptr,
            )
        )

        # Slice to actual received tokens. total_recv_tokens is device tensor.
        torch.npu.synchronize()
        actual_recv = int(total_recv_tokens.cpu().item())
        if actual_recv <= 0:
            actual_recv = 1
        recv_x = recv_x[:actual_recv]
        if quant_mode == 2:
            dynamic_scales_out = dynamic_scales_out[:actual_recv]

        # quant_mode=2: pybind already allocated SHMEM int8 recv_x + float scales;
        # dispatch wrote into those outputs directly. combine needs BF16/FP16 expert
        # output (real expert would write that) — not int8 recv_x, and not a host-side
        # dequant copy. This sample only identity-combines the non-quant path.
        if quant_mode == 2:
            torch.npu.synchronize()
            return None, actual_recv, recv_x, dynamic_scales_out

        # 4) identity expert + 5) combine (bf16/fp16 recv_x)
        expert_out = recv_x
        combine_x = torch.ops.umdk_cam_op_lib.moe_combine_prefill_zb(
            expert_out,
            put_offset,  # ep_recv_counts
            topk_weights,
            topk_idx,
            send_token_idx,
            comm_meta_ptr,
            ep_world_size,
            ep_rank_id,
            1,  # tp_world_size
            0,  # tp_rank_id
            moe_expert_num,
            global_bs,
        )
        # Keep SHMEM tensors (recv_x / num_tokens_per_expert) alive until kernels finish.
        torch.npu.synchronize()
        return combine_x, actual_recv, recv_x, None


def test_base_test(local_rank_id, ep_world_size):
    rank = local_rank_id
    world_size = ep_world_size

    case = CASE_8RANK if world_size <= 8 else CASE_16RANK
    if world_size not in (8, 16):
        # Fallback: require experts divisible by ranks.
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
    quant_mode = case["quant_mode"]
    data_type = torch.bfloat16
    global_bs = batch_size * world_size

    assert moe_expert_num % world_size == 0, "moe_expert_num must be divisible by ep_world_size"
    assert world_size >= 2, "ep_world_size must be >= 2 for ZB normal ops"

    x_np = np.array(gen_x(rank, batch_size, hidden_size), dtype=float).reshape(batch_size, hidden_size)
    x = torch.tensor(x_np, dtype=data_type, device="npu")

    expert_ids_np = np.array(gen_expert_ids(rank, batch_size, topk, moe_expert_num), dtype=np.int32).reshape(
        batch_size, topk
    )
    topk_idx = torch.tensor(expert_ids_np, dtype=torch.int32, device="npu")

    scales_np = np.array(gen_scales(batch_size, topk), dtype=np.float32).reshape(batch_size, topk)
    topk_weights = torch.tensor(scales_np, dtype=torch.float32, device="npu")

    # SHMEM / ZB init (must be after torch.npu.set_device)
    # New Ascend SHMEM Python API uses aclshmem_* names (not shmem_*).
    #
    # ZB kernels treat comm_meta_ptr as a symmetric GVA meta region (sync flags).
    # Do NOT malloc the whole local_mem_size for it — leave heap space for
    # pybind SHMEM tensors (recv_x / num_tokens_per_expert / recv_data).
    ip_port = os.environ.get("SHMEM_IP_PORT", "tcp://127.0.0.1:8666")
    local_mem_size = int(os.environ.get("SHMEM_MEM_SIZE", str(1024**3)))
    # Align with deepep Buffer / fused Buffer::EXT_INFO_SIZE (~1–2MB meta).
    meta_bytes = int(os.environ.get("SHMEM_META_SIZE", str(2 * 1024 * 1024)))

    ret = shm.set_conf_store_tls(False, "")
    if ret != 0:
        raise ValueError("[ERROR] set_conf_store_tls failed")

    init_attrs = shm.InitAttr()
    init_attrs.my_rank = rank
    init_attrs.n_ranks = world_size
    init_attrs.local_mem_size = local_mem_size
    init_attrs.ip_port = ip_port
    if hasattr(shm, "OpEngineType"):
        init_attrs.option_attr.data_op_engine_type = shm.OpEngineType.MTE

    shm_ret = shm.aclshmem_init(init_attrs)
    if shm_ret != 0:
        raise ValueError("[ERROR] aclshmem_init failed")

    # Meta region for ZbSyncFlag (must be SHMEM-symmetric and zeroed).
    meta_elems = meta_bytes // 4
    comm_meta = shm.aclshmem_create_tensor((meta_elems,), torch.int32, device_id=rank)
    comm_meta.zero_()
    comm_meta_ptr = int(comm_meta.data_ptr())

    try:
        mod = PrefillZbModule().npu()
        combine_x, actual_recv, recv_x, scales = mod(
            x=x,
            topk_idx=topk_idx,
            topk_weights=topk_weights,
            comm_meta_ptr=comm_meta_ptr,
            ep_world_size=world_size,
            ep_rank_id=rank,
            moe_expert_num=moe_expert_num,
            quant_mode=quant_mode,
            global_bs=global_bs,
        )
        torch.npu.synchronize()

        if quant_mode == 2:
            assert recv_x.dtype == torch.int8, f"quant recv_x dtype={recv_x.dtype}"
            assert scales is not None and scales.dtype == torch.float32
            assert scales.numel() == actual_recv
            print(
                f"[rank {rank}] normal zb quant dispatch passed, actual_recv={actual_recv}, "
                f"recv_x={tuple(recv_x.shape)} int8, scales={tuple(scales.shape)}",
                flush=True,
            )
        else:
            out_cpu = combine_x.cpu().to(torch.float).numpy()
            # With normalized topk_weights (sum=1) and identity expert, combine ~= x.
            expect_out = x_np.astype(float)
            allclose_nparray(expect_out, out_cpu, rtol=5e-3, atol=5e-3, msg=f"rank{rank}")
            print(
                f"[rank {rank}] normal zb sample passed, actual_recv={actual_recv}, "
                f"combine_shape={tuple(combine_x.shape)}",
                flush=True,
            )
    finally:
        # free via tensor API when available; otherwise free data_ptr
        if hasattr(shm, "aclshmem_free_tensor"):
            shm.aclshmem_free_tensor(comm_meta)
        else:
            shm.aclshmem_free(comm_meta_ptr)
        shm.aclshmem_finalize()


if __name__ == "__main__":
    local_rank = int(os.environ["LOCAL_RANK"])
    world_size = int(os.environ["WORLD_SIZE"])
    # shmem init must come after torch.npu.set_device (or any other aclInit device action)
    torch.npu.set_device(local_rank)
    dist.init_process_group(backend="hccl", rank=local_rank)
    test_base_test(local_rank, world_size)
    dist.destroy_process_group()
