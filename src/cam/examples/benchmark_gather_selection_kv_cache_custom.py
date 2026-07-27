#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Benchmark for GatherSelectionKvCacheCustom vs base gather.
# Create: 2026-07-25
# Note:
# History: 2026-07-25 create GatherSelectionKvCacheCustom benchmark
#

"""Compare original/custom GatherSelectionKvCache with full KV in Host DRAM."""

import argparse
import csv
import gc
import glob
import os

import numpy as np
import torch
import torch_npu
import umdk_cam_op_lib  # noqa: F401 - registers umdk_cam_op_lib torch ops


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", type=int, default=0)
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument("--topk", type=int, default=2048)
    parser.add_argument("--full-seq", type=int, default=4096)
    parser.add_argument("--block-size", type=int, default=128)
    parser.add_argument("--kv-dim", type=int, default=512)
    parser.add_argument("--rope-dim", type=int, default=64)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument(
        "--miss-rate", type=float, default=1.0,
        help="Per-entry miss probability for every token, in [0, 1].")
    parser.add_argument(
        "--profile-dir", default="",
        help="Also capture Level1+PipeUtilization data for kernel-only comparison.")
    parser.add_argument("--profile-steps", type=int, default=10)
    parser.add_argument(
        "--with-original", action="store_true",
        help="Also benchmark umdk_cam_op_lib.gather_selection_kv_cache (PR3058 baseline).")
    return parser.parse_args()


def make_swapped(shape, dtype, device):
    tensor = torch_npu.empty_with_swapped_memory(shape, dtype=dtype, device=device)
    tensor.fill_(0)
    return tensor


def make_status_template(topk_indices, full_seq, miss_rate, rng):
    batch, _, topk = topk_indices.shape
    status = np.empty((batch, 1, topk + 1), dtype=np.int32)
    miss_counts = np.empty(batch, dtype=np.int32)
    universe = np.arange(full_seq, dtype=np.int32)
    for token_idx in range(batch):
        requested = topk_indices[token_idx, 0]
        miss_mask = rng.random(topk) < miss_rate
        miss_count = int(miss_mask.sum())

        # A realistic previous cache is full: hit slots contain requested ids,
        # while miss slots contain valid stale ids outside this request.
        in_request = np.zeros(full_seq, dtype=np.bool_)
        in_request[requested] = True
        stale_pool = universe[~in_request]
        if miss_count > stale_pool.size:
            raise ValueError(
                f"token {token_idx} needs {miss_count} unique stale ids, but full-seq/topk "
                f"leave only {stale_pool.size}; increase --full-seq or lower --miss-rate")
        previous = requested.copy()
        if miss_count > 0:
            previous[miss_mask] = rng.choice(stale_pool, size=miss_count, replace=False)
        status[token_idx, 0, :topk] = previous
        status[token_idx, 0, topk] = topk
        miss_counts[token_idx] = miss_count
    return status, miss_counts


def make_selected_state(args, device, status_template):
    selected_blocks = args.topk // args.block_size
    if selected_blocks * args.block_size != args.topk:
        raise ValueError("topk must be divisible by block-size for this benchmark")
    return {
        "rope": torch.zeros(
            (args.batch * selected_blocks, args.block_size, args.rope_dim),
            dtype=torch.float16, device=device),
        "kv": torch.zeros(
            (args.batch * selected_blocks, args.block_size, args.kv_dim),
            dtype=torch.float16, device=device),
        "table": torch.arange(
            args.batch * selected_blocks, dtype=torch.int32, device=device).reshape(
                args.batch, selected_blocks),
        "status": torch.from_numpy(status_template).to(device),
        "initial_status": torch.from_numpy(status_template).to(device),
    }


def call_gather(op, state, common):
    return op(
        state["rope"], state["kv"], state["table"], state["status"],
        common["topk_indices"], common["full_rope"], common["full_kv"],
        common["full_table"], common["full_actual"], common["q_actual"],
        selection_topk_block_size=1)


def reset_and_call(op, state, common):
    state["status"].copy_(state["initial_status"])
    return call_gather(op, state, common)


def summarize(name, values_ms):
    values = np.asarray(values_ms, dtype=np.float64)
    print(
        f"{name:8s}: median={np.median(values) * 1000:.2f} us, "
        f"mean={np.mean(values) * 1000:.2f} us, "
        f"p90={np.percentile(values, 90) * 1000:.2f} us")


def event_benchmark(args, name, state, common, op):
    outputs = []
    for _ in range(args.warmup):
        outputs.append(reset_and_call(op, state, common))
    torch_npu.npu.synchronize()
    outputs.clear()

    events = []
    for _ in range(args.iterations):
        start = torch.npu.Event(enable_timing=True)
        end = torch.npu.Event(enable_timing=True)
        state["status"].copy_(state["initial_status"])
        start.record()
        outputs.append(call_gather(op, state, common))
        end.record()
        events.append((start, end))
    torch_npu.npu.synchronize()

    times = [start.elapsed_time(end) for start, end in events]
    summarize(name, times)
    status_valid = int(state["status"][0, 0, args.topk].item())
    if status_valid != args.topk:
        raise AssertionError(f"{name} returned status valid_num={status_valid}, expected {args.topk}")
    return times


def report_kernel_csv(profile_dirs):
    files = []
    for profile_dir in profile_dirs:
        candidates = glob.glob(
            os.path.join(profile_dir, "**", "kernel_details.csv"), recursive=True)
        if candidates:
            files.append(max(candidates, key=os.path.getmtime))
    if not files:
        print("kernel_details.csv was not generated; inspect profiler parser logs/output filesystem")
        return

    groups = {"original": [], "custom": []}
    block_dims = {"original": set(), "custom": set()}
    for file_path in files:
        with open(file_path, newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                kernel_name = row.get("Name", "")
                normalized = kernel_name.lower()
                if "gather_selection_kv_cache_custom" in normalized or "gatherselectionkvcachecustom" in normalized:
                    group = "custom"
                elif "gather_selection_kv_cache" in normalized or "gatherselectionkvcache" in normalized:
                    group = "original"
                else:
                    continue
                try:
                    groups[group].append(float(row["Duration(us)"]))
                except (KeyError, TypeError, ValueError):
                    continue
                block_dim = row.get("Block Dim", row.get("Block Num", ""))
                if block_dim:
                    block_dims[group].add(block_dim)

    print("Profiler kernel-only duration:")
    for name in ("original", "custom"):
        values = groups[name]
        if not values:
            print(f"{name:8s}: no matching kernel row")
            continue
        print(
            f"{name:8s}: median={np.median(values):.2f} us, "
            f"mean={np.mean(values):.2f} us, p90={np.percentile(values, 90):.2f} us, "
            f"block_dim={sorted(block_dims[name])}")
    if groups["original"] and groups["custom"]:
        ratio = np.median(groups["original"]) / max(np.median(groups["custom"]), 1e-12)
        print(f"kernel-only median speedup: {ratio:.3f}x")


def capture_profile(args, name, state, common, op):
    if not args.profile_dir:
        return
    output_dir = os.path.join(args.profile_dir, name)
    os.makedirs(output_dir, exist_ok=True)
    experimental_config = torch_npu.profiler._ExperimentalConfig(
        profiler_level=torch_npu.profiler.ProfilerLevel.Level1,
        aic_metrics=torch_npu.profiler.AiCMetrics.PipeUtilization)
    profiler = torch_npu.profiler.profile(
        activities=[
            torch_npu.profiler.ProfilerActivity.CPU,
            torch_npu.profiler.ProfilerActivity.NPU,
        ],
        record_shapes=False,
        profile_memory=False,
        with_stack=False,
        experimental_config=experimental_config,
        schedule=torch_npu.profiler.schedule(
            wait=0, warmup=0, active=args.profile_steps, repeat=1, skip_first=0),
        on_trace_ready=torch_npu.profiler.tensorboard_trace_handler(output_dir))

    outputs = []
    with profiler as prof:
        for _ in range(args.profile_steps):
            state["status"].copy_(state["initial_status"])
            with torch.autograd.profiler.record_function(f"gather_{name}"):
                outputs.append(call_gather(op, state, common))
            prof.step()
        prof.step()  # leave the active window cleanly
    torch_npu.npu.synchronize()
    print(f"{name} profiler data: {os.path.abspath(output_dir)}")


def make_case(args, device, topk_np, status_template):
    full_blocks = args.full_seq // args.block_size
    common = {
        "topk_indices": torch.from_numpy(topk_np).to(device),
        # These tensors are NPU-addressable but their backing storage is Host DRAM.
        # Each operator run receives an independent allocation.
        "full_rope": make_swapped(
            (args.batch * full_blocks, args.block_size, args.rope_dim), torch.float16, device),
        "full_kv": make_swapped(
            (args.batch * full_blocks, args.block_size, args.kv_dim), torch.float16, device),
        "full_table": torch.arange(
            args.batch * full_blocks, dtype=torch.int32, device=device).reshape(
                args.batch, full_blocks),
        "full_actual": torch.full(
            (args.batch,), args.full_seq, dtype=torch.int32, device=device),
        "q_actual": torch.ones((args.batch,), dtype=torch.int32, device=device),
    }
    return make_selected_state(args, device, status_template), common


def clear_case():
    # All tensors belonging to the completed run must be out of scope before
    # this is called. Synchronize first, then release cached HBM allocations.
    torch_npu.npu.synchronize()
    gc.collect()
    torch_npu.npu.empty_cache()
    torch_npu.npu.synchronize()


def main():
    args = parse_args()
    if args.topk < 33 or args.topk > 2048:
        raise ValueError("custom kernel requires 33 <= topk <= 2048")
    if args.full_seq - 1 < args.topk:
        raise ValueError("full-seq - 1 must be >= topk so requested hits exclude the forced latest-token miss")
    if args.full_seq % args.block_size != 0:
        raise ValueError("full-seq must be divisible by block-size for this benchmark")
    if not 0.0 <= args.miss_rate <= 1.0:
        raise ValueError("miss-rate must be in [0, 1]")

    torch_npu.npu.set_device(args.device)
    device = torch.device(f"npu:{args.device}")
    rng = np.random.default_rng(20260722)
    topk_np = np.stack([
        # The kernel intentionally never reuses full_seq - 1. Excluding it keeps
        # the observed miss rate controlled solely by --miss-rate.
        rng.choice(args.full_seq - 1, size=args.topk, replace=False)
        for _ in range(args.batch)
    ]).astype(np.int32).reshape(args.batch, 1, args.topk)
    status_template, miss_counts = make_status_template(
        topk_np, args.full_seq, args.miss_rate, rng)

    lib = torch.ops.umdk_cam_op_lib
    ops = {"custom": lib.gather_selection_kv_cache_custom}
    if args.with_original:
        ops["original"] = lib.gather_selection_kv_cache
    op_names = [name for name in ("original", "custom") if name in ops]

    print(
        f"offload benchmark: B={args.batch}, topk={args.topk}, full_seq={args.full_seq}, "
        f"KV={args.kv_dim}, RoPE={args.rope_dim}, block={args.block_size}, "
        f"requested_miss_rate={args.miss_rate:.4f}")
    print(
        f"actual misses/token: min={miss_counts.min()}, mean={miss_counts.mean():.2f}, "
        f"max={miss_counts.max()}, actual_miss_rate={miss_counts.sum() / (args.batch * args.topk):.6f}")
    print(f"operators: {', '.join(op_names)}")
    print(
        "Eager-call NPU Event window (includes host submission gaps and auxiliary device work; "
        "this is not kernel-only duration):")

    times = {}
    for name in op_names:
        print(f"\n[{name}] allocate -> warmup -> measure")
        state, common = make_case(args, device, topk_np, status_template)
        times[name] = event_benchmark(args, name, state, common, ops[name])
        capture_profile(args, name, state, common, ops[name])
        del state, common
        clear_case()
        print(f"[{name}] tensors released and NPU allocator cache cleared")

    if "original" in times and "custom" in times:
        ratio = np.median(times["original"]) / max(np.median(times["custom"]), 1e-12)
        print(f"\nisolated eager-call median ratio: {ratio:.3f}x")
    if args.profile_dir:
        report_kernel_csv([os.path.join(args.profile_dir, name) for name in op_names])
    else:
        print(
            "For kernel-only comparison, rerun with --profile-dir and use the "
            "'Profiler kernel-only duration' results.")


if __name__ == "__main__":
    main()
