#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: NPU functional + precision test for GatherSelectionSparseFlashAttention.
#

"""NPU eager correctness test for GatherSelectionSparseFlashAttention.

Ported from the functional checks in cann-recipes
``benchmark_gather_selection_sparse_flash_attention.py`` (miss fan-out / status
commit / second-pass hit) plus attention precision vs sequential
gather + ``npu_kv_quant_sparse_flash_attention``.

Requires:
  - A3 (ascend910_93)
  - installed CAM .run + ``umdk_cam_op_lib`` wheel
  - ``torch_npu.empty_with_swapped_memory`` for Host-backed full KV
  - ``npu_kv_quant_sparse_flash_attention`` for the attention golden
  - optional: ``umdk_cam_op_lib.gather_selection_kv_cache`` (else torch gather)

Usage:
  python3 src/cam/examples/test_gather_selection_sparse_flash_attention.py
  GSFA_DEVICE=0 GSFA_MISS_RATES=0,0.5,1 python3 ...
"""

from __future__ import annotations

import math
import os

import numpy as np
import torch
import torch_npu
import umdk_cam_op_lib  # noqa: F401

from torch_npu.testing.testcase import TestCase, run_tests


PACKED_D = 656
QUERY_D = 576
ROPE_D = 64
NOPE_D = 512
ROPE_BYTES = 128  # 64 * fp16
SCALE_BYTES = 16  # 4 * fp32

# FP16 mixed-tolerance (ops-precision-standard float_compute)
FP16_RTOL = 2**-9
FP16_ATOL = 2**-9
FP16_MATCHED_RATIO = 0.99
FP16_MAX_ABS = max(1e-1, 32 * (2**-10))


def _resolve_kqsfa():
    name = "npu_kv_quant_sparse_flash_attention"
    for ns in (torch_npu, getattr(torch.ops, "npu", None), getattr(torch.ops, "_C_ascend", None)):
        if ns is None or not hasattr(ns, name):
            continue
        op = getattr(ns, name)
        if hasattr(op, "default"):
            op = op.default
        if callable(op):
            return op
    return None


def _make_packed_rows(num_rows: int, rng: np.random.Generator) -> np.ndarray:
    """Valid W8A8C8 packed rows: nope int8 + rope fp16 + four positive fp32 scales."""
    rows = np.empty((num_rows, PACKED_D), dtype=np.int8)
    rows[:, :NOPE_D] = rng.integers(-8, 8, size=(num_rows, NOPE_D), dtype=np.int8)
    rope = rng.standard_normal((num_rows, ROPE_D)).astype(np.float16).view(np.int8).reshape(num_rows, ROPE_BYTES)
    rows[:, NOPE_D : NOPE_D + ROPE_BYTES] = rope
    scales = rng.uniform(0.01, 0.05, size=(num_rows, 4)).astype(np.float32).view(np.int8).reshape(
        num_rows, SCALE_BYTES
    )
    rows[:, NOPE_D + ROPE_BYTES :] = scales
    return rows


def _fill_tensor_from_packed(dst: torch.Tensor, packed: np.ndarray):
    """Copy host packed rows into an NPU / swapped tensor without breaking layout."""
    src = torch.from_numpy(packed.reshape(dst.shape))
    if dst.device.type == "npu":
        # swapped Host tensors may not support direct copy_; fill via device staging add.
        dst.zero_()
        dst.add_(src.to(dst.device))
    else:
        dst.copy_(src)


def _make_status(topk_indices: np.ndarray, full_seq: int, miss_rate: float, rng: np.random.Generator):
    batch, topk = topk_indices.shape
    status = np.empty((batch, 1, topk + 1), dtype=np.int32)
    miss_counts = np.zeros(batch, dtype=np.int32)
    universe = np.arange(full_seq, dtype=np.int32)
    for b in range(batch):
        requested = topk_indices[b]
        miss_mask = rng.random(topk) < miss_rate
        miss_count = int(miss_mask.sum())
        previous = requested.copy()
        if miss_count > 0:
            in_request = np.zeros(full_seq, dtype=np.bool_)
            in_request[requested] = True
            stale_pool = universe[~in_request]
            if miss_count > stale_pool.size:
                raise ValueError("increase full_seq or lower miss_rate")
            previous[miss_mask] = rng.choice(stale_pool, size=miss_count, replace=False)
        status[b, 0, :topk] = previous
        status[b, 0, topk] = topk
        miss_counts[b] = miss_count
    return status, miss_counts


def _count_status_misses(status: torch.Tensor, topk: torch.Tensor) -> int:
    # status: [B, 1, K+1], topk: [B, K]
    prev = status[:, 0, : topk.shape[1]]
    return int((prev != topk).sum().item())


def _fill_full_kv_tags(full_kv: torch.Tensor, block_size: int) -> torch.Tensor:
    """Tag each packed row's first nope byte; keep rope/scales intact for later attention."""
    flat = full_kv.view(-1, PACKED_D)
    rows = flat.shape[0]
    tags = (torch.arange(rows, dtype=torch.int16) % 127).to(torch.int8)
    flat[:, 0] = tags.to(flat.device)
    return tags.cpu()


def _mixed_tolerance_pass(actual: torch.Tensor, golden: torch.Tensor, dtype=torch.float16):
    a = actual.detach().float().cpu().reshape(-1)
    g = golden.detach().float().cpu().reshape(-1)
    if dtype == torch.bfloat16:
        rtol, atol, ratio_need, max_abs = 2**-6, 2**-6, 0.99, max(1.0, 32 * (2**-7))
    else:
        rtol, atol, ratio_need, max_abs = FP16_RTOL, FP16_ATOL, FP16_MATCHED_RATIO, FP16_MAX_ABS
    if (not torch.isfinite(a).all()) or (not torch.isfinite(g).all()):
        return (
            False,
            0.0,
            float("nan"),
            f"non-finite values: actual_nan={int((~torch.isfinite(a)).sum())} "
            f"golden_nan={int((~torch.isfinite(g)).sum())} "
            f"actual_shape={tuple(actual.shape)} golden_shape={tuple(golden.shape)}",
        )
    abs_err = (a - g).abs()
    ok = abs_err <= (atol + rtol * g.abs())
    matched = float(ok.float().mean().item())
    max_err = float(abs_err.max().item()) if abs_err.numel() else 0.0
    return matched >= ratio_need and max_err <= max_abs, matched, max_err, ""


def _torch_packed_gather(selection_kv, selection_table, status, topk_indices, full_kv, full_table, block_size):
    """Slot-stable packed INT8 gather on device (sequential baseline producer)."""
    batch, topk = topk_indices.shape
    device = selection_kv.device
    slots = torch.arange(topk, device=device, dtype=torch.int64)
    for b in range(batch):
        req = topk_indices[b].to(torch.int64)
        prev = status[b, 0, :topk].to(torch.int64)
        miss = req != prev
        if not bool(miss.any()):
            status[b, 0, topk] = topk
            continue
        miss_slots = slots[miss]
        miss_ids = req[miss]
        sel_block = miss_slots // block_size
        sel_off = miss_slots % block_size
        phys_sel = selection_table[b, sel_block].to(torch.int64)
        dst = phys_sel * block_size + sel_off
        full_block = miss_ids // block_size
        full_off = miss_ids % block_size
        phys_full = full_table[b, full_block].to(torch.int64)
        src = phys_full * block_size + full_off
        flat_sel = selection_kv.view(-1, PACKED_D)
        flat_full = full_kv.view(-1, PACKED_D)
        flat_sel[dst] = flat_full[src]
        status[b, 0, miss_slots] = req[miss].to(torch.int32)
        status[b, 0, topk] = topk
    return torch.full((batch,), topk, dtype=torch.int32, device=device)


def _call_gather_umdk(selection_kv, selection_table, status, topk_tnd, full_kv, full_table, actual_kv, actual_q):
    empty = torch.tensor([], dtype=torch.int8, device=selection_kv.device)
    # umdk gather accepts TND status/topk as rank-3: [B, S, K(+1)].
    sel_kv = selection_kv.squeeze(2) if selection_kv.dim() == 4 else selection_kv
    full = full_kv.squeeze(2) if full_kv.dim() == 4 else full_kv
    return torch.ops.umdk_cam_op_lib.gather_selection_kv_cache(
        empty,
        sel_kv,
        selection_table,
        status,
        topk_tnd,
        empty,
        full,
        full_table,
        actual_kv,
        actual_q,
        selection_topk_block_size=1,
    )


def _call_kqsfa(kqsfa, query, selection_kv, selection_table, selection_actual_seq, actual_q, scale):
    batch, topk = selection_actual_seq.shape[0], int(selection_actual_seq[0].item())
    slot_indices = torch.arange(topk, dtype=torch.int32, device=query.device).view(1, -1).repeat(batch, 1)
    sparse = slot_indices.unsqueeze(1)  # [T, 1, K]
    return kqsfa(
        query=query,
        key=selection_kv,
        value=selection_kv,
        sparse_indices=sparse,
        scale_value=scale,
        sparse_block_size=1,
        block_table=selection_table,
        actual_seq_lengths_query=actual_q,
        actual_seq_lengths_kv=selection_actual_seq,
        layout_query="TND",
        layout_kv="PA_BSND",
        sparse_mode=3,
        attention_mode=2,
        quant_scale_repo_mode=1,
        tile_size=128,
        key_quant_mode=2,
        value_quant_mode=2,
        rope_head_dim=ROPE_D,
    )


def _call_fused(query, selection_kv, selection_table, status, topk_tnd, full_kv, full_table, actual_q, actual_kv, scale):
    return torch.ops.umdk_cam_op_lib.gather_selection_sparse_flash_attention(
        query,
        selection_kv,
        selection_table,
        status,
        topk_tnd,
        full_kv,
        full_table,
        actual_q,
        actual_kv,
        scale_value=scale,
        key_quant_mode=2,
        value_quant_mode=2,
        sparse_block_size=1,
        layout_query="TND",
        layout_kv="PA_BSND",
        sparse_mode=3,
        attention_mode=2,
        quant_scale_repo_mode=1,
        tile_size=128,
        rope_head_dim=ROPE_D,
        selection_topk_block_size=1,
    )


class TestGatherSelectionSparseFlashAttention(TestCase):
    def setUp(self):
        if not torch.npu.is_available():
            self.skipTest("NPU is required")
        if not hasattr(torch.ops.umdk_cam_op_lib, "gather_selection_sparse_flash_attention"):
            self.skipTest("umdk_cam_op_lib.gather_selection_sparse_flash_attention is not registered")
        if not hasattr(torch_npu, "empty_with_swapped_memory"):
            self.skipTest("torch_npu.empty_with_swapped_memory is required for Host-backed full_kv")
        self.device_id = int(os.environ.get("GSFA_DEVICE", "0"))
        torch_npu.npu.set_device(self.device_id)
        self.device = f"npu:{self.device_id}"
        self.kqsfa = _resolve_kqsfa()
        self.has_umdk_gather = hasattr(torch.ops.umdk_cam_op_lib, "gather_selection_kv_cache")

    def _build_case(self, batch, topk, full_seq, block_size, miss_rate, seed, query_dtype=torch.float16):
        rng = np.random.default_rng(seed)
        if topk % block_size != 0:
            raise ValueError("topk must be divisible by block_size")
        full_blocks = math.ceil(full_seq / block_size)
        sel_blocks = topk // block_size
        topk_np = np.stack([rng.choice(full_seq, size=topk, replace=False) for _ in range(batch)]).astype(np.int32)
        status_np, miss_counts = _make_status(topk_np, full_seq, miss_rate, rng)

        query = torch.randn((batch, 1, QUERY_D), dtype=query_dtype, device=self.device)
        sel_rows = batch * sel_blocks * block_size
        full_rows = batch * full_blocks * block_size
        selection_kv = torch.empty(
            (batch * sel_blocks, block_size, 1, PACKED_D), dtype=torch.int8, device=self.device
        )
        _fill_tensor_from_packed(selection_kv, _make_packed_rows(sel_rows, rng))
        selection_table = torch.arange(batch * sel_blocks, dtype=torch.int32, device=self.device).reshape(
            batch, sel_blocks
        )
        status = torch.from_numpy(status_np).to(self.device)
        topk_t = torch.from_numpy(topk_np).to(self.device)
        full_kv = torch_npu.empty_with_swapped_memory(
            (batch * full_blocks, block_size, 1, PACKED_D), dtype=torch.int8, device=self.device
        )
        _fill_tensor_from_packed(full_kv, _make_packed_rows(full_rows, rng))
        full_table = torch.arange(batch * full_blocks, dtype=torch.int32, device=self.device).reshape(batch, full_blocks)
        actual_q = torch.arange(1, batch + 1, dtype=torch.int32, device=self.device)
        actual_kv = torch.full((batch,), full_seq, dtype=torch.int32, device=self.device)
        scale = 1.0 / math.sqrt(NOPE_D + ROPE_D)
        return {
            "query": query,
            "selection_kv": selection_kv,
            "selection_table": selection_table,
            "status": status,
            "initial_status": status.clone(),
            "initial_selection_kv": selection_kv.clone(),
            "topk": topk_t,
            "full_kv": full_kv,
            "full_table": full_table,
            "actual_q": actual_q,
            "actual_kv": actual_kv,
            "scale": scale,
            "block_size": block_size,
            "expected_misses": int(miss_counts.sum()),
            "query_dtype": query_dtype,
        }

    def _check_miss_fanout(self, case):
        tags = _fill_full_kv_tags(case["full_kv"], case["block_size"])
        case["selection_kv"].zero_()
        case["status"].copy_(case["initial_status"])
        topk = case["topk"]
        before = _count_status_misses(case["status"], topk)
        self.assertEqual(before, case["expected_misses"])

        attn, sel_actual = _call_fused(
            case["query"],
            case["selection_kv"],
            case["selection_table"],
            case["status"],
            topk.unsqueeze(1),
            case["full_kv"],
            case["full_table"],
            case["actual_q"],
            case["actual_kv"],
            case["scale"],
        )
        torch_npu.npu.synchronize()
        self.assertEqual(tuple(attn.shape), (case["query"].shape[0], 1, QUERY_D - ROPE_D))
        self.assertTrue(torch.isfinite(attn.float()).all())
        after = _count_status_misses(case["status"], topk)
        self.assertEqual(after, 0, f"status still has {after} misses after fused call")
        self.assertTrue(torch.equal(sel_actual.cpu(), torch.full((topk.shape[0],), topk.shape[1], dtype=torch.int32)))

        init = case["initial_status"]
        flat_sel = case["selection_kv"].view(-1, PACKED_D)
        checked = 0
        batch, topk_n = topk.shape
        for b in range(batch):
            for s in range(topk_n):
                logical = int(topk[b, s].item())
                prev = int(init[b, 0, s].item())
                if prev == logical:
                    continue
                sel_block = s // case["block_size"]
                sel_off = s % case["block_size"]
                phys_sel = int(case["selection_table"][b, sel_block].item())
                full_block = logical // case["block_size"]
                full_off = logical % case["block_size"]
                phys_full = int(case["full_table"][b, full_block].item())
                dst = phys_sel * case["block_size"] + sel_off
                src = phys_full * case["block_size"] + full_off
                self.assertEqual(int(flat_sel[dst, 0].item()), int(tags[src].item()))
                checked += 1
                if checked >= 32:
                    break
            if checked >= 32:
                break
        if case["expected_misses"] > 0:
            self.assertGreater(checked, 0)

        # Second call must stay all-hit with finite attention.
        attn2, _ = _call_fused(
            case["query"],
            case["selection_kv"],
            case["selection_table"],
            case["status"],
            topk.unsqueeze(1),
            case["full_kv"],
            case["full_table"],
            case["actual_q"],
            case["actual_kv"],
            case["scale"],
        )
        torch_npu.npu.synchronize()
        self.assertEqual(_count_status_misses(case["status"], topk), 0)
        self.assertTrue(torch.isfinite(attn2.float()).all())
        return attn

    def _sequential_attention(self, case):
        selection_kv = case["initial_selection_kv"].clone()
        status = case["initial_status"].clone()
        topk = case["topk"]
        if self.has_umdk_gather:
            sel_actual = _call_gather_umdk(
                selection_kv,
                case["selection_table"],
                status,
                topk.unsqueeze(1),
                case["full_kv"],
                case["full_table"],
                case["actual_kv"],
                case["actual_q"],
            )
        else:
            sel_actual = _torch_packed_gather(
                selection_kv,
                case["selection_table"],
                status,
                topk,
                case["full_kv"],
                case["full_table"],
                case["block_size"],
            )
        torch_npu.npu.synchronize()
        self.assertEqual(_count_status_misses(status, topk), 0)
        return _call_kqsfa(
            self.kqsfa,
            case["query"],
            selection_kv,
            case["selection_table"],
            sel_actual,
            case["actual_q"],
            case["scale"],
        )

    def _run_miss_rate(self, miss_rate: float):
        case = self._build_case(
            batch=2,
            topk=128,
            full_seq=1024,
            block_size=128,
            miss_rate=miss_rate,
            seed=20260909 + int(miss_rate * 100),
        )
        fused_attn = self._check_miss_fanout(case)

        if self.kqsfa is None:
            print(
                f"[warn] miss_rate={miss_rate}: functional OK; skip attention precision "
                "(npu_kv_quant_sparse_flash_attention missing)"
            )
            return

        # Rebuild a fresh case so fused and sequential see the same Host tags/random KV.
        case = self._build_case(
            batch=2,
            topk=128,
            full_seq=1024,
            block_size=128,
            miss_rate=miss_rate,
            seed=20260909 + int(miss_rate * 100) + 7,
        )
        case["status"].copy_(case["initial_status"])
        case["selection_kv"].copy_(case["initial_selection_kv"])
        fused_attn, _ = _call_fused(
            case["query"],
            case["selection_kv"],
            case["selection_table"],
            case["status"],
            case["topk"].unsqueeze(1),
            case["full_kv"],
            case["full_table"],
            case["actual_q"],
            case["actual_kv"],
            case["scale"],
        )
        torch_npu.npu.synchronize()
        seq_attn = self._sequential_attention(case)
        torch_npu.npu.synchronize()
        if isinstance(seq_attn, (tuple, list)):
            seq_attn = seq_attn[0]
        ok, matched, max_err, detail = _mixed_tolerance_pass(fused_attn, seq_attn, case["query_dtype"])
        self.assertTrue(
            ok,
            f"miss_rate={miss_rate}: precision fail matched={matched:.6f} max_abs={max_err} {detail}",
        )
        print(
            f"[ok] miss_rate={miss_rate}: functional+precision "
            f"matched={matched:.6f} max_abs={max_err:.6e} "
            f"gather={'umdk' if self.has_umdk_gather else 'torch'}"
        )

    def test_functional_and_precision(self):
        rates = os.environ.get("GSFA_MISS_RATES", "0,0.5,1")
        for token in rates.split(","):
            token = token.strip()
            if not token:
                continue
            self._run_miss_rate(float(token))


if __name__ == "__main__":
    run_tests()
