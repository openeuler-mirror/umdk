#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Focused eager correctness test for GatherSelectionKvCacheCustom.
# Create: 2026-07-25
# Note:
# History: 2026-07-25 create GatherSelectionKvCacheCustom correctness test
#

"""Focused eager correctness test for GatherSelectionKvCacheCustom.

The custom kernel intentionally supports only S=1, H=1, TOPK>32 and
selection_topk_block_size=1.  This test exercises both cold copies and
same-token selected-cache reuse without depending on output ordering.
"""

import os

import numpy as np
import torch
import torch_npu
import umdk_cam_op_lib  # noqa: F401 - registers umdk_cam_op_lib torch ops

from torch_npu.testing.testcase import TestCase, run_tests


class TestGatherSelectionKvCacheCustom(TestCase):
    def test_cold_copy_and_reuse(self):
        rng = np.random.default_rng(20260721)
        batch = 2
        topk = 64
        full_seq = 128
        block_size = 16
        kv_dim = 32
        rope_dim = 8
        full_blocks_per_batch = full_seq // block_size
        selected_blocks_per_token = topk // block_size

        full_kv = rng.standard_normal(
            (batch * full_blocks_per_batch, block_size, kv_dim), dtype=np.float32).astype(np.float16)
        full_rope = rng.standard_normal(
            (batch * full_blocks_per_batch, block_size, rope_dim), dtype=np.float32).astype(np.float16)
        full_table = np.arange(batch * full_blocks_per_batch, dtype=np.int32).reshape(
            batch, full_blocks_per_batch)

        selected_kv = np.zeros(
            (batch * selected_blocks_per_token, block_size, kv_dim), dtype=np.float16)
        selected_rope = np.zeros(
            (batch * selected_blocks_per_token, block_size, rope_dim), dtype=np.float16)
        selected_table = np.arange(batch * selected_blocks_per_token, dtype=np.int32).reshape(
            batch, selected_blocks_per_token)
        status = np.full((batch, 1, topk + 1), -1, dtype=np.int32)
        topk_indices = np.stack([
            rng.choice(full_seq, size=topk, replace=False) for _ in range(batch)
        ]).astype(np.int32).reshape(batch, 1, topk)

        selected_kv_npu = torch.from_numpy(selected_kv).npu()
        selected_rope_npu = torch.from_numpy(selected_rope).npu()
        selected_table_npu = torch.from_numpy(selected_table).npu()
        status_npu = torch.from_numpy(status).npu()
        # The model's offload path exposes Host DRAM through an NPU-addressable
        # swapped tensor. Keep the golden NumPy arrays on CPU and populate the
        # Host-backed storage through its NPU-visible tensor.
        npu_device = torch.device(f"npu:{torch_npu.npu.current_device()}")
        full_kv_npu = torch_npu.empty_with_swapped_memory(
            full_kv.shape, dtype=torch.float16, device=npu_device)
        full_kv_npu.fill_(0)
        full_kv_npu.add_(torch.from_numpy(full_kv).to(npu_device))
        full_rope_npu = torch_npu.empty_with_swapped_memory(
            full_rope.shape, dtype=torch.float16, device=npu_device)
        full_rope_npu.fill_(0)
        full_rope_npu.add_(torch.from_numpy(full_rope).to(npu_device))
        full_table_npu = torch.from_numpy(full_table).npu()
        full_actual_npu = torch.full((batch,), full_seq, dtype=torch.int32, device="npu")
        q_actual_npu = torch.ones((batch,), dtype=torch.int32, device="npu")

        def run(indices, expected_valid):
            actual = torch.ops.umdk_cam_op_lib.gather_selection_kv_cache_custom(
                selected_rope_npu, selected_kv_npu, selected_table_npu, status_npu,
                torch.from_numpy(indices).npu(), full_rope_npu, full_kv_npu,
                full_table_npu, full_actual_npu, q_actual_npu,
                selection_topk_block_size=1)
            torch_npu.npu.synchronize()
            self.assertRtolEqual(actual.cpu().numpy(), np.full((batch,), expected_valid, dtype=np.int32))
            self._assert_selected_values(
                indices.reshape(batch, topk)[:, :expected_valid], status_npu.cpu().numpy(),
                selected_kv_npu.cpu().numpy(), selected_rope_npu.cpu().numpy(),
                selected_table, full_kv, full_rope, full_table, block_size)

        run(topk_indices, topk)

        # Randomly mix same-token hits and full-KV misses. Override with, e.g.:
        #   GATHER_CUSTOM_MISS_RATE=0.25 python3 test_npu_gather_selection_kv_cache_custom.py
        miss_rate = float(os.environ.get("GATHER_CUSTOM_MISS_RATE", "0.5"))
        if not 0.0 <= miss_rate <= 1.0:
            raise ValueError("GATHER_CUSTOM_MISS_RATE must be in [0, 1]")
        next_indices = topk_indices.copy().reshape(batch, topk)
        for batch_idx in range(batch):
            old_ids = set(next_indices[batch_idx].tolist())
            choices = np.array([idx for idx in range(full_seq) if idx not in old_ids], dtype=np.int32)
            miss_mask = rng.random(topk) < miss_rate
            miss_num = int(miss_mask.sum())
            if miss_num > 0:
                next_indices[batch_idx, miss_mask] = rng.choice(
                    choices, size=miss_num, replace=False)
        run(next_indices.reshape(batch, 1, topk), topk)

        # Select ids currently stored in the upper half and pad the request with -1.
        # This forces selected-cache compaction into lower holes before the all-core phase.
        current_status = status_npu.cpu().numpy().reshape(batch, topk + 1)
        compact_indices = np.full((batch, 1, topk), -1, dtype=np.int32)
        for batch_idx in range(batch):
            compact_indices[batch_idx, 0, : topk // 2] = current_status[batch_idx, topk // 2 : topk]
        run(compact_indices, topk // 2)

    def _assert_selected_values(
        self, topk_indices, status, selected_kv, selected_rope,
        selected_table, full_kv, full_rope, full_table, block_size,
    ):
        batch, valid_num = topk_indices.shape
        cache_topk = status.shape[-1] - 1
        status = status.reshape(batch, cache_topk + 1)
        for batch_idx in range(batch):
            self.assertEqual(int(status[batch_idx, cache_topk]), valid_num)
            for topk_id in topk_indices[batch_idx]:
                positions = np.flatnonzero(status[batch_idx, :cache_topk] == topk_id)
                if len(positions) != 1:
                    self.fail(
                        f"batch={batch_idx}, topk_id={int(topk_id)}, positions={positions.tolist()}, "
                        f"valid_num={valid_num}, requested={topk_indices[batch_idx].tolist()}, "
                        f"status={status[batch_idx].tolist()}"
                    )
                selected_pos = int(positions[0])
                selected_block = selected_table[batch_idx, selected_pos // block_size]
                selected_offset = selected_pos % block_size
                full_block = full_table[batch_idx, int(topk_id) // block_size]
                full_offset = int(topk_id) % block_size
                self.assertRtolEqual(
                    selected_kv[selected_block, selected_offset], full_kv[full_block, full_offset])
                self.assertRtolEqual(
                    selected_rope[selected_block, selected_offset], full_rope[full_block, full_offset])


if __name__ == "__main__":
    run_tests()
