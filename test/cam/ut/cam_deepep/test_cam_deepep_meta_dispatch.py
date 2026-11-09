#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: CPU-only Meta tests for the two cam_deepep_dispatch_* operators
# Create: 2026-11-04
# Note: exercises op registration, the pybind schema (including the mutation
#       aliases), and the Meta kernels' validation plus their identity return
#       of the caller-owned buffers. No NPU or HCCL is required.
# History: 2026-11-04 create file
#          2026-11-05 real dtype/shape cases, alias identity, negative cases
#

import pytest

torch = pytest.importorskip("torch", reason="torch is not installed")
pytest.importorskip("umdk_cam_op_lib", reason="umdk_cam_op_lib wheel is not installed")


def meta_tensor(shape, dtype):
    return torch.empty(shape, dtype=dtype, device="meta")


def assert_aliases(out, ref):
    """The Meta kernel must return the caller's buffer, not a new allocation."""
    assert out is ref, "Meta kernel returned a fresh tensor instead of the mutable input"


def schema_of(op):
    # _get_schema wants the fully qualified name; the second argument is the
    # overload name, not the namespace.
    return str(torch._C._get_schema("umdk_cam_op_lib::" + op, ""))


class TestCamDeepepDispatchMeta:
    def test_schema_marks_mutable_inputs(self):
        send = schema_of("cam_deepep_dispatch_send")
        # round_ledger / afd_workspace / control_buffer / send_status are written
        # in place, and the single output is the caller's status buffer.
        assert "Tensor(a!) control_buffer" in send
        assert "Tensor(b!) round_ledger" in send
        assert "Tensor(c!) afd_workspace" in send
        assert "Tensor(d!) send_status" in send
        assert "-> Tensor(d!)" in send

        recv = schema_of("cam_deepep_dispatch_recv")
        # The three preallocated receive buffers are both written and returned.
        assert "Tensor(a!) recv_x" in recv
        assert "Tensor(b!) recv_sf" in recv
        assert "Tensor(c!) recv_src_metadata" in recv
        assert "-> (Tensor(a!), Tensor(b!), Tensor(c!))" in recv
        # The receive path advances execution_state and the scratch workspace.
        assert "Tensor(d!) execution_state" in recv
        assert "Tensor(e!) afd_workspace" in recv

    def test_dispatch_send(self):
        x = meta_tensor([4, 128], torch.bfloat16)
        sf = meta_tensor([4, 1], torch.int16)
        topk_idx = meta_tensor([4, 2], torch.int64)
        topk_weights = meta_tensor([4, 2], torch.float32)
        token_mask = meta_tensor([4], torch.bool)
        task_info = meta_tensor([64], torch.uint8)
        context = meta_tensor([256], torch.uint8)
        control_buffer = meta_tensor([1024], torch.uint8)
        round_ledger = meta_tensor([256], torch.uint8)
        afd_workspace = meta_tensor([1024], torch.uint8)
        jetty_ptrs = meta_tensor([8], torch.int64)
        send_status = meta_tensor([16], torch.int32)

        out = torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
            x, sf, topk_idx, topk_weights, token_mask, task_info, context,
            control_buffer, round_ledger, afd_workspace, jetty_ptrs,
            send_status, "test_group", 2, 2, 2, 2, 1, 1, 1, 1000, 16, 1,
        )
        assert_aliases(out, send_status)

    def test_dispatch_send_accepts_dummy_sf_when_unpacked(self):
        # bf16 carries no scale factors: the harness passes a one-element int16
        # dummy and num_sf_packs = 0, so no packed layout may be required.
        x = meta_tensor([4, 128], torch.bfloat16)
        sf = meta_tensor([1], torch.int16)
        send_status = meta_tensor([8], torch.int32)
        out = torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
            x, sf, meta_tensor([4, 2], torch.int64), meta_tensor([4, 2], torch.float32),
            meta_tensor([4], torch.bool), meta_tensor([64], torch.uint8),
            meta_tensor([256], torch.uint8), meta_tensor([1024], torch.uint8),
            meta_tensor([256], torch.uint8), meta_tensor([1024], torch.uint8),
            meta_tensor([8], torch.int64), send_status, "test_group",
            2, 2, 2, 2, 0, 0, 0, 1000, 8, 1,
        )
        assert_aliases(out, send_status)

    def test_dispatch_recv(self):
        payload = meta_tensor([1024], torch.uint8)
        context = meta_tensor([256], torch.uint8)
        active = meta_tensor([16], torch.uint8)
        execution_state = meta_tensor([16], torch.uint8)
        afd_workspace = meta_tensor([1024], torch.uint8)
        control_buffer = meta_tensor([1024], torch.uint8)
        recv_x = meta_tensor([8, 128], torch.bfloat16)
        recv_sf = meta_tensor([8, 1], torch.int16)
        recv_src_metadata = meta_tensor([8, 4], torch.int32)

        outs = torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
            payload, context, active, execution_state, afd_workspace,
            control_buffer, recv_x, recv_sf, recv_src_metadata, "test_group",
            2, 2, 2, 2, 1, 8, 8, 1, 4, 0, 1, 1, 1024, 1024, 256, 128, 1, 1,
        )
        assert len(outs) == 3
        for out, ref in zip(outs, (recv_x, recv_sf, recv_src_metadata)):
            assert_aliases(out, ref)

    def test_dispatch_recv_bf16_empty_scale_factors(self):
        # The real bf16 receive buffer is [rows, 0] int16 (no scale factors).
        recv_x = meta_tensor([8, 128], torch.bfloat16)
        recv_sf = meta_tensor([8, 0], torch.int16)
        recv_src_metadata = meta_tensor([8, 4], torch.int32)
        outs = torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
            meta_tensor([1024], torch.uint8), meta_tensor([256], torch.uint8),
            meta_tensor([16], torch.uint8), meta_tensor([16], torch.uint8),
            meta_tensor([1024], torch.uint8), meta_tensor([1024], torch.uint8),
            recv_x, recv_sf, recv_src_metadata, "test_group",
            2, 2, 2, 2, 1, 8, 8, 1, 4, 0, 1, 1, 1024, 1024, 256, 128, 0, 1,
        )
        for out, ref in zip(outs, (recv_x, recv_sf, recv_src_metadata)):
            assert_aliases(out, ref)


class TestCamDeepepDispatchMetaRejects:
    """The Meta kernel must reject what TilingFunc would reject on device."""

    @staticmethod
    def send_args(**overrides):
        args = dict(
            x=meta_tensor([4, 128], torch.bfloat16),
            sf=meta_tensor([4, 1], torch.int16),
            topk_idx=meta_tensor([4, 2], torch.int64),
            topk_weights=meta_tensor([4, 2], torch.float32),
            token_mask=meta_tensor([4], torch.bool),
            task_info=meta_tensor([64], torch.uint8),
            context=meta_tensor([256], torch.uint8),
            control_buffer=meta_tensor([1024], torch.uint8),
            round_ledger=meta_tensor([256], torch.uint8),
            afd_workspace=meta_tensor([1024], torch.uint8),
            jetty_ptrs=meta_tensor([8], torch.int64),
            send_status=meta_tensor([16], torch.int32),
        )
        args.update(overrides)
        return [
            args["x"], args["sf"], args["topk_idx"], args["topk_weights"],
            args["token_mask"], args["task_info"], args["context"],
            args["control_buffer"], args["round_ledger"], args["afd_workspace"],
            args["jetty_ptrs"], args["send_status"], "test_group",
        ]

    def test_send_rejects_topk_idx_dtype(self):
        with pytest.raises(RuntimeError, match="topk_idx must have dtype"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
                *self.send_args(topk_idx=meta_tensor([4, 2], torch.int32)),
                2, 2, 2, 2, 1, 1, 1, 1000, 16, 1,
            )

    def test_send_rejects_experts_not_divisible_by_ranks(self):
        with pytest.raises(RuntimeError, match="num_experts must divide by num_ranks"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
                *self.send_args(), 2, 3, 2, 2, 1, 1, 1, 1000, 16, 1,
            )

    def test_send_rejects_zero_timeout(self):
        with pytest.raises(RuntimeError, match="timeout_cycles must be positive"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
                *self.send_args(), 2, 2, 2, 2, 1, 1, 1, 0, 16, 1,
            )

    def test_send_rejects_negative_sf_stride(self):
        with pytest.raises(RuntimeError, match="sf strides must be nonnegative"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
                *self.send_args(), 2, 2, 2, 2, -1, 1, 1, 1000, 16, 1,
            )

    def test_send_rejects_status_len_mismatch(self):
        with pytest.raises(RuntimeError, match="send_status must be"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_send(
                *self.send_args(send_status=meta_tensor([8], torch.int32)),
                2, 2, 2, 2, 1, 1, 1, 1000, 16, 1,
            )

    @staticmethod
    def recv_args(**overrides):
        args = dict(
            payload=meta_tensor([1024], torch.uint8),
            context=meta_tensor([256], torch.uint8),
            active=meta_tensor([16], torch.uint8),
            execution_state=meta_tensor([16], torch.uint8),
            afd_workspace=meta_tensor([1024], torch.uint8),
            control_buffer=meta_tensor([1024], torch.uint8),
            recv_x=meta_tensor([8, 128], torch.bfloat16),
            recv_sf=meta_tensor([8, 1], torch.int16),
            recv_src_metadata=meta_tensor([8, 4], torch.int32),
        )
        args.update(overrides)
        return [
            args["payload"], args["context"], args["active"],
            args["execution_state"], args["afd_workspace"], args["control_buffer"],
            args["recv_x"], args["recv_sf"], args["recv_src_metadata"], "test_group",
        ]

    def test_recv_rejects_wrong_output_dtype(self):
        with pytest.raises(RuntimeError, match="recv_sf must have dtype"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
                *self.recv_args(recv_sf=meta_tensor([8, 1], torch.uint8)),
                2, 2, 2, 2, 1, 8, 8, 1, 4, 0, 1, 1, 1024, 1024, 256, 128, 1, 1,
            )

    def test_recv_rejects_wrong_output_shape(self):
        with pytest.raises(RuntimeError, match="recv_sf must be"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
                *self.recv_args(recv_sf=meta_tensor([8, 8], torch.int16)),
                2, 2, 2, 2, 1, 8, 8, 1, 4, 0, 1, 1, 1024, 1024, 256, 128, 1, 1,
            )

    def test_recv_rejects_bad_stage_count(self):
        with pytest.raises(RuntimeError, match="num_tokens_per_stage out of range"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
                *self.recv_args(),
                2, 2, 2, 2, 1, 8, 8, 1, 3, 0, 1, 1, 1024, 1024, 256, 128, 1, 1,
            )

    def test_recv_rejects_padding_below_alignment(self):
        with pytest.raises(RuntimeError, match="one expert_alignment"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
                *self.recv_args(),
                2, 2, 2, 2, 1, 8, 8, 128, 4, 0, 1, 1, 1024, 1024, 256, 128, 1, 1,
            )

    def test_recv_rejects_rank_index_out_of_range(self):
        with pytest.raises(RuntimeError, match="rank_idx out of range"):
            torch.ops.umdk_cam_op_lib.cam_deepep_dispatch_recv(
                *self.recv_args(),
                2, 2, 2, 2, 1, 8, 8, 1, 4, 2, 1, 1, 1024, 1024, 256, 128, 1, 1,
            )
