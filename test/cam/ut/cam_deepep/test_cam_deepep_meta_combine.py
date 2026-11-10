#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: CPU-only Meta tests for the two cam_deepep_combine_* operators
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


class TestCamDeepepCombineMeta:
    def test_schema_marks_mutable_inputs(self):
        send = schema_of("cam_deepep_combine_send")
        # The send path advances the caller's control plane and fills completion.
        assert "Tensor(a!) control_buffer" in send
        assert "Tensor(b!) execution_state" in send
        assert "Tensor(c!) afd_workspace" in send
        assert "Tensor(d!) completion" in send
        assert "-> Tensor(d!)" in send

        recv = schema_of("cam_deepep_combine_recv")
        # The five preallocated receive buffers are both written and returned.
        assert "Tensor(d!) combined_x" in recv
        assert "Tensor(e!) combined_topk_idx" in recv
        assert "Tensor(f!) topk_weights" in recv
        assert "Tensor(g!) recv_status" in recv
        assert "Tensor(h!) return_progress" in recv
        assert "-> (Tensor(d!), Tensor(e!), Tensor(f!), Tensor(g!), Tensor(h!))" in recv
        # The receive path also advances round_ledger, the scratch workspace and
        # the peer credit stores that may target the local control buffer.
        assert "Tensor(a!) control_buffer" in recv
        assert "Tensor(b!) round_ledger" in recv
        assert "Tensor(c!) afd_workspace" in recv

    def test_combine_send(self):
        x = meta_tensor([8, 128], torch.bfloat16)
        src_metadata = meta_tensor([8, 4], torch.int32)
        context = meta_tensor([256], torch.uint8)
        active = meta_tensor([16], torch.uint8)
        control_buffer = meta_tensor([1024], torch.uint8)
        execution_state = meta_tensor([16], torch.uint8)
        afd_workspace = meta_tensor([1024], torch.uint8)
        jetty_ptrs = meta_tensor([8], torch.int64)
        completion = meta_tensor([16], torch.uint8)

        out = torch.ops.umdk_cam_op_lib.cam_deepep_combine_send(
            x, src_metadata, context, active, control_buffer, execution_state,
            afd_workspace, jetty_ptrs, completion, "test_group",
            2, 2, 2, 2, 2, 1, 8, 2, 0, 1000, 16, 1,
        )
        assert_aliases(out, completion)

    def test_combine_recv(self):
        payload = meta_tensor([1024], torch.uint8)
        task_info = meta_tensor([64], torch.uint8)
        context = meta_tensor([256], torch.uint8)
        control_buffer = meta_tensor([1024], torch.uint8)
        round_ledger = meta_tensor([256], torch.uint8)
        afd_workspace = meta_tensor([1024], torch.uint8)
        token_mask = meta_tensor([4], torch.bool)
        combined_x = meta_tensor([4, 128], torch.bfloat16)
        combined_topk_idx = meta_tensor([4, 2], torch.int64)
        topk_weights = meta_tensor([4, 2], torch.float32)
        recv_status = meta_tensor([16], torch.int32)
        return_progress = meta_tensor([16], torch.uint8)

        outs = torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
            payload, task_info, context, control_buffer, round_ledger,
            afd_workspace, token_mask, combined_x, combined_topk_idx,
            topk_weights, recv_status, return_progress, "test_group",
            2, 2, 2, 1, 0, 128, 4, 16, 16, 1000, 1,
        )
        assert len(outs) == 5
        refs = (combined_x, combined_topk_idx, topk_weights, recv_status, return_progress)
        for out, ref in zip(outs, refs):
            assert_aliases(out, ref)

    def test_combine_recv_single_round_has_no_progress_bytes(self):
        # Without --round-step the harness passes return_progress_bytes = 0 and
        # an empty uint8 progress tensor.
        combined_x = meta_tensor([4, 128], torch.bfloat16)
        combined_topk_idx = meta_tensor([4, 2], torch.int64)
        topk_weights = meta_tensor([4, 2], torch.float32)
        recv_status = meta_tensor([8], torch.int32)
        return_progress = meta_tensor([0], torch.uint8)
        outs = torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
            meta_tensor([1024], torch.uint8), meta_tensor([64], torch.uint8),
            meta_tensor([256], torch.uint8), meta_tensor([1024], torch.uint8),
            meta_tensor([256], torch.uint8), meta_tensor([1024], torch.uint8),
            meta_tensor([4], torch.bool), combined_x, combined_topk_idx,
            topk_weights, recv_status, return_progress, "test_group",
            2, 2, 2, 0, 1, 128, 4, 8, 0, 1000, 1,
        )
        for out, ref in zip(outs, (combined_x, combined_topk_idx, topk_weights,
                                   recv_status, return_progress)):
            assert_aliases(out, ref)


class TestCamDeepepCombineMetaRejects:
    """The Meta kernel must reject what TilingFunc would reject on device."""

    @staticmethod
    def send_args(**overrides):
        args = dict(
            x=meta_tensor([8, 128], torch.bfloat16),
            src_metadata=meta_tensor([8, 4], torch.int32),
            context=meta_tensor([256], torch.uint8),
            active=meta_tensor([16], torch.uint8),
            control_buffer=meta_tensor([1024], torch.uint8),
            execution_state=meta_tensor([16], torch.uint8),
            afd_workspace=meta_tensor([1024], torch.uint8),
            jetty_ptrs=meta_tensor([8], torch.int64),
            completion=meta_tensor([16], torch.uint8),
        )
        args.update(overrides)
        return [
            args["x"], args["src_metadata"], args["context"], args["active"],
            args["control_buffer"], args["execution_state"], args["afd_workspace"],
            args["jetty_ptrs"], args["completion"], "test_group",
        ]

    def test_send_rejects_completion_dtype(self):
        with pytest.raises(RuntimeError, match="completion must have dtype"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_send(
                *self.send_args(completion=meta_tensor([16], torch.int32)),
                2, 2, 2, 2, 2, 1, 8, 2, 0, 1000, 16, 1,
            )

    def test_send_rejects_rows_below_padded_tokens(self):
        with pytest.raises(RuntimeError, match="x rows must cover max_padded_tokens"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_send(
                *self.send_args(x=meta_tensor([4, 128], torch.bfloat16),
                                src_metadata=meta_tensor([4, 4], torch.int32)),
                2, 2, 2, 2, 2, 1, 8, 2, 0, 1000, 16, 1,
            )

    def test_send_rejects_bad_tile_size(self):
        with pytest.raises(RuntimeError, match="num_tokens_per_tile out of range"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_send(
                *self.send_args(),
                2, 2, 2, 2, 2, 1, 8, 129, 0, 1000, 16, 1,
            )

    @staticmethod
    def recv_args(**overrides):
        args = dict(
            payload=meta_tensor([1024], torch.uint8),
            task_info=meta_tensor([64], torch.uint8),
            context=meta_tensor([256], torch.uint8),
            control_buffer=meta_tensor([1024], torch.uint8),
            round_ledger=meta_tensor([256], torch.uint8),
            afd_workspace=meta_tensor([1024], torch.uint8),
            token_mask=meta_tensor([4], torch.bool),
            combined_x=meta_tensor([4, 128], torch.bfloat16),
            combined_topk_idx=meta_tensor([4, 2], torch.int64),
            topk_weights=meta_tensor([4, 2], torch.float32),
            recv_status=meta_tensor([16], torch.int32),
            return_progress=meta_tensor([16], torch.uint8),
        )
        args.update(overrides)
        return [
            args["payload"], args["task_info"], args["context"],
            args["control_buffer"], args["round_ledger"], args["afd_workspace"],
            args["token_mask"], args["combined_x"], args["combined_topk_idx"],
            args["topk_weights"], args["recv_status"], args["return_progress"],
            "test_group",
        ]

    def test_recv_rejects_topk_idx_dtype(self):
        with pytest.raises(RuntimeError, match="combined_topk_idx must have dtype"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
                *self.recv_args(combined_topk_idx=meta_tensor([4, 2], torch.int32)),
                2, 2, 2, 1, 0, 128, 4, 16, 16, 1000, 1,
            )

    def test_recv_rejects_hidden_not_multiple_of_128(self):
        with pytest.raises(RuntimeError, match="multiple of 128"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
                *self.recv_args(combined_x=meta_tensor([4, 130], torch.bfloat16)),
                2, 2, 2, 1, 0, 130, 4, 16, 16, 1000, 1,
            )

    def test_recv_rejects_progress_byte_mismatch(self):
        with pytest.raises(RuntimeError, match="carry return_progress_bytes bytes"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
                *self.recv_args(return_progress=meta_tensor([8], torch.uint8)),
                2, 2, 2, 1, 0, 128, 4, 16, 16, 1000, 1,
            )

    def test_recv_rejects_bad_round_step(self):
        with pytest.raises(RuntimeError, match="round_step must be 0 or 1"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
                *self.recv_args(),
                2, 2, 2, 2, 0, 128, 4, 16, 16, 1000, 1,
            )

    def test_recv_rejects_status_len_mismatch(self):
        with pytest.raises(RuntimeError, match="recv_status must be"):
            torch.ops.umdk_cam_op_lib.cam_deepep_combine_recv(
                *self.recv_args(recv_status=meta_tensor([8], torch.int32)),
                2, 2, 2, 1, 0, 128, 4, 16, 16, 1000, 1,
            )
