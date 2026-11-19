#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: CPU-only tests for the cam_deepep send write path: batched SQE
#              final flags (one completion per issue batch) and the per-lane UB
#              cache that keeps the combine_send record loop off the GM path
# Create: 2026-11-06
# Note: needs neither an NPU nor the AscendC toolchain. The device code cannot be
#       compiled here, so every claim is pinned twice:
#         1. a literal Python model of issue_write_wqe / issue_write_task
#            (deep_ep/impls/afd/dispatch_send.h) and of HcommJetty's packed_head
#            bookkeeping (deep_ep/comm/handle.h), asserted on WQE words and on
#            the completion counter;
#         2. structural assertions on the C++ source, so the model cannot drift
#            away from the kernel it mirrors without failing here.
#       Both copies of the write path are covered: the vendored templates under
#       deep_ep/impls/afd/ and the runtime-parameterized copy the CAM operators
#       actually compile (cam_deepep_rt_common.h, cam_deepep_*_send_rt.h).
#       Not covered (must be validated in CI / on hardware): the DMA itself, the
#       CQE owner-bit flip, CQ wraparound, fence latency and the actual us gain.
# History: 2026-11-06 create file
#

import ast
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
KERNEL_ROOT = REPO_ROOT / "src" / "cam" / "comm_operator" / "ascend_kernels" / "utils" / "op_kernel"
DISPATCH_SEND_H = KERNEL_ROOT / "deep_ep" / "impls" / "afd" / "dispatch_send.h"
COMBINE_SEND_H = KERNEL_ROOT / "deep_ep" / "impls" / "afd" / "combine_send.h"
HANDLE_H = KERNEL_ROOT / "deep_ep" / "comm" / "handle.h"
# The CAM operators compile the runtime-parameterized copy of the same write
# path, so both copies have to carry the identical SQE encoding.
RT_COMMON_H = KERNEL_ROOT / "cam_deepep_rt_common.h"
OPERATOR_ROOT = KERNEL_ROOT.parents[1]  # src/cam/comm_operator/ascend_kernels
DISPATCH_SEND_RT_H = OPERATOR_ROOT / "cam_deepep_dispatch_send" / "op_kernel" / "cam_deepep_dispatch_send_rt.h"
COMBINE_SEND_RT_H = OPERATOR_ROOT / "cam_deepep_combine_send" / "op_kernel" / "cam_deepep_combine_send_rt.h"

if not DISPATCH_SEND_H.exists():  # pragma: no cover - wheel-only checkouts
    pytest.skip("cam_deepep kernel headers are not part of this checkout", allow_module_level=True)

# One 64B WQEBB is eight u64 words; the header word lives in lane 0 of a WQEBB.
WQEBB_WORDS = 8
OWNER_BIT = 31
ODR_SHIFT, ODR_MASK = 16, 0b111
FENCE_BIT = 19
CQE_BIT = 21
OPCODE_SHIFT = 40


def _eval_int_expr(expr):
    """Evaluate the small integer subset used by the SQE header constants."""
    expr = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]{1,3}\b", r"\1", expr)

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp):
            left, right = visit(node.left), visit(node.right)
            for op, func in ((ast.BitOr, lambda a, b: a | b), (ast.BitAnd, lambda a, b: a & b),
                             (ast.LShift, lambda a, b: a << b), (ast.RShift, lambda a, b: a >> b),
                             (ast.Add, lambda a, b: a + b), (ast.Sub, lambda a, b: a - b),
                             (ast.Mult, lambda a, b: a * b), (ast.FloorDiv, lambda a, b: a // b)):
                if isinstance(node.op, op):
                    return func(left, right)
        raise ValueError("unsupported C++ constant expression: " + expr)

    return visit(ast.parse(expr.strip(), mode="eval"))


def _cpp_const(source, name):
    pattern = r"^\s*(?:static\s+)?constexpr\s+[A-Za-z_][\w:]*\s+" + name + r"\s*=\s*([^;]+);"
    match = re.search(pattern, source, re.MULTILINE)
    assert match is not None, "constant " + name + " not found in the kernel headers"
    return _eval_int_expr(match.group(1))


def _cpp_sizeof(source, type_name):
    match = re.search(r"static_assert\(sizeof\(" + re.escape(type_name) + r"\) == (\d+)\);", source)
    assert match is not None, "sizeof(" + type_name + ") static_assert not found"
    return int(match.group(1))


def _macro_value(source, name):
    match = re.search(r"^\s*#define\s+" + name + r"\s+(\S+)\s*$", source, re.MULTILINE)
    return None if match is None else match.group(1)


DISPATCH_SEND_SRC = DISPATCH_SEND_H.read_text(encoding="utf-8")
COMBINE_SEND_SRC = COMBINE_SEND_H.read_text(encoding="utf-8")
HANDLE_SRC = HANDLE_H.read_text(encoding="utf-8")
RT_COMMON_SRC = RT_COMMON_H.read_text(encoding="utf-8")
DISPATCH_SEND_RT_SRC = DISPATCH_SEND_RT_H.read_text(encoding="utf-8")
COMBINE_SEND_RT_SRC = COMBINE_SEND_RT_H.read_text(encoding="utf-8")

# Constants are parsed, not copied: a header edit that changes the encoding
# without touching this file fails the model tests below.
HEADER_TEMPLATE = _cpp_const(HANDLE_SRC, "kWriteSQEHeaderTemplate")
FINAL_FLAGS = _cpp_const(HANDLE_SRC, "kWriteSQEFinalFlags")
SQ_DEPTH = _cpp_const(HANDLE_SRC, "kSQDepth")
PENDING_WRITES = _cpp_const(DISPATCH_SEND_SRC, "kNumMaxPendingWrites")
WRITES_PER_TASK = _cpp_const(DISPATCH_SEND_SRC, "kNumWritesPerTask")
SQE_HEADER_BYTES = _cpp_sizeof(DISPATCH_SEND_SRC, "AscendC::HcommUrmaSqeCtx")
SGE_BYTES = _cpp_sizeof(DISPATCH_SEND_SRC, "AscendC::HcommUrmaSgeCtx")
# Runtime-parameterized copy (what the CAM operators actually compile).
RT_PENDING_WRITES = _cpp_const(RT_COMMON_SRC, "kNumMaxPendingWrites")
RT_WRITES_PER_TASK = _cpp_const(RT_COMMON_SRC, "kNumWritesPerTask")


def wqebbs_per_token(num_sges):
    """issue_write_wqe's kNumWQEBBsPerToken = (48 + 16 * kNumSGEs + 63) / 64."""
    return (SQE_HEADER_BYTES + SGE_BYTES * num_sges + 63) // 64


def batches(num_records, per_batch=WRITES_PER_TASK):
    """append_write_task emits one batch per WRITES_PER_TASK records plus a tail."""
    sizes, left = [], num_records
    while left > 0:
        take = min(per_batch, left)
        sizes.append(take)
        left -= take
    return sizes


class SendSqeRing:
    """Python twin of the HcommJetty SQ ring and packed_head completion accounting.

    issue() is issue_write_task (one batch), ring_doorbell()/reload() round-trip
    the packed head exactly like HcommJetty, and drain() is
    handle::HcommJetty::drain() waiting for packed_head[63:32] completions.
    """

    def __init__(self, num_sges, batched=True):
        self.num_sges = num_sges
        self.batched = batched
        self.wqebbs = wqebbs_per_token(num_sges)
        self.packed_head = 0
        self.sq = {}
        self.sq_head_gm = 0
        self.num_cqes = 0

    @property
    def head(self):
        return self.packed_head & 0xFFFFFFFF

    @property
    def completions(self):
        return self.packed_head >> 32

    def encode_header(self, token_idx, num_tokens, token_sqebb):
        word = HEADER_TEMPLATE
        if not self.batched or token_idx + 1 == num_tokens:
            word |= FINAL_FLAGS
        word |= ((token_sqebb & SQ_DEPTH) == 0) << OWNER_BIT
        word |= token_sqebb & (SQ_DEPTH - 1)
        return word

    def issue(self, num_tokens):
        assert num_tokens > 0, "issue_write_task returns early on an empty batch"
        assert num_tokens <= WRITES_PER_TASK
        batch_head = self.head
        headers = []
        for token_idx in range(num_tokens):
            token_sqebb = batch_head + token_idx * self.wqebbs
            word = self.encode_header(token_idx, num_tokens, token_sqebb)
            headers.append((token_sqebb, word))
            for lane_idx in range(self.wqebbs * WQEBB_WORDS):
                value = word if lane_idx == 0 else 0
                bb = (token_sqebb + lane_idx // WQEBB_WORDS) & (SQ_DEPTH - 1)
                self.sq.setdefault(bb, [0] * WQEBB_WORDS)[lane_idx % WQEBB_WORDS] = value
        # Device side: one CQE per SQE that requested one (cqe bit in the header).
        self.num_cqes += sum(1 for _, word in headers if (word >> CQE_BIT) & 1)
        completions = self.completions + (1 if self.batched else num_tokens)
        self.packed_head = ((batch_head + num_tokens * self.wqebbs) & 0xFFFFFFFF) | \
                           ((completions & 0xFFFFFFFF) << 32)
        return headers

    def scalar_put(self):
        """handle::HcommJetty::put(): one SQE, always final flags, advance_sq(+1)."""
        head = self.head
        self.sq.setdefault(head & (SQ_DEPTH - 1), [0] * WQEBB_WORDS)[0] = \
            HEADER_TEMPLATE | FINAL_FLAGS
        self.num_cqes += 1
        self.packed_head = ((head + 1) & 0xFFFFFFFF) | (((self.completions + 1) & 0xFFFFFFFF) << 32)

    def ring_doorbell(self):
        self.sq_head_gm = self.packed_head

    def reload(self):
        """A new HcommJetty object re-reads packed_head from sq_head_addr."""
        self.packed_head = self.sq_head_gm

    def drain(self):
        """drain() polls poll_cq(packed_head[63:32]); it must already be satisfiable."""
        assert self.completions == self.num_cqes, (
            "drain() waits for " + str(self.completions) + " CQEs but the encoded SQEs "
            "only produce " + str(self.num_cqes))
        return self.num_cqes


class TestCamDeepepSqeBatching:
    def test_header_template_and_final_flags_bits(self):
        assert (HEADER_TEMPLATE >> ODR_SHIFT) & ODR_MASK == 1
        assert not (HEADER_TEMPLATE >> FENCE_BIT) & 1
        assert not (HEADER_TEMPLATE >> CQE_BIT) & 1
        assert (HEADER_TEMPLATE >> OPCODE_SHIFT) & 0xFF == 0x03  # WRITE
        # odr=5|fence|cqe is exactly what the batch tail adds.
        assert (FINAL_FLAGS >> ODR_SHIFT) & ODR_MASK == 0b100
        assert (FINAL_FLAGS >> FENCE_BIT) & 1
        assert (FINAL_FLAGS >> CQE_BIT) & 1

    @pytest.mark.parametrize("num_sges", [1, 2])
    def test_only_last_sqe_of_a_batch_carries_final_flags(self, num_sges):
        ring = SendSqeRing(num_sges)
        headers = ring.issue(WRITES_PER_TASK)
        assert len(headers) == WRITES_PER_TASK
        with_flags = [idx for idx, (_, word) in enumerate(headers) if (word >> CQE_BIT) & 1]
        assert with_flags == [WRITES_PER_TASK - 1], "only the batch tail may request a CQE"
        for idx, (_, word) in enumerate(headers):
            assert (word >> FENCE_BIT) & 1 == (idx == WRITES_PER_TASK - 1)
            assert (word >> ODR_SHIFT) & ODR_MASK == (5 if idx == WRITES_PER_TASK - 1 else 1)

    def test_legacy_mode_keeps_one_completion_per_record(self):
        ring = SendSqeRing(2, batched=False)
        ring.issue(WRITES_PER_TASK)
        assert ring.completions == WRITES_PER_TASK
        assert ring.num_cqes == WRITES_PER_TASK

    def test_completion_count_advances_once_per_batch(self):
        ring = SendSqeRing(2)
        sizes = batches(35)  # 8 + 8 + 8 + 8 + 3
        assert sizes == [8, 8, 8, 8, 3]
        for size in sizes:
            ring.issue(size)
        assert ring.completions == len(sizes)
        assert ring.completions == ring.num_cqes
        assert ring.drain() == len(sizes)
        # The SQ head still advances per SQE, independently of the completion half.
        assert ring.head == 35 * wqebbs_per_token(2)

    def test_drain_proves_each_flush_group_with_its_last_cqe(self):
        ring = SendSqeRing(2)
        issued = 0
        for size in batches(PENDING_WRITES):  # one flush group: 4 batches / 32 records
            ring.issue(size)
            issued += size
        assert issued == PENDING_WRITES
        assert ring.completions == PENDING_WRITES // WRITES_PER_TASK
        ring.ring_doorbell()
        assert ring.drain() == PENDING_WRITES // WRITES_PER_TASK

    def test_single_record_batch_is_identical_to_the_legacy_encoding(self):
        batched, legacy = SendSqeRing(2), SendSqeRing(2, batched=False)
        assert batched.issue(1) == legacy.issue(1)
        assert batched.completions == legacy.completions == 1

    def test_partial_tail_batch_still_flags_its_last_record(self):
        ring = SendSqeRing(1)
        headers = ring.issue(3)
        assert [(word >> CQE_BIT) & 1 for _, word in headers] == [0, 0, 1]
        assert ring.completions == 1

    @pytest.mark.parametrize("num_sges", [1, 2])
    def test_sq_wrap_keeps_owner_bit_and_batch_tail(self, num_sges):
        ring = SendSqeRing(num_sges)
        # Park the head just before the wrap so the batch straddles it.
        ring.packed_head = SQ_DEPTH - 1
        headers = ring.issue(WRITES_PER_TASK)
        assert [sqebb & (SQ_DEPTH - 1) for sqebb, _ in headers][-1] == \
            (SQ_DEPTH - 1 + (WRITES_PER_TASK - 1) * ring.wqebbs) & (SQ_DEPTH - 1)
        owners = [(word >> OWNER_BIT) & 1 for _, word in headers]
        # owner = (sqe_bb_idx & kSQDepth) == 0, i.e. the lap bit of the head.
        assert owners == [1 if (sqebb & SQ_DEPTH) == 0 else 0 for sqebb, _ in headers]
        assert [(word >> CQE_BIT) & 1 for _, word in headers] == \
            [0] * (WRITES_PER_TASK - 1) + [1]
        assert ring.head == ((SQ_DEPTH - 1 + WRITES_PER_TASK * ring.wqebbs) & 0xFFFFFFFF)
        assert ring.drain() == 1

    def test_completion_counter_survives_a_jetty_reload(self):
        # dispatch_impl rebuilds HcommJetty between the record loop and the route
        # table puts; the high half must survive the sq_head round-trip.
        ring = SendSqeRing(2)
        for size in batches(20):
            ring.issue(size)
        ring.ring_doorbell()
        ring.reload()
        assert ring.completions == len(batches(20))
        ring.scalar_put()  # S2.5 route table: unchanged, one CQE per SQE
        ring.scalar_put()
        assert ring.completions == len(batches(20)) + 2
        assert ring.completions == ring.num_cqes

    def test_batching_never_needs_more_cqes_than_the_old_encoding(self):
        batched, legacy = SendSqeRing(2), SendSqeRing(2, batched=False)
        for size in batches(128):
            batched.issue(size)
            legacy.issue(size)
        assert batched.completions <= legacy.completions
        # The kernel asserts cq_depth > kNumMaxPendingWrites + 10; one flush group
        # now needs at most four CQEs instead of 32.
        assert PENDING_WRITES // WRITES_PER_TASK == 4
        assert PENDING_WRITES // WRITES_PER_TASK <= PENDING_WRITES + 10


class TestCamDeepepSourceContract:
    """Pin the C++ the model above mirrors; these fail if the source drifts."""

    def test_per_record_completion_is_the_default(self):
        assert _macro_value(DISPATCH_SEND_SRC, "CAM_DEEPEP_BATCHED_FINAL_FLAGS") == "0"
        assert "#ifndef CAM_DEEPEP_BATCHED_FINAL_FLAGS" in DISPATCH_SEND_SRC
        assert "constexpr bool kEnableBatchedFinalFlags" in DISPATCH_SEND_SRC

    def test_encoder_flags_only_the_batch_tail(self):
        # The old unconditional "header | final flags" must be gone.
        assert "kWriteSQEHeaderTemplate | handle::kWriteSQEFinalFlags" not in DISPATCH_SEND_SRC
        encoder = DISPATCH_SEND_SRC.split("void issue_write_wqe")[1].split("issue_write_task")[0]
        assert "if (token_idx + 1 == num_tokens)" in encoder
        assert "wqe_word |= handle::kWriteSQEFinalFlags;" in encoder
        # One guarded site plus the legacy branch.
        assert encoder.count("kWriteSQEFinalFlags") == 2

    def test_completion_counter_adds_one_per_batch(self):
        issue = DISPATCH_SEND_SRC.split("inline void issue_write_task")[1]
        issue = issue.split("inline void append_write_task")[0]
        assert "(kEnableBatchedFinalFlags ? 1u : num_tokens)" in issue
        assert "packed_head >> kNumHighHalfShiftBits) + num_tokens" not in issue

    def test_combine_send_record_loop_reads_lane_state_from_ub(self):
        assert "alignas(kNumUbAlignmentBytes) uint32_t lane_src_rank[L], lane_capacity[L];" \
            in COMBINE_SEND_SRC
        assert "alignas(kNumUbAlignmentBytes) uint64_t lane_return_base[L];" in COMBINE_SEND_SRC
        # Hot path: no per-record GM lane read and no direct return_lanes indexing.
        assert "recv_read(lanes + md[0])" not in COMBINE_SEND_SRC
        assert "return_lanes[md[0]]" not in COMBINE_SEND_SRC
        assert "int(ub->lane_src_rank[ml]) != a" in COMBINE_SEND_SRC
        assert "ub->lane_return_base[ml]" in COMBINE_SEND_SRC
        # The preflight capacity check must use the same cached table.
        assert "uint32_t(md[1]) >= ub->lane_capacity[md[0]]" in COMBINE_SEND_SRC
        assert "lanes[md[0]].capacity" not in COMBINE_SEND_SRC

    def test_combine_send_caches_state_in_the_member_scan(self):
        # The cache is filled from reads the validation already performs, so it
        # adds no GM traffic and every cached lane is a live member lane.
        body = COMBINE_SEND_SRC.split("for (uint32_t m = entry.member_begin;")[1]
        scan = body.split("uint64_t rows = 0;")[0]
        for statement in ("ub->lane_src_rank[l] = lane.src_rank_idx;",
                          "ub->lane_capacity[l] = lane.capacity;",
                          "ub->lane_return_base[l] = ret.return_offset;"):
            assert statement in scan
        assert "ub->lane_src_rank[l] = static_cast<uint32_t>(NA);" in COMBINE_SEND_SRC

    def test_dispatch_send_hoists_the_records_offset(self):
        # The old per-record GM read is gone.
        assert "addresses[lane_idx * kNumRanks + f].records_offset" not in DISPATCH_SEND_SRC
        assert DISPATCH_SEND_SRC.count(".records_offset") == 1
        assert "recv_read(addresses + uint64_t(lane_idx) * kNumRanks + f).records_offset" \
            in DISPATCH_SEND_SRC
        # One declaration, one member read, one use inside the record loop.
        assert DISPATCH_SEND_SRC.count("records_offset") == 3
        after = DISPATCH_SEND_SRC.split("const uint64_t records_offset")[1]
        before_loop, loop_and_rest = after.split("for (uint32_t i = 0; i < size; ++i) {")
        assert "recv_read(addresses + uint64_t(lane_idx) * kNumRanks + f).records_offset" \
            in before_loop
        body = loop_and_rest.split("issue_write_task<2, kNumTimeoutCycles>")[0]
        assert body.count("records_offset") == 1, "the record loop must reuse the hoisted base"

class TestCamDeepepRtPathContract:
    """The runtime-parameterized copy is what the CAM operators compile.

    cam_deepep_rt_common.h duplicates issue_write_wqe / issue_write_task and
    cam_deepep_combine_send_rt.h duplicates the combine record loop, so both
    copies must carry the same encoding or the operators keep the old cost.
    """

    def test_rt_copy_stays_in_lockstep_with_the_vendored_one(self):
        assert RT_PENDING_WRITES == PENDING_WRITES
        assert RT_WRITES_PER_TASK == WRITES_PER_TASK
        assert _macro_value(RT_COMMON_SRC, "CAM_DEEPEP_BATCHED_FINAL_FLAGS") == "0"
        assert "#ifndef CAM_DEEPEP_BATCHED_FINAL_FLAGS" in RT_COMMON_SRC
        assert "constexpr bool kEnableBatchedFinalFlags" in RT_COMMON_SRC
        # One record is one SQE in both copies, so the model applies unchanged.
        assert wqebbs_per_token(1) == 1 and wqebbs_per_token(2) == 2

    def test_rt_encoder_flags_only_the_batch_tail(self):
        assert "kWriteSQEHeaderTemplate | handle::kWriteSQEFinalFlags" not in RT_COMMON_SRC
        encoder = RT_COMMON_SRC.split("void issue_write_wqe")[1].split("issue_write_task")[0]
        assert "if (token_idx + 1 == num_tokens)" in encoder
        assert "wqe_word |= handle::kWriteSQEFinalFlags;" in encoder
        assert encoder.count("kWriteSQEFinalFlags") == 2

    def test_rt_completion_counter_adds_one_per_batch(self):
        issue = RT_COMMON_SRC.split("inline void issue_write_task")[1]
        issue = issue.split("inline void append_write_task")[0]
        assert "(kEnableBatchedFinalFlags ? 1u : num_tokens)" in issue
        assert "packed_head >> kNumHighHalfShiftBits) + num_tokens" not in issue
        # The SQ head advance is untouched: num_tokens records * WQEBBsPerToken.
        assert "uint32_t(current_head + num_tokens * kNumWQEBBsPerToken)" in issue

    def test_rt_combine_send_uses_the_ub_lane_cache(self):
        assert "uint32_t lane_src_rank, lane_capacity, lane_return_base, control;" \
            in COMBINE_SEND_RT_SRC
        assert "o.lane_src_rank = reserve_region(at, 4u * p.num_source_lanes);" in COMBINE_SEND_RT_SRC
        assert "o.lane_capacity = reserve_region(at, 4u * p.num_source_lanes);" in COMBINE_SEND_RT_SRC
        assert "o.lane_return_base = reserve_region(at, 8u * p.num_source_lanes);" in COMBINE_SEND_RT_SRC
        # Hot path: no per-record GM lane read, no direct return lane indexing.
        assert "recv_read(lanes + md[0])" not in COMBINE_SEND_RT_SRC
        assert "return_lanes[md[0]]" not in COMBINE_SEND_RT_SRC
        assert "int(lane_src_rank[ml]) != a" in COMBINE_SEND_RT_SRC
        assert "lane_return_base[ml]" in COMBINE_SEND_RT_SRC
        assert "uint32_t(md[1]) >= lane_capacity[md[0]]" in COMBINE_SEND_RT_SRC
        assert "lanes[md[0]].capacity" not in COMBINE_SEND_RT_SRC
        # The cache is filled during the member scan that already validates it.
        scan = COMBINE_SEND_RT_SRC.split("for (uint32_t m = entry.member_begin;")[1]
        scan = scan.split("uint64_t rows = 0;")[0]
        for statement in ("lane_src_rank[l] = lane.src_rank_idx;",
                          "lane_capacity[l] = lane.capacity;",
                          "lane_return_base[l] = ret.return_offset;"):
            assert statement in scan
        assert "lane_src_rank[l] = uint32_t(num_src_ranks);" in COMBINE_SEND_RT_SRC

    def test_rt_dispatch_send_hoists_the_records_offset(self):
        # Exactly one GM read of the record base, and it sits outside the loop.
        read = "addresses[lane_idx * num_ranks + f].records_offset"
        assert DISPATCH_SEND_RT_SRC.count(read) == 1
        assert "const uint64_t records_offset = " + read + ";" in DISPATCH_SEND_RT_SRC
        after = DISPATCH_SEND_RT_SRC.split("const uint64_t records_offset")[1]
        _, loop_and_rest = after.split("for (uint32_t i = 0; i < size; ++i) {")
        body = loop_and_rest.split("issue_write_task<2>")[0]
        assert body.count("records_offset") == 1
        assert read not in body, "the record loop must reuse the hoisted base"

    def test_rt_combine_send_batches_yield_one_completion_each(self):
        # cam_deepep_combine_send_rt.h appends one SGE record per row (kNumSGEs = 1).
        ring = SendSqeRing(1)
        for size in batches(35, per_batch=RT_WRITES_PER_TASK):
            ring.issue(size)
        assert ring.completions == 5
        assert ring.completions == ring.num_cqes
        assert ring.drain() == 5
        assert ring.head == 35 * wqebbs_per_token(1)
