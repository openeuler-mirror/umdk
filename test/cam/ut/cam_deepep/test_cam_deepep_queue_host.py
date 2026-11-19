# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
"""Execute the production SQ encoder/helpers on a CPU with a doorbell-driven CQ.

This checks C++ queue bookkeeping and UB layout, not AscendC compilation,
hardware ordering, DMA visibility, or device performance.
"""

import os
import pathlib
import re
import shlex
import shutil
import subprocess

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[4]
OPS = ROOT / "src/cam/comm_operator/ascend_kernels"
COMMON = OPS / "utils/op_kernel"


def _definition(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def _constant(source, name):
    match = re.search(r"(?:static )?constexpr\s+\w+\s+" + name + r"\s*=[^;]+;", source)
    assert match, name
    return match.group()


@pytest.mark.parametrize("runtime", [True, False], ids=["runtime", "vendored"])
@pytest.mark.parametrize("mode", [None, 0, 1], ids=["default", "per_record", "batched"])
def test_production_queue_helpers_and_ub_layout(tmp_path, runtime, mode):
    compiler = shlex.split(os.environ.get("CXX", "g++"), posix=os.name != "nt")
    if not compiler or not shutil.which(compiler[0]):
        pytest.skip("a C++17 compiler (CXX or g++) is required for the host queue test")
    header = COMMON / ("cam_deepep_rt_common.h" if runtime else "deep_ep/impls/afd/dispatch_send.h")
    source = header.read_text(encoding="utf-8")
    handle = (COMMON / "deep_ep/comm/handle.h").read_text(encoding="utf-8")
    combine = (OPS / "cam_deepep_combine_send/op_kernel/cam_deepep_combine_send_rt.h").read_text(
        encoding="utf-8")
    host = (OPS / "cam_deepep_combine_send/op_host/cam_deepep_combine_send.cpp").read_text(
        encoding="utf-8")
    # The host must admit the allocated window, including the newly cached lanes.
    assert "OP_TILING_CHECK(dynUbSize < kCombineSendUbBytes," in host
    assert "tiling->numUbBytes = dynUbSize;" in host
    assert "context->SetDynUBufSize(dynUbSize)" in host

    end = source.index("inline void append_write_task")
    append = _definition(source, "inline void append_write_task")
    transport = source[source.index("constexpr uint32_t kNumWritesPerTask"):end + len(append)]
    timeout_template = "" if runtime else "template <int64_t kNumTimeoutCycles> "
    helpers = "\n".join(timeout_template + _definition(source, marker)
                        for marker in ("inline void flush_writes", "inline void put_at_offset"))
    switch_begin = source.index("#ifndef CAM_DEEPEP_BATCHED_FINAL_FLAGS")
    switch_end = source.index(";", source.index("constexpr bool kEnableBatchedFinalFlags")) + 1
    ub_begin = combine.index("struct CombineSendParams")
    ub_end = combine.index("// Same phases as combine_send_impl")
    harness = pathlib.Path(__file__).with_name("cam_deepep_queue_host.cpp.in").read_text(encoding="utf-8")
    replacements = {
        "@HANDLE_CONSTANTS@": "\n".join(_constant(handle, name) for name in (
            "kNumWQEBBBytes", "kSQDepth", "kWriteSQEHeaderTemplate", "kWriteSQEFinalFlags")),
        "@PENDING_CONSTANT@": _constant(source, "kNumMaxPendingWrites"),
        "@SWITCH@": source[switch_begin:switch_end],
        "@HELPERS@": helpers,
        "@TRANSPORT@": transport,
        "@TIMEOUT_ARGUMENT@": "" if runtime else ", 1000000000",
        "@TIMEOUT_TEMPLATE@": "" if runtime else "<1000000000>",
        "@UB_LAYOUT@": combine[ub_begin:ub_end],
        "@HOST_BUDGET@": _constant(host, "kCombineSendUbBytes"),
    }
    for marker, value in replacements.items():
        harness = harness.replace(marker, value)
    assert not re.search(r"@[A-Z_]+@", harness)
    cpp = tmp_path / "queue.cpp"
    binary = tmp_path / ("queue.exe" if os.name == "nt" else "queue")
    cpp.write_text(harness, encoding="utf-8")
    override = [] if mode is None else [f"-DCAM_DEEPEP_BATCHED_FINAL_FLAGS={mode}"]
    compiled = subprocess.run(
        compiler + ["-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", *override, str(cpp), "-o", str(binary)],
        capture_output=True, text=True, timeout=60, check=False)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "queue and UB checks passed" in result.stdout
