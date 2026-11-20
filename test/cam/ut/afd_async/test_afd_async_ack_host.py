# SPDX-License-Identifier: MIT
"""Run the DR/CS transaction headers with host memory in place of GM and UB."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


def test_transaction_retirement_and_ack_publication(tmp_path):
    compiler = shlex.split(os.environ.get("CXX", "g++"), posix=os.name != "nt")
    if not compiler or not shutil.which(compiler[0]):
        pytest.skip("CXX or g++ with C++17 support required")
    kernels = Path(__file__).resolve().parents[4] / "src/cam/comm_operator/ascend_kernels"
    binary = tmp_path / ("ack.exe" if os.name == "nt" else "ack")
    subprocess.run([
        *compiler, "-std=c++17", "-O2", "-UNDEBUG", "-fno-strict-aliasing", "-Wno-unknown-pragmas",
        "-I", str(kernels), "-I", str(kernels / "utils/op_kernel"),
        str(Path(__file__).with_name("afd_async_ack_host.cpp")), "-o", str(binary),
    ], check=True, timeout=60)
    subprocess.run([str(binary)], check=True, timeout=15)
