"""pytest config for Phase 3 scenario tests (Group E).

The scenario tests require a real AIGW binary with kvc enabled (built via
./build.sh, started with aigw_config_kvc.json). When the binary isn't
available (e.g. local dev without the CGO/Rust/LightGBM toolchain), the
scenario tests are skipped — the pure-logic tests (Group A-D) still run.

To run the scenario tests, set AIGW_BIN=/path/to/aigw (and ensure mock_vllm
is started, or the orchestrator starts it). Then:
    pytest test/e2e/agent/test_scenario_*.py -q
"""

from __future__ import annotations

import os
import shutil

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requires_aigw_binary: needs a built AIGW binary with kvc enabled"
    )


def pytest_collection_modifyitems(config, items):
    # skip scenario tests if no AIGW binary is available
    aigw_bin = os.environ.get("AIGW_BIN") or shutil.which("aigw")
    if aigw_bin:
        return
    skip = pytest.mark.skip(reason="AIGW_BIN not set / aigw binary not on PATH")
    for item in items:
        if "requires_aigw_binary" in item.keywords:
            item.add_marker(skip)
