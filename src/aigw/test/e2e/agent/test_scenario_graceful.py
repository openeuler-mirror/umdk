"""Scenario 2: graceful unregister + re-register (Phase 3 Group E2/E3).

A graceful unregister does NOT trigger OffloadAll (that's a crash-suspected
trigger). Agent A is unregistered then re-registered, resumes the task.

Asserted: AIGW state stays in the Active family (no Suspected->Recovering),
AND mock-vLLM received ZERO offload hints.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_scenario  # type: ignore

pytestmark = pytest.mark.requires_aigw_binary


def test_graceful_unregister(tmp_path):
    argv = [
        "--scenario", "graceful_unregister",
        "--agents", "4", "--task", "fix_failing_test",
        "--turn-k", "3", "--delay-s", "5",
        "--heartbeat-interval", "2",
        "--workspace-root", str(tmp_path / "graceful"),
        "--start-mock-vllm",
    ]
    rc = run_scenario.main(argv)
    assert rc == 0, "graceful_unregister scenario failed (see report above)"
