"""Scenario 3: heartbeat timeout (Phase 3 Group E2/E3).

Agent A's heartbeat is paused (SIGUSR1) at turn k; AIGW ages it through
Active -> Suspected -> Recovering -> Gone. Suspected -> OffloadAll (offload
hint), Gone -> TTLAging (evict hint). Agent A is halted (not expected to pass
its task judge); survivors B/C/D still pass.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_scenario  # type: ignore

pytestmark = pytest.mark.requires_aigw_binary


def test_heartbeat_timeout(tmp_path):
    argv = [
        "--scenario", "heartbeat_timeout",
        "--agents", "4", "--task", "fix_failing_test",
        "--turn-k", "3",
        "--delay-s", "30",  # wait_gone_s — needs to exceed GoneFinalizeSec(5)+margin
        "--heartbeat-interval", "2",
        "--workspace-root", str(tmp_path / "heartbeat_timeout"),
        "--start-mock-vllm",
    ]
    rc = run_scenario.main(argv)
    assert rc == 0, "heartbeat_timeout scenario failed (see report above)"
