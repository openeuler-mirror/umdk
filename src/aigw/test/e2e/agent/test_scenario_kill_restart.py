"""Scenario 1 (main): kill + restart (Phase 3 Group E2/E3).

Spec §3 T2-T5: agent A crashed at turn k -> AIGW 90s no-heartbeat -> SUSPECTED
-> OffloadAll -> POST /v1/kvc/offload; restart reuses agent_id -> RECOVERING
-> ACTIVE -> PrefetchMRU -> POST /v1/kvc/prefetch.

Asserted bidirectionally: AIGW debug state sequence
[Active, Suspected, Recovering, Active] AND mock-vLLM received offload + prefetch.
"""

from __future__ import annotations

import importlib
import os

import pytest

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "run_scenario", os.path.join(_here, "run_scenario.py")
)
run_scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_scenario)  # type: ignore

pytestmark = pytest.mark.requires_aigw_binary


def test_kill_restart(tmp_path):
    argv = [
        "--scenario", "kill_restart",
        "--agents", "4", "--task", "fix_failing_test",
        "--turn-k", "3", "--delay-s", "10",
        "--heartbeat-interval", "2",
        "--workspace-root", str(tmp_path / "kill_restart"),
        "--start-mock-vllm",
    ]
    rc = run_scenario.main(argv)
    assert rc == 0, "kill_restart scenario failed (see report above)"
