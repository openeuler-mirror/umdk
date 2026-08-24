"""Bidirectional assertion helpers (Phase 3 Group E2).

Phase 3's exit criterion (spec §1 Phase 3): three fault scenarios, each proved
by asserting BOTH sides:
  - AIGW side: the agent's state-transition sequence walked the right path
    (Active→Suspected→Recovering→Active for kill_restart, etc.) — via the
    debug API GET /aigw/v1/agents/{id} (Phase 2 wired this).
  - vLLM side: the matching hint reached the mock vLLM — via its call log.

These helpers poll the AIGW debug endpoint and read the mock_vllm CallLog.
"""

from __future__ import annotations

import time
from typing import Any

from aigw_client import AigwClient  # type: ignore


# Phase 2's AgentState enum (internal/agentregistry/types.go): Registered=0,
# Active=1, Suspected=2, Recovering=3, Gone=4. Verified against the real debug
# endpoint JSON (yt_aigw_build container, 2026-07-14): the field is capitalized
# "State" (Go struct field names serialize verbatim, not snake-cased) and the
# value is the numeric enum. After register the agent is State=0 (Registered);
# it moves to Active=1 once a heartbeat or get-suggestion (implicit hb) lands.
_STATE_NAMES = {0: "Registered", 1: "Active", 2: "Suspected",
                3: "Recovering", 4: "Gone"}


def state_name(state: int) -> str:
    return _STATE_NAMES.get(state, f"Unknown({state})")


def _agent_detail(aigw: AigwClient, agent_id: str) -> dict[str, Any] | None:
    try:
        d = aigw.agent_detail(agent_id)
        return d if isinstance(d, dict) else None
    except Exception:  # noqa: BLE001
        return None


def get_state(aigw: AigwClient, agent_id: str) -> str | None:
    d = _agent_detail(aigw, agent_id)
    if d is None:
        return None
    # The debug endpoint serializes the Go struct field verbatim as "State".
    # Accept "State" (verified shape) and "state" (defensive, in case a future
    # wrapper lowercases keys).
    st = d.get("State", d.get("state"))
    if isinstance(st, int):
        return state_name(st)
    if isinstance(st, str):
        return st
    return None


def wait_for_state(aigw: AigwClient, agent_id: str, target: str | set[str],
                    timeout: float = 30.0, interval: float = 0.5) -> str | None:
    """Poll until the agent reaches a target state (or set of states). Returns
    the state reached, or None on timeout."""
    targets = {target} if isinstance(target, str) else set(target)
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = get_state(aigw, agent_id)
        if st in targets:
            return st
        time.sleep(interval)
    return None


def assert_state_sequence(aigw: AigwClient, agent_id: str, expected: list[str],
                            total_timeout: float = 60.0,
                            interval: float = 0.5) -> tuple[bool, str]:
    """Assert the agent walked through `expected` state transitions in order.
    Polls, recording the distinct states seen in order, until the expected
    sequence appears as a subsequence OR timeout. Returns (ok, observed_str)."""
    seen: list[str] = []
    last = None
    deadline = time.time() + total_timeout
    while time.time() < deadline:
        st = get_state(aigw, agent_id)
        if st is not None and st != last:
            seen.append(st)
            last = st
            # check if expected is a subsequence of seen
            if _is_subsequence(expected, seen):
                return True, "->".join(seen)
        time.sleep(interval)
    return _is_subsequence(expected, seen), "->".join(seen)


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
    it = iter(haystack)
    return all(n in it for n in needle)


def assert_hint_received(call_log: Any, op: str, min_count: int = 1) -> tuple[bool, str]:
    """Assert the mock vLLM received >= min_count POST /v1/kvc/{op} calls."""
    n = call_log.count(op)
    return (n >= min_count, f"{op} count={n} (min {min_count})")


def assert_no_hint(call_log: Any, op: str) -> tuple[bool, str]:
    """Assert the mock vLLM received ZERO /v1/kvc/{op} calls (graceful path)."""
    n = call_log.count(op)
    return (n == 0, f"{op} count={n} (expected 0)")
