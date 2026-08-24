"""FaultDriver unit tests (Phase 3 Group D1) for scenario state machines.

Exercises the 3 scenario state machines + turn parser against a fake
supervisor (no real agent process). The fake supervisor records calls and
lets await_turn return immediately (or after a tiny sleep), so the scenarios
run fast. delay_s / wait_gone_s are shrunk to ~0 in tests."""

from __future__ import annotations

import signal
from unittest.mock import MagicMock

import pytest

from aigw_client import AigwClient  # type: ignore
from fault_driver import (  # type: ignore
    AgentCtx,
    FaultDriver,
    reached_turn,
    parse_turns,
)


class _FakeSupervisor:
    """Records every call; await_turn returns immediately."""
    def __init__(self):
        self.calls: list[str] = []
        self._pids = {"a1": 99999}

    def agent_pid(self, agent_id):
        self.calls.append(f"pid:{agent_id}")
        return self._pids.get(agent_id, 0)

    def await_turn(self, agent_id, k, timeout=60.0):
        self.calls.append(f"await:{agent_id}:{k}")

    def kill_agent(self, agent_id):
        self.calls.append(f"kill:{agent_id}")
        self._pids.pop(agent_id, None)

    def send_signal(self, agent_id, sig):
        self.calls.append(f"signal:{agent_id}:{sig}")

    def restart_agent(self, agent_id, session_id, task, workspace, from_turn):
        self.calls.append(f"restart:{agent_id}:{from_turn}")
        self._pids[agent_id] = 100000


@pytest.fixture
def driver():
    sup = _FakeSupervisor()
    aigw = MagicMock(spec=AigwClient)
    return FaultDriver(aigw_client=aigw, supervisor=sup), sup, aigw


def test_kill_restart_sequence(driver):
    fd, sup, aigw = driver
    r = fd.kill_restart(AgentCtx("a1", "s1", "fix_failing_test", "/ws"),
                        turn_k=3, delay_s=0.01)
    assert r.scenario == "kill_restart"
    # ordered calls: await -> pid -> kill -> (delay) -> restart
    assert sup.calls[0] == "await:a1:3"
    assert sup.calls[1] == "pid:a1"
    assert sup.calls[2] == "kill:a1"
    assert sup.calls[3] == "restart:a1:3"
    assert any(e.endswith("restarted") for e in r.events)


def test_graceful_unregister_sequence(driver):
    fd, sup, aigw = driver
    r = fd.graceful_unregister(AgentCtx("a1", "s1", "fix_failing_test", "/ws"),
                               turn_k=2, delay_s=0.01)
    assert r.scenario == "graceful_unregister"
    assert sup.calls[0] == "await:a1:2"
    # unregister + register must hit the aigw client
    aigw.unregister.assert_called_once_with("a1")
    aigw.register.assert_called_once_with("a1", ["test-model"])
    # supervisor restarts after re-register
    assert sup.calls[-1] == "restart:a1:2"


def test_heartbeat_timeout_sequence(driver):
    fd, sup, aigw = driver
    r = fd.heartbeat_timeout(AgentCtx("a1", "s1", "fix_failing_test", "/ws"),
                             turn_k=3, wait_gone_s=0.01)
    assert r.scenario == "heartbeat_timeout"
    assert sup.calls[0] == "await:a1:3"
    # SIGUSR1 must be sent
    assert sup.calls[1] == f"signal:a1:{signal.SIGUSR1}"
    # no kill, no restart (agent stays paused -> aged to Gone by AIGW)
    assert not any(c.startswith("kill:") for c in sup.calls)
    assert not any(c.startswith("restart:") for c in sup.calls)


def test_parse_turns():
    lines = ["TURN 1", "some log", "TURN 2", "TURN 3", "garbage", "TURN 4"]
    assert parse_turns(lines) == [1, 2, 3, 4]


def test_reached_turn():
    assert reached_turn(["TURN 1", "TURN 2"], 2) is True
    assert reached_turn(["TURN 1"], 2) is False
