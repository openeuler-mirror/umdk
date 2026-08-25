"""Fault-injection driver (Phase 3 Group D1).

Orchestrates the three fault scenarios from the verification spec §3 (lines
202-213), firing at a precise turn k (spec R4: turn-count trigger so the agent
doesn't crash at an arbitrary moment and produce noise).

Three scenarios:
  kill_restart       — SIGKILL the agent process at turn k, wait Δs (Δ tuned to
                       AIGW's HeartbeatTimeoutSec/RecoverWindowSec so it hits
                       Suspected vs Recovering), restart reusing agent_id+
                       session_id (the agent recovers then resumes from turn k).
  graceful_unregister — aigw.unregister(agent_id) at turn k, wait Δs, re-register,
                        resume agent (no kill).
  heartbeat_timeout  — SIGUSR1 the agent (flips pause_heartbeat) + block get-
                        suggestion so AIGW sees no heartbeat; wait until AIGW ages
                        Active→Suspected→Recovering→Gone.

Design: the driver talks to an AgentSupervisor abstraction (start/kill/pid/
await_turn/send_signal) so it's testable with a fake supervisor (no real
agent process). The real supervisor (subprocess.Popen-based) lives in the
orchestrator (Group E1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass
class ScenarioResult:
    agent_id: str
    scenario: str
    turn_k: int
    delay_s: float
    events: list[str] = field(default_factory=list)

    def add(self, msg: str) -> None:
        self.events.append(f"{time.time():.3f} {msg}")


@dataclass
class AgentCtx:
    """
    Correlated agent identity params.

    Grouped to keep scenario methods below the too-many-arguments threshold
    (G.FNM.03).
    """

    agent_id: str
    session_id: str
    task: str
    workspace: str


class AgentSupervisor(Protocol):
    """Minimal contract the driver needs from the agent process manager."""

    def agent_pid(self, agent_id: str) -> int:
        ...

    def await_turn(self, agent_id: str, k: int, timeout: float = 60.0) -> None:
        ...

    def kill_agent(self, agent_id: str) -> None:
        ...

    def send_signal(self, agent_id: str, sig: int) -> None:
        ...

    def restart_agent(self, agent_id: str, session_id: str, task: str,
                      workspace: str, from_turn: int) -> None:
        ...


class FaultDriver:
    def __init__(self, aigw_client: Any, supervisor: AgentSupervisor) -> None:
        self.aigw = aigw_client
        self.sup = supervisor

    # ---- scenario 1: kill + restart ----
    def kill_restart(self, ctx: AgentCtx, turn_k: int = 3,
                     delay_s: float = 10.0) -> ScenarioResult:
        r = ScenarioResult(ctx.agent_id, "kill_restart", turn_k, delay_s)
        r.add(f"awaiting turn {turn_k}")
        self.sup.await_turn(ctx.agent_id, turn_k)
        r.add(f"reached turn {turn_k}; killing pid={self.sup.agent_pid(ctx.agent_id)}")
        self.sup.kill_agent(ctx.agent_id)
        r.add("killed; waiting delay")
        time.sleep(delay_s)
        r.add("delay elapsed; restarting agent (recover)")
        self.sup.restart_agent(ctx.agent_id, ctx.session_id, ctx.task,
                               ctx.workspace, from_turn=turn_k)
        r.add("restarted")
        return r

    # ---- scenario 2: graceful unregister + re-register ----
    def graceful_unregister(self, ctx: AgentCtx, turn_k: int = 3,
                            delay_s: float = 5.0) -> ScenarioResult:
        r = ScenarioResult(ctx.agent_id, "graceful_unregister", turn_k, delay_s)
        self.sup.await_turn(ctx.agent_id, turn_k)
        r.add(f"reached turn {turn_k}; unregister")
        self.aigw.unregister(ctx.agent_id)
        r.add("unregistered; waiting delay")
        time.sleep(delay_s)
        r.add("re-registering")
        self.aigw.register(ctx.agent_id, ["test-model"])
        r.add("re-registered; restarting agent (register)")
        self.sup.restart_agent(ctx.agent_id, ctx.session_id, ctx.task,
                               ctx.workspace, from_turn=turn_k)
        return r

    # ---- scenario 3: heartbeat timeout ----
    def heartbeat_timeout(self, ctx: AgentCtx, turn_k: int = 3, wait_gone_s: float = 0.0) -> ScenarioResult:
        """
        SIGUSR1 freezes the agent.

        No explicit hb, no get-suggestion implicit hb. Returns immediately —
        run_scenario's assert_state_sequence polls the AIGW debug endpoint and
        captures Active->Suspected->Recovering->Gone as it happens (rather
        than sleeping blind then missing states already finalized + removed).
        wait_gone_s is kept for backward compat but defaults to 0 (no blind
        sleep).
        """
        r = ScenarioResult(ctx.agent_id, "heartbeat_timeout", turn_k, wait_gone_s)
        self.sup.await_turn(ctx.agent_id, turn_k)
        r.add(f"reached turn {turn_k}; sending SIGUSR1 to freeze agent")
        import signal as _sig
        self.sup.send_signal(ctx.agent_id, _sig.SIGUSR1)
        r.add("agent frozen; AIGW aging will run Active->Gone")
        if wait_gone_s > 0:
            time.sleep(wait_gone_s)
        return r


# ---- turn-counter parser (parses agent stdout "TURN k" lines) ----

def parse_turns(stdout_lines: list[str]) -> list[int]:
    """Extract the turn numbers the agent has reached, in order."""
    turns = []
    for line in stdout_lines:
        line = line.strip()
        if line.startswith("TURN "):
            try:
                turns.append(int(line.split()[1]))
            except (IndexError, ValueError):
                continue
    return turns


def reached_turn(stdout_lines: list[str], k: int) -> bool:
    return k in parse_turns(stdout_lines)
