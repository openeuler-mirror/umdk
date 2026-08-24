"""Subprocess-based AgentSupervisor (Phase 3 Group E1).

The real supervisor: spawns minimal_react_agent.py as a subprocess, tracks the
pid, parses `TURN k` from stdout (the fault_driver turn counter, R4), and
implements kill/restart/send_signal. Used by run_scenario.py.

Each agent runs in its own workspace; the supervisor keeps a stdout-reader
thread per agent so await_turn can block on a specific turn being reached.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any

from fault_driver import reached_turn  # type: ignore

_AGENT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "minimal_react_agent.py")


class _AgentProcess:
    def __init__(self, proc: subprocess.Popen, workspace: str) -> None:
        self.proc = proc
        self.workspace = workspace
        self.stdout_lines: list[str] = []
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._start_reader()

    def _start_reader(self) -> None:
        def _read():
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                with self._lock:
                    self.stdout_lines.append(line.rstrip("\n"))
        self._reader = threading.Thread(target=_read, daemon=True)
        self._reader.start()

    def turn_lines(self) -> list[str]:
        with self._lock:
            return list(self.stdout_lines)


class SubprocessSupervisor:
    """Real supervisor: spawns agent subprocesses, tracks them by agent_id."""

    def __init__(self, aigw_url: str, vllm_url: str, model: str,
                 heartbeat_interval: float = 0.0,
                 turn_delay: float = 0.0) -> None:
        self.aigw_url = aigw_url
        self.vllm_url = vllm_url
        self.model = model
        self.hb = heartbeat_interval
        self.turn_delay = turn_delay
        self._agents: dict[str, _AgentProcess] = {}

    def _start(self, agent_id: str, session_id: str, task: str,
               workspace: str, restart: bool, from_turn: int = 0) -> None:
        os.makedirs(workspace, exist_ok=True)
        argv = [
            sys.executable, _AGENT_SCRIPT,
            "--aigw-url", self.aigw_url, "--vllm-url", self.vllm_url,
            "--agent-id", agent_id, "--session-id", session_id,
            "--model", self.model, "--task", task, "--task-prompt", f"do {task}",
            "--workspace", workspace, "--max-turns", "20",
        ]
        if self.hb > 0:
            argv += ["--heartbeat-interval", str(self.hb)]
        if self.turn_delay > 0:
            argv += ["--turn-delay-s", str(self.turn_delay)]
        if restart:
            argv += ["--restart"]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        self._agents[agent_id] = _AgentProcess(proc, workspace)

    def start_agent(self, agent_id: str, session_id: str, task: str,
                    workspace: str) -> None:
        self._start(agent_id, session_id, task, workspace, restart=False)

    def restart_agent(self, agent_id: str, session_id: str, task: str,
                      workspace: str, from_turn: int = 0) -> None:
        # kill any lingering proc, then start fresh with --restart
        self.kill_agent(agent_id)
        self._start(agent_id, session_id, task, workspace, restart=True, from_turn=from_turn)

    def agent_pid(self, agent_id: str) -> int:
        ap = self._agents.get(agent_id)
        return ap.proc.pid if ap and ap.proc.poll() is None else 0

    def await_turn(self, agent_id: str, k: int, timeout: float = 60.0) -> None:
        ap = self._agents.get(agent_id)
        if ap is None:
            raise RuntimeError(f"unknown agent {agent_id}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if reached_turn(ap.turn_lines(), k):
                return
            if ap.proc.poll() is not None:
                raise RuntimeError(f"agent {agent_id} exited before turn {k}")
            time.sleep(0.2)
        raise TimeoutError(f"agent {agent_id} did not reach turn {k}")

    def kill_agent(self, agent_id: str) -> None:
        ap = self._agents.get(agent_id)
        if ap and ap.proc.poll() is None:
            ap.proc.send_signal(signal.SIGKILL)
            ap.proc.wait(timeout=5)

    def send_signal(self, agent_id: str, sig: int) -> None:
        ap = self._agents.get(agent_id)
        if ap and ap.proc.poll() is None:
            ap.proc.send_signal(sig)

    def stop_all(self) -> None:
        for aid in list(self._agents):
            self.kill_agent(aid)
