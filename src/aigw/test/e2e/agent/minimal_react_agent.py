"""Minimal ReAct agent (Phase 3 Group C1).

A thin ReAct loop driven by mock_vllm's stub LLM (which emits a scripted
solution per task). Per turn:
  1. get_suggestion(model, ..., agent_id, session_id) — carries X-Agent-Id/
     X-Session-Id = implicit heartbeat (Phase 2 C3).
  2. POST the running transcript to mock_vllm /v1/chat/completions (the stub
     returns the next scripted Action).
  3. Parse `Action: <tool>` + `Action Input: <arg>`; exec the tool in the
     workspace; append `Observation: <result>`.
  4. On `Final Answer:` -> break.

Lifecycle: register on start; recover (reuse agent_id+session_id) on restart;
a background heartbeat thread (optional, used by the heartbeat-timeout scenario
to make the timeout observable when the thread is killed).

fault_driver contract:
  - prints `TURN k` to stdout each turn (turn-counter source, spec R4).
  - persists transcript.json each turn so a restarted agent resumes from turn k
    (not turn 0) — so fault_driver's turn-k trigger is meaningful post-restart.
  - installs a SIGUSR1 handler flipping `pause_heartbeat` (heartbeat-timeout
    scenario: fault_driver sends SIGUSR1 to halt the heartbeat thread without
    killing the process).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any

# sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aigw_client import AigwClient, AigwError  # type: ignore


# ---- tools (exec in the agent's workspace) ----

def tool_bash_exec(arg: str, workspace: str) -> str:
    # arg = the command line; shell=False requires a token list (no shell metachar
    # expansion). shlex.split parses the command line into argv safely.
    try:
        r = subprocess.run(
            shlex.split(arg), shell=False, cwd=workspace, capture_output=True,
            text=True, timeout=10,
        )
        out = r.stdout
        if r.returncode != 0:
            out += f"\n[exit {r.returncode}]\n{r.stderr}"
        return out.strip() or "[no output]"
    except subprocess.TimeoutExpired:
        return "[timeout]"


def tool_read_file(arg: str, workspace: str) -> str:
    path = os.path.join(workspace, arg)
    if not os.path.isfile(path):
        return f"[no such file: {arg}]"
    with open(path) as f:
        return f.read()


def tool_write_file(arg: str, workspace: str) -> str:
    # arg format: "path|content"
    if "|" not in arg:
        return "[usage: path|content]"
    path, content = arg.split("|", 1)
    full = os.path.join(workspace, path)
    os.makedirs(os.path.dirname(full) or workspace, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    return f"[wrote {path}]"


def tool_grep_find(arg: str, workspace: str) -> str:
    # arg format: "pattern|path" or "pattern"
    parts = arg.split("|", 1)
    pattern = parts[0]
    sub = parts[1] if len(parts) > 1 else "."
    root = os.path.join(workspace, sub)
    rx = re.compile(pattern)
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, workspace)
            try:
                with open(fp, errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        if rx.search(line):
                            hits.append(f"{rel}:{i}: {line.rstrip()}")
            except (OSError, UnicodeDecodeError):
                continue
            if len(hits) > 50:
                break
    return "\n".join(hits) if hits else "[no matches]"


TOOLS = {
    "bash_exec": tool_bash_exec,
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "grep_find": tool_grep_find,
}

_ACTION_RE = re.compile(r"Action:\s*(\w+)\s*\n\s*Action Input:\s*(.*)", re.S)
_FINAL_RE = re.compile(r"Final Answer:", re.I)


# ---- the agent ----

class MinimalReactAgent:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.aigw = AigwClient(args.aigw_url)
        self.transcript: list[dict[str, str]] = []
        self.turn = 0
        self.pause_heartbeat = False  # SIGUSR1 flips this (hb thread only)
        self.paused = False  # SIGUSR1 flips this (whole agent: no get-suggestion)
        self._hb_stop = threading.Event()
        self._hb_thread: threading.Thread | None = None
        self.workspace = args.workspace
        os.makedirs(self.workspace, exist_ok=True)
        self._load_transcript()

    # ---- transcript persistence (so restart resumes from turn k) ----
    @property
    def transcript_path(self) -> str:
        return os.path.join(self.workspace, "transcript.json")

    def _load_transcript(self) -> None:
        if os.path.exists(self.transcript_path):
            try:
                with open(self.transcript_path) as f:
                    self.transcript = json.load(f)
                    # turn counter resumes from persisted length
                    self.turn = len(
                        [m for m in self.transcript if m.get("role") == "assistant"]
                    )
            except (json.JSONDecodeError, OSError):
                self.transcript = []

    def _save_transcript(self) -> None:
        with open(self.transcript_path, "w") as f:
            json.dump(self.transcript, f, indent=2)

    # ---- lifecycle ----
    def register(self) -> None:
        try:
            self.aigw.register(self.args.agent_id, [self.args.model])
            print(f"[agent {self.args.agent_id}] registered", flush=True)
        except AigwError as e:
            print(f"[agent {self.args.agent_id}] register failed: {e}", flush=True)

    def recover(self) -> None:
        """On restart-after-kill, reuse agent_id+session_id to resume.

        AIGW's Recover rejects an agent already in Gone state (registry.go:273
        — 'must Register, not Recover'). If the kill/restart delay pushed the
        agent past Gone, fall back to a fresh Register (registry.go:194
        overwrites the Gone record with StateRegistered), then the first
        heartbeat moves it Active. Either path lands the agent back in Active,
        which is what the kill_restart assertion expects."""
        try:
            self.aigw.recover(self.args.agent_id, [self.args.model])
            print(f"[agent {self.args.agent_id}] recovered (resume from turn {self.turn})", flush=True)
        except AigwError as e:
            print(f"[agent {self.args.agent_id}] recover failed ({e.status}); "
                  f"agent likely Gone -> re-registering", flush=True)
            try:
                self.aigw.register(self.args.agent_id, [self.args.model])
                print(f"[agent {self.args.agent_id}] re-registered after Gone", flush=True)
            except AigwError as e2:
                print(f"[agent {self.args.agent_id}] re-register failed: {e2}", flush=True)

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.is_set():
            if not self.pause_heartbeat:
                try:
                    self.aigw.heartbeat(
                        self.args.agent_id, [self.args.model], [self.args.session_id]
                    )
                except AigwError as e:
                    print(f"[agent {self.args.agent_id}] hb failed: {e.status}", flush=True)
            self._hb_stop.wait(self.args.heartbeat_interval)

    def start_heartbeat(self) -> None:
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()

    def stop_heartbeat(self) -> None:
        self._hb_stop.set()

    # ---- per-turn ----
    def _system_prompt(self) -> str:
        return f"{self.args.task_prompt}\n\nTASK: {self.args.task}"

    def _call_llm(self) -> str:
        """POST transcript to mock_vllm /v1/chat/completions, return assistant text."""
        messages = [{"role": "system", "content": self._system_prompt()}]
        messages.extend(self.transcript)
        body = json.dumps({"model": self.args.model, "messages": messages}).encode()
        req = urllib.request.Request(
            self.args.vllm_url + "/v1/chat/completions",
            data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
        return resp["choices"][0]["message"]["content"]

    def _do_tool(self, action: str, arg: str) -> str:
        fn = TOOLS.get(action)
        if fn is None:
            return f"[unknown action: {action}]"
        try:
            return fn(arg, self.workspace)
        except Exception as e:  # noqa: BLE001
            return f"[tool error: {e}]"

    def run_turn(self) -> bool:
        """One ReAct turn. Returns True if the loop should continue (not final)."""
        # SIGUSR1 pauses the whole agent (heartbeat_timeout scenario): spin
        # without calling get_suggestion (implicit hb) or _call_llm, so AIGW
        # sees neither explicit nor implicit heartbeat and ages the agent all
        # the way Active->Suspected->Recovering->Gone. Pausing only the
        # heartbeat thread leaves implicit hb (get-suggestion) still firing,
        # which keeps the agent Active and defeats the scenario.
        while self.paused:
            time.sleep(0.5)
        self.turn += 1
        print(f"TURN {self.turn}", flush=True)
        # implicit heartbeat via get_suggestion
        try:
            self.aigw.get_suggestion(
                self.args.model, {"prompt": f"turn {self.turn}"},
                self.args.agent_id, self.args.session_id,
            )
        except AigwError as e:
            print(f"[agent {self.args.agent_id}] get-suggestion failed: {e.status}", flush=True)
        # call the stub LLM
        text = self._call_llm()
        self.transcript.append({"role": "assistant", "content": text})
        self._save_transcript()
        if _FINAL_RE.search(text):
            print(f"[agent {self.args.agent_id}] final answer at turn {self.turn}", flush=True)
            return False
        m = _ACTION_RE.search(text)
        if not m:
            print(f"[agent {self.args.agent_id}] no action parsed; stopping", flush=True)
            return False
        action, arg = m.group(1), m.group(2).strip()
        obs = self._do_tool(action, arg)
        self.transcript.append({"role": "user", "content": f"Observation: {obs}"})
        self._save_transcript()
        if self.args.turn_delay_s > 0:
            time.sleep(self.args.turn_delay_s)
        return True

    def run(self, on_restart: bool = False) -> int:
        if on_restart:
            self.recover()
        else:
            self.register()
        if self.args.heartbeat_interval > 0:
            self.start_heartbeat()
        try:
            while self.turn < self.args.max_turns:
                if not self.run_turn():
                    break
        finally:
            self.stop_heartbeat()
            self._save_transcript()
        return 0


def _install_sigusr1(agent: MinimalReactAgent) -> None:
    def _h(signum, frame):  # noqa: ARG001
        agent.pause_heartbeat = True  # stop explicit heartbeat thread
        agent.paused = True  # freeze the ReAct loop (no get-suggestion = no
                              # implicit hb either) so AIGW ages to Gone
        print(f"[agent {agent.args.agent_id}] SIGUSR1: paused (no hb, no get-suggestion)", flush=True)
    signal.signal(signal.SIGUSR1, _h)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--aigw-url", default="http://127.0.0.1:8701")
    p.add_argument("--vllm-url", default="http://127.0.0.1:18000")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--model", default="test-model")
    p.add_argument("--task", required=True, help="task name (fix_failing_test|add_docstring|refactor_func)")
    p.add_argument("--task-prompt", default="", help="task brief (defaults derived from task name)")
    p.add_argument("--workspace", required=True)
    p.add_argument("--heartbeat-interval", type=float, default=0.0,
                   help="seconds between explicit heartbeats; 0 = off (implicit only)")
    p.add_argument("--turn-delay-s", type=float, default=0.0,
                   help="seconds to sleep between ReAct turns (slows the loop so a "
                        "mid-run kill actually catches the agent still running)")
    p.add_argument("--max-turns", type=int, default=20)
    p.add_argument("--restart", action="store_true",
                   help="recover (reuse agent_id+session_id) instead of register")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    agent = MinimalReactAgent(args)
    _install_sigusr1(agent)
    return agent.run(on_restart=args.restart)


if __name__ == "__main__":
    raise SystemExit(main())
