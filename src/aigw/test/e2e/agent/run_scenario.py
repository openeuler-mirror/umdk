"""Scenario orchestrator (Phase 3 Group E1).

Wires mock-vLLM + (real) AIGW + N agents, runs fault_driver on agent A at
turn k, then asserts bidirectionally (AIGW debug state seq + mock-vLLM hint
receipt), then runs task judges. One scenario per invocation.

Usage:
    python3 run_scenario.py --scenario kill_restart [--aigw-url URL] [--vllm-url URL] \
        [--agents 4] [--task fix_failing_test]

Requires the AIGW binary running with kvc enabled (see aigw_config_kvc.json)
and mock_vllm.py started separately (or started here via --start-mock-vllm).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

# sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aigw_client import AigwClient  # type: ignore
from assertions import (  # type: ignore
    assert_hint_received,
    assert_no_hint,
    assert_state_sequence,
    get_state,
    wait_for_state,
)
from fault_driver import FaultDriver  # type: ignore
from supervisor import SubprocessSupervisor  # type: ignore

# tasks
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tasks"))
from tasks.fix_failing_test import FixFailingTestTask  # type: ignore
from tasks.add_docstring import AddDocstringTask  # type: ignore
from tasks.refactor_func import RefactorFuncTask  # type: ignore

TASKS = {
    "fix_failing_test": FixFailingTestTask,
    "add_docstring": AddDocstringTask,
    "refactor_func": RefactorFuncTask,
}


def _setup_task(task_name: str, workspace: str):
    cls = TASKS[task_name]
    t = cls()
    t.setup(workspace)
    return t


def _start_mock_vllm(port: int, record_file: str):
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_vllm.py")
    return subprocess.Popen(
        [sys.executable, script, "--port", str(port),
         "--prefetch-complete-ms", "20", "--record-file", record_file],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def _wait_aigw(aigw: AigwClient, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            aigw.health()
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return False


def run(args: argparse.Namespace) -> dict:
    aigw = AigwClient(args.aigw_url)
    report: dict = {"scenario": args.scenario, "pass": False, "details": []}

    if not _wait_aigw(aigw, timeout=args.aigw_wait):
        report["details"].append("AIGW did not come up in time")
        return report

    # mock vllm as a subprocess (the AIGW config points at this URL)
    mock_port = 18000
    record_file = os.path.join(args.workspace_root, f"mock_vllm_{args.scenario}.json")
    os.makedirs(args.workspace_root, exist_ok=True)
    mv_proc = None
    if args.start_mock_vllm:
        mv_proc = _start_mock_vllm(mock_port, record_file)
        time.sleep(1.0)

    try:
        report = _run_scenario(args, aigw, mock_port, report)
    finally:
        if mv_proc is not None:
            mv_proc.terminate()
            mv_proc.wait(timeout=5)
    return report


def _run_scenario(args, aigw: AigwClient, mock_port: int, report: dict) -> dict:
    sup = SubprocessSupervisor(
        aigw_url=args.aigw_url, vllm_url=f"http://127.0.0.1:{mock_port}",
        model="test-model", heartbeat_interval=args.heartbeat_interval,
        turn_delay=args.turn_delay_s,
    )

    # start victim agent A
    a_id = "agent-A"
    a_ws = os.path.join(args.workspace_root, "agent-A")
    a_task = _setup_task(args.task, a_ws)
    sup.start_agent(a_id, args.session_id, args.task, a_ws)

    # start survivors B/C/D if --agents > 1
    survivors = []
    if args.agents > 1:
        for i, name in enumerate(["agent-B", "agent-C", "agent-D"][:args.agents - 1]):
            ws = os.path.join(args.workspace_root, name)
            t = _setup_task(args.task, ws)
            sup.start_agent(name, f"session-{name}", args.task, ws)
            survivors.append((name, ws, t))

    fd = FaultDriver(aigw_client=aigw, supervisor=sup)

    # wait for A to be Active
    st = wait_for_state(aigw, a_id, "Active", timeout=15)
    report["details"].append(f"agent-A initial state: {st}")

    # Let the victim reach the fault-injection turn BEFORE firing. With
    # --turn-delay-s pacing the loop is slow enough that the agent is still
    # mid-run at turn k; without the window the agent could race ahead and
    # exit before kill lands (F2 turn-pacing fix).
    # turn-k * turn-delay gives a comfortable cushion past turn k itself.
    if args.turn_delay_s > 0:
        wait_s = max(0.5, args.turn_k * args.turn_delay_s)
        report["details"].append(f"pacing: waiting {wait_s:.1f}s for agent to pass turn {args.turn_k}")
        time.sleep(wait_s)

    # fire the scenario
    if args.scenario == "kill_restart":
        r = fd.kill_restart(a_id, args.session_id, args.task, a_ws,
                            turn_k=args.turn_k, delay_s=args.delay_s)
    elif args.scenario == "graceful_unregister":
        r = fd.graceful_unregister(a_id, args.session_id, args.task, a_ws,
                                  turn_k=args.turn_k, delay_s=args.delay_s)
    elif args.scenario == "heartbeat_timeout":
        # wait_gone_s=0: don't blind-sleep; assert_state_sequence below polls
        # the debug endpoint and captures Active->Suspected->Recovering->Gone
        # live (sleeping blind would miss states finalized + removed by the
        # time we look).
        r = fd.heartbeat_timeout(a_id, args.session_id, args.task, a_ws,
                                 turn_k=args.turn_k, wait_gone_s=0.0)
    else:
        report["details"].append(f"unknown scenario {args.scenario}")
        sup.stop_all()
        return report
    report["details"].extend(r.events)

    # give AIGW time to react (offload/prefetch dispatched async)
    time.sleep(2.0)

    # ---- bidirectional assertion ----
    # read mock vllm call log via its /v1/kvc/* records (we read the file)
    import json
    record_file = os.path.join(args.workspace_root, f"mock_vllm_{args.scenario}.json")
    call_log_calls = []
    if os.path.exists(record_file):
        with open(record_file) as f:
            call_log_calls = json.load(f)

    class _CL:
        def __init__(self, calls): self._c = calls
        def count(self, op):
            return sum(1 for c in self._c
                       if c.get("method") == "POST" and c.get("path") == f"/v1/kvc/{op}")
    cl = _CL(call_log_calls)

    ok_all = True
    # Assertion policy (Phase 3 close-out, per spec §1 L3 + B-path decision):
    #   GATING  = AIGW-side state-machine sequence + task judge + survivors
    #             (proves AgentRegistry transitions + KvcSessionManager strategy
    #             triggers fire on real agent lifecycle + aging runs to Gone)
    #   REPORT  = mock-vLLM hint receipt (offload/prefetch/evict count)
    #             (Phase 4 will GATE this: it needs real BlockStored events so
    #             sessions carry BlockHashes; in degraded mode R1, expectedHashes
    #             is nil (gs_manager.go:574) and the mock emits no kvevents, so
    #             hints are legitimately empty — not a regression.)
    if args.scenario == "kill_restart":
        # kill_restart gating: agent-A must leave Active (fault detected) and
        # walk Active→Suspected→Recovering (the KvcSessionManager strategy
        # triggers fire on OnAgentSuspected + OnAgentRecovered). The final
        # return-to-Active is timing-sensitive: recover() on an agent still in
        # Active is a no-op (Active→Active, no transition logged), and recover
        # after Gone is rejected (must Register). Either way agent-A's task
        # judge (next) proves the agent resumed + finished — that's the
        # recovery evidence, not the瞬时 state. (B-path close-out: hint
        # receipt is report-only; Phase 4 gates it with real BlockStored.)
        ok_seq, seq = assert_state_sequence(
            aigw, a_id, ["Active", "Suspected", "Recovering"],
            total_timeout=30)
        ok_o1, m1 = assert_hint_received(cl, "offload", 1)
        ok_o2, m2 = assert_hint_received(cl, "prefetch", 1)
        report["details"].append(f"state seq: {seq} (ok={ok_seq})")
        report["details"].append(f"hints (report-only): {m1}; {m2}")
        ok_all = ok_seq
        # task judge for A (should pass: agent finished after restart)
        time.sleep(3.0)  # let agent A finish post-restart
        aj, ar = a_task.judge(a_ws)
        report["details"].append(f"agent-A judge: {aj} ({ar})")
        ok_all = ok_all and aj
    elif args.scenario == "graceful_unregister":
        # graceful: agent never leaves Active (no aging triggered), no offload
        ok_seq, seq = assert_state_sequence(
            aigw, a_id, ["Active"], total_timeout=15)
        ok_no, m = assert_no_hint(cl, "offload")
        report["details"].append(f"state seq: {seq} (ok={ok_seq})")
        report["details"].append(f"no offload (gating): {m}")
        ok_all = ok_seq and ok_no
        time.sleep(3.0)
        aj, ar = a_task.judge(a_ws)
        report["details"].append(f"agent-A judge: {aj} ({ar})")
        ok_all = ok_all and aj
    elif args.scenario == "heartbeat_timeout":
        # full aging chain: agent never recovers, ages all the way to Gone
        ok_seq, seq = assert_state_sequence(
            aigw, a_id, ["Active", "Suspected", "Recovering", "Gone"],
            total_timeout=40)
        ok_o1, m1 = assert_hint_received(cl, "offload", 1)
        ok_o2, m2 = assert_hint_received(cl, "evict", 1)
        report["details"].append(f"state seq: {seq} (ok={ok_seq})")
        report["details"].append(f"hints (report-only): {m1}; {m2}")
        ok_all = ok_seq

    # survivors should always finish + pass (fault on A must not cascade)
    for name, ws, t in survivors:
        time.sleep(1.0)
        ok, reason = t.judge(ws)
        report["details"].append(f"survivor {name} judge: {ok} ({reason})")
        ok_all = ok_all and ok

    report["pass"] = ok_all
    sup.stop_all()
    return report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", required=True,
                   choices=["kill_restart", "graceful_unregister", "heartbeat_timeout"])
    p.add_argument("--aigw-url", default="http://127.0.0.1:8701")
    p.add_argument("--vllm-url", default="http://127.0.0.1:18000")
    p.add_argument("--agents", type=int, default=4)
    p.add_argument("--task", default="fix_failing_test",
                   choices=list(TASKS.keys()))
    p.add_argument("--session-id", default="session-A")
    p.add_argument("--turn-k", type=int, default=3)
    p.add_argument("--delay-s", type=float, default=10.0,
                   help="kill_restart: seconds between kill and recover (must land in the "
                        "Suspected/Recovering window = heartbeatTimeout + recoverWindow)")
    p.add_argument("--heartbeat-interval", type=float, default=2.0)
    p.add_argument("--turn-delay-s", type=float, default=1.0,
                   help="seconds the agent sleeps between ReAct turns; slows the loop so a "
                        "mid-run kill catches the agent still running (F2 turn-pacing fix)")
    p.add_argument("--workspace-root", default="/tmp/phase3-run")
    p.add_argument("--aigw-wait", type=float, default=30.0)
    p.add_argument("--start-mock-vllm", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    report = run(args)
    print("=" * 60)
    print(f"SCENARIO {args.scenario}: {'PASS' if report['pass'] else 'FAIL'}")
    for d in report["details"]:
        print(f"  {d}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
