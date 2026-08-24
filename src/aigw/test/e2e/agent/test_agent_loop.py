"""Agent loop test (Phase 3 Group C1) — exercises the ReAct loop + tools +
judge path against mock_vllm's stub LLM and a tiny mock AIGW (no real AIGW
needed). Proves the loop drives the scripted solution to a passing judge
before any fault injection is involved."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# ensure the agent module is importable (use importlib to avoid sys.path.insert)
import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_module(name, rel_path):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_HERE, rel_path)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mra = _load_module("minimal_react_agent", "minimal_react_agent.py")
MockVllm = _load_module("mock_vllm", "mock_vllm.py").MockVllm
FixFailingTestTask = _load_module(
    "tasks.fix_failing_test", os.path.join("tasks", "fix_failing_test.py")
).FixFailingTestTask


class _MockAigwHandler(BaseHTTPRequestHandler):
    """Bare-bones AIGW: returns 2xx for register/heartbeat/recover/get-suggestion."""

    def log_message(self, fmt, *args):  # noqa: D401
        pass

    def _ok(self, code=200):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n:
            self.rfile.read(n)
        if self.path.endswith("/agents/register"):
            self._ok(201)
        elif self.path.endswith("/get-suggestion"):
            out = json.dumps(
                {"prefill_url": "http://x", "decode_url": "http://x", "session_id": "s"}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        else:
            self._ok(200)

    def do_GET(self):  # noqa: N802
        self._ok(200)


@pytest.fixture
def mock_stack():
    # mock AIGW
    aigw_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockAigwHandler)
    ta = threading.Thread(target=aigw_srv.serve_forever, daemon=True)
    ta.start()
    aigw_url = f"http://127.0.0.1:{aigw_srv.server_address[1]}"
    # mock vllm
    mv = MockVllm(port=0, prefetch_complete_ms=10)
    mv.start()
    yield aigw_url, mv
    mv.stop()
    aigw_srv.shutdown()
    aigw_srv.server_close()


def _run_agent(aigw_url, vllm_url, task_name, workspace, agent_id="a-test"):
    argv = [
        "--aigw-url", aigw_url, "--vllm-url", vllm_url,
        "--agent-id", agent_id, "--session-id", "s-test",
        "--model", "test-model", "--task", task_name,
        "--task-prompt", f"do {task_name}",
        "--workspace", workspace, "--heartbeat-interval", "0",
        "--max-turns", "8",
    ]
    return mra.main(argv)


def test_agent_drives_fix_failing_test_to_pass(mock_stack):
    aigw_url, mv = mock_stack
    ws = tempfile.mkdtemp(prefix="phase3-agent-")
    try:
        task = FixFailingTestTask()
        task.setup(ws)
        rc = _run_agent(aigw_url, mv.base_url, "fix_failing_test", ws)
        assert rc == 0
        ok, reason = task.judge(ws)
        assert ok, f"judge failed: {reason}"
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def test_agent_persists_transcript_for_resume(mock_stack):
    """transcript.json exists after the loop so a restart resumes from turn k."""
    aigw_url, mv = mock_stack
    ws = tempfile.mkdtemp(prefix="phase3-agent-")
    try:
        FixFailingTestTask().setup(ws)
        _run_agent(aigw_url, mv.base_url, "fix_failing_test", ws)
        assert os.path.exists(os.path.join(ws, "transcript.json"))
    finally:
        shutil.rmtree(ws, ignore_errors=True)
