"""Mock vLLM for Phase 3 fault-injection e2e.

A stdlib-only (http.server) stand-in for vLLM's KVC control plane + a stub
chat-completions endpoint. It honors the wire contract locked in Phase 1
(see memory `phase1-vllm-kvc-control-plane`), so AIGW's `VllmKvcClient`
retry/poll logic (Phase 2) behaves realistically against it:

  POST /v1/kvc/offload  -> 200 KvcAck (status accepted, block_placements {h:"cpu"})
  POST /v1/kvc/prefetch -> 202 + job_id when work accepted (else 200+rejected)
  POST /v1/kvc/evict    -> 200 KvcAck (purged_hashes)
  GET  /v1/kvc/jobs/{id}-> 200 KvcJobStatus (running -> done after prefetch_complete_ms)
  POST /v1/chat/completions -> stub LLM: walks a scripted ReAct solution for the
                                active task so the agent loop terminates.

Every /v1/kvc/* call is recorded in a thread-safe list for the bidirectional
assertion layer (E2/E3): AIGW state-machine transition + mock-vLLM hint receipt.

No real GPU<->CPU transfer happens here (Phase 4 scope). The mock's job is to
(a) return contract-correct acks so AIGW's hint-sender/poller is exercised,
(b) be observable so the test can prove "AIGW dispatched the right hint."
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

logger = logging.getLogger(__name__)


def _now_ms() -> int:
    return int(time.time() * 1000)


class _CallLog:
    """Thread-safe record of every /v1/kvc/* call. The assertion layer reads
    this to prove AIGW dispatched the expected hint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: list[dict[str, Any]] = []

    def record(self, method: str, path: str, body: Any) -> None:
        with self._lock:
            self._calls.append(
                {"ts": _now_ms(), "method": method, "path": path, "body": body}
            )

    def calls(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._calls)

    def count(self, op: str) -> int:
        """Count POST /v1/kvc/{op} calls (op in offload|prefetch|evict)."""
        with self._lock:
            return sum(
                1
                for c in self._calls
                if c["method"] == "POST" and c["path"] == f"/v1/kvc/{op}"
            )

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()


class _JobStore:
    """Pending/done prefetch jobs. A background thread flips pending->done
    after prefetch_complete_ms so AIGW's poller observes running->done."""

    def __init__(self, complete_ms: int) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._next = 0
        self._complete_ms = complete_ms

    def create(self, hint_id: str, hashes: list[int]) -> str:
        with self._lock:
            jid = f"job-{self._next}"
            self._next += 1
            self._jobs[jid] = {
                "hint_id": hint_id,
                "hashes": list(hashes),
                "status": "running",
                "created_ms": _now_ms(),
            }
        # schedule completion
        t = threading.Thread(
            target=self._complete_later, args=(jid,), daemon=True
        )
        t.start()
        return jid

    def _complete_later(self, jid: str) -> None:
        time.sleep(self._complete_ms / 1000.0)
        with self._lock:
            j = self._jobs.get(jid)
            if j is not None and j["status"] == "running":
                j["status"] = "done"
                j["done_hashes"] = list(j["hashes"])
                j["blocks_pinned"] = True
                j["completed_ms"] = _now_ms()

    def status(self, jid: str) -> dict[str, Any] | None:
        with self._lock:
            j = self._jobs.get(jid)
            if j is None:
                return None
            return {
                "job_id": jid,
                "status": j["status"],
                "done_hashes": j.get("done_hashes", []),
                "failed_hashes": [],
                "blocks_pinned": j.get("blocks_pinned", False),
            }


# Stub LLM: a small per-task state machine that walks a scripted ReAct solution.
# The agent is exercising the *harness* (lifecycle + tool loop), not solving
# tasks creatively; the stub drives a deterministic solution so the loop
# terminates and the judge has a real artifact to check.
_TASK_SCRIPTS: dict[str, list[str]] = {
    # each entry is the next Action to emit, in order; the final one is
    # "Final Answer: done" which breaks the loop. Scripts are padded with
    # busywork turns (read_file/grep_find) so the agent is still running at
    # turn k=4-5 when fault_driver injects — the real work (write_file) lands
    # mid-loop, leaving enough window for AIGW to age + the fault to fire
    # before the agent finishes.
    "fix_failing_test": [
        "Action: bash_exec\nAction Input: cat calc.py",
        "Action: read_file\nAction Input: test_calc.py",
        "Action: grep_find\nAction Input: add",
        "Action: write_file\nAction Input: calc.py|def add(a, b):\n    return a + b\n",
        "Action: bash_exec\nAction Input: python3 -m pytest test_calc.py -q",
        "Action: read_file\nAction Input: calc.py",
        "Final Answer: done",
    ],
    "add_docstring": [
        "Action: bash_exec\nAction Input: cat mod.py",
        "Action: read_file\nAction Input: mod.py",
        "Action: grep_find\nAction Input: def",
        (
            "Action: write_file\nAction Input: mod.py|\"\"\"mod doc.\"\"\"\n"
            "def f():\n    \"\"\"f doc.\"\"\"\n    return 1\ndef g():\n"
            "    \"\"\"g doc.\"\"\"\n    return 2\ndef h():\n    \"\"\"h doc.\"\"\"\n"
            "    return 3\n"
        ),
        "Action: bash_exec\nAction Input: python3 -m py_compile mod.py",
        "Final Answer: done",
    ],
    "refactor_func": [
        "Action: bash_exec\nAction Input: cat mod.py",
        "Action: read_file\nAction Input: mod.py",
        "Action: grep_find\nAction Input: old_name",
        "Action: write_file\nAction Input: mod.py|def new_name():\n    return 42\n",
        "Action: bash_exec\nAction Input: python3 -c \"import mod; print(mod.new_name())\"",
        "Final Answer: done",
    ],
}


class _StubLLM:
    """Returns the next scripted Action for the active task, indexed by the
    number of assistant messages already in the caller's transcript.

    Stateless: the step is derived from the transcript itself, so the stub
    works correctly across (a) a fresh start (0 assistant msgs -> script[0]),
    (b) restart-after-kill (N assistant msgs -> script[N], resuming in sync
    with the persisted transcript), and (c) concurrent agents on the same task
    name (each agent's transcript is independent, so their step indices don't
    collide — unlike a process-level turn counter keyed by task name, which
    two agents on the same task would race and corrupt)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()  # guards _TASK_SCRIPTS reads only

    def respond(self, task_name: str, assistant_count: int) -> str:
        script = _TASK_SCRIPTS.get(task_name)
        if script is None:
            return "Final Answer: no script"
        with self._lock:
            idx = max(0, assistant_count)
            if idx >= len(script):
                return "Final Answer: done"
            return script[idx]


def make_handler(call_log: _CallLog, jobs: _JobStore, stub: _StubLLM):
    """Build a request handler closed over the shared mutable state."""

    class _Handler(BaseHTTPRequestHandler):
        # quiet the default logger; the harness logs enough
        def log_message(self, fmt, *args):  # noqa: D401
            pass

        def _send_json(self, code: int, obj: dict[str, Any]) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> Any:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n == 0:
                return {}
            raw = self.rfile.read(n)
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"_raw": raw.decode("utf-8", "replace")}

        # ---- KVC control plane ----
        def do_POST(self):  # noqa: N802
            path = self.path.split("?")[0]
            body = self._read_body()
            if path == "/v1/kvc/offload":
                call_log.record("POST", path, body)
                hashes = body.get("block_hashes", []) if isinstance(body, dict) else []
                ack = {
                    "hint_id": body.get("hint_id", ""),
                    "status": "accepted",
                    "accepted_hashes": list(hashes),
                    "in_flight_hashes": [],
                    "missing_hashes": [],
                    "failed_hashes": [],
                    "block_placements": {int(h): "cpu" for h in hashes},
                    "job_id": None,
                }
                self._send_json(200, ack)
                return
            if path == "/v1/kvc/prefetch":
                call_log.record("POST", path, body)
                hashes = body.get("block_hashes", []) if isinstance(body, dict) else []
                if not hashes:
                    # nothing to prefetch -> 200 + rejected, no job_id (Phase 1
                    # contract: prefetch 202 ONLY when work accepted).
                    self._send_json(
                        200,
                        {
                            "hint_id": body.get("hint_id", ""),
                            "status": "rejected",
                            "missing_hashes": [],
                            "job_id": None,
                        },
                    )
                    return
                jid = jobs.create(body.get("hint_id", ""), list(hashes))
                self._send_json(
                    202,
                    {
                        "hint_id": body.get("hint_id", ""),
                        "status": "accepted",
                        "accepted_hashes": list(hashes),
                        "job_id": jid,
                    },
                )
                return
            if path == "/v1/kvc/evict":
                call_log.record("POST", path, body)
                hashes = body.get("block_hashes", []) if isinstance(body, dict) else []
                self._send_json(
                    200,
                    {
                        "hint_id": body.get("hint_id", ""),
                        "status": "accepted",
                        "purged_hashes": list(hashes),
                        "not_found_hashes": [],
                    },
                )
                return
            if path == "/v1/chat/completions":
                # stub LLM. Extract task name from the first system/user message
                # (the agent sets it as a system prompt prefix "TASK: <name>"),
                # and count assistant messages already in the transcript so the
                # stub resumes at the right step after a restart-after-kill.
                task, asst_count = self._extract_task_and_count(body)
                resp_text = stub.respond(task, asst_count)
                # minimal OpenAI-shaped response
                self._send_json(
                    200,
                    {
                        "id": "chatcmpl-stub",
                        "object": "chat.completion",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": resp_text},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )
                return
            self._send_json(404, {"error": "not_found", "path": path})

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path.startswith("/v1/kvc/jobs/"):
                jid = path.rsplit("/", 1)[-1]
                st = jobs.status(jid)
                if st is None:
                    self._send_json(404, {"error": "job_not_found", "job_id": jid})
                    return
                self._send_json(200, st)
                return
            self._send_json(404, {"error": "not_found", "path": path})

        def _extract_task_and_count(self, body: Any) -> tuple[str, int]:
            """Pull the task name (from the system-prompt "TASK: <name>" stamp)
            and the count of assistant messages already in the transcript
            (the stub's step index — see _StubLLM.respond)."""
            if not isinstance(body, dict):
                return "", 0
            task = ""
            asst = 0
            for msg in body.get("messages", []):
                role = msg.get("role")
                if role == "system":
                    content = msg.get("content", "")
                    if "TASK:" in content:
                        task = content.split("TASK:", 1)[1].strip().split()[0]
                elif role == "assistant":
                    asst += 1
            return task, asst

    return _Handler


class MockVllm:
    """A running mock vLLM server. Use as:

        mv = MockVllm(port=0)
        mv.start()
        base = mv.base_url
        ... exercise AIGW ...
        calls = mv.call_log.calls()
        mv.stop()
    """

    def __init__(
        self,
        port: int = 0,
        prefetch_complete_ms: int = 50,
    ) -> None:
        self.call_log = _CallLog()
        self.jobs = _JobStore(prefetch_complete_ms)
        self.stub = _StubLLM()
        handler = make_handler(self.call_log, self.jobs, self.stub)
        self._srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self._thread: threading.Thread | None = None
        self._port = self._srv.server_address[1]

    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def _main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--prefetch-complete-ms", type=int, default=50)
    ap.add_argument("--record-file", default="")
    args = ap.parse_args()
    mv = MockVllm(port=args.port, prefetch_complete_ms=args.prefetch_complete_ms)
    mv.start()
    logger.info(f"mock_vllm listening on {mv.base_url}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        mv.stop()
        if args.record_file:
            with open(args.record_file, "w") as f:
                json.dump(mv.call_log.calls(), f, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
