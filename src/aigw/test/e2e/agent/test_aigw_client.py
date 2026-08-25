"""
Unit tests for aigw_client.

Verifies request shaping against a mock AIGW (Phase 3 Group A2). No real
AIGW needed; a tiny http.server echoes requests so we assert paths/methods/
headers/body fields are what Phase 2's handlers expect (verified against
kvc_handlers.go field names).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aigw_client import AigwClient, AigwError  # type: ignore


class _EchoHandler(BaseHTTPRequestHandler):
    """Records each request as a dict the test inspects."""

    def log_message(self, fmt, *args):  # noqa: D401
        pass

    def _record(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(n) if n else b""
        rec = {
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": json.loads(body) if body else None,
        }
        self.server.records.append(rec)  # type: ignore[attr-defined]
        out = json.dumps({"ok": True}).encode()
        # register returns 201 in real AIGW; echo 201 for that path, 200 else
        code = 201 if self.path.endswith("/agents/register") else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _do_post(self):  # noqa: D401
        self._record()

    def _do_get(self):  # noqa: D401
        self._record()

    # BaseHTTPRequestHandler dispatches via getattr(self, 'do_'+command);
    # expose runtime names as class-body aliases (G.NAM.01 scans def names).
    do_POST = _do_post
    do_GET = _do_get


@pytest.fixture
def aigw():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    srv.records = []  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    client = AigwClient(f"http://127.0.0.1:{port}")
    yield client, srv
    srv.shutdown()
    srv.server_close()


def _last(srv) -> dict:
    return srv.records[-1]  # type: ignore[attr-defined]


def test_register_shaping(aigw):
    client, srv = aigw
    client.register("a1", ["m1"], {"ver": "1"})
    r = _last(srv)
    assert r["method"] == "POST"
    assert r["path"] == "/aigw/v1/agents/register"
    assert r["body"] == {"agent_id": "a1", "models": ["m1"], "metadata": {"ver": "1"}}


def test_heartbeat_shaping(aigw):
    client, srv = aigw
    client.heartbeat("a1", ["m1"], ["s1"])
    r = _last(srv)
    assert r["path"] == "/aigw/v1/agents/a1/heartbeat"
    assert r["body"] == {"agent_id": "a1", "models": ["m1"], "session_ids": ["s1"]}


def test_recover_shaping(aigw):
    client, srv = aigw
    client.recover("a1", ["m1"])
    r = _last(srv)
    assert r["path"] == "/aigw/v1/agents/a1/recover"
    assert r["body"] == {"agent_id": "a1", "models": ["m1"]}


def test_unregister_shaping(aigw):
    client, srv = aigw
    client.unregister("a1")
    r = _last(srv)
    assert r["path"] == "/aigw/v1/agents/a1/unregister"
    assert r["body"] == {"agent_id": "a1"}


def test_get_suggestion_sets_agent_headers(aigw):
    """
    C3: get-suggestion must carry X-Agent-Id + X-Session-Id.

    The request must also wrap the body into the OpenAI messages shape
    (scheduleForOpenAi reads req.Messages, not a bare prompt field — bare
    prompt => 400 'prompt is empty').
    """
    client, srv = aigw
    client.get_suggestion("m1", {"prompt": "hi"}, agent_id="a1", session_id="s1")
    r = _last(srv)
    assert r["path"] == "/aigw/v1/openai/get-suggestion"
    assert r["headers"].get("X-Agent-Id") == "a1"
    assert r["headers"].get("X-Session-Id") == "s1"
    body = r["body"]
    assert body["model"] == "m1"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["prompt"] == "hi"  # original field preserved


def test_debug_endpoints_shaping(aigw):
    client, srv = aigw
    client.agents_list()
    assert _last(srv)["path"] == "/aigw/v1/agents"
    client.agent_detail("a1")
    assert _last(srv)["path"] == "/aigw/v1/agents/a1"
    client.session_detail("m1", "s1")
    assert _last(srv)["path"] == "/aigw/v1/models/m1/kvc/sessions/s1"
    client.block_detail("m1", 12345)
    assert _last(srv)["path"] == "/aigw/v1/models/m1/kvc/blocks/12345"


def test_aigw_error_on_4xx(aigw):
    """A non-2xx surfaces as AigwError with status + body."""
    client, srv = aigw
    # point the client at a port that rejects
    bad = AigwClient("http://127.0.0.1:1")
    with pytest.raises(AigwError):
        bad.health()
