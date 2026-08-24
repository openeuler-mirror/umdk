#!/usr/bin/env python3
"""
Mock Provider Server for AIGW Provider-Pool E2E Testing

Simulates an OpenAI-compatible upstream provider. It exposes:
  POST /v1/chat/completions  - chat endpoint (JSON or SSE streaming)
  POST /_control             - flip fault mode at runtime: {"fault": "none|500|429|401"}
  GET  /_stats               - {"hits": N} request counter for failover/concurrency asserts
  GET  /health               - liveness probe

Fault injection (in priority order):
  1. per-request override:  header "X-Mock-Inject" or query "?inject=500|429|401"
  2. server fault mode:     --fault startup flag, mutable via POST /_control

Usage:
    python3 mock_e2e_provider_server.py --port 19100 --name primary --fault none
"""

import argparse
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ProviderState:
    """Mutable per-server state shared across handler instances."""

    def __init__(self, name: str, fault: str):
        self.name = name
        self.fault = fault
        self.hits = 0
        self.lock = threading.Lock()

    def record_hit(self) -> int:
        with self.lock:
            self.hits += 1
            return self.hits


FAULT_BODIES = {
    "500": (500, {"error": {"message": "mock internal server error", "type": "server_error"}}),
    "429": (429, {"error": {"message": "mock rate limit exceeded", "type": "rate_limit_error"}}),
    "401": (401, {"error": {"message": "mock invalid api key", "type": "auth_error"}}),
}


def make_handler(state: ProviderState):
    class ProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print(f"[Provider-{state.name}] {self.address_string()} - {fmt % args}")

        def _send_json(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _query_inject(self) -> str:
            if "?" not in self.path:
                return ""
            query = self.path.split("?", 1)[1]
            for pair in query.split("&"):
                if pair.startswith("inject="):
                    return pair[len("inject="):]
            return ""

        def _resolve_fault(self) -> str:
            override = self.headers.get("X-Mock-Inject") or self._query_inject()
            if override:
                return override
            return state.fault

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._send_json(200, {"status": "ok", "name": state.name})
            elif path == "/_stats":
                self._send_json(200, {"hits": state.hits, "name": state.name})
            else:
                self.send_error(404, "Not Found")

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path == "/_control":
                self._handle_control()
            elif path == "/v1/chat/completions":
                self._handle_chat()
            else:
                self.send_error(404, "Not Found")

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode() if length > 0 else "{}"
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}

        def _handle_control(self):
            body = self._read_body()
            fault = body.get("fault")
            if fault is not None:
                state.fault = fault
            self._send_json(200, {"fault": state.fault, "name": state.name})

        def _handle_chat(self):
            state.record_hit()
            request = self._read_body()
            fault = self._resolve_fault()

            if fault and fault != "none":
                code, payload = FAULT_BODIES.get(
                    fault, (500, {"error": {"message": f"mock fault {fault}"}})
                )
                self._send_json(code, payload)
                return

            model = request.get("model", "mock-model")
            if request.get("stream", False):
                self._handle_stream(model)
            else:
                self._handle_unary(model)

        def _handle_unary(self, model: str):
            payload = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "served_by": state.name,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant",
                                "content": f"hello from {state.name}"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 8, "completion_tokens": 12, "total_tokens": 20},
            }
            self._send_json(200, payload)

        def _handle_stream(self, model: str):
            # Close after the final chunk so the proxy reader sees EOF and the
            # SSE relay terminates cleanly.
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
            created = int(time.time())
            for word in [f"hello", "from", state.name]:
                chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": {"content": word + " "},
                                 "finish_reason": None}],
                }
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.02)

            final = {
                "id": chunk_id, "object": "chat.completion.chunk", "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    return ProviderHandler


def run(port: int, name: str, fault: str):
    state = ProviderState(name, fault)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    print(f"[Provider-{name}] listening on 127.0.0.1:{port} (fault={fault})")
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Mock provider server for AIGW E2E")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", type=str, default="provider")
    parser.add_argument("--fault", type=str, default="none",
                        choices=["none", "500", "429", "401"])
    args = parser.parse_args()
    run(args.port, args.name, args.fault)


if __name__ == "__main__":
    main()
