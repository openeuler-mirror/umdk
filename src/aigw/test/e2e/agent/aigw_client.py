"""Thin urllib client for AIGW's agent + KVC debug endpoints (Phase 3 Group A2).

Wraps the endpoints wired in Phase 2 (internal/server/http_server.go:145-151 +
kvc_handlers.go). All calls are unsigned — the Phase 3 AIGW is configured with
no HMAC key, so `WithHMAC` passes through (pkg/crypto/hmac.go:197-203).

Endpoint map (verified on branch k8s):
  POST /aigw/v1/agents/register                 -> register
  POST /aigw/v1/agents/{id}/heartbeat           -> heartbeat
  POST /aigw/v1/agents/{id}/recover             -> recover (reuse agent_id+session_id)
  POST /aigw/v1/agents/{id}/unregister          -> unregister
  GET  /aigw/v1/agents                          -> agents_list (debug)
  GET  /aigw/v1/agents/{id}                     -> agent_detail (debug: state)
  GET  /aigw/v1/agents/{id}/sessions/{sid}     -> session_detail (alias to kvc route)
  GET  /aigw/v1/models/{m}/kvc/sessions/{sid}   -> session_detail (canonical kvc route)
  GET  /aigw/v1/models/{m}/kvc/blocks/{h}       -> block_detail
  POST /aigw/v1/openai/get-suggestion           -> get_suggestion (carries X-Agent-Id/
                                                                 X-Session-Id; implicit
                                                                 heartbeat per C3)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from typing import Any


class AigwError(Exception):
    """Non-2xx response from AIGW. Carries status + body for diagnosis."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"AIGW {status}: {body}")
        self.status = status
        self.body = body


class AigwClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8701") -> None:
        # strip trailing slash so path joins are clean
        self.base_url = base_url.rstrip("/")

    # ---- low-level ----
    def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> Any:
        url = self.base_url + path
        data = None
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        if body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if not raw:
                    return None
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise AigwError(e.code, e.read().decode("utf-8", "replace")) from e
        except urllib.error.URLError as e:
            # connection refused / unreachable host — surface as AigwError(0)
            raise AigwError(0, str(e)) from e

    # ---- agent lifecycle ----
    def register(
        self, agent_id: str, models: list[str], metadata: dict[str, str] | None = None
    ) -> Any:
        return self._request(
            "POST", "/aigw/v1/agents/register",
            {"agent_id": agent_id, "models": models, "metadata": metadata or {}},
        )

    def heartbeat(
        self, agent_id: str, models: list[str], session_ids: list[str]
    ) -> Any:
        return self._request(
            "POST", f"/aigw/v1/agents/{agent_id}/heartbeat",
            {"agent_id": agent_id, "models": models, "session_ids": session_ids},
        )

    def recover(self, agent_id: str, models: list[str]) -> Any:
        return self._request(
            "POST", f"/aigw/v1/agents/{agent_id}/recover",
            {"agent_id": agent_id, "models": models},
        )

    def unregister(self, agent_id: str) -> Any:
        return self._request(
            "POST", f"/aigw/v1/agents/{agent_id}/unregister",
            {"agent_id": agent_id},
        )

    # ---- get-suggestion (carries implicit heartbeat) ----
    def get_suggestion(self, model: str, body: dict[str, Any], agent_id: str,
                       session_id: str) -> Any:
        """POST /aigw/v1/openai/get-suggestion. Sets X-Agent-Id + X-Session-Id
        so AIGW's implicit-heartbeat path (http_server.go:392-398) fires.

        AIGW's scheduleForOpenAi decodes an OpenAI-shaped body and reads
        req.Messages (processMessages), so the body must carry a `messages`
        array (a bare `prompt` field yields 'prompt is empty' 400). The handler
        also forwards req.UUID verbatim into GetSuggestionIn.UUID, and
        AigwManager.GetSuggestion rejects an empty UUID with 500 ('The length
        of UUID is invalid') — *before* the implicit-heartbeat path runs, so a
        missing UUID silently disables implicit heartbeat (and never registers
        a KVC session for the agent). Generate a fresh UUID per call so each
        turn's request is distinct (CheckReqExists dedups by UUID)."""
        if "messages" not in body:
            # wrap a plain prompt into the OpenAI messages shape
            prompt = body.get("prompt", body.get("text", "phase3 turn"))
            body = {**body, "messages": [{"role": "user", "content": prompt}]}
        body = {**body, "model": model}
        if not body.get("UUID"):
            body["UUID"] = f"phase3-{uuid.uuid4().hex}"
        return self._request(
            "POST", "/aigw/v1/openai/get-suggestion",
            body,
            extra_headers={"X-Agent-Id": agent_id, "X-Session-Id": session_id},
        )

    # ---- debug (assertion layer reads these) ----
    def agents_list(self) -> Any:
        return self._request("GET", "/aigw/v1/agents")

    def agent_detail(self, agent_id: str) -> Any:
        return self._request("GET", f"/aigw/v1/agents/{agent_id}")

    def session_detail(self, model: str, session_id: str) -> Any:
        return self._request(
            "GET", f"/aigw/v1/models/{model}/kvc/sessions/{session_id}"
        )

    def block_detail(self, model: str, block_hash: int) -> Any:
        return self._request(
            "GET", f"/aigw/v1/models/{model}/kvc/blocks/{block_hash}"
        )

    def health(self) -> Any:
        return self._request("GET", "/aigw/v1/health")
