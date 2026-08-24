#!/usr/bin/env python3
"""
End-to-end tests for the AIGW provider pool.

Launches two mock provider servers plus a real aigw process configured in
provider mode, then drives traffic through aigw's forwarding endpoint to
verify: non-stream success, streaming, failover from a faulty primary,
cooldown after repeated 5xx, and a small concurrency burst.

The aigw binary is located via the AIGW_BIN env var, falling back to
../../output/aigw/aigw. If no binary is found the suite is skipped.

Run:
    pytest test/e2e/test_e2e_provider.py -v
    # or standalone
    python3 test/e2e/test_e2e_provider.py
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
MOCK_SERVER = os.path.join(HERE, "mock_e2e_provider_server.py")
MODEL = "gpt-4o-mini"
COOLDOWN_DURATION_SEC = 2


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _find_aigw_bin() -> str:
    env = os.environ.get("AIGW_BIN")
    if env and os.path.isfile(env):
        return env
    default = os.path.normpath(os.path.join(HERE, "..", "..", "output", "aigw", "aigw"))
    if os.path.isfile(default):
        return default
    return ""


def _wait_http(url: str, timeout: float = 15.0, method: str = "GET") -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.request(method, url, timeout=1)
            if resp.status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.2)
    return False


class MockProvider:
    """Wraps a mock provider server subprocess."""

    def __init__(self, name: str, fault: str = "none"):
        self.name = name
        self.port = _free_port()
        self.proc = subprocess.Popen(
            [sys.executable, MOCK_SERVER, "--port", str(self.port),
             "--name", name, "--fault", fault],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def wait_ready(self):
        assert _wait_http(f"{self.base_url}/health"), f"mock {self.name} not ready"

    def set_fault(self, fault: str):
        requests.post(f"{self.base_url}/_control", json={"fault": fault}, timeout=2)

    def hits(self) -> int:
        return requests.get(f"{self.base_url}/_stats", timeout=2).json()["hits"]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class AigwProcess:
    """Wraps a real aigw process running a provider-mode config."""

    def __init__(self, deployments, log_dir):
        self.port = _free_port()
        self.log_dir = log_dir
        cfg = {
            "global": {
                "host": "127.0.0.1",
                "port": str(self.port),
                "logPath": log_dir,
                "logLevel": "error",
                "securitySchema": "default",
                "snapshotUpdateInterval": 60,
                "reqTimeout": 60,
            },
            "discovery": {"enable": False},
            "predictor": {"predictType": "none"},
            "proxy": {
                "enable": True,
                "timeout": 30,
                "maxRetry": 0,
                "retryBaseInterval": 50,
                "retryMaxInterval": 500,
                "circuitBreaker": {
                    "enabled": False,
                    "failureThreshold": 5,
                    "successThreshold": 2,
                    "timeout": 30,
                },
            },
            "globalSchedulers": [{
                "model": MODEL,
                "mode": "provider",
                "providerPool": {
                    "strategy": "simple-shuffle",
                    "cooldown": {
                        "failureThreshold": 3,
                        "durationSec": COOLDOWN_DURATION_SEC,
                        "rateLimitDurationSec": COOLDOWN_DURATION_SEC,
                        "auth401FloorSec": COOLDOWN_DURATION_SEC,
                    },
                    "retry": {"maxFailoverEndpoints": 3, "maxRetriesPerEndpoint": 0},
                    "deployments": deployments,
                },
            }],
            "limits": {
                "totalInsNum": 2048, "insNumPerModel": 128, "modelNum": 128,
                "concurrency": 256, "maxPromptRunes": 4096,
            },
        }
        fd, self.cfg_path = tempfile.mkstemp(suffix=".json", prefix="aigw-provider-")
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)

        bin_path = _find_aigw_bin()
        self.proc = subprocess.Popen(
            [bin_path, f"--config={self.cfg_path}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def wait_ready(self):
        assert _wait_http(f"{self.url}/aigw/v1/health"), "aigw not ready"

    def chat(self, stream=False, timeout=30):
        body = {"model": MODEL, "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]}
        return requests.post(f"{self.url}/aigw/v1/openai/chat/completions",
                             json=body, stream=stream, timeout=timeout)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            os.remove(self.cfg_path)
        except OSError:
            pass


def _dep(id_, base_url):
    # Distinct apiKey per deployment => distinct cross-pool StateKey, so failover
    # and cooldown treat the two endpoints independently.
    return {"id": id_, "provider": "openai", "apiBase": base_url,
            "apiKey": f"sk-e2e-{id_}", "tpm": 60000, "rpm": 500}


@pytest.fixture(scope="module")
def cluster():
    if not _find_aigw_bin():
        pytest.skip("aigw binary not found; set AIGW_BIN or build output/aigw/aigw")

    primary = MockProvider("primary", fault="none")
    backup = MockProvider("backup", fault="none")
    primary.wait_ready()
    backup.wait_ready()

    log_dir = tempfile.mkdtemp(prefix="aigw-e2e-log-")
    aigw = AigwProcess(
        deployments=[_dep("primary", primary.base_url), _dep("backup", backup.base_url)],
        log_dir=log_dir,
    )
    try:
        aigw.wait_ready()
        yield {"aigw": aigw, "primary": primary, "backup": backup}
    finally:
        aigw.stop()
        primary.stop()
        backup.stop()


def _reset(cluster):
    cluster["primary"].set_fault("none")
    cluster["backup"].set_fault("none")
    # Let any active cooldown expire so each test starts from a clean pool.
    time.sleep(COOLDOWN_DURATION_SEC + 0.5)


def test_non_stream_success(cluster):
    _reset(cluster)
    resp = cluster["aigw"].chat(stream=False)
    assert resp.status_code == 200
    data = resp.json()
    assert data["usage"]["total_tokens"] == 20
    assert data["served_by"] in ("primary", "backup")


def test_streaming_success(cluster):
    _reset(cluster)
    resp = cluster["aigw"].chat(stream=True)
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("Content-Type", "")
    body = resp.content.decode()
    assert "hello" in body
    assert "[DONE]" in body


def test_failover_primary_fault(cluster):
    _reset(cluster)
    # Primary always 500: every request must still succeed via backup failover.
    cluster["primary"].set_fault("500")
    for _ in range(5):
        resp = cluster["aigw"].chat(stream=False)
        assert resp.status_code == 200
        assert resp.json()["served_by"] == "backup"


def test_cooldown_after_repeated_5xx(cluster):
    _reset(cluster)
    # Both endpoints fault: once both trip cooldown the pool returns 502.
    cluster["primary"].set_fault("500")
    cluster["backup"].set_fault("500")
    seen_502 = False
    for _ in range(8):
        resp = cluster["aigw"].chat(stream=False)
        if resp.status_code == 502:
            seen_502 = True
            break
    assert seen_502, "expected 502 once all endpoints cooled down"

    # Recovery: heal upstreams and wait out the cooldown window.
    cluster["primary"].set_fault("none")
    cluster["backup"].set_fault("none")
    time.sleep(COOLDOWN_DURATION_SEC + 1.0)
    resp = cluster["aigw"].chat(stream=False)
    assert resp.status_code == 200


def test_concurrency_burst(cluster):
    _reset(cluster)
    n = 50

    def one():
        return cluster["aigw"].chat(stream=False).status_code

    with ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(lambda _: one(), range(n)))
    assert all(c == 200 for c in codes), f"non-200 responses: {codes}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
