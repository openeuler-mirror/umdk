"""Unit tests for mock_vllm — contract shape + call log (Phase 3 Group A1)."""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

import pytest

from mock_vllm import MockVllm  # type: ignore


def _post(base: str, path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def mv():
    m = MockVllm(port=0, prefetch_complete_ms=20)
    m.start()
    yield m
    m.stop()


def test_offload_returns_accepted_with_cpu_placements(mv):
    code, ack = _post(
        mv.base_url, "/v1/kvc/offload",
        {"hint_id": "h1", "block_hashes": [101, 102]},
    )
    assert code == 200
    assert ack["status"] == "accepted"
    assert ack["accepted_hashes"] == [101, 102]
    # JSON object keys are strings on the wire; AIGW's VllmKvcClient sees the
    # same {str:int64} shape, so assert the string-keyed form here.
    assert ack["block_placements"] == {"101": "cpu", "102": "cpu"}
    assert ack["job_id"] is None
    assert mv.call_log.count("offload") == 1


def test_prefetch_returns_202_with_job_id(mv):
    code, ack = _post(
        mv.base_url, "/v1/kvc/prefetch",
        {"hint_id": "h2", "block_hashes": [201]},
    )
    assert code == 202
    assert ack["status"] == "accepted"
    assert ack["job_id"].startswith("job-")
    assert mv.call_log.count("prefetch") == 1


def test_prefetch_empty_hashes_returns_200_rejected_no_job(mv):
    """Phase 1 contract: prefetch 202 ONLY when work accepted; empty -> 200."""
    code, ack = _post(
        mv.base_url, "/v1/kvc/prefetch",
        {"hint_id": "h2b", "block_hashes": []},
    )
    assert code == 200
    assert ack["status"] == "rejected"
    assert ack["job_id"] is None


def test_prefetch_job_polls_running_then_done(mv):
    _, ack = _post(
        mv.base_url, "/v1/kvc/prefetch",
        {"hint_id": "h3", "block_hashes": [301]},
    )
    jid = ack["job_id"]
    # immediately: running
    c0, st0 = _get(mv.base_url, f"/v1/kvc/jobs/{jid}")
    assert c0 == 200
    assert st0["status"] in ("running", "done")
    # after completion window: done + pinned
    time.sleep(0.06)
    c1, st1 = _get(mv.base_url, f"/v1/kvc/jobs/{jid}")
    assert c1 == 200
    assert st1["status"] == "done"
    assert st1["done_hashes"] == [301]
    assert st1["blocks_pinned"] is True


def test_job_status_404_for_unknown(mv):
    c, st = _get(mv.base_url, "/v1/kvc/jobs/does-not-exist")
    assert c == 404
    assert st["error"] == "job_not_found"


def test_evict_returns_purged(mv):
    code, ack = _post(
        mv.base_url, "/v1/kvc/evict",
        {"hint_id": "h4", "block_hashes": [401, 402]},
    )
    assert code == 200
    assert ack["status"] == "accepted"
    assert ack["purged_hashes"] == [401, 402]
    assert mv.call_log.count("evict") == 1


def test_chat_completions_stub_drives_script(mv):
    """Stub LLM emits the scripted action sequence for fix_failing_test.

    The stub indexes its step by the number of assistant messages already in
    the transcript (so it resumes correctly after a restart). To drive the
    script forward we must accumulate each assistant reply back into the
    messages, exactly as minimal_react_agent does."""
    messages = [
        {"role": "system", "content": "You are a coder. TASK: fix_failing_test"},
        {"role": "user", "content": "fix it"},
    ]
    seen = []
    for _ in range(8):
        c, r = _post(mv.base_url, "/v1/chat/completions",
                     {"model": "m", "messages": messages})
        assert c == 200
        text = r["choices"][0]["message"]["content"]
        seen.append(text)
        # accumulate: the agent appends the assistant reply + an observation;
        # only the assistant reply advances the stub's step index.
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content": "Observation: ok"})
        if text.startswith("Final Answer"):
            break
    assert any("write_file" in s for s in seen)
    assert seen[-1].startswith("Final Answer")


def test_call_log_records_all_kvc_ops(mv):
    _post(mv.base_url, "/v1/kvc/offload", {"hint_id": "a", "block_hashes": [1]})
    _post(mv.base_url, "/v1/kvc/evict", {"hint_id": "b", "block_hashes": [2]})
    calls = mv.call_log.calls()
    assert len(calls) == 2
    assert {c["path"] for c in calls} == {"/v1/kvc/offload", "/v1/kvc/evict"}


def test_stub_resumes_from_transcript_length_after_restart(mv):
    """Regression for the restart-after-kill desync (Phase 3 F2 bug).

    After a kill+restart, minimal_react_agent reloads transcript.json and posts
    a request whose messages already contain N assistant entries. The stub
    must return script[N] (resume in sync), NOT script[0] (which would desync
    the loop and make the agent stop early). This must hold even though the
    stub keeps no per-agent state and the same task name was used before."""
    # first "incarnation": run 3 turns, building up a transcript
    messages = [
        {"role": "system", "content": "TASK: fix_failing_test"},
        {"role": "user", "content": "go"},
    ]
    for _ in range(3):
        c, r = _post(mv.base_url, "/v1/chat/completions",
                     {"model": "m", "messages": messages})
        assert c == 200
        messages.append({"role": "assistant",
                         "content": r["choices"][0]["message"]["content"]})
        messages.append({"role": "user", "content": "Observation: ok"})
    # 3 turns -> 3 assistant msgs == script[0..2]; script[2] is grep_find.
    # next step (script[3]) is write_file — that's what resume must return.
    assert "grep_find" in messages[-2]["content"]  # the 3rd assistant reply

    # second "incarnation" after restart: the agent reloads the transcript
    # (3 assistant entries) and posts it fresh. The stub must resume at
    # script[3], not restart at script[0].
    c, r = _post(mv.base_url, "/v1/chat/completions",
                 {"model": "m", "messages": messages})
    assert c == 200
    text = r["choices"][0]["message"]["content"]
    assert "write_file" in text, f"stub desynced after restart: got {text!r}"
