# Phase 3 — Agent Layer + Fault Injection Driver — Implementation Plan

> **For agentic workers:** Execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Inline TDD where a test applies (same cadence as Phase 1/2).

**Goal:** Build the agent-side harness + fault-injection driver that exercises AIGW's `internal/agentregistry` state machine and `KvcSessionManager` strategy triggers (OffloadAll on Suspected, PrefetchMRU on Recovered, TTLAging eviction on Gone) under three fault scenarios, with **bidirectional assertions**: AIGW state transitions (via debug API) AND vLLM hint receipt (via mock vLLM call log). This is Layer 3 (L3) of the verification spec.

**Upstream spec:** `docs/superpowers/specs/2026-07-11-agent-restart-fault-verification-design.md` §1 Phase 3 (lines 99-111) + §3 single-experiment flow (lines 193-217) for the kill+restart timeline. Phase 3 is the verification harness for Phase 2's Go code (branch `k8s`).

**Landing form (locked with user this session):** Mock-双端, CPU-container-runnable. The agent talks to a **real running AIGW** (Go binary, `k8s` branch, `kvc.enabled=true`, **no HMAC key** → `EnableHmac()` returns false → `WithHMAC` passes through unsigned, per `pkg/crypto/hmac.go:197-203`). vLLM is a **Python mock** (records `/v1/kvc/*` calls for assertion; does NOT do real GPU↔CPU transfer — that's Phase 4). The LLM is a **stub/echo** that returns ReAct-friendly responses so the agent genuinely runs its tool loop; task judges check observable artifacts (diff / test pass), NOT LLM prose (spec risk R5 mitigation).

**Why not real vLLM/LLM:** the remote container `yt_aigw_build` is CPU-only torch with no GPU. Spec §3's T2/T4 assume real GPU↔CPU copies — those can't run here. Mock-vLLM + stub-LLM still let us prove the contract Phase 3 owns: **agent crash/restart → AIGW state machine walks the right transitions → the right hint reaches vLLM**. Real transfer latency is a Phase 4 metric, out of scope here.

---

## Critical integration facts (verified on branch `k8s` 2026-07-13)

Every path/behavior below was verified against current code. They override any stale assumption.

| # | Fact | Verified at |
|---|---|---|
| C1 | Agent HTTP endpoints already exist & wired: `POST /aigw/v1/agents/register`, `POST /aigw/v1/agents/{id}/heartbeat\|recover\|unregister`, `GET /aigw/v1/agents` (list), `GET /aigw/v1/agents/{id}` (detail), `GET /aigw/v1/models/{m}/kvc/sessions/{sid}` + `/blocks/{h}` (debug). All gated on `s.manager.GetAgentRegistry() != nil` (== `kvc.enabled`). | `internal/server/http_server.go:145-151`, `internal/server/kvc_handlers.go` (handlers) |
| C2 | HMAC is bypassable in dev: `NewHmacManager(nil)` (http_server.go:62) → `EnableHmac() = len(hmacKey)!=0` = false → `WithHMAC` calls `next` directly (no signature check). **Phase 3 AIGW config omits all HMAC keys → agent calls endpoints unsigned.** | `pkg/crypto/hmac.go:45-57,197-203,292-294` |
| C3 | `get-suggestion` carries implicit heartbeat: when `Kvc.Enabled && Kvc.Agent.ImplicitHeartbeatFromRequests` and request has `X-Agent-Id` header, AIGW treats the schedule call as a heartbeat. Agent's per-turn `get-suggestion` thus doubles as heartbeat — no separate heartbeat goroutine needed for the "healthy" path (but explicit heartbeat still used to model recover re-registration). | `internal/server/http_server.go:322,392-398`; `internal/server/kvc_implicit_heartbeat_test.go` |
| C4 | AgentRegistry 5-state machine + Subscriber callbacks exist & fire: `Register→Active` on first heartbeat, `Active→Suspected` on heartbeat timeout, `Suspected→Recovering` after recover window, `Recovering→Gone` after recover timeout, `Recovering→Active` on `Recover()`. Subscriber callbacks: `OnAgentActive/Suspected/Recovered/Gone/Unregistered`. | `internal/agentregistry/types.go:8-49`, `internal/agentregistry/registry.go` |
| C5 | Strategy triggers are wired: `kvcSubscriberAdapter` routes `OnAgentSuspected→planAndDispatchOffload`, `OnAgentRecovered→planAndDispatchPrefetch`, `OnAgentGone→aging`. **Phase 3's bidirectional assertion = prove these fired by checking both AIGW debug state AND mock-vLLM received the matching hint.** | `internal/gs/kvc_session_manager.go:514-529` |
| C6 | KvcConfig fields: `Kvc.Enabled`, `Kvc.Agent.{HeartbeatIntervalSec,HeartbeatTimeoutSec,RecoverWindowSec,RecoverTimeoutSec,GoneFinalizeSec,RegisterGraceSec,ImplicitHeartbeatFromRequests}`, `Kvc.Vllm` (points AIGW at vLLM — **set to mock vLLM URL**), `Kvc.Agent.Offload/Prefetch/Aging` (strategy configs). | `internal/base/kvc_type.go:5-46` |
| C7 | Config timeouts must be SHORT for e2e (spec uses 90s heartbeat-timeout in T2; we shrink to ~2-5s so a fault scenario completes in <60s wall-clock). Same struct fields, just small values. | `internal/base/kvc_type.go:14-19` |
| C8 | Existing e2e Python client style: `test/e2e/test_prefix_cache_client.py` uses stdlib `urllib` (no pip deps), `http.server`-style mock servers in `test/e2e/mock_*_server.py`. **Phase 3 agent + mock-vLLM follow this stdlib-only style** so no new deps install in the container. | `test/e2e/test_prefix_cache_client.py`, `test/e2e/mock_prefix_cache_server.py` |
| C9 | AIGW Go binary builds in remote container `yt_aigw_build` via `./build.sh` (CGO+Rust+LightGBM; see [[aigw-build-env-constraints]]). Python runs on the same container. Both AIGW + mock-vLLM + agent run as localhost processes on the container. | memory `aigw-build-env-constraints` |
| C10 | `VllmKvcClient` (AIGW's hint sender) talks to vLLM's `/v1/kvc/{offload,prefetch,evict}` + `GET /v1/kvc/jobs/{id}`. The mock vLLM must implement exactly these 4 paths + return contract-correct acks (prefetch = 202+job_id, offload/evict = 200, job poll = running→done). Phase 1's router (vllm repo) is the spec; the mock replicates that wire shape. | Phase 1 memory `phase1-vllm-kvc-control-plane` (locked contract) |

---

## File Structure

All new files under `test/e2e/agent/`. **No Go core code changes** — Phase 2 already wired everything Phase 3 exercises. The only Go artifact is a config fixture + a build step.

| File | Responsibility |
|---|---|
| `test/e2e/agent/__init__.py` | package marker |
| `test/e2e/agent/mock_vllm.py` | stdlib `http.server` mock vLLM: `/v1/kvc/{offload,prefetch,evict}` + `/v1/kvc/jobs/{id}` + `/v1/chat/completions` (stub LLM). Records every `/v1/kvc/*` call (path + body + ts) in a thread-safe list for assertion. CLI: `--port`, `--record-file`. |
| `test/e2e/agent/aigw_client.py` | thin urllib client for AIGW: `register/heartbeat/recover/unregister`, `get_suggestion` (carries X-Agent-Id/X-Session-Id), `agent_detail` (debug state), `session_detail`, `block_detail`. No deps. |
| `test/e2e/agent/minimal_react_agent.py` | the agent: system prompt + 4 tools (bash_exec, read_file, write_file, grep_find — see task scope) + ReAct loop. Per turn: `get_suggestion` (implicit heartbeat) → forward "LLM call" to mock-vLLM `/v1/chat/completions` → tool exec → loop. On start: `register`. Optional explicit `heartbeat` goroutine (thread). On restart: `recover` (reuse agent_id+session_id). |
| `test/e2e/agent/tasks/__init__.py` | package marker |
| `test/e2e/agent/tasks/base.py` | `Task` ABC: `prompt() -> str`, `judge(agent_workspace_dir) -> tuple[bool,str]` (checks observable artifacts, not prose). |
| `test/e2e/agent/tasks/fix_failing_test.py` | task: a mini repo with a failing test; agent must locate+fix; judge runs `pytest`/`go test` and checks pass. |
| `test/e2e/agent/tasks/add_docstring.py` | task: a module missing docstrings; agent adds them; judge runs a linter check. |
| `test/e2e/agent/tasks/refactor_func.py` | task: a function to rename+extract; judge checks renamed symbol present + tests still pass. |
| `test/e2e/agent/fault_driver.py` | fault orchestration: takes (scenario, turn_k, agent_pid, agent_id, recover_delay_Δ). Scenario ∈ {`kill_restart`, `graceful_unregister`, `heartbeat_timeout`}. Uses turn-counter from agent's stdout to fire at exact turn k (spec R4). Restarts agent reusing agent_id+session_id after Δ seconds. |
| `test/e2e/agent/run_scenario.py` | orchestrator: builds AIGW binary (or assumes prebuilt), starts mock-vLLM + AIGW + N agents, runs fault_driver for agent A, asserts bidirectionally (AIGW debug state seq + mock-vLLM call log), collects task judge verdict. One scenario per invocation; a wrapper script runs all 3. |
| `test/e2e/agent/aigw_config_kvc.json` | AIGW config fixture: `kvc.enabled=true`, short timeouts (2-5s), `ImplicitHeartbeatFromRequests=true`, `vllm` endpoint = `http://127.0.0.1:<mock_vllm_port>`, no HMAC keys. |
| `test/e2e/agent/conftest.py` | pytest fixtures: start mock-vLLM + AIGW process, yield base URLs, teardown. Reuse across scenario tests. |
| `test/e2e/agent/test_scenario_kill_restart.py` | scenario 1: kill+restart, assert SUSPECTED→(RECOVERING)→ACTIVE + offload→prefetch hints received. |
| `test/e2e/agent/test_scenario_graceful.py` | scenario 2: unregister+re-register, assert Unregistered→(register)→Active + (no offload expected — graceful) or aging path. |
| `test/e2e/agent/test_scenario_heartbeat_timeout.py` | scenario 3: stop heartbeats Ns, assert Active→Suspected→...→Gone + OffloadAll + TTLAging evict hint. |
| `test/e2e/agent/test_judges.py` | unit tests for the 3 task judges (no AIGW needed) — prove judges catch pass/fail correctly (R5). |
| `test/e2e/agent/README.md` | how to run: `python run_scenario.py --scenario kill_restart`; prerequisites (AIGW binary built). |

Modified: **none in Go core.** Only `configs/` may get a kvc example block (optional, the fixture lives in `test/e2e/agent/`).

---

## Task ordering

- **Group A — Mock vLLM + AIGW client (foundation, no AIGW needed):** A1 mock_vllm, A2 aigw_client. These are pure HTTP stdlib; testable in isolation.
- **Group B — Tasks + judges (no AIGW needed):** B1 task base, B2-B4 the 3 tasks + judges, B5 judge unit tests.
- **Group C — Agent:** C1 minimal_react_agent (ReAct loop + tools + lifecycle calls). Tested against mock-vLLM stub LLM alone first.
- **Group D — Fault driver:** D1 fault_driver (3 scenarios, turn-counter trigger).
- **Group E — Orchestrator + bidirectional assertion:** E1 run_scenario (wires mock-vLLM+AIGW+agents), E2 conftest fixtures, E3 the 3 scenario tests with assertions.
- **Group F — Full run + docs:** F1 build AIGW binary in container + config fixture, F2 run all 3 scenarios green, F3 README + memory update.

Groups A+B are parallelizable (no shared contract). C depends on A+B. D depends on C. E depends on D. F depends on E.

---

## Group A — Mock vLLM + AIGW client

### Task A1: `mock_vllm.py`

A stdlib `http.server.ThreadingHTTPServer` mock of vLLM's KVC control plane + a stub chat-completions endpoint. It records every `/v1/kvc/*` call.

- [ ] **Step 1: contract from Phase 1.** Re-read the locked contract (Phase 1 memory): `POST /v1/kvc/offload`→200 `KvcAck` (status accepted/partial/rejected, accepted_hashes, block_placements {hash→"cpu"}); `POST /v1/kvc/prefetch`→ **202 + job_id** when work accepted (else 200+rejected, no job_id); `POST /v1/kvc/evict`→200 (purged_hashes/not_found_hashes); `GET /v1/kvc/jobs/{id}`→200 `KvcJobStatus` (running/done/failed, done_hashes, blocks_pinned). The mock must honor this so AIGW's `VllmKvcClient` retry/poll logic (Phase 2) behaves realistically.
- [ ] **Step 2: write `mock_vllm.py`.** Endpoints:
  - `POST /v1/kvc/offload` — accept all requested hashes; return `{"hint_id":..,"status":"accepted","accepted_hashes":[...],"block_placements":{h:"cpu"}}`, 200.
  - `POST /v1/kvc/prefetch` — create a job_id `f"job-{n}"`, store pending, return 202 `{"hint_id":..,"status":"accepted","job_id":"job-n"}`. A background thread (or poll-driven) flips pending→done after `prefetch_complete_ms` (config, default 50ms) so AIGW's poll sees running→done.
  - `POST /v1/kvc/evict` — return `{"hint_id":..,"status":"accepted","purged_hashes":[...]}`, 200.
  - `GET /v1/kvc/jobs/{id}` — return job status from the pending/done map.
  - `POST /v1/chat/completions` — stub LLM: parse the ReAct-style `Action:` block from the last user msg; if a tool call is requested, echo back a response that either emits the next `Action:` or `Final Answer: <task result>`. Deterministic-ish (seeded by turn count) so the agent loop terminates. Keep simple: a small state machine that walks a scripted solution for the active task (the agent is exercising the *harness*, not solving tasks creatively).
  - Thread-safe `record` list: `[(ts, method, path, body)]`, append under a `threading.Lock`. CLI: `--port 0` (auto), `--prefetch-complete-ms 50`, `--record-file /tmp/mock_vllm_calls.json`.
- [ ] **Step 3: write `test_mock_vllm.py`.** Start the server on port 0, hit the 4 KVC endpoints + chat, assert responses match contract + record list has the entries. Use `urllib` only.
- [ ] **Step 4: run** `PYTHONPATH=test/e2e/agent python3 -m pytest test/e2e/agent/test_mock_vllm.py -q`. Acceptance: green.
- [ ] **Step 5: commit.** `feat(phase3): mock vLLM control plane + stub LLM (Group A1)`

### Task A2: `aigw_client.py`

- [ ] **Step 1: write `aigw_client.py`.** `AigwClient(base_url)` with: `register(agent_id, models, metadata)`, `heartbeat(agent_id, models, session_ids)`, `recover(agent_id, models)`, `unregister(agent_id)`, `get_suggestion(model, body, agent_id, session_id)` (sets `X-Agent-Id`/`X-Session-Id` headers, returns prefill/decode urls), `agent_detail(agent_id)` (GET debug), `agents_list()`, `session_detail(model, sid)`, `block_detail(model, hash)`. urllib, JSON, raises on non-2xx with body in error.
- [ ] **Step 2: test against mock AIGW.** A tiny `http.server` stand-in that echoes the request body + method, to verify headers/paths/JSON shaping without a real AIGW. `test_aigw_client.py`.
- [ ] **Step 3: run** pytest. Acceptance: green.
- [ ] **Step 4: commit.** `feat(phase3): AIGW HTTP client (Group A2)`

---

## Group B — Tasks + judges

### Task B1: `tasks/base.py`

- [ ] **Step 1: `Task` ABC** with `name`, `prompt() -> str` (the task brief given to the agent), `setup(workspace_dir) -> None` (materializes the mini repo), `judge(workspace_dir) -> tuple[bool, str]` (pass/fail + reason). `judge` MUST inspect artifacts (files / test exit codes), never parse LLM prose.
- [ ] **Step 2: commit.** `feat(phase3): task base class (Group B1)`

### Task B2: `tasks/fix_failing_test.py` + judge

- [ ] **Step 1: setup** materializes a 2-file mini Python repo: `calc.py` (a buggy `add(a,b)=a-b`), `test_calc.py` (`assert add(1,2)==3`). The agent must fix `calc.py`.
- [ ] **Step 2: judge** runs `python3 -m pytest test_calc.py` in `workspace_dir`; pass iff exit 0.
- [ ] **Step 3: unit test** `test_tasks.py::test_fix_failing_test_judge` — pre-seed a fixed repo, assert judge passes; pre-seed the broken repo, assert judge fails.
- [ ] **Step 4: commit.** `feat(phase3): fix-failing-test task + judge (Group B2)`

### Task B3: `tasks/add_docstring.py` + judge

- [ ] **Step 1: setup** materializes `mod.py` with 3 undocumented funcs. judge uses `python3 -m py_compile` + a tiny AST check (`ast.get_docstring` non-null for each top-level func) — no external linter dep.
- [ ] **Step 2: unit test** pass/fail cases.
- [ ] **Step 3: commit.** `feat(phase3): add-docstring task + judge (Group B3)`

### Task B4: `tasks/refactor_func.py` + judge

- [ ] **Step 1: setup** materializes `mod.py` with `old_name()` + a caller; agent renames to `new_name()`. judge: `grep -q "def new_name" mod.py` and `! grep -q "def old_name" mod.py` and `python3 -c "import mod; mod.new_name()"` exits 0.
- [ ] **Step 2: unit test** pass/fail.
- [ ] **Step 3: commit.** `feat(phase3): refactor task + judge (Group B4)`

### Task B5: judge unit-test bundle

- [ ] **Step 1: ensure `test_tasks.py`** covers all 3 judges pass+fail. Run `PYTHONPATH=test/e2e/agent python3 -m pytest test/e2e/agent/test_tasks.py -q`. Acceptance: green. (R5 closure: judges proven to catch non-work.)
- [ ] **Step 2: commit** if not already committed with B2-B4. `test(phase3): task judge pass/fail coverage (Group B5)`

---

## Group C — `minimal_react_agent.py`

### Task C1: the agent

- [ ] **Step 1: write `minimal_react_agent.py`.** ReAct loop:
  - On start: `aigw.register(agent_id, models=[model], metadata={...})`.
  - Optional background thread: `aigw.heartbeat(...)` every `heartbeat_interval` (default 30s, but tests set 2s). Only used in the heartbeat-timeout scenario's "healthy" phase so the timeout is observable when the thread is killed.
  - Loop per turn:
    1. `get_suggestion(model, body, agent_id, session_id)` → prefill/decode urls (implicit heartbeat per C3).
    2. POST to mock-vLLM `/v1/chat/completions` with the running tool transcript.
    3. Parse `Action: <tool>` + `Action Input: <arg>` from the stub LLM response; exec the tool (bash_exec/read_file/write_file/grep_find) in a workspace dir; append `Observation: <result>` to transcript.
    4. If `Final Answer:` → break.
  - On restart (same agent_id+session_id): `aigw.recover(agent_id, models=[model])` before resuming the loop. The loop resumes from the last persisted turn (agent writes `transcript.json` each turn) so it doesn't restart from turn 0 — important for fault_driver's turn-k trigger to be meaningful post-restart.
  - CLI: `--aigw-url`, `--vllm-url`, `--agent-id`, `--session-id`, `--model`, `--task <name>`, `--workspace <dir>`, `--heartbeat-interval <sec>`, `--max-turns 20`.
  - Prints a `TURN k` line to stdout each turn (fault_driver's turn-counter source, R4).
- [ ] **Step 2: tools.** `bash_exec(cmd, cwd=workspace)` (subprocess, timeout 10s, return stdout+rc); `read_file(path)`; `write_file(path, content)`; `grep_find(pattern, path)` (stdlib `re`). No shell-injection hardening needed (dev harness, trusted input).
- [ ] **Step 3: test against mock-vLLM alone (no AIGW).** `test_agent_loop.py`: start mock_vllm, run agent with `--aigw-url` pointed at a tiny mock that no-ops register/heartbeat, `--task fix_failing_test`. Assert agent produces `Final Answer` within max_turns AND the judge passes on the workspace. This proves the ReAct loop + tools + judge path before AIGW is involved.
- [ ] **Step 4: run** pytest. Acceptance: green.
- [ ] **Step 5: commit.** `feat(phase3): minimal ReAct agent + tools (Group C1)`

---

## Group D — `fault_driver.py`

### Task D1: fault orchestration

- [ ] **Step 1: write `fault_driver.py`.** API: `FaultDriver(aigw_client, agent_supervisor)`. `agent_supervisor` is an object that can `start_agent(agent_id, session_id, task, from_turn=0)`, `agent_pid(agent_id)`, `kill_agent(agent_id)`, `stop_heartbeats(agent_id)`, `await_turn(agent_id, k, timeout)`.
  - Scenario `kill_restart`: `await_turn(A, k)` → `kill_agent(A)` (SIGKILL via subprocess) → wait Δs → `start_agent(A, same session_id, same task, from_turn=k)` (the agent `recover()`s then resumes). Δ ∈ {short=2s, mid=10s} to hit Suspected vs Recovering entry (tuned to AIGW's `HeartbeatTimeoutSec`/`RecoverWindowSec`).
  - Scenario `graceful_unregister`: `await_turn(A, k)` → `aigw.unregister(A)` → wait Δs → `aigw.register(A,...)` again → resume agent (no kill).
  - Scenario `heartbeat_timeout`: `await_turn(A, k)` → `stop_heartbeats(A)` (kills the heartbeat thread + blocks get-suggestion by setting a flag) → wait until AIGW ages A Active→Suspected→Recovering→Gone.
  - Each scenario records a `ScenarioResult(agent_id, scenario, turn_k, events)` for the assertion layer.
- [ ] **Step 2: `agent_supervisor` impl.** Spawns `minimal_react_agent.py` via `subprocess.Popen([sys.executable, "minimal_react_agent.py", ...])`, tracks pid, pipes stdout to a turn-counter parser. `stop_heartbeats` = send the agent a SIGUSR1 (agent installs a signal handler that flips an internal "pause_heartbeat" flag) OR simpler: kill the heartbeat thread by setting a file flag the agent polls. Pick the signal approach; document it.
- [ ] **Step 3: unit test** the turn-counter parser + the 3 scenario state machines against a fake supervisor (no real agent). `test_fault_driver.py`.
- [ ] **Step 4: commit.** `feat(phase3): fault injection driver — 3 scenarios (Group D1)`

---

## Group E — Orchestrator + bidirectional assertion

### Task E1: `run_scenario.py` + conftest

- [ ] **Step 1: `conftest.py` fixtures.** `mock_vllm_proc` (starts mock_vllm on port 0, yields base_url + record list accessor), `aigw_proc` (assumes prebuilt binary at `output/aigw` — built in F1; starts it with `--config=test/e2e/agent/aigw_config_kvc.json`, yields base_url, waits on `/aigw/v1/health`), `clean_workspace` (tmpdir per test). Teardown kills both.
- [ ] **Step 2: `run_scenario.py`.** Wires fixtures programmatically (not via pytest) so it can be invoked as a script: `python run_scenario.py --scenario kill_restart --agents 4 --task fix_failing_test`. Starts mock-vLLM + AIGW + N agents (A= Victim with fault at turn k; B/C/D= survivors), runs fault_driver, then asserts (E3 logic), then runs task judge for each agent, prints a per-scenario report.
- [ ] **Step 3: `aigw_config_kvc.json`.** `kvc.enabled=true`, `HeartbeatTimeoutSec=3`, `RecoverWindowSec=3`, `RecoverTimeoutSec=5`, `GoneFinalizeSec=5`, `ImplicitHeartbeatFromRequests=true`, `vllm` endpoint = mock-vllm url, NO hmac keys. (Short timeouts so a scenario completes in <60s.)
- [ ] **Step 4: commit.** `feat(phase3): orchestrator + conftest + config (Group E1)`

### Task E2-E3: scenario tests with bidirectional assertion

- [ ] **Step 1: assertion helpers** in `assertions.py`:
  - `assert_state_sequence(aigw, agent_id, expected_transitions)` — polls `GET /aigw/v1/agents/{id}`, reconstructs the transition sequence from the `SuspectedAt/RecoveringAt/GoneAt` timestamps + current state, asserts it matches `expected` (e.g. `[Active, Suspected, Recovering, Active]` for kill_restart).
  - `assert_hint_received(mock_vllm_record, op, min_count=1)` — scans the record list for `POST /v1/kvc/{op}` calls, asserts ≥ min_count.
  - `assert_hint_hashes_correlate(aigw, mock_vllm_record, agent_id)` — the block_hashes in the offload hint should correspond to agent A's session's blocks (from `session_detail`). (Correlation, not exact equality — the mock LLM produces deterministic blocks.)
- [ ] **Step 2: `test_scenario_kill_restart.py`.** Start 4 agents (A=fix_failing_test, B/C/D=other tasks), fault_driver kill_restart on A at turn k=3, Δ=10s. Assert: AIGW state sequence for A = `[Active→Suspected→Recovering→Active]`; mock-vLLM received ≥1 `POST /v1/kvc/offload` (during Suspected) AND ≥1 `POST /v1/kvc/prefetch` (during Recover); task judge passes for A (agent finished after restart) AND B/C/D (survivors finished, not disrupted).
- [ ] **Step 3: `test_scenario_graceful.py`.** graceful_unregister on A at turn k=3, Δ=5s, re-register. Assert: state sequence includes `[Active→Unregistered]` (or the registry's graceful path) then back to Active; **no offload hint expected** (graceful unregister doesn't trigger OffloadAll — that's a crash-suspected trigger); task judge passes for A.
- [ ] **Step 4: `test_scenario_heartbeat_timeout.py`.** stop_heartbeats on A at turn k=3, wait > `GoneFinalizeSec`. Assert: state sequence `[Active→Suspected→Recovering→Gone]`; mock-vLLM received `POST /v1/kvc/offload` (Suspected→OffloadAll) AND `POST /v1/kvc/evict` (Gone→TTLAging); task judge for A is not expected to pass (agent was halted) — assert it was halted cleanly; B/C/D still pass.
- [ ] **Step 5: run all 3** `python -m pytest test/e2e/agent/test_scenario_*.py -q -p no:cacheprovider`. Acceptance: all green. (If AIGW binary not yet built, gate these behind a `@pytest.mark.requires_aigw_binary` and ensure F1 runs them.)
- [ ] **Step 6: commit.** `test(phase3): 3 fault scenarios with bidirectional assertion (Group E2-E3)`

---

## Group F — Build + full run + docs

### Task F1: build AIGW binary + smoke

- [ ] **Step 1: in remote container** `yt_aigw_build`, `cd /opt/aigw` (or wherever the aigw repo is mounted) and `./build.sh`. Verify `output/aigw` exists. (See [[aigw-build-env-constraints]] for the known CGO/Rust/LightGBM build path.)
- [ ] **Step 2: sync** the `test/e2e/agent/` files + `aigw_config_kvc.json` into the container.
- [ ] **Step 3: smoke** — start mock-vLLM + AIGW, `curl /aigw/v1/health` → 200; `curl -X POST /aigw/v1/agents/register ...` → 200. Acceptance: AIGW comes up with kvc endpoints enabled (log line "KVC agent lifecycle + debug endpoints enabled").
- [ ] **Step 4: commit** any container-path notes to the README. `chore(phase3): build + smoke (Group F1)`

### Task F2: full scenario run

- [ ] **Step 1: run** all 3 scenarios end-to-end in the container. Acceptance: all green, report printed. If a scenario flakes, debug (most likely cause: timing — AIGW aging vs fault_driver Δ; tune the config timeouts, not the spec).
- [ ] **Step 2: capture** the report output into `test/e2e/agent/last_run_report.txt` (untracked, for the record).
- [ ] **Step 3: commit** any timing fixes. `fix(phase3): scenario timing (Group F2)` (only if needed)

### Task F3: docs + memory

- [ ] **Step 1: `README.md`** — prereqs (built `output/aigw`), how to run a single scenario, how to interpret the bidirectional assertion.
- [ ] **Step 2: memory update** — `phase3-agent-fault-injection.md` (new) recording: 3 scenarios, the mock-双端 landing decision, AIGW no-HMAC path (C2), short-timeout config, the turn-counter trigger (R4), the bidirectional assertion pattern, container build path. + `MEMORY.md` index line.
- [ ] **Step 3: commit.** `docs(phase3): README + memory (Group F3)`

---

## Verification matrix (spec fault scenarios → tests)

| Spec scenario | Test | AIGW state asserted | vLLM hint asserted | Task judge |
|---|---|---|---|---|
| kill+restart (main) | test_scenario_kill_restart | Active→Suspected→Recovering→Active | offload (Suspected) + prefetch (Recovering) | A pass + B/C/D pass |
| graceful unregister | test_scenario_graceful | Active→Unregistered→Active | none (graceful) | A pass |
| heartbeat timeout | test_scenario_heartbeat_timeout | Active→Suspected→Recovering→Gone | offload (Suspected) + evict (Gone) | A halted; B/C/D pass |

## Out of scope (Phase 4)

- Real GPU↔CPU transfer latency, TTFT/prefill-token/cache-hit metrics, baseline-vs-enabled benchmark — all Phase 4 (L4), needs a GPU host.
- Real LLM (the stub LLM is sufficient to drive the harness + exercise the turn loop + judges).
- N>8 agents (resource contention tuning) — Phase 4 scale.

## Execution note

Run in remote container `yt_aigw_build` (see [[aigw-build-env-constraints]]): build AIGW Go binary there, run Python agent/mock-vllm/tests there (CPU torch is fine — no torch needed for Phase 3 at all, pure stdlib). Sync files via `sshpass`+`scp`+`docker cp` (same pattern as Phase 1). Inline TDD (subagent dispatch was broken in Phase 2's session key; if it works now, the Group A/B tasks parallelize cleanly).
