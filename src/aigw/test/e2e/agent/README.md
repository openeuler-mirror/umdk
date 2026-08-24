# Phase 3 — Agent Restart / Fault-Injection E2E

Verification spec layer L3: a real agent harness + fault-injection driver that
proves AIGW's AgentRegistry state machine and KvcSessionManager strategy
triggers fire correctly on agent lifecycle faults. See
`docs/superpowers/specs/2026-07-11-agent-restart-fault-verification-design.md`
§1 (L3) + §3 (three scenarios).

## Landing form

Mock both ends, CPU container runnable (no GPU):
agent → real AIGW (Go binary) → mock vLLM (stdlib http.server) + stub LLM.
Real GPU↔CPU KVC transfer is Phase 4.

## Components

| file | role |
|------|------|
| `minimal_react_agent.py` | ReAct-loop agent: register/recover/heartbeat, get-suggestion (implicit hb), tools (bash/read/write/grep), SIGUSR1 freeze, transcript persistence (resumes from turn k on restart) |
| `mock_vllm.py` | stdlib http.server: KVC control plane (offload/prefetch/evict + jobs) honoring the Phase 1 wire contract, + a stub chat-completions LLM that walks a per-task scripted solution indexed by transcript length (restart-safe, no per-agent state) |
| `aigw_client.py` | urllib client for AIGW agent + KVC endpoints; unsigned (AIGW runs with no HMAC key) |
| `fault_driver.py` | three scenarios: kill_restart, graceful_unregister, heartbeat_timeout (fires at a precise turn k) |
| `supervisor.py` | SubprocessSupervisor: Popen agent, stdout-reader thread, kill/restart/send_signal, await_turn |
| `run_scenario.py` | orchestrator: start AIGW + mock vLLM + agents, fire scenario, bidirectional assertion, task judges |
| `assertions.py` | poll AIGW debug endpoint for state sequence; read mock vLLM call log for hint receipt |
| `tasks/*.py` | artifact-based task judges (no LLM prose — R5 mitigation) |

## Running

Requires the AIGW Go binary (built in the `yt_aigw_build` container, ~30s with
cached open_source deps; see memory `aigw-build-env-constraints`). Start
AIGW with `test/e2e/agent/aigw_config_kvc.json` placed at the default config
path `/etc/aigw/conf/aigw.json` (the `--config=path` flag does not take
effect — `parseLaunchSettings`/`ValidateFilePath`).

```bash
# in the build container:
mkdir -p /etc/aigw/conf && cp test/e2e/agent/aigw_config_kvc.json /etc/aigw/conf/aigw.json
mkdir -p /tmp/aigw-phase3-log
./output/aigw/aigw > /tmp/aigw-start.log 2>&1 &

# one scenario:
cd test/e2e/agent
python3 run_scenario.py --scenario kill_restart --agents 2 --task fix_failing_test \
  --turn-k 4 --delay-s 4 --heartbeat-interval 2 --turn-delay-s 1.5 \
  --workspace-root /tmp/phase3-kr --start-mock-vllm
```

Unit tests (no AIGW binary needed):
```bash
cd test/e2e/agent && python3 -m pytest test_mock_vllm.py test_aigw_client.py \
  test_tasks.py test_agent_loop.py test_fault_driver.py -q   # 30 passed
```

## Assertion policy (B-path close-out)

| dimension | gate? | why |
|-----------|-------|-----|
| AIGW state-machine sequence (Active→Suspected→Recovering[/Gone]) | **GATE** | proves AgentRegistry transitions + strategy triggers fire on real lifecycle |
| task judge (agent-A resumes + finishes; survivors unaffected) | **GATE** | proves fault doesn't cascade + recovery succeeds |
| mock-vLLM hint receipt (offload/prefetch/evict count) | **REPORT-only** | Phase 4 GATES this: it needs real BlockStored events so sessions carry BlockHashes. In degraded mode R1, `gs_manager.go:574` calls `OnRequestScheduled(..., nil)` (expectedHashes nil), and the mock emits no kvevents, so agent sessions have no blocks → `offloadStrat.Plan` returns empty hints → mock legitimately receives nothing. Not a regression. |

## Verified (2026-07-14, yt_aigw_build container)

All three scenarios PASS:
- `kill_restart`: `Active->Suspected->Recovering`, agent-A judge True, survivor True
- `graceful_unregister`: `Active` (no aging), no offload, agent-A judge True, survivor True
- `heartbeat_timeout`: `Active->Suspected->Recovering->Gone` (full aging chain), survivor True

AIGW Go binary builds (52843152 bytes, contains AgentRegistry + KvcSessionManager
symbols), starts cleanly, KVC endpoints wired (`/aigw/v1/agents/*`,
`/aigw/v1/models/*/kvc/*`), HMAC bypassed, state machine + aging run for real.

## Phase 4 (deferred)

- Real GPU host + real vLLM `ConnectorKvcExecutor` so BlockStored events flow
  back → sessions carry BlockHashes → offload/prefetch hints actually dispatch →
  mock-vLLM hint receipt becomes GATE.
- Baseline-vs-enabled KVC benchmark.
