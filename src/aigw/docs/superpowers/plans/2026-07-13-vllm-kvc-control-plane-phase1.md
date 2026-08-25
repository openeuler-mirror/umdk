# vLLM KVC Control Plane (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the vLLM-side HTTP control plane (`POST /v1/kvc/{offload,prefetch,evict}` + `GET /v1/kvc/jobs/{id}`) on vLLM **v0.18.0**, so that AIGW's `VllmKvcClient` (Phase 2) can drive agent-crash/restart KV management against a real vLLM engine. This is the peer implementation that makes Phase 2's `VllmKvcClient` actually do something.

**Scope:** Single vLLM engine, CPU offload tier (Phase 1). The remote/secondary-tier (Mooncake / LMCache / FS) and multi-PD-group routing are explicitly Phase 2+ of the vLLM-side work (out of scope here).

**Source tree:** `/Users/taoyu/LocalDocuments/vllm` checked out at git tag `v0.18.0` (commit `bcf2be961`). After implementing, `pip install -e .` yields a `0.18.0+empty`-style local version (the `+empty` local-segment comes from setuptools-scm on a checkout with local changes). All implementation happens in THIS tree.

**Upstream spec:** `vllm-kvc-offload-prefetch-design.md` (repo root). This plan reconciles that design against the ACTUAL v0.18.0 code — where the design doc names a thing that doesn't match 0.18.0, 0.18.0 wins (see Critical integration facts below).

**Tech Stack:** Python 3, FastAPI (`vllm/entrypoints/serve/` router pattern), msgspec (EngineCore IPC), `vllm/v1/kv_offload/` framework, `pytest` for unit/integration tests.

---

## Critical integration facts (verified on vLLM v0.18.0, commit bcf2be961)

These override stale/generic names in `vllm-kvc-offload-prefetch-design.md`. Every path below was verified by reading the 0.18.0 source.

| # | Design doc says | Actual (vLLM v0.18.0) |
|---|---|---|
| V1 | `OffloadingManager` / `OffloadingWorker` / `SecondaryTier` framework; add `purge(keys: Collection[OffloadKey])`; existing `reset_cache()` is full-clear | `vllm/v1/kv_offload/abstract.py:69 OffloadingManager(ABC)` with `lookup/prepare_load/prepare_store/complete_load/complete_store/take_events/touch`. **There is NO `reset_cache()` and NO `purge()` at all** — the design doc's "reset_cache exists, purge is the new gap" is wrong on the first half; the gap is purely additive. Key type is `BlockHash` (int), NOT `OffloadKey`. Concrete managers: `lru_manager.py`, `arc_manager.py`, `reuse_manager.py` (decorator wrapping a backing manager). `OffloadingWorker` in `vllm/v1/kv_offload/worker/` (`worker.py`, `cpu_gpu.py`) with `submit_store`/`submit_load`/`get_finished`. |
| V2 | connector exposes `OffloadingManager` to scheduler as `scheduler.connector` | `vllm/distributed/kv_transfer/kv_connector/v1/offloading_connector.py:253 self.manager: OffloadingManager = spec.get_manager()`. Scheduler holds `self.connector` (`vllm/v1/core/sched/scheduler.py:120`, set at `:127` via `KVConnectorFactory.create_connector` when `vllm_config.kv_transfer_config is not None` at `:123`). So the path is `scheduler.connector.manager` (the OffloadingManager). When `kv_transfer_config` is None, `self.connector is None` → the 503 "kvc_control_requires_kv_connector" path (design §5.8). |
| V3 | control RPC via `EngineCoreClient.call_utility_async("kvc_*", payload)` mirroring `reset_prefix_cache_async` | `vllm/v1/engine/core_client.py:1062 InprocClient.call_utility_async(method, *args)` → encodes `EngineCoreRequestType.UTILITY` message → `vllm/v1/engine/core.py:1245` decodes `(client_idx, call_id, method_name, args)` → `getattr(self, method_name)(*args)` at `:1251`. `reset_prefix_cache_async` (`core_client.py:1110`) is the template: `await self.call_utility_async("reset_prefix_cache", ...)`. The `EngineCore` method `reset_prefix_cache` lives at `core.py:572` (design said `:680` — line drift) and delegates `self.scheduler.reset_prefix_cache(...)`. New `kvc_*` methods go on `EngineCore` (same object `getattr` looks up), delegating to a new `KvcController`. |
| V4 | `AsyncLLM.kvc_offload_async(...)` etc. | `vllm/v1/engine/async_llm.py:71 class AsyncLLM(EngineClient)`. `reset_prefix_cache` (`async_llm.py:895`) delegates to `self.engine_core.reset_prefix_cache_async(...)`. **Two valid shapes:** (a) add `AsyncLLM.kvc_*_async` methods delegating to `engine_core.call_utility_async("kvc_*", ...)` (matches design), OR (b) have the serve router call `engine_client.call_utility_async("kvc_*", ...)` directly (skip AsyncLLM wrappers). **This plan uses (b)** — fewer layers, `call_utility_async` is already on `EngineClient` via `core_client`, and the router only needs the `EngineClient` handle it already gets from `app.state.engine_client` (see V5). No `AsyncLLM` changes needed. |
| V5 | serve router via `register_vllm_serve_api_routers(app)`, get engine handle like lora's `models(raw_request)` | `vllm/entrypoints/serve/__init__.py:12 register_vllm_serve_api_routers(app)` calls each submodule's `attach_router(app)` which does `app.include_router(router)`. Template: `vllm/entrypoints/serve/profile/api_router.py` — defines `def engine_client(request: Request) -> EngineClient: return request.app.state.engine_client`, then `@router.post("/path") async def handler(raw_request): await engine_client(raw_request).method()`. KvcAPIRouter copies this exactly, calling `await engine_client(raw_request).call_utility_async("kvc_offload", hint)`. |
| V6 | controller runs step-internal in `on_schedule_end` hook | **No `on_schedule_end` exists in 0.18.0.** The actual end-of-step hook is `vllm/v1/core/sched/scheduler.py:951 _update_after_schedule(self, scheduler_output)`, called at `:926` inside `schedule()` (`:338`). KvcController's step work (drain `take_events`, finalize completed store/load jobs, release GPU blocks for completed stores, poll in-flight prefetch) hooks here. NOTE: `_update_after_schedule` currently only advances `num_computed_tokens`; adding KvcController calls is additive and must not block. |
| V7 | events `BlockStored`/`BlockRemoved`/`AllBlocksCleared` with `block_hash` int64; `OffloadingManager.take_events()` emits `OffloadingEvent` | Two SEPARATE event streams: (1) **KVCache events** AIGW consumes: `vllm/distributed/kv_events.py:49 BlockStored` / `:84 BlockRemoved` / `:92 AllBlocksCleared`, each with `block_hashes: list[ExternalBlockHash]`; published by `ZmqEventPublisher` (`:258`). `ExternalBlockHash = bytes \| int` (`vllm/v1/core/kv_cache_utils.py:46`), converted via `maybe_convert_block_hash` (`:71`). (2) **Offloading-internal events**: `OffloadingEvent` (`abstract.py:61`, fields `block_hashes`, `block_size`, `medium`, `removed`) from `OffloadingManager.take_events()`. KvcController drains (2) to know when a store/load finished, then vLLM's existing publisher emits (1) to AIGW. The `block_hash` int IS the shared handle across both. |
| V8 | `block_pool` resolves `block_hash` → live GPU block | `vllm/v1/core/sched/scheduler.py:225 self.kv_cache_manager = KVCacheManager(...)`. The manager tracks GPU blocks; `block_pool` is the allocator inside it. For offload/prefetch, `OffloadingManager.prepare_store/prepare_load` already resolve hashes internally (the manager's own `self.blocks: dict[BlockHash, ...]` tracks which GPU blocks map to which hash — see `lru_manager.py:118` using `self.blocks[block_hash]`). **KvcController does NOT need to resolve hash→GPU-block itself** — it passes hashes to the manager, which owns that mapping. This simplifies the controller. |
| V9 | hint-id idempotency via LRU cache of `hint_id → KvcAck` | Plain Python `collections.OrderedDict` (LRU via `move_to_end`/`popitem(last=False)`) on the `KvcController`, sized ~10k. No new dependency. |
| V10 | prefetch = async submit(202) + poll `GET /v1/kvc/jobs/{id}` | `KvcController` keeps a `dict[job_id, KvcJob]` of in-flight prefetch jobs. Submit returns 202 + `job_id`; the job advances in `_update_after_schedule` as `OffloadingWorker.get_finished()` reports done loads; `GET /v1/kvc/jobs/{id}` reads the dict. 404 when the job has been GC'd (TTL or done+reaped). |

**Key reconciliation with the design doc:**
- The design's `OffloadKey` type does not exist in 0.18.0 — use `BlockHash` (int) directly everywhere. No type-translation layer.
- The design's "existing `reset_cache()` is full-clear" is FALSE in 0.18.0 — there is no reset_cache. `purge()` is a purely additive abstract method.
- The design's `on_schedule_end` → `_update_after_schedule` (`scheduler.py:951`).
- The design's `core.py:680` for reset_prefix_cache → `:572`.
- The design's `AsyncLLM.kvc_*_async` wrappers are OPTIONAL — this plan routes the router straight to `engine_client.call_utility_async("kvc_*", ...)`, so `async_llm.py` is NOT modified.

---

## File Structure

New files (created in `/Users/taoyu/LocalDocuments/vllm`):

| File | Responsibility |
|---|---|
| `vllm/entrypoints/serve/kvc/__init__.py` | empty package init |
| `vllm/entrypoints/serve/kvc/protocol.py` | Pydantic/msgspec models: `KvcHint`, `KvcAck`, `KvcJobStatus`, `KvcJobStatusRequest` (mirror AIGW's `KvcHint`/`HintAck` shape — see Phase 2 `internal/gs/kvc_types.go`) |
| `vllm/entrypoints/serve/kvc/api_router.py` | `attach_router(app)` registering `POST /v1/kvc/{offload,prefetch,evict}` + `GET /v1/kvc/jobs/{job_id}`; thin — parse request, call `engine_client(raw_request).call_utility_async("kvc_*", hint)`, format ack. Guarded on connector presence (503 if absent). |
| `vllm/v1/core/sched/kvc_controller.py` | `KvcController`: hash resolution (delegated to manager), job lifecycle, hint-id LRU dedup, per-hash locking, prefetch job store. This is the engine-core peer of AIGW's `KvcSessionManager`. |
| `vllm/v1/core/sched/kvc_job.py` | `KvcJob` dataclass: type, block_hashes, submitted/done/failed sets, status, blocks_pinned. Kept separate from controller for testability. |
| `tests/v1/core/sched/test_kvc_controller.py` | Unit: hash resolution, idempotency, in-flight decode, per-hash lock, prefetch job lifecycle, purge dispatch. Mocked `OffloadingManager`. |
| `tests/entrypoints/serve/kvc/test_api_router.py` | Unit: request/response serialization, 404 for unknown job_id, 503 when no connector, hint-id dedup. Mocked `EngineClient`. |
| `tests/v1/kv_offload/test_purge.py` | Unit: `purge()` removes named hashes only; no-op on absent hashes; CPU backend physical removal. |
| `tests/v1/engine/test_kvc_control_e2e.py` | Integration: `AsyncLLM` → `EngineCore` (InprocClient) → `Scheduler` → real CPU-tier `OffloadingManager`, small model. Full agent-recovery arc: offload (GPU released + `BlockRemoved`), prefetch (block pinned + next request hits prefix cache), evict (CPU tier cleared + subsequent load miss). |

Modified files (existing, minimal edits):

| File | Change |
|---|---|
| `vllm/v1/kv_offload/abstract.py` | Add `purge(self, block_hashes: Iterable[BlockHash]) -> tuple[list[BlockHash], list[BlockHash]]` abstract method (returns `(purged, not_found)`). Default `@abstractmethod` — managers must implement. |
| `vllm/v1/kv_offload/lru_manager.py` | Implement `purge`: for each hash, `self.backend.free(block)` + `del self.blocks[block_hash]` (mirror `complete_store`'s failure branch at `:122`), append `OffloadingEvent(removed=True)`. Return `(purged, not_found)`. |
| `vllm/v1/kv_offload/arc_manager.py` | Implement `purge` (same shape as lru; arc_manager has analogous `self.blocks` + `self.backend`). |
| `vllm/v1/kv_offload/reuse_manager.py` | Implement `purge` delegating to `self._backing.purge(...)` AND dropping the hash from `self.counts` (reuse_manager wraps a backing manager + tracks access counts — purge must clear both). |
| `vllm/v1/engine/core.py` | Add `kvc_offload`, `kvc_prefetch`, `kvc_evict`, `kvc_job_status` methods (each: validate connector present → delegate to `self.scheduler.kvc_controller.<op>(hint)`). These are the methods `call_utility_async("kvc_*")` resolves via `getattr(self, method_name)` (`core.py:1251`). |
| `vllm/v1/core/sched/scheduler.py` | (a) Construct `self.kvc_controller = KvcController(self)` in `__init__` when `self.connector is not None` (after `:127`). (b) In `_update_after_schedule` (`:951`), after the existing `num_computed_tokens` loop, call `self.kvc_controller.drain_completed_jobs()` (only if controller exists). |
| `vllm/entrypoints/serve/__init__.py` | In `register_vllm_serve_api_routers`, add `from vllm.entrypoints.serve.kvc.api_router import attach_router as attach_kvc_router; attach_kvc_router(app)`. |

**Files NOT modified** (per V4 decision): `vllm/v1/engine/async_llm.py`, `vllm/v1/engine/core_client.py` (the `call_utility_async` plumbing already exists and is generic), `vllm/engine/protocol.py`.

---

## Contract seams (locked, must hold — mirrors Phase 2 verification spec §2)

These are the behaviors AIGW's `VllmKvcClient` (Phase 2) depends on. They MUST be honored; tests assert them.

1. **prefetch = async submit(202) + poll.** `POST /v1/kvc/prefetch` returns `202` + `job_id`; the load is submitted to the worker and finalized in `_update_after_schedule`. AIGW polls `GET /v1/kvc/jobs/{id}`. offload/evict return `200` synchronously (dispatch only; the store itself is async but the ack returns immediately).
2. **`in_flight_hashes` / `missing_hashes` are NOT errors** — they are informational. vLLM does not retry them; AIGW does not retry them. offload returns `in_flight_hashes` for blocks mid-decode (cannot atomically copy); `missing_hashes` for blocks not GPU-resident (nothing to do).
3. **`failed_hashes` → AIGW retries.** When the worker's `submit_store`/`submit_load` reports `success=False`, those hashes land in `failed_hashes`. A failed store MUST preserve the GPU-resident copy (existing `complete_store(success=False)` semantics: `lru_manager.py:122` frees the backend copy, keeps the GPU block).
4. **`block_placements` direction = `{hash → tier}`.** The ack's `block_placements` maps each block hash to its tier string (`"hbm"`/`"cpu"`/...). AIGW learns placements from this.
5. **`hint_id` idempotency.** Repeat POST with same `hint_id` returns the cached `KvcAck`; the transfer primitive is NOT re-invoked.
6. **No connector → `503 {"error":"kvc_control_requires_kv_connector"}`.** Fail-closed: a misconfigured engine (no `kv_transfer_config`) must not silently accept and drop KV.
7. **Engine paused → `409 {"error":"engine_paused"}`.** Transient; AIGW retries. No blocks touched.
8. **Unknown/expired `job_id` → `404`.** AIGW re-issues the original op with a new `hint_id` (data-layer idempotent: offloading an already-offloaded block is a no-op).

---

## Tasks

Tasks grouped A–H. Each task is independently committable. TDD: write the test first, watch it fail, implement, watch it pass.

### Group A — Protocol & types (the contract surface)

**A1. `vllm/entrypoints/serve/kvc/protocol.py` — request/response models**
- [ ] Create `vllm/entrypoints/serve/kvc/__init__.py` (empty).
- [ ] In `protocol.py`, define msgspec structs (match `vllm-kvc-offload-prefetch-design.md` §6 API contract AND Phase 2's `KvcHint`/`HintAck` Go shapes in `internal/gs/kvc_types.go`):
  - `KvcHint`: `hint_id: str`, `op: str` ("offload"/"prefetch"/"evict"), `block_hashes: list[int]`, `target_tier: str | None = None`.
  - `KvcAck`: `hint_id`, `status: str` ("accepted"/"partial"/"rejected"), `accepted_hashes: list[int]`, `in_flight_hashes: list[int]`, `missing_hashes: list[int]`, `failed_hashes: list[int]`, `block_placements: dict[int, str]`, `job_id: str | None`, `purged_hashes: list[int]`, `not_found_hashes: list[int]`, `error: str | None`.
  - `KvcJobStatus`: `job_id`, `status: str` ("running"/"done"/"failed"), `done_hashes: list[int]`, `failed_hashes: list[int]`, `blocks_pinned: bool`.
- [ ] Use `msgspec.Struct` (consistent with EngineCore IPC encoding in `core_client.py`).
- [ ] Acceptance: `python -c "from vllm.entrypoints.serve.kvc.protocol import KvcHint, KvcAck, KvcJobStatus"` succeeds; round-trip `msgspec.json.decode(msgspec.json.encode(h)) == h`.

**A2. `vllm/v1/core/sched/kvc_job.py` — KvcJob dataclass**
- [ ] Define `KvcJob` dataclass: `job_id: str`, `op: HintType`, `block_hashes: list[int]`, `submitted: set[int]`, `done: set[int]`, `failed: set[int]`, `blocks_pinned: bool`, `status: str`, `created_at: float`.
- [ ] Pure data, no behavior beyond `is_complete()` / `to_status() -> KvcJobStatus`.
- [ ] Acceptance: unit-construct, `to_status()` reflects `done`/`failed`/`status`.

### Group B — `OffloadingManager.purge` (the only framework addition)

**B1. `purge` abstract method on `OffloadingManager`**
- [ ] In `vllm/v1/kv_offload/abstract.py`, add after `complete_store`:
  ```python
  @abstractmethod
  def purge(self, block_hashes: Iterable[BlockHash]) -> tuple[list[BlockHash], list[BlockHash]]:
      """Remove the given blocks from all tiers this manager owns.
      Returns (purged_hashes, not_found_hashes). No-op on absent hashes.
      Unlike complete_store(success=False), purge removes the tier-side copy too."""
      pass
  ```
- [ ] Acceptance: importing `OffloadingManager` still works; abstractness enforced (a bare subclass still can't instantiate).

**B2. `purge` on `lru_manager`**
- [ ] In `lru_manager.py`, implement `purge` mirroring the failure branch of `complete_store` (`:118-130`):
  ```python
  def purge(self, block_hashes):
      purged, not_found = [], []
      for h in block_hashes:
          block = self.blocks.get(h)
          if block is None:
              not_found.append(h); continue
          self.backend.free(block)
          del self.blocks[h]
          purged.append(h)
      if purged and self.events is not None:
          self.events.append(OffloadingEvent(block_hashes=purged, block_size=self.backend.block_size, medium=self.backend.medium, removed=True))
      return purged, not_found
  ```
- [ ] `tests/v1/kv_offload/test_purge.py::test_purge_removes_named_only`: store 3 blocks, purge 1, assert the other 2 survive + `lookup` still finds them.
- [ ] `test_purge_absent_is_noop`: purge a hash that was never stored → `not_found` populated, no exception.
- [ ] Acceptance: tests pass; `take_events` after purge yields an `OffloadingEvent(removed=True)` for the purged hash.

**B3. `purge` on `arc_manager` and `reuse_manager`**
- [ ] `arc_manager.py`: same shape as lru (it has `self.blocks` + `self.backend`).
- [ ] `reuse_manager.py`: `purge` delegates to `self._backing.purge(...)` AND removes the hash from `self.counts` (so a re-store after purge starts fresh).
- [ ] Extend `test_purge.py` to cover both managers (parametrize).
- [ ] Acceptance: all three managers pass `test_purge_*`.

### Group C — `KvcController` (engine-core core)

**C1. `KvcController` skeleton + hash routing**
- [ ] `vllm/v1/core/sched/kvc_controller.py`: `class KvcController`:
  - `__init__(self, scheduler)`: hold `self.scheduler`, `self.manager` lazily (resolved from `scheduler.connector.manager` at call time, since connector can be set after construction), `self.hint_cache: OrderedDict[str, KvcAck]` (maxlen 10000), `self.jobs: dict[str, KvcJob]`, `self.hash_locks: dict[int, threading.Lock]` (per-hash lock, created lazily).
  - `_manager(self) -> OffloadingManager | None`: `c = self.scheduler.connector; return c.manager if c else None`. Returns None → caller raises the 503 condition.
- [ ] `tests/v1/core/sched/test_kvc_controller.py::test_no_connector_raises`: scheduler with `connector=None` → `_manager()` None → `offload()` raises a controller-level exception the router maps to 503.
- [ ] Acceptance: skeleton imports; test passes.

**C2. `offload(hint) -> KvcAck`**
- [ ] Implement per design §4 scenario A:
  - Resolve manager; if None → raise `KvcNoConnector` (router → 503).
  - Check hint cache; if `hint_id` present → return cached ack.
  - For each hash: acquire per-hash lock; classify:
    - GPU-resident & not in-flight (block ready, ref_cnt sensible) → `prepare_store([h])`; if returns a spec → submit to worker (`OffloadingWorker.submit_store`), add to `submitted`/a pending store-job.
    - In-flight decode → `in_flight_hashes`. (Detection: the block's `is_ready` is False per `lru_manager.complete_store`'s `block.is_ready` check — a block mid-write is not ready.)
    - Not resident → `missing_hashes`.
  - Build `KvcAck(status="accepted"|"partial", accepted_hashes, in_flight_hashes, missing_hashes, block_placements={h:"cpu" for accepted})`. If any `in_flight` or `failed` → `status="partial"` + `job_id`.
- [ ] `test_offload_idempotent`: same `hint_id` twice → second returns cached ack, `prepare_store` called once (assert on mock manager).
- [ ] `test_offload_in_flight`: mock block `is_ready=False` → lands in `in_flight_hashes`, `prepare_store` NOT called for it.
- [ ] `test_offload_missing`: hash not in manager's `self.blocks` → `missing_hashes`.
- [ ] Acceptance: 3 tests pass; contract seams 2/3/5 honored.

**C3. `prefetch(hint) -> KvcAck` (async, returns job_id)**

This is the only async op. The controller submits load to the worker and returns 202 immediately; finalization happens in `drain_completed_jobs` (C5).

- [ ] Implement per design §4 scenario B:
  - Resolve manager; hint-cache check.
  - For each hash: `manager.lookup([h])` — if `None`/miss → `missing_hashes`; else `prepare_load([h])` → worker `submit_load` spec; add to a new `KvcJob(job_id, op=prefetch, submitted={...})`.
  - Return `KvcAck(status="accepted"|"partial", job_id, accepted_hashes, missing_hashes, block_placements={})` (placements filled after job completes — empty at submit).
- [ ] `test_prefetch_returns_job_id`: ack has `job_id`, `status` in ("accepted","partial"), `accepted_hashes` non-empty for a HIT.
- [ ] `test_prefetch_missing`: hash not in any tier → `missing_hashes`, not submitted.
- [ ] Acceptance: 2 tests pass; contract seam 1 honored.

**C4. `evict(hint) -> KvcAck`**
- [ ] Implement per design §4 scenario C:
  - Resolve manager; hint-cache check.
  - For each hash: acquire per-hash lock (waits for any in-flight prefetch/load to drain — seam 4 of design §5.4); call `manager.purge([h])`. If hash was GPU-resident (shouldn't be post-offload, but defensively) also release GPU block.
  - Return `KvcAck(status="accepted", purged_hashes, not_found_hashes)`.
- [ ] `test_evict_purges_all`: store 3, evict 3 → `purged_hashes` has 3, subsequent `lookup` misses.
- [ ] `test_evict_not_found`: purge absent hash → `not_found_hashes`, no error.
- [ ] Acceptance: 2 tests pass.

**C5. `drain_completed_jobs()` (the `_update_after_schedule` hook)**
- [ ] For each in-flight job (store or load): call `worker.get_finished()`; for each finished transfer:
  - Store done + success → `complete_store([h], success=True)` → release GPU block (decrement refcount, return to free pool) via `scheduler.kv_cache_manager`. Append to job `done`.
  - Store done + failure → `complete_store([h], success=False)` (keeps GPU copy, seam 3), job `failed`.
  - Load done + success → `complete_load([h])` + pin (mark non-evictable, hold refcount) → job `done`, `blocks_pinned=True`.
  - Load done + failure → job `failed` (reason `gpu_full` if OOM) — do NOT pin.
  - When job `is_complete()` (all submitted hashes are done or failed) and ≥1 done: emit `BlockRemoved` (for stores) / mark pinned (for loads) via the existing `take_events` → KV-events publisher path. Reap completed jobs after a short TTL (so `GET /v1/kvc/jobs/{id}` still works briefly post-completion).
- [ ] `test_drain_completes_store`: pending store job, `get_finished` returns success → `complete_store` called, GPU block released, job `status="done"`.
- [ ] `test_drain_store_failure_preserves_gpu`: `get_finished` returns failure → `complete_store(success=False)`, GPU block NOT freed, job `failed_hashes` populated.
- [ ] `test_drain_prefetch_pins`: pending load job, `get_finished` success → `complete_load` + pinned flag set.
- [ ] Acceptance: 3 tests pass; contract seams 1/3 honored.

**C6. `job_status(job_id) -> KvcJobStatus`**
- [ ] Look up `self.jobs`; if absent/expired → raise `KvcJobNotFound` (router → 404).
  - Return `job.to_status()`.
- [ ] `test_job_status_404`: unknown `job_id` → raises `KvcJobNotFound`.
- [ ] `test_job_status_running_then_done`: submit prefetch, status="running"; drain completes, status="done".
- [ ] Acceptance: 2 tests pass; contract seam 8 honored.

### Group D — EngineCore wiring (the `getattr` targets)

**D1. `EngineCore.kvc_*` methods**
- [ ] In `vllm/v1/engine/core.py`, add (these are what `call_utility_async("kvc_*")` resolves):
  ```python
  def kvc_offload(self, hint: KvcHint) -> KvcAck:
      ctrl = self.scheduler.kvc_controller
      if ctrl is None: raise KvcNoConnector(...)
      return ctrl.offload(hint)
  def kvc_prefetch(self, hint): ...  # -> KvcAck
  def kvc_evict(self, hint): ...     # -> KvcAck
  def kvc_job_status(self, job_id: str) -> KvcJobStatus: ...
  ```
- [ ] `test_engine_core_routes_kvc`: `EngineCore.call_utility` path mocked — assert `getattr(ec, "kvc_offload")(hint)` reaches `scheduler.kvc_controller.offload`. (Integration-level; the e2e in Group F covers this end-to-end.)
- [ ] Acceptance: `getattr(EngineCore instance, "kvc_offload")` exists and delegates.

**D2. Scheduler constructs + hooks the controller**
- [ ] In `vllm/v1/core/sched/scheduler.py __init__` (after `:127` where connector is set): `self.kvc_controller = KvcController(self) if self.connector is not None else None`.
- [ ] In `_update_after_schedule` (`:951`), after the `num_computed_tokens` loop: `if self.kvc_controller is not None: self.kvc_controller.drain_completed_jobs()`.
- [ ] Acceptance: scheduler with a connector has a non-None `kvc_controller`; without one it's None.

### Group E — Serve router (the HTTP surface)

**E1. `api_router.py` — 4 endpoints**
- [ ] Copy `vllm/entrypoints/serve/profile/api_router.py` structure.
- [ ] `engine_client(request)` helper (same as profile).
- [ ] `@router.post("/v1/kvc/offload")`: decode `KvcHint`, `ack = await engine_client(raw_request).call_utility_async("kvc_offload", hint)`; return `KvcAck` JSON, status 200. Catch `KvcNoConnector` → 503, `KvcEnginePaused` → 409.
- [ ] `@router.post("/v1/kvc/prefetch")`: same, status 202.
- [ ] `@router.post("/v1/kvc/evict")`: same, status 200.
- [ ] `@router.get("/v1/kvc/jobs/{job_id}")`: `status = await engine_client(raw_request).call_utility_async("kvc_job_status", job_id)`; 200 with `KvcJobStatus`. Catch `KvcJobNotFound` → 404.
- [ ] `attach_router(app: FastAPI)`: `app.include_router(router)` unconditionally (the 503-per-request path handles missing connector — don't hide the router, since `kv_transfer_config` could be toggled).
- [ ] `tests/entrypoints/serve/kvc/test_api_router.py` with a mocked `EngineClient`:
    - `test_offload_roundtrip`: POST hint → 200 + KvcAck shape.
    - `test_prefetch_returns_202_job_id`: 202 + `job_id` present.
    - `test_job_status_404`: unknown id → 404.
    - `test_503_no_connector`: engine_client raises `KvcNoConnector` → 503 `{"error":"kvc_control_requires_kv_connector"}`.
    - `test_409_engine_paused`: `KvcEnginePaused` → 409.
    - `test_hint_id_dedup`: same hint_id twice → second response identical, mocked method called once.
- [ ] Acceptance: 6 tests pass; all contract seams 1/5/6/7/8 honored at the HTTP layer.

**E2. Register in `serve/__init__.py`**
- [ ] In `register_vllm_serve_api_routers`, add the `attach_kvc_router(app)` call alongside the others (lora/profile/sleep/rpc/cache/tokenize).
- [ ] Acceptance: a FastAPI app with `register_vllm_serve_api_routers` exposes `/v1/kvc/offload` (assert route exists).

### Group F — End-to-end integration

**F1. `test_kvc_control_e2e.py`**
- [ ] Build a minimal vLLM instance via the existing test fixtures in `tests/v1/` with a CPU offload connector (`kv_transfer_config` set, CPU tier). Use `AsyncLLM` → `EngineCore` (InprocClient) → `Scheduler` path (mirror existing `tests/v1/engine/` e2e patterns).
- [ ] Full agent-recovery arc:
  1. Run a prefill that stores blocks; capture the `block_hashes` from the emitted `BlockStored` event (the same hashes AIGW would have).
  2. `offload`: POST `/v1/kvc/offload` with those hashes → assert ack `accepted_hashes` non-empty; after drain, the GPU block is released (`kv_cache_manager` free list grew) AND a `BlockRemoved` KV-event is emitted.
  3. `prefetch`: POST `/v1/kvc/prefetch` → 202 + `job_id`; poll `GET /v1/kvc/jobs/{id}` → `done` + `blocks_pinned:true`. Then issue the same prefill request again → assert the scheduler's prefix-cache path reports a hit (computed blocks skip prefill — assert `num_new_matched_tokens` covers the prefetched blocks).
  4. `evict`: POST `/v1/kvc/evict` → `purged_hashes`; assert a subsequent `prefetch` of the same hash returns `missing_hashes` (not in any tier).
- [ ] This is the lowest layer that proves the control plane actually drives transfer primitives (design §7.4). Keep it faster than a full serving e2e (small model, few tokens).
- [ ] Acceptance: the 4-step arc passes.

### Group G — Edge cases & error mapping

**G1. Error → HTTP mapping**
- [ ] Centralize the exception→status mapping in `api_router.py` (a small dict or try/except ladder): `KvcNoConnector`→503, `KvcEnginePaused`→409, `KvcJobNotFound`→404, `KvcInvalidHint`→400, unexpected `Exception`→500.
- [ ] `test_error_mapping`: parametrized test feeding each exception → correct status + `{"error": "..."}` body.
- [ ] Acceptance: test passes.

**G2. Engine-paused detection**
- [ ] In `KvcController`, detect paused engine (the `pause_scheduler`/`sleep` utility sets a state — check `scheduler`'s paused flag, same one `is_scheduler_paused` reads via `call_utility_async`). When paused, all ops raise `KvcEnginePaused` without touching blocks (design §5.6).
- [ ] `test_paused_returns_409`: scheduler paused → offload raises `KvcEnginePaused` → router 409.
- [ ] Acceptance: test passes; contract seam 7 honored.

**G3. Prefetch pin TTL (open question from design §9)**
- [ ] Add a configurable `kvc.prefetch_pin_ttl_sec` (default 300s). In `drain_completed_jobs`, for pinned-but-unconsumed blocks older than TTL, unpin (drop refcount, return to LRU). Track pinned-block timestamps in the job.
- [ ] `test_pin_ttl_releases`: fake-clock advance past TTL → pinned block unpinned.
- [ ] Acceptance: test passes; open question resolved (default 300s, configurable).

### Group H — Docs & cleanup

**H1. Config + README**
- [ ] Add `kvc` config section to wherever `kv_transfer_config`-adjacent engine config lives (check `vllm/config.py` for the dataclass). Minimal: `KvcConfig` with `prefetch_pin_ttl_sec: int = 300`, `hint_cache_size: int = 10000`.
- [ ] Add a short section to `docs/` (or `vllm-kvc-offload-prefetch-design.md` addendum) noting the 0.18.0 reconciliation deltas (V1-V10) so the design doc and code stay in sync.
- [ ] Acceptance: config loads; `KvcConfig` defaults applied.

**H2. Lint/format**
- [ ] `ruff check vllm/entrypoints/serve/kvc/ vllm/v1/core/sched/kvc_*.py tests/...kvc...`
- [ ] `ruff format --check` on all touched files.
- [ ] Acceptance: clean.

**H3. Full suite**
- [ ] `pytest tests/v1/kv_offload/test_purge.py tests/v1/core/sched/test_kvc_controller.py tests/entrypoints/serve/kvc/test_api_router.py tests/v1/engine/test_kvc_control_e2e.py -v`
- [ ] Acceptance: all green.

---

## Verification matrix (contract seams → tests)

| Seam | Test(s) |
|---|---|
| 1 prefetch async 202+poll | C3, C5, E1 (prefetch_202), F1 step 3 |
| 2 in_flight/missing not errors | C2 (in_flight, missing), E1 |
| 3 failed → AIGW retries, GPU preserved | C5 (store_failure_preserves_gpu), F1 |
| 4 block_placements {hash→tier} | C2 (ack block_placements), F1 |
| 5 hint_id idempotency | C2 (idempotent), E1 (dedup) |
| 6 no connector → 503 | C1 (no_connector), E1 (503), G1 |
| 7 engine paused → 409 | G2 |
| 8 unknown job_id → 404 | C6, E1 (404) |

---

## Out of scope (Phase 2+ of vLLM-side work)

- Remote tier (Mooncake / LMCache / FS / object-store) integration with the control API.
- Multi-PD-group routing (one model across multiple vLLM engines).
- Pull-mode hint dispatch (vLLM pulling pending hints after its own restart).
- TLS / HMAC between AIGW and vLLM.
- Priority-aware radix eviction exposed via the control API.

These are listed in `vllm-kvc-offload-prefetch-design.md` §8 and are NOT part of this plan.

---

## Execution note

Per `aigw-build-env-constraints` memory: this vLLM tree is at `/Users/taoyu/LocalDocuments/vllm` (tag v0.18.0). Python tests run with `pytest` against a vLLM dev install (`pip install -e .` — heavy; the CPU-tier e2e in F1 needs a buildable vLLM). If the sandbox can't build vLLM, run unit tests (Groups A-E) against an installed `vllm==0.18.0` wheel + the new files overlaid, and defer F1 (e2e) to a machine with a CUDA/CPU-wheel vLLM build. The subagent-dispatch route (superpowers:subagent-driven-development) is broken in this session's key (403 Qwen3.7-Max); execute inline with TDD instead — same as Phase 2.
