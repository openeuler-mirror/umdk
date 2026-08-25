# AIGW Provider Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an IntelliRouter-style Provider Pool scheduling path to aigw so selected models route to OpenAI-compatible SaaS API endpoints (API-key pooling, quota awareness, adaptive routing, per-endpoint cooldown) while existing instance scheduling is untouched.

**Architecture:** A new self-contained `internal/apipool/` package holds Deployment config, a process-wide shared `State` (quota/cooldown/latency keyed by `(provider, hash(apiKey))`), provider adapters, and 5 strategies. `AigwManager` holds one shared `*State` and a `poolTable`, dispatching by the optional `mode` field (default `"instance"`). `http_server.forwardChatCompletions` splits into `forwardToInstance` (unchanged logic) and `forwardToProvider` (failover loop). `internal/gs/` is untouched; `proxy.go` only gains a `FullURL` field.

**Tech Stack:** Go 1.24, `testing` + `github.com/stretchr/testify/assert`, zerolog via `huawei.com/aigw/pkg/log`. Module path `huawei.com/aigw`.

**Spec:** `docs/superpowers/specs/2026-06-09-aigw-provider-pool-design.md`

**Naming note:** The spec uses hypothetical `SchedulerConfig`/`LBConfig`. The ACTUAL code (in `internal/base/aigw_type.go`) uses `GlobalSchedulerConfig` and `LoadBalancerConfig` (LoadBalancer is a value, not a pointer). This plan uses the actual names. `CooldownConfig`, `RetryConfig`, `ProviderPoolConfig`, `DeploymentConfig` are added to `internal/base` so `apipool` consumes them without an import cycle (base imports nothing from apipool).

---

### Task 1: apipool package skeleton — Deployment + StateKey

**Files:**
- Create: `internal/apipool/deployment.go`
- Test: `internal/apipool/deployment_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/deployment_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStateKey_FingerprintDeterministic(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	assert.Equal(t, d1.StateKey(), d2.StateKey())
	assert.Equal(t, 16, len(d1.StateKey().KeyFingerprint))
}

func TestStateKey_DifferentKeyDifferentFingerprint(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "openai", APIKey: "sk-xyz"}
	assert.NotEqual(t, d1.StateKey(), d2.StateKey())
}

func TestStateKey_SameKeyDifferentProvider(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "deepseek", APIKey: "sk-abc"}
	assert.NotEqual(t, d1.StateKey(), d2.StateKey())
	assert.Equal(t, d1.StateKey().KeyFingerprint, d2.StateKey().KeyFingerprint)
}

func TestStateKey_NoPlaintextKey(t *testing.T) {
	d := &Deployment{Provider: "openai", APIKey: "sk-secret", Timeout: 30 * time.Second}
	assert.NotContains(t, d.StateKey().KeyFingerprint, "sk-secret")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestStateKey -v`
Expected: FAIL — undefined: Deployment, StateKey

- [ ] **Step 3: Write minimal implementation**

```go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Deployment data model and cross-pool StateKey for the provider pool.
 * Create: 2026-06-09
 */

// Package apipool provides IntelliRouter-style provider pool scheduling for AIGW.
package apipool

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// DeploymentStatus is the runtime health status of a deployment endpoint.
type DeploymentStatus int

const (
	// StatusHealthy means the endpoint is selectable.
	StatusHealthy DeploymentStatus = iota
	// StatusCooldown means the endpoint is temporarily skipped.
	StatusCooldown
)

// Deployment is the immutable configuration of one provider endpoint.
type Deployment struct {
	ID        string
	ModelName string
	APIKey    string
	APIBase   string
	Provider  string

	TPM int // 0 = unlimited
	RPM int // 0 = unlimited

	Tags             []string
	Timeout          time.Duration
	VerifySSL        bool
	AuthHeaderName   string
	AuthHeaderPrefix string
}

// StateKey is the cross-pool addressing key for shared quota/cooldown/latency.
// Same (provider, apiKey) shares one state entry across multiple model pools.
type StateKey struct {
	Provider       string
	KeyFingerprint string // = sha256(apiKey)[:16], avoids retaining plaintext key
}

// StateKey computes the cross-pool key for this deployment.
func (d *Deployment) StateKey() StateKey {
	sum := sha256.Sum256([]byte(d.APIKey))
	return StateKey{
		Provider:       d.Provider,
		KeyFingerprint: hex.EncodeToString(sum[:])[:16],
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestStateKey -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/deployment.go internal/apipool/deployment_test.go
git commit -m "feat(apipool): add Deployment model and cross-pool StateKey"
```

---

### Task 2: slidingWindow (1-minute lazy-eviction counter)

**Files:**
- Create: `internal/apipool/state.go`
- Test: `internal/apipool/sliding_window_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/sliding_window_test.go
package apipool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlidingWindow_SumWithinWindow(t *testing.T) {
	w := newSlidingWindow(60)
	w.add(1000, 10)
	w.add(1010, 20)
	assert.Equal(t, 30, w.sum(1030))
}

func TestSlidingWindow_EvictsExpired(t *testing.T) {
	w := newSlidingWindow(60)
	w.add(1000, 10) // expires at 1060
	w.add(1050, 20)
	// now=1061: first event (ts=1000) is older than 60s -> evicted
	assert.Equal(t, 20, w.sum(1061))
}

func TestSlidingWindow_EmptyIsZero(t *testing.T) {
	w := newSlidingWindow(60)
	assert.Equal(t, 0, w.sum(1000))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestSlidingWindow -v`
Expected: FAIL — undefined: newSlidingWindow

- [ ] **Step 3: Write minimal implementation** (start `state.go`)

```go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Shared runtime State (quota/cooldown/latency) for the provider pool.
 * Create: 2026-06-09
 */

package apipool

// swEvent is one timestamped contribution to a sliding window.
type swEvent struct {
	ts  int64 // unix seconds
	val int
}

// slidingWindow is a fixed-duration counter with lazy eviction on query.
type slidingWindow struct {
	windowSec int64
	events    []swEvent
}

func newSlidingWindow(windowSec int64) *slidingWindow {
	return &slidingWindow{windowSec: windowSec}
}

func (w *slidingWindow) add(ts int64, val int) {
	w.events = append(w.events, swEvent{ts: ts, val: val})
}

// sum evicts events older than the window then returns the total.
func (w *slidingWindow) sum(now int64) int {
	cutoff := now - w.windowSec
	idx := 0
	for idx < len(w.events) && w.events[idx].ts <= cutoff {
		idx++
	}
	if idx > 0 {
		w.events = w.events[idx:]
	}
	total := 0
	for _, e := range w.events {
		total += e.val
	}
	return total
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestSlidingWindow -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/state.go internal/apipool/sliding_window_test.go
git commit -m "feat(apipool): add sliding window counter for quota tracking"
```

---

### Task 3: State quota tracking — NewState, RecordSuccess, RemainingTPM/RPM

**Files:**
- Modify: `internal/apipool/state.go` (append)
- Test: `internal/apipool/state_quota_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/state_quota_test.go
package apipool

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func testCfg() *base.CooldownConfig {
	return &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300}
}

func TestState_RemainingTPM_Unlimited(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	assert.Equal(t, intMax, s.RemainingTPM(k, 0)) // tpm=0 means unlimited
}

func TestState_RemainingTPM_TracksTokens(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 100*time.Millisecond, 400)
	assert.Equal(t, 600, s.RemainingTPM(k, 1000))
}

func TestState_RemainingRPM_TracksRequests(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 100*time.Millisecond, 10)
	s.RecordSuccess(k, false, 100*time.Millisecond, 10)
	assert.Equal(t, 498, s.RemainingRPM(k, 500))
}

func TestState_RemainingTPM_NeverNegative(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, time.Millisecond, 2000)
	assert.Equal(t, 0, s.RemainingTPM(k, 1000))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestState_Remaining -v`
Expected: FAIL — undefined: NewState, intMax

- [ ] **Step 3: Write minimal implementation** (append to `state.go`)

```go
import (
	"math"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
)

const intMax = math.MaxInt

// State holds runtime status shared across all provider pools, addressed by StateKey.
type State struct {
	mu      sync.RWMutex // protects entries map add/lookup only
	cfg     *base.CooldownConfig
	entries map[StateKey]*stateEntry
}

type stateEntry struct {
	mu sync.RWMutex

	status           DeploymentStatus
	cooldownUntil    int64
	consecutiveFails int
	auth401Attempts  int

	tokenBucket *slidingWindow
	rpmBucket   *slidingWindow

	avgTTFT         float64
	avgTotalLatency float64

	totalRequests int64
	totalTokens   int64
	totalFailures int64
}

// NewState creates a shared State with the given cooldown config.
func NewState(cfg *base.CooldownConfig) *State {
	return &State{cfg: cfg, entries: make(map[StateKey]*stateEntry)}
}

func (s *State) getOrCreate(k StateKey) *stateEntry {
	s.mu.RLock()
	e := s.entries[k]
	s.mu.RUnlock()
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.entries[k]; e != nil {
		return e
	}
	e = &stateEntry{
		status:      StatusHealthy,
		tokenBucket: newSlidingWindow(60),
		rpmBucket:   newSlidingWindow(60),
	}
	s.entries[k] = e
	return e
}

// RecordSuccess records a successful call. When stream is true latency is the TTFT;
// otherwise it is the total request latency.
func (s *State) RecordSuccess(k StateKey, stream bool, latency time.Duration, tokens int) {
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Unix()
	e.status = StatusHealthy
	e.consecutiveFails = 0
	e.auth401Attempts = 0
	e.totalRequests++
	e.totalTokens += int64(tokens)
	e.rpmBucket.add(now, 1)
	if tokens > 0 {
		e.tokenBucket.add(now, tokens)
	}
	e.recordLatency(stream, latency)
}

// RemainingTPM returns the remaining tokens-per-minute budget; tpm=0 means unlimited.
func (s *State) RemainingTPM(k StateKey, tpm int) int {
	if tpm <= 0 {
		return intMax
	}
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	rem := tpm - e.tokenBucket.sum(time.Now().Unix())
	if rem < 0 {
		return 0
	}
	return rem
}

// RemainingRPM returns the remaining requests-per-minute budget; rpm=0 means unlimited.
func (s *State) RemainingRPM(k StateKey, rpm int) int {
	if rpm <= 0 {
		return intMax
	}
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	rem := rpm - e.rpmBucket.sum(time.Now().Unix())
	if rem < 0 {
		return 0
	}
	return rem
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestState_Remaining -v`
Expected: PASS (note: `recordLatency` is defined in Task 4; add a temporary stub `func (e *stateEntry) recordLatency(stream bool, latency time.Duration) {}` to compile, replaced in Task 4)

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/state.go internal/apipool/state_quota_test.go
git commit -m "feat(apipool): add State quota tracking with shared StateKey addressing"
```

---

### Task 4: State latency EMA split (TTFT vs total)

**Files:**
- Modify: `internal/apipool/state.go` (replace the `recordLatency` stub)
- Test: `internal/apipool/state_latency_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/state_latency_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestState_FirstSampleAssignedDirectly(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 200*time.Millisecond, 10)
	assert.InDelta(t, 0.2, s.AvgLatency(k, false), 1e-9)
}

func TestState_EMAWithAlpha02(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 200*time.Millisecond, 10) // avg=0.2
	s.RecordSuccess(k, false, 400*time.Millisecond, 10) // 0.2*0.4 + 0.8*0.2 = 0.24
	assert.InDelta(t, 0.24, s.AvgLatency(k, false), 1e-9)
}

func TestState_StreamRecordsTTFTSeparately(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, true, 50*time.Millisecond, 10)   // TTFT bucket
	s.RecordSuccess(k, false, 900*time.Millisecond, 10) // total bucket
	assert.InDelta(t, 0.05, s.AvgLatency(k, true), 1e-9)
	assert.InDelta(t, 0.9, s.AvgLatency(k, false), 1e-9)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestState_EMA -v` and `-run TestState_Stream -v`
Expected: FAIL — undefined: AvgLatency (and stub returns wrong value)

- [ ] **Step 3: Write minimal implementation** (replace the stub in `state.go`)

```go
const emaAlpha = 0.2

func (e *stateEntry) recordLatency(stream bool, latency time.Duration) {
	sample := latency.Seconds()
	if stream {
		if e.avgTTFT == 0 {
			e.avgTTFT = sample
		} else {
			e.avgTTFT = emaAlpha*sample + (1-emaAlpha)*e.avgTTFT
		}
		return
	}
	if e.avgTotalLatency == 0 {
		e.avgTotalLatency = sample
	} else {
		e.avgTotalLatency = emaAlpha*sample + (1-emaAlpha)*e.avgTotalLatency
	}
}

// AvgLatency returns the EMA latency in seconds; TTFT when stream is true, total otherwise.
func (s *State) AvgLatency(k StateKey, stream bool) float64 {
	e := s.getOrCreate(k)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if stream {
		return e.avgTTFT
	}
	return e.avgTotalLatency
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'TestState_(First|EMA|Stream)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/state.go internal/apipool/state_latency_test.go
git commit -m "feat(apipool): add EMA latency tracking split by TTFT/total"
```

---

### Task 5: cooldown.go — ErrorKind classification + duration policy

**Files:**
- Create: `internal/apipool/cooldown.go`
- Test: `internal/apipool/cooldown_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/cooldown_test.go
package apipool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		want   ErrorKind
	}{
		{"network", 0, errors.New("dial tcp: timeout"), ErrNetwork},
		{"canceled", 0, context.Canceled, ErrCanceled},
		{"timeout408", 408, nil, ErrTimeout},
		{"ratelimit429", 429, nil, ErrRateLimit},
		{"auth401", 401, nil, ErrAuth},
		{"auth403", 403, nil, ErrAuth},
		{"notfound404", 404, nil, ErrNotFound},
		{"client400", 400, nil, ErrClient4xx},
		{"client422", 422, nil, ErrClient4xx},
		{"server500", 500, nil, ErrServer5xx},
		{"server503", 503, nil, ErrServer5xx},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ClassifyError(c.status, c.err))
		})
	}
}

func TestDurationFor(t *testing.T) {
	cfg := testCfg() // Duration=60, RateLimit=90, Auth401Floor=300
	assert.Equal(t, 60*time.Second, durationFor(ErrServer5xx, 0, cfg))
	assert.Equal(t, 60*time.Second, durationFor(ErrNetwork, 0, cfg))
	assert.Equal(t, 90*time.Second, durationFor(ErrRateLimit, 0, cfg))
	// 401 exponential: floor * 2^(attempts-1), capped at 8h
	assert.Equal(t, 5*time.Minute, durationFor(ErrAuth, 1, cfg))
	assert.Equal(t, 10*time.Minute, durationFor(ErrAuth, 2, cfg))
	assert.Equal(t, 30*time.Minute, durationFor(ErrAuth, 3, cfg))
	assert.Equal(t, 120*time.Minute, durationFor(ErrAuth, 4, cfg))
	assert.Equal(t, 480*time.Minute, durationFor(ErrAuth, 5, cfg))
	assert.Equal(t, 8*time.Hour, durationFor(ErrAuth, 99, cfg)) // capped
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run 'TestClassifyError|TestDurationFor' -v`
Expected: FAIL — undefined: ErrorKind, ClassifyError, durationFor

- [ ] **Step 3: Write minimal implementation**

```go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Error classification and cooldown duration policy for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"context"
	"errors"
	"time"

	"huawei.com/aigw/internal/base"
)

// ErrorKind classifies a forward failure to drive failover/cooldown decisions.
type ErrorKind int

const (
	// ErrNetwork is a transport-level failure (counts, fixed cooldown, failover).
	ErrNetwork ErrorKind = iota
	// ErrServer5xx is an upstream 5xx (counts, fixed cooldown, failover).
	ErrServer5xx
	// ErrRateLimit is HTTP 429 (counts, rate-limit cooldown, failover).
	ErrRateLimit
	// ErrTimeout is HTTP 408 (counts, fixed cooldown, failover).
	ErrTimeout
	// ErrAuth is HTTP 401/403 (counts, exponential-backoff cooldown, failover).
	ErrAuth
	// ErrNotFound is HTTP 404 (failover, no count, no cooldown).
	ErrNotFound
	// ErrClient4xx is HTTP 400/422 (no failover, no count, passthrough).
	ErrClient4xx
	// ErrCanceled is a client/context cancellation (no count, exit loop).
	ErrCanceled
)

const auth401CapDuration = 8 * time.Hour

// ClassifyError maps an HTTP status code and/or transport error to an ErrorKind.
func ClassifyError(statusCode int, err error) ErrorKind {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ErrCanceled
		}
		if statusCode == 0 {
			return ErrNetwork
		}
	}
	switch {
	case statusCode == 408:
		return ErrTimeout
	case statusCode == 429:
		return ErrRateLimit
	case statusCode == 401 || statusCode == 403:
		return ErrAuth
	case statusCode == 404:
		return ErrNotFound
	case statusCode == 400 || statusCode == 422:
		return ErrClient4xx
	case statusCode >= 500:
		return ErrServer5xx
	default:
		return ErrNetwork
	}
}

// counts reports whether this kind increments consecutiveFails.
func (k ErrorKind) counts() bool {
	switch k {
	case ErrNetwork, ErrServer5xx, ErrRateLimit, ErrTimeout, ErrAuth:
		return true
	default:
		return false
	}
}

// durationFor computes the cooldown duration for a triggering failure.
// auth401Attempts is the post-increment count for ErrAuth.
func durationFor(kind ErrorKind, auth401Attempts int, cfg *base.CooldownConfig) time.Duration {
	switch kind {
	case ErrRateLimit:
		return time.Duration(cfg.RateLimitDurationSec) * time.Second
	case ErrAuth:
		d := time.Duration(cfg.Auth401FloorSec) * time.Second
		for i := 1; i < auth401Attempts; i++ {
			d *= 2
			if d >= auth401CapDuration {
				return auth401CapDuration
			}
		}
		return d
	default:
		return time.Duration(cfg.DurationSec) * time.Second
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'TestClassifyError|TestDurationFor' -v`
Expected: PASS (requires `base.CooldownConfig` from Task 16; if implementing strictly in order, do Task 16's struct first or add a temporary local `CooldownConfig` — recommended: implement Task 16's base structs before this task. See "Ordering note" at end of plan.)

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/cooldown.go internal/apipool/cooldown_test.go
git commit -m "feat(apipool): add error classification and cooldown duration policy"
```

---

### Task 6: State.RecordFailure + cooldown state machine + lazy recovery

**Files:**
- Modify: `internal/apipool/state.go` (append)
- Test: `internal/apipool/state_cooldown_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/state_cooldown_test.go
package apipool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState_EntersCooldownAfterThreshold(t *testing.T) {
	s := NewState(testCfg()) // FailureThreshold=3
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	assert.True(t, s.IsAvailable(k))
	s.RecordFailure(k, ErrServer5xx)
	s.RecordFailure(k, ErrServer5xx)
	assert.True(t, s.IsAvailable(k), "2 fails < threshold")
	s.RecordFailure(k, ErrServer5xx)
	assert.False(t, s.IsAvailable(k), "3 fails >= threshold -> cooldown")
}

func TestState_LazyRecovery(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrServer5xx)
	}
	assert.False(t, s.IsAvailable(k))
	// force cooldownUntil into the past
	s.forceCooldownUntil(k, 0)
	assert.True(t, s.IsAvailable(k), "expired cooldown recovers lazily")
}

func TestState_404DoesNotCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 5; i++ {
		s.RecordFailure(k, ErrNotFound)
	}
	assert.True(t, s.IsAvailable(k), "404 never triggers cooldown")
}

func TestState_4xxDoesNotCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 5; i++ {
		s.RecordFailure(k, ErrClient4xx)
	}
	assert.True(t, s.IsAvailable(k))
}

func TestState_SuccessClearsFailCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordFailure(k, ErrServer5xx)
	s.RecordFailure(k, ErrServer5xx)
	s.RecordSuccess(k, false, 0, 0)
	s.RecordFailure(k, ErrServer5xx)
	assert.True(t, s.IsAvailable(k), "success reset count, 1 fail < threshold")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run 'TestState_(Enters|Lazy|404|4xx|Success)' -v`
Expected: FAIL — undefined: IsAvailable, RecordFailure, forceCooldownUntil

- [ ] **Step 3: Write minimal implementation** (append to `state.go`)

```go
// IsAvailable returns true if the endpoint is HEALTHY, recovering lazily on expiry.
func (s *State) IsAvailable(k StateKey) bool {
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status == StatusCooldown && time.Now().Unix() >= e.cooldownUntil {
		e.status = StatusHealthy
		e.consecutiveFails = 0
	}
	return e.status == StatusHealthy
}

// Status returns the current status (recovering lazily on expiry).
func (s *State) Status(k StateKey) DeploymentStatus {
	if s.IsAvailable(k) {
		return StatusHealthy
	}
	return StatusCooldown
}

// RecordFailure records a failed call and may enter cooldown.
func (s *State) RecordFailure(k StateKey, kind ErrorKind) {
	if !kind.counts() {
		return
	}
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()

	e.totalFailures++
	e.consecutiveFails++
	if kind == ErrAuth {
		e.auth401Attempts++
	}
	if e.consecutiveFails >= s.cfg.FailureThreshold {
		e.status = StatusCooldown
		e.cooldownUntil = time.Now().Unix() + int64(durationFor(kind, e.auth401Attempts, s.cfg).Seconds())
	}
}

// forceCooldownUntil is a test helper to override the cooldown deadline.
func (s *State) forceCooldownUntil(k StateKey, ts int64) {
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cooldownUntil = ts
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'TestState_(Enters|Lazy|404|4xx|Success)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/state.go internal/apipool/state_cooldown_test.go
git commit -m "feat(apipool): add cooldown state machine with lazy recovery"
```

---

### Task 7: State 401/403 exponential backoff

**Files:**
- Test only: `internal/apipool/state_auth_test.go` (logic already in Task 6 RecordFailure)

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/state_auth_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// cooldownRemaining returns the configured cooldown seconds for the entry.
func (s *State) cooldownRemainingSec(k StateKey) int64 {
	e := s.getOrCreate(k)
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cooldownUntil - time.Now().Unix()
}

func TestState_401ExponentialBackoff(t *testing.T) {
	s := NewState(testCfg()) // threshold=3, auth floor=300s
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}

	// Need >= threshold consecutive fails to enter cooldown each round.
	expect := []int64{300, 600, 1800, 7200, 28800} // 5/10/30/120/480 min
	for round, want := range expect {
		// drive to threshold with ErrAuth (each increments auth401Attempts)
		for i := 0; i < 3; i++ {
			s.RecordFailure(k, ErrAuth)
		}
		got := s.cooldownRemainingSec(k)
		assert.InDelta(t, want, got, 2, "round %d", round)
		// recover for next round without clearing auth attempts: expire cooldown
		s.forceCooldownUntil(k, 0)
		assert.True(t, s.IsAvailable(k))
	}
}

func TestState_SuccessResetsAuthAttempts(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrAuth)
	}
	assert.InDelta(t, int64(300), s.cooldownRemainingSec(k), 2)
	s.forceCooldownUntil(k, 0)
	_ = s.IsAvailable(k)
	s.RecordSuccess(k, false, 0, 0) // clears auth401Attempts
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrAuth)
	}
	assert.InDelta(t, int64(300), s.cooldownRemainingSec(k), 2, "back to floor after success")
}
```

> **Note on IsAvailable + auth attempts:** `IsAvailable` lazy recovery clears `consecutiveFails` but NOT `auth401Attempts`. Only `RecordSuccess` clears `auth401Attempts`. Verify the Task 6 implementation matches — `IsAvailable` must not reset `auth401Attempts`. This is correct as written in Task 6.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run 'TestState_(401|SuccessResets)' -v`
Expected: FAIL initially only if logic wrong; if Task 6 is correct these PASS. (TDD: these tests pin the backoff contract.)

- [ ] **Step 3: Implementation** — none beyond Task 6; if a test fails, fix `RecordFailure`/`IsAvailable` so `auth401Attempts` survives lazy recovery and resets only on success.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'TestState_(401|SuccessResets)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/state_auth_test.go
git commit -m "test(apipool): pin 401/403 exponential backoff contract"
```

---

### Task 8: State concurrency safety (-race smoke test)

**Files:**
- Test only: `internal/apipool/state_race_test.go`

- [ ] **Step 1: Write the test**

```go
// internal/apipool/state_race_test.go
package apipool

import (
	"sync"
	"testing"
	"time"
)

func TestState_ConcurrentAccess(t *testing.T) {
	s := NewState(testCfg())
	keys := []StateKey{
		{Provider: "openai", KeyFingerprint: "a"},
		{Provider: "openai", KeyFingerprint: "b"},
	}
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			k := keys[g%len(keys)]
			for i := 0; i < 100; i++ {
				s.RecordSuccess(k, i%2 == 0, 10*time.Millisecond, 5)
				s.RecordFailure(k, ErrServer5xx)
				_ = s.IsAvailable(k)
				_ = s.RemainingTPM(k, 1000)
				_ = s.RemainingRPM(k, 500)
				_ = s.AvgLatency(k, true)
			}
		}(g)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run with race detector**

Run: `go test ./internal/apipool/ -run TestState_ConcurrentAccess -race -v`
Expected: PASS, no data race reported

- [ ] **Step 3: Commit**

```bash
git add internal/apipool/state_race_test.go
git commit -m "test(apipool): add concurrency race smoke test for State"
```

---

### Task 9: Provider Adapter layer — base + registry + OpenAICompat

**Files:**
- Create: `internal/apipool/adapter/base.go`
- Create: `internal/apipool/adapter/registry.go`
- Create: `internal/apipool/adapter/openai_compat.go`
- Test: `internal/apipool/adapter/adapter_test.go`

> **Import note:** the adapter package needs `*apipool.Deployment`. To avoid an `apipool ↔ adapter` import cycle, the `Adapter` interface takes the fields it needs as a small local interface rather than importing apipool. Define a `Target` interface in `base.go` that `*apipool.Deployment` satisfies structurally via getters — OR (simpler, chosen here) keep adapters in the SAME package `apipool` (no subpackage). The spec's directory layout is aspirational; a single `apipool` package avoids the cycle. **This plan places adapter and strategy code as files within `package apipool`** (filenames `adapter_*.go`, `strategy_*.go`) to keep `*Deployment`/`*State` directly usable. Update the spec's appendix mentally: same package, separate files.

Revised files for this task:
- Create: `internal/apipool/adapter.go`
- Test: `internal/apipool/adapter_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/adapter_test.go
package apipool

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenAICompatAdapter_BuildURL(t *testing.T) {
	a := newOpenAICompatAdapter("openai")
	dep := &Deployment{APIBase: "https://api.openai.com", Provider: "openai"}
	assert.Equal(t, "https://api.openai.com/v1/chat/completions",
		a.BuildURL(dep, "/v1/chat/completions", false))
}

func TestOpenAICompatAdapter_InjectAuthBearer(t *testing.T) {
	a := newOpenAICompatAdapter("openai")
	dep := &Deployment{APIKey: "sk-abc", Provider: "openai"}
	h := http.Header{}
	a.InjectAuth(h, dep)
	assert.Equal(t, "Bearer sk-abc", h.Get("Authorization"))
}

func TestOpenAICompatAdapter_CustomAuthHeader(t *testing.T) {
	a := newOpenAICompatAdapter("custom")
	dep := &Deployment{APIKey: "k1", Provider: "custom", AuthHeaderName: "X-Api-Key", AuthHeaderPrefix: ""}
	h := http.Header{}
	a.InjectAuth(h, dep)
	assert.Equal(t, "k1", h.Get("X-Api-Key"))
	assert.Empty(t, h.Get("Authorization"))
}

func TestRegistry_GetKnownProvider(t *testing.T) {
	r := NewDefaultRegistry()
	a, err := r.Get("openai")
	assert.NoError(t, err)
	assert.NotNil(t, a)
}

func TestRegistry_GetUnknownProvider(t *testing.T) {
	r := NewDefaultRegistry()
	_, err := r.Get("no-such-provider")
	assert.Error(t, err)
}

func TestRegistry_DefaultProvidersRegistered(t *testing.T) {
	r := NewDefaultRegistry()
	for _, p := range []string{"openai", "vllm", "deepseek", "dashscope", "siliconflow", "zhipu", "custom"} {
		_, err := r.Get(p)
		assert.NoError(t, err, "provider %s should be registered", p)
	}
}

func TestDashscopeAdapter_BuildURLPrefix(t *testing.T) {
	r := NewDefaultRegistry()
	a, _ := r.Get("dashscope")
	dep := &Deployment{APIBase: "https://dashscope.aliyuncs.com", Provider: "dashscope"}
	assert.Equal(t, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
		a.BuildURL(dep, "/v1/chat/completions", false))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run 'Adapter|Registry' -v`
Expected: FAIL — undefined: newOpenAICompatAdapter, NewDefaultRegistry

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/adapter.go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Provider adapters (URL build + auth injection) for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"fmt"
	"net/http"
)

// Adapter builds the upstream URL and injects auth headers for a deployment.
type Adapter interface {
	BuildURL(dep *Deployment, route string, stream bool) string
	InjectAuth(headers http.Header, dep *Deployment)
}

// Registry maps a provider identifier to an Adapter.
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds or replaces an adapter for a provider name.
func (r *Registry) Register(name string, a Adapter) {
	r.adapters[name] = a
}

// Get returns the adapter for a provider, or an error if unregistered.
func (r *Registry) Get(provider string) (Adapter, error) {
	a, ok := r.adapters[provider]
	if !ok {
		return nil, fmt.Errorf("apipool: unknown provider %q", provider)
	}
	return a, nil
}

// NewDefaultRegistry registers all first-version OpenAI-compatible providers.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	for _, p := range []string{"openai", "vllm", "deepseek", "siliconflow", "zhipu", "custom"} {
		r.Register(p, newOpenAICompatAdapter(p))
	}
	r.Register("dashscope", &dashscopeAdapter{openAICompatAdapter{provider: "dashscope"}})
	return r
}

// openAICompatAdapter covers providers whose API equals OpenAI's: {APIBase}{route}.
type openAICompatAdapter struct {
	provider string
}

func newOpenAICompatAdapter(provider string) *openAICompatAdapter {
	return &openAICompatAdapter{provider: provider}
}

func (a *openAICompatAdapter) BuildURL(dep *Deployment, route string, stream bool) string {
	return dep.APIBase + route
}

func (a *openAICompatAdapter) InjectAuth(headers http.Header, dep *Deployment) {
	if dep.AuthHeaderName != "" {
		val := dep.APIKey
		if dep.AuthHeaderPrefix != "" {
			val = dep.AuthHeaderPrefix + " " + dep.APIKey
		}
		headers.Set(dep.AuthHeaderName, val)
		return
	}
	headers.Set("Authorization", "Bearer "+dep.APIKey)
}

// dashscopeAdapter prefixes the route with /compatible-mode.
type dashscopeAdapter struct {
	openAICompatAdapter
}

func (a *dashscopeAdapter) BuildURL(dep *Deployment, route string, stream bool) string {
	return dep.APIBase + "/compatible-mode" + route
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'Adapter|Registry' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/adapter.go internal/apipool/adapter_test.go
git commit -m "feat(apipool): add provider adapter layer and registry"
```

---

### Task 10: Strategy base + simple-shuffle + factory

**Files:**
- Create: `internal/apipool/strategy.go` (Context, Strategy, filterAvailable, factory)
- Create: `internal/apipool/strategy_simple_shuffle.go`
- Test: `internal/apipool/strategy_simple_shuffle_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/strategy_simple_shuffle_test.go
package apipool

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func depList() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a"},
		{ID: "b", Provider: "openai", APIKey: "k-b"},
		{ID: "c", Provider: "openai", APIKey: "k-c"},
	}
}

func TestSimpleShuffle_PicksAvailable(t *testing.T) {
	s := NewState(testCfg())
	st := newSimpleShuffle(s)
	st.rng = rand.New(rand.NewSource(1))
	deps := depList()
	got := st.Select(deps, &Context{})
	assert.NotNil(t, got)
}

func TestSimpleShuffle_SkipsCooldown(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	// put a and b into cooldown
	for _, d := range deps[:2] {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newSimpleShuffle(s)
	st.rng = rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		got := st.Select(deps, &Context{})
		assert.Equal(t, "c", got.ID, "only c is healthy")
	}
}

func TestSimpleShuffle_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newSimpleShuffle(s)
	assert.Nil(t, st.Select(deps, &Context{}))
}

func TestFactory_CreatesSimpleShuffle(t *testing.T) {
	s := NewState(testCfg())
	st, err := CreateStrategy("simple-shuffle", s, nil)
	assert.NoError(t, err)
	assert.Equal(t, "simple-shuffle", st.Name())
}

func TestFactory_UnknownStrategy(t *testing.T) {
	s := NewState(testCfg())
	_, err := CreateStrategy("no-such", s, nil)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run 'SimpleShuffle|Factory' -v`
Expected: FAIL — undefined: newSimpleShuffle, Context, CreateStrategy

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/strategy.go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Strategy interface, shared helpers, and factory for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import "fmt"

// Context carries per-request hints for strategy selection.
type Context struct {
	Model     string
	Messages  []map[string]any
	PromptLen int  // reserved; first version strategies do not read it
	Stream    bool // selects TTFT vs total latency signal
}

// Strategy selects one deployment from a candidate list.
type Strategy interface {
	Name() string
	Select(deployments []*Deployment, ctx *Context) *Deployment
}

// filterAvailable returns deployments whose shared state is HEALTHY.
func filterAvailable(state *State, deps []*Deployment) []*Deployment {
	out := make([]*Deployment, 0, len(deps))
	for _, d := range deps {
		if state.IsAvailable(d.StateKey()) {
			out = append(out, d)
		}
	}
	return out
}

func optFloat(opts map[string]any, key string, def float64) float64 {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}

func optInt(opts map[string]any, key string, def int) int {
	return int(optFloat(opts, key, float64(def)))
}

// CreateStrategy builds a strategy by name, sharing the given State.
func CreateStrategy(name string, state *State, opts map[string]any) (Strategy, error) {
	switch name {
	case "simple-shuffle":
		return newSimpleShuffle(state), nil
	case "lowest-latency":
		return newLowestLatency(state, opts), nil
	case "token-aware":
		return newTokenAware(state, opts), nil
	case "rate-limit-aware":
		return newRateLimitAware(state, opts), nil
	case "adaptive":
		return newAdaptive(state, opts), nil
	default:
		return nil, fmt.Errorf("apipool: unknown strategy %q", name)
	}
}
```

```go
// internal/apipool/strategy_simple_shuffle.go
package apipool

import "math/rand"

type simpleShuffle struct {
	state *State
	rng   *rand.Rand
}

func newSimpleShuffle(state *State) *simpleShuffle {
	return &simpleShuffle{state: state, rng: rand.New(rand.NewSource(rand.Int63()))}
}

func (s *simpleShuffle) Name() string { return "simple-shuffle" }

func (s *simpleShuffle) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	return avail[s.rng.Intn(len(avail))]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run 'SimpleShuffle|Factory' -v`
Expected: PASS (requires Task 11-14 constructors to exist for `CreateStrategy` to compile — add minimal stub constructors now or implement 11-14 before running the factory test. Recommended: stub `newLowestLatency/newTokenAware/newRateLimitAware/newAdaptive` returning a `simpleShuffle` temporarily, replaced in their tasks.)

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/strategy.go internal/apipool/strategy_simple_shuffle.go internal/apipool/strategy_simple_shuffle_test.go
git commit -m "feat(apipool): add strategy interface, factory, and simple-shuffle"
```

---

### Task 11: lowest-latency strategy

**Files:**
- Create: `internal/apipool/strategy_lowest_latency.go`
- Test: `internal/apipool/strategy_lowest_latency_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/strategy_lowest_latency_test.go
package apipool

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLowestLatency_PicksLowestTotal(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	s.RecordSuccess(deps[0].StateKey(), false, 500*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 1)
	s.RecordSuccess(deps[2].StateKey(), false, 300*time.Millisecond, 1)
	st := newLowestLatency(s, map[string]any{"explorationRatio": 0.0})
	st.rng = rand.New(rand.NewSource(1))
	assert.Equal(t, "b", st.Select(deps, &Context{Stream: false}).ID)
}

func TestLowestLatency_StreamUsesTTFT(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	// dep a: low TTFT, high total; dep b: high TTFT, low total
	s.RecordSuccess(deps[0].StateKey(), true, 50*time.Millisecond, 1)
	s.RecordSuccess(deps[0].StateKey(), false, 900*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), true, 400*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 1)
	s.RecordSuccess(deps[2].StateKey(), true, 600*time.Millisecond, 1)
	st := newLowestLatency(s, map[string]any{"explorationRatio": 0.0})
	st.rng = rand.New(rand.NewSource(1))
	assert.Equal(t, "a", st.Select(deps, &Context{Stream: true}).ID, "stream picks lowest TTFT")
}

func TestLowestLatency_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newLowestLatency(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestLowestLatency -v`
Expected: FAIL — newLowestLatency stub returns simpleShuffle, wrong selection

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/strategy_lowest_latency.go
package apipool

import "math/rand"

type lowestLatency struct {
	state            *State
	explorationRatio float64
	rng              *rand.Rand
}

func newLowestLatency(state *State, opts map[string]any) *lowestLatency {
	return &lowestLatency{
		state:            state,
		explorationRatio: optFloat(opts, "explorationRatio", 0.1),
		rng:              rand.New(rand.NewSource(rand.Int63())),
	}
}

func (s *lowestLatency) Name() string { return "lowest-latency" }

func (s *lowestLatency) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	if s.rng.Float64() < s.explorationRatio {
		return avail[s.rng.Intn(len(avail))]
	}
	best := avail[0]
	bestLat := s.state.AvgLatency(best.StateKey(), ctx.Stream)
	for _, d := range avail[1:] {
		lat := s.state.AvgLatency(d.StateKey(), ctx.Stream)
		if lat < bestLat {
			best, bestLat = d, lat
		}
	}
	return best
}
```

> Replace the temporary `newLowestLatency` stub from Task 10 with this real implementation.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestLowestLatency -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/strategy_lowest_latency.go internal/apipool/strategy_lowest_latency_test.go
git commit -m "feat(apipool): add lowest-latency strategy with epsilon-greedy"
```

---

### Task 12: token-aware strategy

**Files:**
- Create: `internal/apipool/strategy_token_aware.go`
- Test: `internal/apipool/strategy_token_aware_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/strategy_token_aware_test.go
package apipool

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func tpmDeps() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", TPM: 1000},
		{ID: "b", Provider: "openai", APIKey: "k-b", TPM: 1000},
	}
}

func TestTokenAware_PicksMostRemaining(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 800) // a: 200 left
	s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 100) // b: 900 left
	st := newTokenAware(s, map[string]any{"tokenThreshold": 50})
	st.rng = rand.New(rand.NewSource(1))
	assert.Equal(t, "b", st.Select(deps, &Context{}).ID)
}

func TestTokenAware_AllBelowThresholdFallsBack(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 990) // 10 left
	s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 980) // 20 left
	st := newTokenAware(s, map[string]any{"tokenThreshold": 100})
	st.rng = rand.New(rand.NewSource(1))
	got := st.Select(deps, &Context{})
	assert.NotNil(t, got, "falls back to shuffle among available")
}

func TestTokenAware_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newTokenAware(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestTokenAware -v`
Expected: FAIL — stub returns wrong selection

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/strategy_token_aware.go
package apipool

import "math/rand"

type tokenAware struct {
	state     *State
	threshold int
	rng       *rand.Rand
}

func newTokenAware(state *State, opts map[string]any) *tokenAware {
	return &tokenAware{
		state:     state,
		threshold: optInt(opts, "tokenThreshold", 1000),
		rng:       rand.New(rand.NewSource(rand.Int63())),
	}
}

func (s *tokenAware) Name() string { return "token-aware" }

func (s *tokenAware) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	best := avail[0]
	bestRem := s.state.RemainingTPM(best.StateKey(), best.TPM)
	anyAboveThreshold := bestRem >= s.threshold
	for _, d := range avail[1:] {
		rem := s.state.RemainingTPM(d.StateKey(), d.TPM)
		if rem >= s.threshold {
			anyAboveThreshold = true
		}
		if rem > bestRem {
			best, bestRem = d, rem
		}
	}
	if !anyAboveThreshold {
		return avail[s.rng.Intn(len(avail))] // degrade to shuffle
	}
	return best
}
```

> Replace the temporary `newTokenAware` stub from Task 10.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestTokenAware -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/strategy_token_aware.go internal/apipool/strategy_token_aware_test.go
git commit -m "feat(apipool): add token-aware strategy with shuffle fallback"
```

---

### Task 13: rate-limit-aware strategy

**Files:**
- Create: `internal/apipool/strategy_rate_limit_aware.go`
- Test: `internal/apipool/strategy_rate_limit_aware_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/strategy_rate_limit_aware_test.go
package apipool

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func rpmDeps() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", RPM: 10},
		{ID: "b", Provider: "openai", APIKey: "k-b", RPM: 10},
	}
}

func TestRateLimitAware_PicksMostRemaining(t *testing.T) {
	s := NewState(testCfg())
	deps := rpmDeps()
	for i := 0; i < 8; i++ { // a used 8 -> 2 left
		s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 1)
	}
	for i := 0; i < 2; i++ { // b used 2 -> 8 left
		s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 1)
	}
	st := newRateLimitAware(s, map[string]any{"rpmThreshold": 1})
	st.rng = rand.New(rand.NewSource(1))
	assert.Equal(t, "b", st.Select(deps, &Context{}).ID)
}

func TestRateLimitAware_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := rpmDeps()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newRateLimitAware(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestRateLimitAware -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/strategy_rate_limit_aware.go
package apipool

import "math/rand"

type rateLimitAware struct {
	state     *State
	threshold int
	rng       *rand.Rand
}

func newRateLimitAware(state *State, opts map[string]any) *rateLimitAware {
	return &rateLimitAware{
		state:     state,
		threshold: optInt(opts, "rpmThreshold", 10),
		rng:       rand.New(rand.NewSource(rand.Int63())),
	}
}

func (s *rateLimitAware) Name() string { return "rate-limit-aware" }

func (s *rateLimitAware) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	best := avail[0]
	bestRem := s.state.RemainingRPM(best.StateKey(), best.RPM)
	anyAbove := bestRem >= s.threshold
	for _, d := range avail[1:] {
		rem := s.state.RemainingRPM(d.StateKey(), d.RPM)
		if rem >= s.threshold {
			anyAbove = true
		}
		if rem > bestRem {
			best, bestRem = d, rem
		}
	}
	if !anyAbove {
		return avail[s.rng.Intn(len(avail))]
	}
	return best
}
```

> Replace the temporary `newRateLimitAware` stub from Task 10.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestRateLimitAware -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/strategy_rate_limit_aware.go internal/apipool/strategy_rate_limit_aware_test.go
git commit -m "feat(apipool): add rate-limit-aware strategy"
```

---

### Task 14: adaptive strategy (weighted scoring)

**Files:**
- Create: `internal/apipool/strategy_adaptive.go`
- Test: `internal/apipool/strategy_adaptive_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/strategy_adaptive_test.go
package apipool

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAdaptive_LowLatencyHighTokenWins(t *testing.T) {
	s := NewState(testCfg())
	deps := []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", TPM: 1000, RPM: 100},
		{ID: "b", Provider: "openai", APIKey: "k-b", TPM: 1000, RPM: 100},
	}
	// a: high latency, low token remaining
	s.RecordSuccess(deps[0].StateKey(), false, 2*time.Second, 950)
	// b: low latency, high token remaining
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 50)
	st := newAdaptive(s, nil)
	st.rng = rand.New(rand.NewSource(1))
	assert.Equal(t, "b", st.Select(deps, &Context{Stream: false}).ID)
}

func TestAdaptive_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newAdaptive(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}

func TestAdaptive_UnlimitedQuotaScoresOne(t *testing.T) {
	s := NewState(testCfg())
	deps := []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a"}, // TPM/RPM = 0 (unlimited)
	}
	st := newAdaptive(s, nil)
	got := st.Select(deps, &Context{})
	assert.Equal(t, "a", got.ID)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run TestAdaptive -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/strategy_adaptive.go
package apipool

import (
	"math"
	"math/rand"
)

const adaptiveLatencyBaselineSec = 1.0

type adaptive struct {
	state                                            *State
	wHealth, wToken, wRPM, wLatency                  float64
	rng                                              *rand.Rand
}

func newAdaptive(state *State, opts map[string]any) *adaptive {
	var weights map[string]any
	if opts != nil {
		if w, ok := opts["weights"].(map[string]any); ok {
			weights = w
		}
	}
	return &adaptive{
		state:    state,
		wHealth:  optFloat(weights, "health", 1.0),
		wToken:   optFloat(weights, "token", 0.5),
		wRPM:     optFloat(weights, "rpm", 0.3),
		wLatency: optFloat(weights, "latency", 0.2),
		rng:      rand.New(rand.NewSource(rand.Int63())),
	}
}

func (s *adaptive) Name() string { return "adaptive" }

func (s *adaptive) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	var best *Deployment
	bestScore := math.Inf(-1)
	ties := 0
	for _, d := range avail {
		score := s.score(d, ctx)
		switch {
		case score > bestScore:
			best, bestScore, ties = d, score, 1
		case score == bestScore:
			ties++
			if s.rng.Intn(ties) == 0 { // reservoir tie-break
				best = d
			}
		}
	}
	return best
}

func (s *adaptive) score(d *Deployment, ctx *Context) float64 {
	k := d.StateKey()
	healthScore := 1.0 // filtered to HEALTHY already; reserved for extension

	tokenScore := 1.0
	if d.TPM > 0 {
		tokenScore = math.Min(1.0, float64(s.state.RemainingTPM(k, d.TPM))/float64(d.TPM))
	}
	rpmScore := 1.0
	if d.RPM > 0 {
		rpmScore = math.Min(1.0, float64(s.state.RemainingRPM(k, d.RPM))/float64(d.RPM))
	}
	latencyScore := 1.0 / (1.0 + s.state.AvgLatency(k, ctx.Stream)/adaptiveLatencyBaselineSec)

	return s.wHealth*healthScore + s.wToken*tokenScore + s.wRPM*rpmScore + s.wLatency*latencyScore
}
```

> Replace the temporary `newAdaptive` stub from Task 10.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run TestAdaptive -v`
Expected: PASS. Then run the full strategy + factory suite: `go test ./internal/apipool/ -run 'SimpleShuffle|Factory|LowestLatency|TokenAware|RateLimitAware|Adaptive' -v`

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/strategy_adaptive.go internal/apipool/strategy_adaptive_test.go
git commit -m "feat(apipool): add adaptive weighted-scoring strategy"
```

---

### Task 15: ApiPoolManager — wiring deployments + state + strategy + adapters

**Files:**
- Create: `internal/apipool/pool_manager.go`
- Test: `internal/apipool/pool_manager_test.go`

> Depends on `base.ProviderPoolConfig`/`base.DeploymentConfig`/`base.RetryConfig` (Task 16). Implement Task 16's base structs first if going strictly in order — see Ordering note at end.

- [ ] **Step 1: Write the failing test**

```go
// internal/apipool/pool_manager_test.go
package apipool

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func poolCfg() *base.ProviderPoolConfig {
	return &base.ProviderPoolConfig{
		Strategy: "simple-shuffle",
		Cooldown: testCfg(),
		Retry:    &base.RetryConfig{MaxFailoverEndpoints: 3, MaxRetriesPerEndpoint: 2},
		Deployments: []base.DeploymentConfig{
			{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "k-a", TPM: 1000, RPM: 100},
			{ID: "b", Provider: "deepseek", APIBase: "https://api.deepseek.com", APIKey: "k-b"},
		},
	}
}

func TestNewApiPoolManager_OK(t *testing.T) {
	s := NewState(testCfg())
	p, err := NewApiPoolManager("gpt-4o-mini", poolCfg(), s, NewDefaultRegistry())
	assert.NoError(t, err)
	assert.Equal(t, 3, p.MaxFailoverEndpoints())
	assert.Len(t, p.deployments, 2)
}

func TestNewApiPoolManager_UnknownProviderFails(t *testing.T) {
	s := NewState(testCfg())
	cfg := poolCfg()
	cfg.Deployments[0].Provider = "no-such"
	_, err := NewApiPoolManager("m", cfg, s, NewDefaultRegistry())
	assert.Error(t, err)
}

func TestNewApiPoolManager_UnknownStrategyFails(t *testing.T) {
	s := NewState(testCfg())
	cfg := poolCfg()
	cfg.Strategy = "no-such"
	_, err := NewApiPoolManager("m", cfg, s, NewDefaultRegistry())
	assert.Error(t, err)
}

func TestApiPoolManager_SelectExceptSkipsTried(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	first := p.Select(&Context{})
	assert.NotNil(t, first)
	tried := map[StateKey]bool{first.StateKey(): true}
	second := p.SelectExcept(&Context{}, tried)
	assert.NotNil(t, second)
	assert.NotEqual(t, first.ID, second.ID)
}

func TestApiPoolManager_OnFailureEntersCooldown(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	dep := p.deployments[0]
	for i := 0; i < 3; i++ {
		p.OnFailure(dep, 500, nil)
	}
	assert.False(t, s.IsAvailable(dep.StateKey()))
}

func TestApiPoolManager_OnSuccessRecordsLatency(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	dep := p.deployments[0]
	p.OnSuccess(dep, 200*time.Millisecond, 100)
	assert.InDelta(t, 0.2, s.AvgLatency(dep.StateKey(), false), 1e-9)
	assert.Equal(t, 900, s.RemainingTPM(dep.StateKey(), dep.TPM))
}

func TestApiPoolManager_GetAdapter(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	a, err := p.GetAdapter("openai")
	assert.NoError(t, err)
	assert.NotNil(t, a)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apipool/ -run ApiPoolManager -v`
Expected: FAIL — undefined: NewApiPoolManager

- [ ] **Step 3: Write minimal implementation**

```go
// internal/apipool/pool_manager.go
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ApiPoolManager wires deployments, shared State, strategy and adapters.
 * Create: 2026-06-09
 */

package apipool

import (
	"time"

	"huawei.com/aigw/internal/base"
)

const (
	defaultMaxFailoverEndpoints = 3
	defaultMaxRetriesPerEndpoint = 2
)

// ApiPoolManager selects provider deployments for one model and records results
// into the shared State.
type ApiPoolManager struct {
	model       string
	deployments []*Deployment
	state       *State
	strategy    Strategy
	registry    *Registry

	maxFailover int
}

// NewApiPoolManager builds a pool manager from config, sharing the given State.
func NewApiPoolManager(model string, cfg *base.ProviderPoolConfig, state *State, registry *Registry) (*ApiPoolManager, error) {
	deps := make([]*Deployment, 0, len(cfg.Deployments))
	for _, dc := range cfg.Deployments {
		if _, err := registry.Get(dc.Provider); err != nil {
			return nil, err
		}
		verify := true
		if dc.VerifySSL != nil {
			verify = *dc.VerifySSL
		}
		deps = append(deps, &Deployment{
			ID:               dc.ID,
			ModelName:        model,
			APIKey:           dc.APIKey,
			APIBase:          dc.APIBase,
			Provider:         dc.Provider,
			TPM:              dc.TPM,
			RPM:              dc.RPM,
			Tags:             dc.Tags,
			Timeout:          time.Duration(dc.Timeout) * time.Second,
			VerifySSL:        verify,
			AuthHeaderName:   dc.AuthHeaderName,
			AuthHeaderPrefix: dc.AuthHeaderPrefix,
		})
	}

	strat, err := CreateStrategy(cfg.Strategy, state, cfg.StrategyOptions)
	if err != nil {
		return nil, err
	}

	maxFailover := defaultMaxFailoverEndpoints
	if cfg.Retry != nil && cfg.Retry.MaxFailoverEndpoints > 0 {
		maxFailover = cfg.Retry.MaxFailoverEndpoints
	}

	return &ApiPoolManager{
		model:       model,
		deployments: deps,
		state:       state,
		strategy:    strat,
		registry:    registry,
		maxFailover: maxFailover,
	}, nil
}

// MaxFailoverEndpoints returns the cap on cross-endpoint failover attempts.
func (p *ApiPoolManager) MaxFailoverEndpoints() int { return p.maxFailover }

// Select picks a deployment via the configured strategy, or nil if none available.
func (p *ApiPoolManager) Select(ctx *Context) *Deployment {
	return p.strategy.Select(p.deployments, ctx)
}

// SelectExcept picks a deployment skipping any StateKey already tried.
func (p *ApiPoolManager) SelectExcept(ctx *Context, exclude map[StateKey]bool) *Deployment {
	candidates := make([]*Deployment, 0, len(p.deployments))
	for _, d := range p.deployments {
		if !exclude[d.StateKey()] {
			candidates = append(candidates, d)
		}
	}
	return p.strategy.Select(candidates, ctx)
}

// GetAdapter returns the adapter for a provider.
func (p *ApiPoolManager) GetAdapter(provider string) (Adapter, error) {
	return p.registry.Get(provider)
}

// OnSuccess records a non-streaming success (total latency).
func (p *ApiPoolManager) OnSuccess(dep *Deployment, latency time.Duration, tokens int) {
	p.state.RecordSuccess(dep.StateKey(), false, latency, tokens)
}

// OnStreamSuccess records a streaming success completion (TTFT already recorded).
func (p *ApiPoolManager) OnStreamSuccess(dep *Deployment, tokens int) {
	p.state.RecordSuccess(dep.StateKey(), true, 0, tokens)
}

// OnFirstChunk records the streaming TTFT.
func (p *ApiPoolManager) OnFirstChunk(dep *Deployment, ttft time.Duration) {
	p.state.RecordSuccess(dep.StateKey(), true, ttft, 0)
}

// OnFailure classifies and records a failure into the shared State.
func (p *ApiPoolManager) OnFailure(dep *Deployment, statusCode int, err error) ErrorKind {
	kind := ClassifyError(statusCode, err)
	p.state.RecordFailure(dep.StateKey(), kind)
	return kind
}
```

> **Note on OnStreamSuccess/OnFirstChunk double-counting RPM:** both call `RecordSuccess` which increments the RPM bucket. For a streaming request this would double-count one request. Fix: `OnStreamSuccess` should NOT increment rpm again. Simplest approach — drop `OnStreamSuccess`'s state write entirely and only record tokens via a dedicated method. Implement `OnStreamSuccess` as:
> ```go
> func (p *ApiPoolManager) OnStreamSuccess(dep *Deployment, tokens int) {
> 	p.state.AddTokens(dep.StateKey(), tokens)
> }
> ```
> and add to `state.go`:
> ```go
> // AddTokens records token usage without touching latency/rpm (for stream completion).
> func (s *State) AddTokens(k StateKey, tokens int) {
> 	if tokens <= 0 { return }
> 	e := s.getOrCreate(k)
> 	e.mu.Lock(); defer e.mu.Unlock()
> 	e.totalTokens += int64(tokens)
> 	e.tokenBucket.add(time.Now().Unix(), tokens)
> }
> ```
> `OnFirstChunk` records TTFT + the single RPM increment (it is the request's success signal). Adjust the test `TestApiPoolManager_OnSuccess...` accordingly; add a `TestApiPoolManager_StreamSuccessNoDoubleRPM` test asserting RPM only increments once across OnFirstChunk + OnStreamSuccess.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apipool/ -run ApiPoolManager -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/apipool/pool_manager.go internal/apipool/state.go internal/apipool/pool_manager_test.go
git commit -m "feat(apipool): add ApiPoolManager wiring deployments/state/strategy/adapters"
```

---

### Task 16: base config types — Mode + ProviderPoolConfig + DeploymentConfig + CooldownConfig + RetryConfig

**Files:**
- Modify: `internal/base/aigw_type.go` (extend `GlobalSchedulerConfig`, add new types)
- Test: `internal/base/aigw_type_test.go`

> Note: `internal/base/aigw_type.go` ALREADY defines a `CircuitBreakerConfig` and a `ProxyConfig`. Do NOT collide names. Add `Mode`, `ProviderPool` to `GlobalSchedulerConfig` and the new types below.

- [ ] **Step 1: Write the failing test**

```go
// internal/base/aigw_type_test.go
package base

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGlobalSchedulerConfig_ProviderModeUnmarshal(t *testing.T) {
	data := `{
		"model": "gpt-4o-mini",
		"mode": "provider",
		"providerPool": {
			"strategy": "adaptive",
			"cooldown": {"failureThreshold": 3, "durationSec": 60, "rateLimitDurationSec": 90, "auth401FloorSec": 300},
			"retry": {"maxFailoverEndpoints": 3, "maxRetriesPerEndpoint": 2},
			"deployments": [
				{"id": "a", "provider": "openai", "apiBase": "https://api.openai.com", "apiKey": "sk-x", "tpm": 60000, "rpm": 500}
			]
		}
	}`
	var cfg GlobalSchedulerConfig
	assert.NoError(t, json.Unmarshal([]byte(data), &cfg))
	assert.Equal(t, "provider", cfg.Mode)
	assert.NotNil(t, cfg.ProviderPool)
	assert.Equal(t, "adaptive", cfg.ProviderPool.Strategy)
	assert.Len(t, cfg.ProviderPool.Deployments, 1)
	assert.Equal(t, 60000, cfg.ProviderPool.Deployments[0].TPM)
	assert.Equal(t, 300, cfg.ProviderPool.Cooldown.Auth401FloorSec)
}

func TestGlobalSchedulerConfig_ModeOptionalDefaultsEmpty(t *testing.T) {
	data := `{"model": "m", "blockSize": 128, "deployPolicy": "mixed"}`
	var cfg GlobalSchedulerConfig
	assert.NoError(t, json.Unmarshal([]byte(data), &cfg))
	assert.Equal(t, "", cfg.Mode, "missing mode unmarshals to empty; treated as instance downstream")
	assert.Nil(t, cfg.ProviderPool)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/base/ -run GlobalSchedulerConfig -v`
Expected: FAIL — GlobalSchedulerConfig has no field Mode/ProviderPool

- [ ] **Step 3: Write minimal implementation**

Add two fields to the existing `GlobalSchedulerConfig` struct (after `LoadBalancer`):

```go
	// Mode selects scheduling path: "instance" (default when empty) | "provider".
	Mode string `json:"mode,omitempty"`
	// ProviderPool holds config for mode=provider.
	ProviderPool *ProviderPoolConfig `json:"providerPool,omitempty"`
```

Add the new types (anywhere in the file, e.g. after `GlobalSchedulerConfig`):

```go
// ProviderPoolConfig configures a provider (SaaS API) pool for mode=provider.
type ProviderPoolConfig struct {
	Strategy        string             `json:"strategy"`
	StrategyOptions map[string]any     `json:"strategyOptions,omitempty"`
	Cooldown        *CooldownConfig    `json:"cooldown,omitempty"`
	Retry           *RetryConfig       `json:"retry,omitempty"`
	Deployments     []DeploymentConfig `json:"deployments"`
}

// CooldownConfig configures per-endpoint cooldown behavior.
type CooldownConfig struct {
	FailureThreshold     int `json:"failureThreshold"`
	DurationSec          int `json:"durationSec"`
	RateLimitDurationSec int `json:"rateLimitDurationSec"`
	Auth401FloorSec      int `json:"auth401FloorSec"`
}

// RetryConfig configures cross-endpoint failover and per-endpoint retry caps.
type RetryConfig struct {
	MaxFailoverEndpoints  int `json:"maxFailoverEndpoints"`
	MaxRetriesPerEndpoint int `json:"maxRetriesPerEndpoint"`
}

// DeploymentConfig is one provider endpoint in a ProviderPoolConfig.
type DeploymentConfig struct {
	ID               string   `json:"id,omitempty"`
	Provider         string   `json:"provider"`
	APIBase          string   `json:"apiBase"`
	APIKey           string   `json:"apiKey"`
	TPM              int      `json:"tpm,omitempty"`
	RPM              int      `json:"rpm,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Timeout          int      `json:"timeout,omitempty"`
	VerifySSL        *bool    `json:"verifySsl,omitempty"`
	AuthHeaderName   string   `json:"authHeaderName,omitempty"`
	AuthHeaderPrefix string   `json:"authHeaderPrefix,omitempty"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/base/ -run GlobalSchedulerConfig -v`
Expected: PASS. Also `go build ./...` to confirm nothing else broke.

- [ ] **Step 5: Commit**

```bash
git add internal/base/aigw_type.go internal/base/aigw_type_test.go
git commit -m "feat(base): add provider pool config types and optional mode field"
```

---

### Task 17: config validation — provider pool fail-fast

**Files:**
- Modify: `internal/core/config_manager.go` (add `validateProviderPool`, call from `validateGlobalSchedulersConfig`)
- Test: `internal/core/config_manager_provider_test.go`

> Read `internal/core/config_manager.go` first: `validateGlobalSchedulersConfig` (~line 349) and `validateLoadBalancer` (~line 222) show the existing validation style and error wrapping. Mirror it.

- [ ] **Step 1: Write the failing test**

```go
// internal/core/config_manager_provider_test.go
package core

import (
	"testing"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func validProviderGsc() *base.GlobalSchedulerConfig {
	return &base.GlobalSchedulerConfig{
		Model: "gpt-4o-mini",
		Mode:  "provider",
		ProviderPool: &base.ProviderPoolConfig{
			Strategy: "adaptive",
			Deployments: []base.DeploymentConfig{
				{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-x"},
			},
		},
	}
}

func TestValidateProviderPool_OK(t *testing.T) {
	assert.NoError(t, validateProviderPool(validProviderGsc()))
}

func TestValidateProviderPool_EmptyDeployments(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments = nil
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_NilPool(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool = nil
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_UnknownProvider(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments[0].Provider = "no-such"
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_CustomNeedsAuthHeader(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments[0].Provider = "custom"
	gsc.ProviderPool.Deployments[0].AuthHeaderName = ""
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_BadStrategy(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Strategy = "no-such"
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateMode_InvalidLiteral(t *testing.T) {
	gsc := &base.GlobalSchedulerConfig{Model: "m", Mode: "bogus"}
	assert.Error(t, validateModeField(gsc))
}

func TestValidateMode_EmptyIsInstance(t *testing.T) {
	gsc := &base.GlobalSchedulerConfig{Model: "m", Mode: ""}
	assert.NoError(t, validateModeField(gsc))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/core/ -run 'ValidateProviderPool|ValidateMode' -v`
Expected: FAIL — undefined: validateProviderPool, validateModeField

- [ ] **Step 3: Write minimal implementation**

Add to `config_manager.go` (uses `apipool.NewDefaultRegistry` and `apipool.CreateStrategy` to validate provider/strategy names without duplicating lists):

```go
import (
	// ... existing imports
	"huawei.com/aigw/internal/apipool"
)

// validateModeField validates the optional mode literal.
func validateModeField(gsc *base.GlobalSchedulerConfig) error {
	switch gsc.Mode {
	case "", "instance", "provider":
		return nil
	default:
		return fmt.Errorf("model %q: invalid mode %q (want instance|provider)", gsc.Model, gsc.Mode)
	}
}

// validateProviderPool validates a mode=provider scheduler config.
func validateProviderPool(gsc *base.GlobalSchedulerConfig) error {
	pp := gsc.ProviderPool
	if pp == nil {
		return fmt.Errorf("model %q: mode=provider requires providerPool", gsc.Model)
	}
	if len(pp.Deployments) == 0 {
		return fmt.Errorf("model %q: providerPool.deployments must not be empty", gsc.Model)
	}
	if _, err := apipool.CreateStrategy(pp.Strategy, apipool.NewState(&base.CooldownConfig{}), pp.StrategyOptions); err != nil {
		return fmt.Errorf("model %q: %w", gsc.Model, err)
	}
	registry := apipool.NewDefaultRegistry()
	for _, d := range pp.Deployments {
		if _, err := registry.Get(d.Provider); err != nil {
			return fmt.Errorf("model %q: %w", gsc.Model, err)
		}
		if d.Provider == "custom" && d.AuthHeaderName == "" {
			return fmt.Errorf("model %q deployment %q: custom provider requires authHeaderName", gsc.Model, d.ID)
		}
		if d.APIBase == "" || d.APIKey == "" {
			return fmt.Errorf("model %q deployment %q: apiBase and apiKey required", gsc.Model, d.ID)
		}
	}
	return nil
}
```

In `validateGlobalSchedulersConfig`, for each scheduler config call `validateModeField` first, then branch: if `Mode == "provider"` call `validateProviderPool` and skip the instance/loadBalancer checks; else run the existing instance validation. Add at the top of the per-config loop:

```go
		if err := validateModeField(&gsc); err != nil {
			return err
		}
		if gsc.Mode == "provider" {
			if err := validateProviderPool(&gsc); err != nil {
				return err
			}
			continue // skip instance-mode loadBalancer/blockSize validation
		}
		// ... existing instance-mode validation unchanged
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/core/ -run 'ValidateProviderPool|ValidateMode' -v`
Expected: PASS. Also `go test ./internal/core/ -v` to confirm existing config tests still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/core/config_manager.go internal/core/config_manager_provider_test.go
git commit -m "feat(core): validate provider pool config with fail-fast"
```

---

### Task 18: AigwManager — shared State, poolTable, GetModelMode/GetApiPool, Init dispatch, SdkMode fail-fast

**Files:**
- Modify: `internal/core/aigw_manager.go`
- Test: `internal/core/aigw_manager_provider_test.go`

> Read `internal/core/aigw_manager.go` first: the `AigwManager` struct (~line 50), `NewAigwManager` (~line 70), `Init` (~line 91 — loops `gsConfigs` calling `RegisterModel`), `RegisterModel` (~line 488), and the `runtimeMode base.RuntimeMode` field. `base.SdkMode` is the constant to check for fail-fast.

- [ ] **Step 1: Write the failing test**

```go
// internal/core/aigw_manager_provider_test.go
package core

import (
	"testing"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func providerConfig() *base.AigwConfig {
	return &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model: "gpt-4o-mini",
				Mode:  "provider",
				ProviderPool: &base.ProviderPoolConfig{
					Strategy: "simple-shuffle",
					Deployments: []base.DeploymentConfig{
						{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-x"},
					},
				},
			},
		},
	}
}

func TestAigwManager_GetModelMode(t *testing.T) {
	m, err := NewAigwManager(providerConfig())
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	defer m.Uninit()

	mode, err := m.GetModelMode("gpt-4o-mini")
	assert.NoError(t, err)
	assert.Equal(t, "provider", mode)

	_, err = m.GetModelMode("unknown-model")
	assert.Error(t, err)
}

func TestAigwManager_GetApiPool(t *testing.T) {
	m, _ := NewAigwManager(providerConfig())
	assert.NoError(t, m.Init())
	defer m.Uninit()
	assert.NotNil(t, m.GetApiPool("gpt-4o-mini"))
	assert.Nil(t, m.GetApiPool("unknown-model"))
}

func TestAigwManager_SdkModeProviderFailFast(t *testing.T) {
	m, err := NewAigwManager(providerConfig(), WithRuntimeMode(base.SdkMode))
	assert.NoError(t, err)
	assert.Error(t, m.Init(), "SdkMode + provider config must fail-fast")
}

func TestAigwManager_MissingModeTreatedAsInstance(t *testing.T) {
	// A scheduler config without mode must NOT be routed to apipool.
	cfg := &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{
			{Model: "instance-model", BlockSize: 128, DeployPolicy: "mixed",
				LoadBalancer: base.LoadBalancerConfig{Mixed: "roundRobin"}},
		},
	}
	m, _ := NewAigwManager(cfg)
	assert.NoError(t, m.Init())
	defer m.Uninit()
	mode, err := m.GetModelMode("instance-model")
	assert.NoError(t, err)
	assert.Equal(t, "instance", mode)
	assert.Nil(t, m.GetApiPool("instance-model"))
}
```

> **Check `WithRuntimeMode`**: confirm the option exists (grep `WithRuntimeMode` / `AIGWManagerOption` in `internal/core/`). If the existing option has a different name, use that name in the test. If instance-mode `Init` requires ZK/discovery that won't run in a unit test, gate the instance test with the existing test pattern (look at how other `aigw_manager` tests construct a manager — there may be a `SkipInstanceConnection` path). Adjust the instance test to match the established convention rather than forcing a real connection.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/core/ -run TestAigwManager_ -v`
Expected: FAIL — undefined: GetModelMode, GetApiPool; struct lacks poolTable/apiPoolState

- [ ] **Step 3: Write minimal implementation**

Add fields to `AigwManager` struct:

```go
	poolTable    map[string]*apipool.ApiPoolManager
	apiPoolState *apipool.State
	registry     *apipool.Registry
```

In `NewAigwManager`, initialize them:

```go
	manager := &AigwManager{
		config:       config,
		gsTable:      make(map[string]*gs.GlobalSchedulerManager),
		tkTable:      make(map[string]tokenizers.Tokenizer),
		poolTable:    make(map[string]*apipool.ApiPoolManager),
		registry:     apipool.NewDefaultRegistry(),
	}
```

In `Init`, replace the `for _, config := range gsConfigs { RegisterModel }` loop with mode dispatch. First create the shared State (use the first provider pool's cooldown config, or a default; cooldown config is per-pool in spec but State holds one cfg — use a merged/default cfg, documented below):

```go
	// Build shared provider-pool State. Cooldown config is taken from the first
	// provider pool encountered; all pools share one State (cross-pool quota).
	manager.apiPoolState = apipool.NewState(defaultCooldownConfig())

	for i := range gsConfigs {
		gsc := gsConfigs[i]
		mode := gsc.Mode
		if mode == "" {
			mode = "instance"
		}
		switch mode {
		case "provider":
			if manager.runtimeMode == base.SdkMode {
				manager.Uninit()
				return fmt.Errorf("SdkMode does not support provider mode (model %q); use IntelliRouter SDK", gsc.Model)
			}
			if gsc.ProviderPool != nil && gsc.ProviderPool.Cooldown != nil {
				manager.apiPoolState.SetCooldownConfig(gsc.ProviderPool.Cooldown)
			}
			pool, err := apipool.NewApiPoolManager(gsc.Model, gsc.ProviderPool, manager.apiPoolState, manager.registry)
			if err != nil {
				manager.Uninit()
				return err
			}
			manager.poolTable[gsc.Model] = pool
		default:
			if err := manager.RegisterModel(&gsc); err != nil {
				log.Error().Msgf("init aigw error: %v", err)
				manager.Uninit()
				return err
			}
		}
	}
```

Add helper + accessors + State.SetCooldownConfig:

```go
// defaultCooldownConfig returns sane defaults used until a provider pool overrides it.
func defaultCooldownConfig() *base.CooldownConfig {
	return &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300}
}

// GetModelMode returns "instance" or "provider" for a configured model.
func (manager *AigwManager) GetModelMode(model string) (string, error) {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	if _, ok := manager.poolTable[model]; ok {
		return "provider", nil
	}
	if _, ok := manager.gsTable[model]; ok {
		return "instance", nil
	}
	return "", fmt.Errorf("unknown model %q", model)
}

// GetApiPool returns the provider pool for a model, or nil if not a provider model.
func (manager *AigwManager) GetApiPool(model string) *apipool.ApiPoolManager {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	return manager.poolTable[model]
}
```

Add to `internal/apipool/state.go`:

```go
// SetCooldownConfig updates the cooldown config (used at init when a pool config is found).
func (s *State) SetCooldownConfig(cfg *base.CooldownConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}
```

> **Cooldown-config-per-pool caveat:** the spec allows each provider pool its own cooldown config, but State holds one shared `cfg` (because State is shared cross-pool). For the first version, the LAST provider pool's cooldown config wins for the whole shared State. Document this in the config example (Task 20). If divergent per-pool cooldowns become a requirement later, move `cfg` into `stateEntry` — out of scope now (YAGNI).

Add the `apipool` import to `aigw_manager.go`. In `Uninit`, no pool teardown is needed (pools hold no goroutines/connections), but clear `poolTable` for symmetry if desired.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/core/ -run TestAigwManager_ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/core/aigw_manager.go internal/apipool/state.go internal/core/aigw_manager_provider_test.go
git commit -m "feat(core): dispatch by mode, shared provider State, SdkMode fail-fast"
```

---

### Task 19: proxy.go — add FullURL field

**Files:**
- Modify: `internal/proxy/proxy.go` (`ForwardRequest` struct + URL build)
- Test: `internal/proxy/proxy_fullurl_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/proxy/proxy_fullurl_test.go
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardRequest_UsesFullURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pm := NewProxyManager(context.Background(), nil)
	defer pm.Stop()

	res, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:  "POST",
		FullURL: srv.URL + "/v1/chat/completions",
		Headers: http.Header{},
		Body:    []byte(`{"model":"x"}`),
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "/v1/chat/completions", gotPath)
}

func TestForwardRequest_FallsBackToTargetURLPlusRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pm := NewProxyManager(context.Background(), nil)
	defer pm.Stop()

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "POST",
		TargetURL: srv.URL,
		Route:     "/v1/chat/completions",
		Headers:   http.Header{},
		Body:      []byte(`{}`),
	})
	assert.NoError(t, err)
	assert.Equal(t, "/v1/chat/completions", gotPath)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestForwardRequest_ -v`
Expected: FAIL — ForwardRequest has no field FullURL

- [ ] **Step 3: Write minimal implementation**

Add `FullURL` to the `ForwardRequest` struct (after `Route`):

```go
	FullURL   string            // When non-empty, used verbatim instead of TargetURL+Route
```

Change the URL build (currently `targetURL := req.TargetURL + req.Route` at ~line 120):

```go
	// 1. Build complete URL (FullURL wins when set)
	targetURL := req.FullURL
	if targetURL == "" {
		targetURL = req.TargetURL + req.Route
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestForwardRequest_ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/proxy_fullurl_test.go
git commit -m "feat(proxy): support FullURL for provider pool forwarding"
```

---

### Task 20: http_server — split forwardChatCompletions + forwardToProvider + get-suggestion guard

**Files:**
- Modify: `internal/server/http_server.go`
- Test: `internal/server/http_server_provider_test.go`

> Read `internal/server/http_server.go:367-507` (`forwardChatCompletions`) and the SSE loop. The split keeps the existing logic in `forwardToInstance` verbatim.

- [ ] **Step 1: Refactor — extract `forwardToInstance` (no behavior change)**

Move the body of `forwardChatCompletions` AFTER request parsing (from "Build prompt" through the SSE/non-stream response handling) into a new method:

```go
func (s *HttpServer) forwardToInstance(w http.ResponseWriter, r *http.Request, model string, stream bool, messages []chatMessage, body []byte) {
	// ... exact existing logic (GetSuggestion -> proxy.ForwardRequest -> SSE/non-stream) ...
}
```

Then change `forwardChatCompletions` to parse + dispatch:

```go
func (s *HttpServer) forwardChatCompletions(w http.ResponseWriter, r *http.Request) {
	// ... existing method/body/JSON parse producing req.Model, req.Stream, req.Messages, body ...

	mode, err := s.manager.GetModelMode(req.Model)
	if err != nil {
		http.Error(w, "unknown model", http.StatusNotFound)
		return
	}
	switch mode {
	case "provider":
		s.forwardToProvider(w, r, req.Model, req.Stream, body)
	default:
		s.forwardToInstance(w, r, req.Model, req.Stream, req.Messages, body)
	}
}
```

Run `go build ./... && go test ./internal/server/ -v` to confirm the refactor is behavior-preserving before adding provider logic. Commit this refactor separately:

```bash
git add internal/server/http_server.go
git commit -m "refactor(server): extract forwardToInstance from forwardChatCompletions"
```

- [ ] **Step 2: Write the failing test for forwardToProvider**

```go
// internal/server/http_server_provider_test.go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/proxy"

	"github.com/stretchr/testify/assert"
)

// buildProviderServer wires a real AigwManager (provider mode) pointing at a mock upstream.
func buildProviderServer(t *testing.T, upstreamURL string) *HttpServer {
	cfg := &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{{
			Model: "gpt-4o-mini", Mode: "provider",
			ProviderPool: &base.ProviderPoolConfig{
				Strategy: "simple-shuffle",
				Cooldown: &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300},
				Retry:    &base.RetryConfig{MaxFailoverEndpoints: 3, MaxRetriesPerEndpoint: 0},
				Deployments: []base.DeploymentConfig{
					{ID: "a", Provider: "openai", APIBase: upstreamURL, APIKey: "sk-test"},
				},
			},
		}},
	}
	m, err := core.NewAigwManager(cfg)
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	t.Cleanup(m.Uninit)
	return NewHttpServerForTest(m, proxy.NewProxyManager(nil, nil)) // see note below
}

func TestForwardToProvider_NonStreamSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[],"usage":{"total_tokens":42}}`))
	}))
	defer upstream.Close()

	s := buildProviderServer(t, upstream.URL)
	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "messages": []any{}})
	req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	s.forwardChatCompletions(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "total_tokens")
}

func TestForwardToProvider_AllCooldown502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	s := buildProviderServer(t, upstream.URL)

	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "messages": []any{}})
	for i := 0; i < 3; i++ { // drive the single deployment into cooldown
		req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		s.forwardChatCompletions(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}
```

> **Test wiring note:** check how `HttpServer` is constructed in existing tests (look for an existing `http_server_test.go` and the real constructor name/signature — it may be `NewHttpServer(...)` taking the manager + proxy + config). Use the real constructor; `NewHttpServerForTest` above is a placeholder — replace with the actual one. If no test-friendly constructor exists, add a minimal one or set the unexported fields the same way existing tests do. Confirm the route path constant for chat completions matches the real router registration.

- [ ] **Step 3: Implement `forwardToProvider`**

```go
func (s *HttpServer) forwardToProvider(w http.ResponseWriter, r *http.Request, model string, stream bool, body []byte) {
	pool := s.manager.GetApiPool(model)
	if pool == nil {
		http.Error(w, "unknown model", http.StatusNotFound)
		return
	}
	pctx := &apipool.Context{Model: model, Stream: stream}
	triedKeys := map[apipool.StateKey]bool{}
	var lastStatus int

	for attempt := 0; attempt < pool.MaxFailoverEndpoints(); attempt++ {
		if r.Context().Err() != nil {
			return // client gone; don't waste quota
		}
		dep := pool.SelectExcept(pctx, triedKeys)
		if dep == nil {
			break
		}
		triedKeys[dep.StateKey()] = true

		adapter, err := pool.GetAdapter(dep.Provider)
		if err != nil {
			continue
		}
		headers := r.Header.Clone()
		adapter.InjectAuth(headers, dep)

		forwardReq := &proxy.ForwardRequest{
			Method:  "POST",
			FullURL: adapter.BuildURL(dep, "/v1/chat/completions", stream),
			Headers: headers,
			Body:    body,
			Stream:  stream,
		}

		start := time.Now()
		result, err := s.proxyMgr.ForwardRequest(r.Context(), forwardReq)
		if err != nil {
			// network or 5xx collapsed by proxy
			kind := pool.OnFailure(dep, 0, err)
			if kind == apipool.ErrCanceled {
				return
			}
			continue
		}
		if result.StatusCode >= 400 {
			lastStatus = result.StatusCode
			kind := pool.OnFailure(dep, result.StatusCode, nil)
			if kind == apipool.ErrClient4xx { // 400/422 — passthrough, no failover
				writeProviderNonStream(w, result)
				return
			}
			continue // 429/401/403/404/5xx -> failover
		}

		// 2xx
		if stream && result.StreamReader != nil {
			s.streamProviderResponse(w, pool, dep, result, start)
			return
		}
		pool.OnSuccess(dep, time.Since(start), parseUsageTokens(result.Body))
		writeProviderNonStream(w, result)
		return
	}

	if lastStatus != 0 {
		http.Error(w, "all providers failed", lastStatus)
		return
	}
	http.Error(w, "all providers failed", http.StatusBadGateway)
}

// streamProviderResponse writes the SSE stream, recording TTFT on the first event.
func (s *HttpServer) streamProviderResponse(w http.ResponseWriter, pool *apipool.ApiPoolManager, dep *apipool.Deployment, result *proxy.ForwardResult, start time.Time) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	firstChunk := false
	tokens := 0
	for {
		event, err := result.StreamReader.ReadEvent()
		if err == io.EOF {
			pool.OnStreamSuccess(dep, tokens)
			return
		}
		if err != nil {
			if !firstChunk {
				// no bytes sent yet, but header already written; cannot failover -> end
				pool.OnFailure(dep, 0, err)
			}
			return
		}
		if !firstChunk {
			firstChunk = true
			pool.OnFirstChunk(dep, time.Since(start))
		}
		if event.Event != "" {
			fmt.Fprintf(w, "event: %s\n", event.Event)
		}
		fmt.Fprintf(w, "data: %s\n\n", event.Data)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if t := parseUsageTokens([]byte(event.Data)); t > 0 {
			tokens = t // last usage chunk wins (stream_options include_usage)
		}
	}
}

func writeProviderNonStream(w http.ResponseWriter, result *proxy.ForwardResult) {
	for k, v := range result.Headers {
		if k == "Transfer-Encoding" || k == "Connection" {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

// parseUsageTokens extracts usage.total_tokens from an OpenAI-style JSON body; 0 if absent.
func parseUsageTokens(body []byte) int {
	var parsed struct {
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0
	}
	return parsed.Usage.TotalTokens
}
```

Add the get-suggestion guard in the get-suggestion handler (the handler calling `s.manager.GetSuggestion` ~line 347): before scheduling, if `mode, _ := s.manager.GetModelMode(req.Model); mode == "provider"` return `http.Error(w, "model is in provider mode, must use /chat/completions endpoint", http.StatusBadRequest)`.

Add imports: `"time"`, `"huawei.com/aigw/internal/apipool"` (confirm `io`, `encoding/json`, `fmt` already imported).

> **`StreamReader.ReadEvent` event struct:** confirm the field names (`event.Event`, `event.Data`) match `internal/proxy` StreamReader — the existing SSE loop at line 474-491 already uses them, so reuse verbatim.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/server/ -run TestForwardToProvider -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/server/http_server.go internal/server/http_server_provider_test.go
git commit -m "feat(server): add provider-pool forwarding path with failover and TTFT"
```

---

### Task 21: configs/aigw.json — example provider pool config

**Files:**
- Modify: `configs/aigw.json` (add a commented provider example alongside existing instance config)

> Read `configs/aigw.json` first to match its structure and indentation. JSON has no comments, so add a real (disabled-by-placeholder) provider entry in `globalSchedulers` with a clear fake apiKey, and document the `mode` field + cooldown-config-shared caveat (Task 18) in the spec rather than the JSON.

- [ ] **Step 1: Add a provider entry to `globalSchedulers`**

```json
{
  "model": "gpt-4o-mini",
  "mode": "provider",
  "providerPool": {
    "strategy": "adaptive",
    "strategyOptions": {
      "tokenThreshold": 1000,
      "rpmThreshold": 10,
      "explorationRatio": 0.1,
      "weights": { "health": 1.0, "token": 0.5, "rpm": 0.3, "latency": 0.2 }
    },
    "cooldown": { "failureThreshold": 3, "durationSec": 60, "rateLimitDurationSec": 90, "auth401FloorSec": 300 },
    "retry": { "maxFailoverEndpoints": 3, "maxRetriesPerEndpoint": 2 },
    "deployments": [
      { "id": "openai-primary", "provider": "openai", "apiBase": "https://api.openai.com", "apiKey": "REPLACE_ME", "tpm": 60000, "rpm": 500 },
      { "id": "deepseek-backup", "provider": "deepseek", "apiBase": "https://api.deepseek.com", "apiKey": "REPLACE_ME", "tpm": 100000, "rpm": 1000 }
    ]
  }
}
```

- [ ] **Step 2: Validate it loads**

Run: `go test ./internal/core/ -run Config -v` (ensure config load/validate passes if any test reads the example), and `./output/aigw --config=configs/aigw.json` smoke (expect it to start or fail only on REPLACE_ME apiKey reachability, not on parse/validate).

- [ ] **Step 3: Commit**

```bash
git add configs/aigw.json
git commit -m "docs(config): add provider pool example to aigw.json"
```

---

### Task 22: Integration tests (httptest-backed)

**Files:**
- Test: `internal/server/http_server_provider_integration_test.go`

Cover the v2-critical scenarios from spec §9 not already covered in Task 20. Each uses `httptest.Server` upstreams and the real `AigwManager`+`HttpServer` (reuse `buildProviderServer` helper, extended to accept multiple deployments).

- [ ] **Step 1: Write the tests**

```go
// internal/server/http_server_provider_integration_test.go
package server
// imports as in Task 20 test, plus "sync/atomic", "time"

// 1. 5xx triggers cooldown then recovery (force expiry via short durationSec).
// 2. Two-endpoint failover: primary 503, backup 200 -> client gets 200 from backup.
// 3. 401 exponential backoff: assert deployment cooldown grows 5/10/30 min across rounds
//    (use State accessor via manager; or assert via repeated availability windows).
// 4. Streaming first-chunk-before failover: primary errors before any chunk, backup streams.
// 5. Streaming mid-stream failure: client gets partial + EOF, no failover.
// 6. Cross-pool shared quota: two models (gpt-4o-mini, gpt-4o) configured with the SAME
//    provider+apiKey; exhaust TPM via one model's calls; assert the other sees reduced
//    RemainingTPM (inspect via a test accessor on the shared State or via behavior).
// 7. ctx cancel: cancel r.Context() mid-loop -> forwardToProvider returns without writing 502.
// 8. 100-goroutine concurrency against a mock upstream; assert no race (-race) and
//    consistent success count.
```

> Each scenario is a `t.Run` subtest. For scenarios needing to read shared State (3, 6), add a small exported test accessor on `core.AigwManager` (e.g. `ApiPoolStateForTest() *apipool.State`) guarded by a `_test.go`-only file, OR assert purely via observable HTTP behavior (preferred — keeps production API clean). Use behavior-based assertions where possible; only add a test accessor if behavior alone can't distinguish the case.

- [ ] **Step 2: Run with race detector**

Run: `go test ./internal/server/ -run Provider -race -v`
Expected: PASS, no races

- [ ] **Step 3: Commit**

```bash
git add internal/server/http_server_provider_integration_test.go
git commit -m "test(server): integration tests for provider pool failover/cooldown/quota"
```

---

### Task 23: E2E test (mock provider server)

**Files:**
- Create: `test/e2e/mock_e2e_provider_server.py`
- Create: `test/e2e/test_e2e_provider.py`

> Read the existing `test/e2e/` layout first (mock server + test conventions, how aigw is launched). Mirror the existing mock server style.

- [ ] **Step 1: Mock provider server**

`mock_e2e_provider_server.py`: a Flask/http.server app exposing `POST /v1/chat/completions` that:
- returns a normal OpenAI-style JSON (with `usage.total_tokens`) by default,
- supports query/header-driven fault injection: `?inject=500|429|401`, and an SSE streaming mode when request body has `"stream": true` (emit a few `data:` chunks then `data: [DONE]`).

- [ ] **Step 2: E2E test**

`test_e2e_provider.py`:
- start two mock provider servers + aigw with a provider-mode config pointing at them,
- assert: non-stream success, streaming response, primary-fault failover to backup, cooldown after repeated 5xx, and a small concurrency burst.

- [ ] **Step 3: Run**

Run the existing e2e runner (match how `test_e2e_*.py` are executed in the repo; e.g. `pytest test/e2e/test_e2e_provider.py`).
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add test/e2e/mock_e2e_provider_server.py test/e2e/test_e2e_provider.py
git commit -m "test(e2e): add provider pool end-to-end tests with mock servers"
```

---

## Ordering Note (important for strict sequential execution)

Several apipool tasks reference `base.CooldownConfig`/`base.ProviderPoolConfig`/`base.RetryConfig` (Task 16) and `apipool` is imported by `internal/core` (Task 17/18). To keep each task green:

1. **Do Task 16 (base types) BEFORE Task 3** — `state.go` imports `base.CooldownConfig`. Either reorder Task 16 to right after Task 2, or temporarily define a local `CooldownConfig` in apipool and swap to `base.CooldownConfig` at Task 16. **Recommended: move Task 16 to execute right after Task 2.**
2. Strategy factory (Task 10) references constructors from Tasks 11-14 — use temporary stubs returning `simpleShuffle` until each real constructor lands, as noted in Task 10.
3. Tasks 17/18 (core) require all of apipool (Tasks 1-16) complete.
4. Task 20 requires Tasks 18 + 19.

A clean execution order: 1, 2, 16, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23.

## Definition of Done

- `go build ./...` clean
- `go test ./internal/apipool/... -race -cover` green
- `go test ./internal/core/... ./internal/proxy/... ./internal/server/... -v` green
- `./build.sh --ut` green
- E2E (`test/e2e/test_e2e_provider.py`) green
- Existing instance-mode behavior unchanged (no edits to `internal/gs/`; instance tests still pass)
- No plaintext API key in logs or State (only `KeyFingerprint`)
