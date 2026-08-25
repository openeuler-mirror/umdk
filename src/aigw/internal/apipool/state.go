/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Shared runtime State (quota/cooldown/latency) for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"math"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
)

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
	if e.consecutiveFails >= s.cfg.FailureThreshold {
		e.status = StatusCooldown
		if kind == ErrAuth {
			e.auth401Attempts++
		}
		e.cooldownUntil = time.Now().Unix() + int64(durationFor(kind, e.auth401Attempts, s.cfg).Seconds())
	}
}

// AddTokens records token usage without touching latency/rpm (for stream completion).
func (s *State) AddTokens(k StateKey, tokens int) {
	if tokens <= 0 {
		return
	}
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.totalTokens += int64(tokens)
	e.tokenBucket.add(time.Now().Unix(), tokens)
}

// SetCooldownConfig updates the cooldown config (used at init when a pool config is found).
func (s *State) SetCooldownConfig(cfg *base.CooldownConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// forceCooldownUntil is a test helper to override the cooldown deadline.
func (s *State) forceCooldownUntil(k StateKey, ts int64) {
	e := s.getOrCreate(k)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cooldownUntil = ts
}
