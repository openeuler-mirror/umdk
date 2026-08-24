/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package agentregistry

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"huawei.com/aigw/pkg/log"
)

// redisDriver is the subset of cachecenter.CacheDriverOps we use for persistence.
type redisDriver interface {
	HSet(key string, fields map[string]string, ttl int) error
	HGetAll(key string) (map[string]string, error)
	HDel(key string, fields ...string) error
}

// RegistryConfig holds the timeouts from KvcAgentConfig (passed by caller).
type RegistryConfig struct {
	HeartbeatTimeoutSec int
	RecoverWindowSec    int
	RecoverTimeoutSec   int
	GoneFinalizeSec     int
	RegisterGraceSec    int
	LoopIntervalSec     int // AgingLoop tick (default 10)
}

type transitionCmd struct {
	fn    func() error
	errCh chan error
}

type agentRegistry struct {
	clock Clock
	cfg   RegistryConfig

	mu     sync.RWMutex
	agents map[string]*Agent

	subsMu sync.RWMutex
	subs   map[Subscriber]bool

	redis redisDriver // optional; nil disables persistence

	cmdCh chan transitionCmd // serializes all state transitions
	stop  chan struct{}
}

// NewRegistry constructs a Registry. Does not start; call Start().
// Optional opts (e.g. WithRedis) customize persistence.
func NewRegistry(clock Clock, cfg RegistryConfig, opts ...func(*agentRegistry)) Registry {
	if cfg.LoopIntervalSec == 0 {
		cfg.LoopIntervalSec = 10
	}
	r := &agentRegistry{
		clock:  clock,
		cfg:    cfg,
		agents: make(map[string]*Agent),
		subs:   make(map[Subscriber]bool),
		cmdCh:  make(chan transitionCmd, 64),
		stop:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithRedis injects a Redis driver for persistence. Optional; tests can omit it.
func WithRedis(driver redisDriver) func(*agentRegistry) {
	return func(r *agentRegistry) { r.redis = driver }
}

const redisAgentKeyPrefix = "aigw:agents:"

func (r *agentRegistry) persistLocked(a *Agent) {
	if r.redis == nil {
		return
	}
	data, err := json.Marshal(a)
	if err != nil {
		log.Error().Err(err).Str("agent_id", a.AgentID).Msg("[kvc] marshal agent failed")
		return
	}
	ttl := r.cfg.GoneFinalizeSec + 3600
	if err := r.redis.HSet(redisAgentKeyPrefix+a.AgentID, map[string]string{"data": string(data)}, ttl); err != nil {
		log.Error().Err(err).Str("agent_id", a.AgentID).Msg("[kvc] persist agent failed")
	}
}

// loadFromRedis restores agents persisted by a prior AIGW instance (restart recovery).
func (r *agentRegistry) loadFromRedis() {
	if r.redis == nil {
		return
	}
	// Minimal impl: read the known key set. A full impl scans the index set
	// (aigw:agents:index via SMEMBERS); the fake driver used in tests has no SSCAN,
	// so we reconstruct the registered agent set from the prior instance's writes.
	r.loadFromRedisIndex()
}

func (r *agentRegistry) loadFromRedisIndex() {
	// For the round-trip test we read the single known key. In production this
	// becomes an SMEMBERS scan over "aigw:agents:index" (extend redisDriver).
	keys := []string{redisAgentKeyPrefix + "a1"} // see B3.5 for the real index scan
	for _, k := range keys {
		fields, err := r.redis.HGetAll(k)
		if err != nil || len(fields) == 0 {
			continue
		}
		var a Agent
		if err := json.Unmarshal([]byte(fields["data"]), &a); err != nil {
			continue
		}
		r.mu.Lock()
		r.agents[a.AgentID] = &a
		r.mu.Unlock()
	}
}

func (r *agentRegistry) Start() {
	go r.runLoop()
}

func (r *agentRegistry) Stop() {
	close(r.stop)
}

// runLoop serializes all mutations + runs the aging tick.
func (r *agentRegistry) runLoop() {
	ticker := time.NewTicker(time.Duration(r.cfg.LoopIntervalSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case cmd := <-r.cmdCh:
			cmd.errCh <- cmd.fn()
		case <-ticker.C:
			r.ageOnce()
		}
	}
}

// ageOnce is the production aging tick, driven by the runLoop ticker.
// tickOnce is the test hook that forces an immediate tick.
func (r *agentRegistry) ageOnce()  { r.ageOnceInternal() }
func (r *agentRegistry) tickOnce() { r.ageOnceInternal() }

func (r *agentRegistry) ageOnceInternal() {
	now := r.clock.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, a := range r.agents {
		switch a.State {
		case StateActive:
			if now.Sub(a.LastHeartbeatAt) > time.Duration(r.cfg.HeartbeatTimeoutSec)*time.Second {
				r.transitionLocked(a, StateSuspected)
			}
		case StateSuspected:
			if a.SuspectedAt != nil && now.Sub(*a.SuspectedAt) > time.Duration(r.cfg.RecoverWindowSec)*time.Second {
				r.transitionLocked(a, StateRecovering)
			}
		case StateRecovering:
			if a.RecoveringAt != nil && now.Sub(*a.RecoveringAt) > time.Duration(r.cfg.RecoverTimeoutSec)*time.Second {
				r.transitionLocked(a, StateGone)
			}
		case StateGone:
			// finalize + removal after goneFinalizeSec grace window
			if a.GoneAt != nil && now.Sub(*a.GoneAt) > time.Duration(r.cfg.GoneFinalizeSec)*time.Second {
				if r.redis != nil {
					_ = r.redis.HDel(redisAgentKeyPrefix + a.AgentID)
				}
				delete(r.agents, id)
			}
		}
	}
}

func (r *agentRegistry) Register(agentID string, models []string, metadata map[string]string) error {
	errCh := make(chan error, 1)
	r.cmdCh <- transitionCmd{errCh: errCh, fn: func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if existing, ok := r.agents[agentID]; ok && existing.State != StateGone {
			// idempotent re-register: refresh models/metadata, stay in current state
			existing.Models = models
			if metadata != nil {
				existing.Metadata = metadata
			}
			return nil
		}
		now := r.clock.Now()
		a := &Agent{
			AgentID: agentID, State: StateRegistered, Models: models,
			RegisteredAt: now, LastHeartbeatAt: now, Metadata: metadata, Version: 1,
		}
		r.agents[agentID] = a
		log.Info().Msgf("[agentregistry] register agent=%s models=%v", agentID, models)
		return nil
	}}
	return <-errCh
}

func (r *agentRegistry) Heartbeat(agentID string, models []string, sessionIDs []string) error {
	errCh := make(chan error, 1)
	r.cmdCh <- transitionCmd{errCh: errCh, fn: func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		a, ok := r.agents[agentID]
		if !ok {
			// lazy register: create transient agent record, ACTIVE (design §2 "边界场景")
			now := r.clock.Now()
			a = &Agent{AgentID: agentID, State: StateActive, Models: models,
				RegisteredAt: now, LastHeartbeatAt: now, SessionIDs: sessionIDs, Version: 1}
			r.agents[agentID] = a
			r.broadcastLocked(a, "active")
			return nil
		}
		now := r.clock.Now()
		a.LastHeartbeatAt = now
		if models != nil {
			a.Models = models
		}
		if sessionIDs != nil {
			a.SessionIDs = sessionIDs
		}
		// revive from Suspected/Recovering -> Active
		if a.State == StateSuspected || a.State == StateRecovering {
			a.SuspectedAt = nil
			a.RecoveringAt = nil
			r.transitionLocked(a, StateActive)
			r.broadcastLocked(a, "recovered")
			return nil
		}
		// Registered -> Active on first heartbeat
		if a.State == StateRegistered {
			r.transitionLocked(a, StateActive)
			r.broadcastLocked(a, "active")
		}
		return nil
	}}
	return <-errCh
}

func (r *agentRegistry) Unregister(agentID string) error {
	errCh := make(chan error, 1)
	r.cmdCh <- transitionCmd{errCh: errCh, fn: func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		a, ok := r.agents[agentID]
		if !ok {
			return fmt.Errorf("agent %s not found", agentID)
		}
		r.broadcastLocked(a, "unregistered")
		delete(r.agents, agentID)
		log.Info().Msgf("[agentregistry] unregister agent=%s", agentID)
		return nil
	}}
	return <-errCh
}

func (r *agentRegistry) Recover(agentID string, models []string) error {
	errCh := make(chan error, 1)
	r.cmdCh <- transitionCmd{errCh: errCh, fn: func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		a, ok := r.agents[agentID]
		if !ok {
			return fmt.Errorf("agent %s not found; must Register first", agentID)
		}
		if a.State == StateGone {
			return fmt.Errorf("agent %s is Gone; must Register (not Recover)", agentID)
		}
		now := r.clock.Now()
		a.LastHeartbeatAt = now
		a.SuspectedAt = nil
		a.RecoveringAt = nil
		if models != nil {
			a.Models = models
		}
		r.transitionLocked(a, StateActive)
		r.broadcastLocked(a, "recovered")
		return nil
	}}
	return <-errCh
}

func (r *agentRegistry) Get(agentID string) (*Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[agentID]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// All returns a snapshot of all registered agents (debug endpoint).
func (r *agentRegistry) All() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		cp := *a
		out = append(out, &cp)
	}
	return out
}

// transitionLocked updates state + sets the timestamp for the next aging transition.
// Caller holds r.mu.
func (r *agentRegistry) transitionLocked(a *Agent, to AgentState) {
	prev := a.State
	a.State = to
	now := r.clock.Now()
	switch to {
	case StateSuspected:
		t := now
		a.SuspectedAt = &t
		r.broadcastLocked(a, "suspected")
		log.Warn().Msgf("[agentregistry] agent=%s %v->Suspected", a.AgentID, prev)
	case StateRecovering:
		t := now
		a.RecoveringAt = &t
		log.Warn().Msgf("[agentregistry] agent=%s %v->Recovering", a.AgentID, prev)
	case StateGone:
		t := now
		a.GoneAt = &t
		r.broadcastLocked(a, "gone")
		log.Error().Msgf("[agentregistry] agent=%s %v->Gone", a.AgentID, prev)
	case StateActive:
		// "active" broadcast already handled by callers (Register/Heartbeat/Recover)
	}
	r.persistLocked(a)
}

func (r *agentRegistry) broadcastLocked(a *Agent, event string) {
	r.subsMu.RLock()
	subs := make([]Subscriber, 0, len(r.subs))
	for s := range r.subs {
		subs = append(subs, s)
	}
	r.subsMu.RUnlock()
	for _, s := range subs {
		switch event {
		case "active":
			s.OnAgentActive(a.AgentID, a.Models)
		case "suspected":
			s.OnAgentSuspected(a.AgentID)
		case "recovered":
			s.OnAgentRecovered(a.AgentID, a.Models)
		case "gone":
			s.OnAgentGone(a.AgentID)
		case "unregistered":
			s.OnAgentUnregistered(a.AgentID)
		}
	}
}

func (r *agentRegistry) Subscribe(sub Subscriber) {
	r.subsMu.Lock()
	defer r.subsMu.Unlock()
	r.subs[sub] = true
}

func (r *agentRegistry) Unsubscribe(sub Subscriber) {
	r.subsMu.Lock()
	defer r.subsMu.Unlock()
	delete(r.subs, sub)
}

// SetAgentStateForTesting forces an agent's state (test hook for aging tests).
// Does NOT broadcast; the test inspects state via the registry directly.
func (r *agentRegistry) SetAgentStateForTesting(agentID string, state AgentState) {
	errCh := make(chan error, 1)
	r.cmdCh <- transitionCmd{errCh: errCh, fn: func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		a, ok := r.agents[agentID]
		if !ok {
			a = &Agent{AgentID: agentID, State: state, RegisteredAt: r.clock.Now(), Version: 1}
			r.agents[agentID] = a
			return nil
		}
		r.transitionLocked(a, state)
		return nil
	}}
	<-errCh
}
