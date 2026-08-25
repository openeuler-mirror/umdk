/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"context"
	"sync"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/kvevents"
	"huawei.com/aigw/internal/stats"
	"huawei.com/aigw/pkg/log"
)

// KvcSessionConfig is the per-model KVC session config (derived from base.KvcConfig at wiring time).
type KvcSessionConfig struct {
	SessionTtlSec           int
	BlockTtlSec             int
	PendingBlockMatchTtlSec int
	MaxRetries              int
	Offload                 base.KvcOffloadConfig
	Prefetch                base.KvcPrefetchConfig
	Aging                   base.KvcAgingConfig
}

func defaultKvcSessionConfig() KvcSessionConfig {
	return KvcSessionConfig{
		SessionTtlSec: 86400, BlockTtlSec: 3600, PendingBlockMatchTtlSec: 60, MaxRetries: 5,
		Offload:  base.KvcOffloadConfig{Mode: "all", BatchSize: 5, TargetTier: "ddr", DelayBetweenBatchesMs: 100},
		Prefetch: base.KvcPrefetchConfig{Mode: "mru", TopN: 10, BatchSize: 5, DelayBetweenBatchesMs: 100},
		Aging:    base.KvcAgingConfig{Mode: "ttl", LoopIntervalSec: 60, EvictGraceSec: 3600, SessionIdleEvictSec: 604800, BatchSize: 10},
	}
}

type pendingBlock struct {
	expectedHashes  map[int64]bool
	prefillInstance string
	createdAt       time.Time
}

// KvcSessionManager owns session↔block attribution for one model, generates KvcHints
// via strategies on agent state transitions, and dispatches them through KvcHintSender.
type KvcSessionManager struct {
	modelName     string
	agentRegistry agentregistry.Registry
	hintSender    KvcHintSender
	config        KvcSessionConfig
	clock         agentregistry.Clock

	mu            sync.RWMutex
	sessions      map[string]*Session
	blocks        map[int64]*BlockInfo
	agentBlocks   map[string]map[int64]bool
	pendingBlocks map[string]*pendingBlock

	offloadStrat  OffloadStrategy
	prefetchStrat PrefetchStrategy
	agingStrat    SessionAgingStrategy

	// statsRef is the shared gs-wide stats instance; nil in D1, injected at wiring (H1).
	// When nil, OnBlockStored uses a throwaway local counter for match-miss (counts are
	// best-effort until wired).
	statsRef *stats.DataPlaneStats

	recoveryInterval time.Duration // HintRecoveryLoop tick (default 60s; tests override)
	agingInterval    time.Duration // per-model aging loop tick (default = cfg.Aging.LoopIntervalSec)

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func NewKvcSessionManager(model string, reg agentregistry.Registry, sender KvcHintSender,
	cfg KvcSessionConfig, clock agentregistry.Clock) *KvcSessionManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &KvcSessionManager{
		modelName: model, agentRegistry: reg, hintSender: sender,
		config: cfg, clock: clock,
		sessions: make(map[string]*Session), blocks: make(map[int64]*BlockInfo),
		agentBlocks: make(map[string]map[int64]bool), pendingBlocks: make(map[string]*pendingBlock),
		ctx: ctx, cancel: cancel,
	}
	m.offloadStrat, _ = NewOffloadStrategy(cfg.Offload)
	m.prefetchStrat, _ = NewPrefetchStrategy(cfg.Prefetch)
	m.agingStrat, _ = NewSessionAgingStrategy(cfg.Aging)
	return m
}

func (m *KvcSessionManager) Start() {
	// subscribe to agent registry (kvcSubscriberAdapter forwards to m.OnAgent*).
	m.agentRegistry.Subscribe(&kvcSubscriberAdapter{mgr: m})
	// per-model aging loop
	m.wg.Add(1)
	go m.agingLoop()
	// pending-hint recovery loop (drains PendingHints enqueued by F1)
	m.wg.Add(1)
	go m.hintRecoveryLoop()
}

func (m *KvcSessionManager) Stop() {
	m.cancel()
	m.wg.Wait()
}

// OnRequestScheduled is called from gs_manager.handleSchedule after a successful schedule.
// prefillInstance = result.PrefillUrl; expectedHashes = computed prefix block hashes.
func (m *KvcSessionManager) OnRequestScheduled(sessionID, agentID, prefillInstance string, expectedHashes []int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	s, ok := m.sessions[sessionID]
	if !ok {
		s = &Session{SessionID: sessionID, AgentID: agentID, Model: m.modelName, State: SessionActive}
		m.sessions[sessionID] = s
	}
	s.LastPrefillInstance = prefillInstance
	s.LastRequestAt = now
	s.AccessCount++
	s.AccessFrequency = computeEMA(s.AccessFrequency, 1.0, 0.3)
	// record pending blocks for attribution
	emap := make(map[int64]bool, len(expectedHashes))
	for _, h := range expectedHashes {
		emap[h] = true
	}
	m.pendingBlocks[sessionID] = &pendingBlock{expectedHashes: emap, prefillInstance: prefillInstance, createdAt: now}
	// reverse index
	if _, ok := m.agentBlocks[agentID]; !ok {
		m.agentBlocks[agentID] = make(map[int64]bool)
	}
}

// OnBlockStored indexes the block and attributes it to pending sessions whose
// prefillInstance matches and whose expectedHashes contains the block hash.
func (m *KvcSessionManager) OnBlockStored(event kvevents.BlockStored) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for _, h := range event.BlockHashes {
		bi, ok := m.blocks[h]
		if !ok {
			bi = &BlockInfo{BlockHash: h, Model: event.ModelName, Instance: event.InstanceName,
				Sessions: make(map[string]bool), StoredAt: now, LastSeenAt: now}
			m.blocks[h] = bi
		} else {
			bi.LastSeenAt = now
		}
		// match against pending sessions
		matched := false
		for sid, pb := range m.pendingBlocks {
			if pb.prefillInstance != event.InstanceName {
				continue
			}
			// Degraded mode (D4): empty expectedHashes = attribute ALL blocks from
			// this instance to the session (used when vLLM hash algorithm not yet
			// validated — R1). Otherwise attribute only the expected hashes.
			if len(pb.expectedHashes) == 0 || pb.expectedHashes[h] {
				s, ok := m.sessions[sid]
				if ok {
					if !containsInt64(s.BlockHashes, h) {
						s.BlockHashes = append(s.BlockHashes, h)
					}
					bi.Sessions[sid] = true
					if m.agentBlocks[s.AgentID] != nil {
						m.agentBlocks[s.AgentID][h] = true
					}
					matched = true
				}
			}
		}
		if !matched {
			// best-effort miss counter; wiring (H1) injects the shared gs-wide stats instance.
			if m.statsRef != nil {
				m.statsRef.Record(stats.StatBlockMatchMiss)
			}
			log.Debug().Msgf("[kvc] block %d match miss (instance=%s)", h, event.InstanceName)
		}
	}
	// prune stale pending (TTL)
	m.pruneStalePendingLocked(now)
}

// OnBlockRemoved removes the block from the index and detaches it from sessions.
func (m *KvcSessionManager) OnBlockRemoved(event kvevents.BlockRemoved) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range event.BlockHashes {
		bi, ok := m.blocks[h]
		if !ok {
			continue
		}
		for sid := range bi.Sessions {
			if s, ok := m.sessions[sid]; ok {
				s.BlockHashes = removeInt64(s.BlockHashes, h)
			}
		}
		delete(m.blocks, h)
		// cleanup reverse index
		for agentID, hashes := range m.agentBlocks {
			delete(hashes, h)
			if len(hashes) == 0 {
				delete(m.agentBlocks, agentID)
			}
		}
	}
}

// OnAllBlocksCleared resets all block state (model reinit / instance flush).
func (m *KvcSessionManager) OnAllBlocksCleared(event kvevents.AllBlocksCleared) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks = make(map[int64]*BlockInfo)
	m.pendingBlocks = make(map[string]*pendingBlock)
	for _, s := range m.sessions {
		s.BlockHashes = nil
	}
	m.agentBlocks = make(map[string]map[int64]bool)
}

// GetSession / GetBlock / HasPending — test accessors (also used by debug API in G3).
func (m *KvcSessionManager) GetSession(sid string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	return s, ok
}
func (m *KvcSessionManager) GetBlock(h int64) *BlockInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blocks[h]
}
func (m *KvcSessionManager) HasPending(sid string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.pendingBlocks[sid]
	return ok
}

// SetClock replaces the clock (test hook for strategy determinism).
func (m *KvcSessionManager) SetClock(c agentregistry.Clock) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clock = c
}

// SetMaxRetries overrides the retry limit (test hook).
func (m *KvcSessionManager) SetMaxRetries(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.MaxRetries = n
}

// SetRecoveryInterval overrides the HintRecoveryLoop tick interval (test hook).
func (m *KvcSessionManager) SetRecoveryInterval(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoveryInterval = d
}

// SetAgingInterval overrides the per-model aging loop interval (test hook).
func (m *KvcSessionManager) SetAgingInterval(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agingInterval = d
}

// ForceAgentState forces an agent's state in the underlying registry (test hook).
func (m *KvcSessionManager) ForceAgentState(agentID string, state agentregistry.AgentState) {
	m.agentRegistry.SetAgentStateForTesting(agentID, state)
}

// SetSessionState forces a session's state (test hook for strategy filtering).
// Creates the session if absent.
func (m *KvcSessionManager) SetSessionState(sid string, state SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		s = &Session{SessionID: sid, Model: m.modelName, State: state}
		m.sessions[sid] = s
		return
	}
	s.State = state
}

// SetSessionStateForAgent forces a session's state + agentID (test hook).
func (m *KvcSessionManager) SetSessionStateForAgent(sid, agentID string, state SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		s = &Session{SessionID: sid, AgentID: agentID, Model: m.modelName, State: state}
		m.sessions[sid] = s
		return
	}
	s.State = state
	s.AgentID = agentID
}

// AddSuspendedSession creates a SUSPENDED session for an agent at a given LastRequestAt (test hook).
func (m *KvcSessionManager) AddSuspendedSession(sid, agentID string, lastRequestAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sid] = &Session{
		SessionID: sid, AgentID: agentID, Model: m.modelName,
		State: SessionSuspended, LastRequestAt: lastRequestAt,
	}
}

// AddTerminatedSession creates a TERMINATED session with a TerminatedAt timestamp (test hook).
func (m *KvcSessionManager) AddTerminatedSession(sid, agentID string, terminatedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sid] = &Session{
		SessionID: sid, AgentID: agentID, Model: m.modelName,
		State: SessionTerminated, TerminatedAt: &terminatedAt,
	}
}

// AddActiveSession creates an ACTIVE session for an agent (test hook).
func (m *KvcSessionManager) AddActiveSession(sid, agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	m.sessions[sid] = &Session{
		SessionID: sid, AgentID: agentID, Model: m.modelName,
		State: SessionActive, LastRequestAt: now,
	}
}

// DefaultKvcSessionConfigForTest returns the default KvcSessionConfig for tests (exported).
func DefaultKvcSessionConfigForTest() KvcSessionConfig { return defaultKvcSessionConfig() }

// SetKvcSessionManagerForTest sets the per-model KvcSessionManager on a GlobalSchedulerManager
// (test-only wiring helper; production wiring happens in startManagers/H1).
func SetKvcSessionManagerForTest(g *GlobalSchedulerManager, m *KvcSessionManager) {
	g.kvcSessionMgr = m
}

// InjectSessionBlockForTest simulates a scheduled request + BlockStored event for a session
// (test-only: lets HTTP e2e tests populate a session's blocks without a real instance).
func (m *KvcSessionManager) InjectSessionBlockForTest(sessionID, agentID, instance string, hashes []int64) {
	m.OnRequestScheduled(sessionID, agentID, instance, hashes)
	m.OnBlockStored(kvevents.BlockStored{BlockHashes: hashes, InstanceName: instance, ModelName: m.modelName})
}

// SessionsSnapshot returns a shallow copy of all sessions (test hook + strategy input).
func (m *KvcSessionManager) SessionsSnapshot() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		cp := *s
		out = append(out, &cp)
	}
	return out
}

// BlocksSnapshot returns a shallow copy of all blocks (test hook + strategy input).
func (m *KvcSessionManager) BlocksSnapshot() map[int64]*BlockInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[int64]*BlockInfo, len(m.blocks))
	for h, b := range m.blocks {
		cp := *b
		out[h] = &cp
	}
	return out
}

func (m *KvcSessionManager) pruneStalePendingLocked(now time.Time) {
	ttl := time.Duration(m.config.PendingBlockMatchTtlSec) * time.Second
	for sid, pb := range m.pendingBlocks {
		if now.Sub(pb.createdAt) > ttl {
			delete(m.pendingBlocks, sid)
		}
	}
}

func computeEMA(prev, sample, weight float64) float64 {
	return prev*(1-weight) + sample*weight
}

func (m *KvcSessionManager) agingLoop() {
	defer m.wg.Done()
	interval := m.agingInterval
	if interval == 0 {
		interval = time.Duration(m.config.Aging.LoopIntervalSec) * time.Second
	}
	if interval == 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.runAgingOnce()
		}
	}
}

// kvcKveventsAdapter adapts *KvcSessionManager to the kvevents.EventHandler interface
// (whose methods return error; KvcSessionManager's don't). Returns nil — errors are
// already logged inside OnBlockStored/OnBlockRemoved/OnAllBlocksCleared.
type kvcKveventsAdapter struct{ m *KvcSessionManager }

func (a kvcKveventsAdapter) OnBlockStored(e kvevents.BlockStored) error {
	a.m.OnBlockStored(e)
	return nil
}
func (a kvcKveventsAdapter) OnBlockRemoved(e kvevents.BlockRemoved) error {
	a.m.OnBlockRemoved(e)
	return nil
}
func (a kvcKveventsAdapter) OnAllBlocksCleared(e kvevents.AllBlocksCleared) error {
	a.m.OnAllBlocksCleared(e)
	return nil
}

// AsKveventsHandler returns a kvevents.EventHandler view of this KvcSessionManager.
func (m *KvcSessionManager) AsKveventsHandler() kvevents.EventHandler {
	return kvcKveventsAdapter{m: m}
}

// runAgingOnce builds an AgentStates snapshot from the registry, runs the aging strategy,
// and dispatches the resulting evict hints. Per-model, driven by agingLoop.
func (m *KvcSessionManager) runAgingOnce() {
	states := make(map[string]agentregistry.AgentState)
	m.mu.RLock()
	agentIDs := make(map[string]bool)
	snap := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		agentIDs[s.AgentID] = true
		cp := *s
		snap = append(snap, &cp)
	}
	m.mu.RUnlock()
	for id := range agentIDs {
		if a, ok := m.agentRegistry.Get(id); ok {
			states[id] = a.State
		}
	}
	ctx := AgingContext{Model: m.modelName, Now: m.clock.Now(), AgentStates: states}
	hints, _ := m.agingStrat.Plan(ctx, snap)
	for _, h := range hints {
		ack, err := m.hintSender.Send(m.ctx, h)
		if err == nil {
			m.applyAck(h, ack)
		}
	}
}

// hintRecoveryLoop drains PendingHints enqueued by dispatchHintWithRetry (failed_hashes).
func (m *KvcSessionManager) hintRecoveryLoop() {
	defer m.wg.Done()
	interval := m.recoveryInterval
	if interval == 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.retryPendingHints()
		}
	}
}

func (m *KvcSessionManager) retryPendingHints() {
	m.mu.RLock()
	type pendingRef struct {
		sid string
		ph  PendingHint
	}
	var pending []pendingRef
	for sid, s := range m.sessions {
		for _, ph := range s.PendingHints {
			pending = append(pending, pendingRef{sid: sid, ph: ph})
		}
	}
	m.mu.RUnlock()
	now := m.clock.Now()
	for _, p := range pending {
		if now.Before(p.ph.NextRetryAt) {
			continue
		}
		ack, err := m.hintSender.Send(m.ctx, p.ph.Hint)
		if err != nil {
			continue
		}
		m.applyAck(p.ph.Hint, ack)
		if len(ack.FailedHashes) == 0 {
			// clear this session's pending hints that match
			m.mu.Lock()
			if s, ok := m.sessions[p.sid]; ok {
				filtered := s.PendingHints[:0]
				for _, ph := range s.PendingHints {
					if ph.Hint.HintID != p.ph.Hint.HintID {
						filtered = append(filtered, ph)
					}
				}
				s.PendingHints = filtered
			}
			m.mu.Unlock()
		}
	}
}

// planAndDispatchOffload runs the offload strategy and dispatches the resulting hint(s).
// Called by kvcSubscriberAdapter on OnAgentSuspected.
func (m *KvcSessionManager) planAndDispatchOffload(ctx OffloadContext) (int, error) {
	m.dispatchOffloadForAgent(ctx.AgentID)
	return 0, nil
}

// planAndDispatchPrefetch runs the prefetch strategy and dispatches the resulting hint(s).
// Called by kvcSubscriberAdapter on OnAgentRecovered.
func (m *KvcSessionManager) planAndDispatchPrefetch(ctx PrefetchContext) (int, error) {
	m.dispatchPrefetchForAgent(ctx.AgentID)
	return 0, nil
}

// terminateSessions marks all sessions for an agent Terminated; the aging loop evicts
// after the grace window. Called by kvcSubscriberAdapter on OnAgentGone.
func (m *KvcSessionManager) terminateSessions(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for _, s := range m.sessions {
		if s.AgentID == agentID && s.State != SessionEvicted {
			s.State = SessionTerminated
			s.TerminatedAt = &now
		}
	}
}

// evictAgentSessions immediately evicts all sessions for an agent (used on unregister).
func (m *KvcSessionManager) evictAgentSessions(agentID string) error {
	hint := &KvcHint{HintID: newHintID(), Type: HintEvict, Model: m.modelName, AgentID: agentID,
		IssuedAt: m.clock.Now(), IssuedReason: "session_close"}
	m.mu.RLock()
	for _, s := range m.sessions {
		if s.AgentID == agentID {
			hint.Sessions = append(hint.Sessions, SessionHint{SessionID: s.SessionID, BlockHashes: s.BlockHashes})
		}
	}
	m.mu.RUnlock()
	if len(hint.Sessions) == 0 {
		return nil
	}
	ack, _ := m.hintSender.Send(m.ctx, hint)
	m.applyAck(hint, ack)
	return nil
}

// CloseSession evicts a single session's blocks (used by the session-close HTTP endpoint).
func (m *KvcSessionManager) CloseSession(sessionID string) error {
	m.mu.RLock()
	s, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil // session not tracked by this manager; not an error (iterates all managers)
	}
	hint := &KvcHint{HintID: newHintID(), Type: HintEvict, Model: m.modelName, AgentID: s.AgentID,
		IssuedAt: m.clock.Now(), IssuedReason: "session_close",
		Sessions: []SessionHint{{SessionID: sessionID, BlockHashes: s.BlockHashes}}}
	ack, _ := m.hintSender.Send(m.ctx, hint)
	m.applyAck(hint, ack)
	return nil
}

// dispatchOffloadForAgent plans offload hints for the agent's active sessions and dispatches them.
func (m *KvcSessionManager) dispatchOffloadForAgent(agentID string) {
	m.mu.RLock()
	sessions := m.agentSessionsLocked(agentID)
	blocks := m.blocksSnapshotLocked()
	clock := m.clock
	m.mu.RUnlock()
	ctx := OffloadContext{AgentID: agentID, Model: m.modelName, Reason: "agent_suspected", Now: clock.Now()}
	hints, _ := m.offloadStrat.Plan(ctx, sessions, blocks)
	for _, h := range hints {
		m.dispatchHintWithRetry(h, HintOffload)
	}
}

func (m *KvcSessionManager) dispatchPrefetchForAgent(agentID string) {
	m.mu.RLock()
	sessions := m.agentSessionsLocked(agentID)
	blocks := m.blocksSnapshotLocked()
	clock := m.clock
	m.mu.RUnlock()
	ctx := PrefetchContext{AgentID: agentID, Model: m.modelName, Reason: "agent_recovered", Now: clock.Now()}
	hints, _ := m.prefetchStrat.Plan(ctx, sessions, blocks)
	for _, h := range hints {
		m.dispatchHintWithRetry(h, HintPrefetch)
	}
}

// dispatchHintWithRetry sends a hint and applies the ack. Per verification spec §2 接缝 1:
// in_flight_hashes/missing_hashes are NOT retried (decode mid-write / not resident).
// failed_hashes → synchronously retry up to maxRetries (with a fresh hint_id each time);
// if still failing after exhaustion, mark Session.HintFailed + enqueue to PendingHints for
// HintRecoveryLoop (F2). Network/5xx error (VllmKvcClient exhausted its internal retries)
// → mark HintFailed immediately.
func (m *KvcSessionManager) dispatchHintWithRetry(hint *KvcHint, kind HintType) {
	maxRetries := m.config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 5
	}
	cur := hint
	for attempt := 0; ; attempt++ {
		ack, err := m.hintSender.Send(m.ctx, cur)
		if err != nil {
			m.markHintFailed(hint)
			return
		}
		m.applyAck(cur, ack)
		// in_flight_hashes & missing_hashes: no retry (not errors)
		if len(ack.FailedHashes) == 0 {
			return
		}
		if attempt >= maxRetries {
			// exhausted retries on failed_hashes — mark failed + enqueue for F2 recovery loop
			m.markHintFailed(hint)
			m.enqueueRetry(hint, ack, kind)
			return
		}
		// build a retry hint with only the failed hashes + fresh hint_id
		cur = m.retryHintFromFailed(cur, ack, kind)
	}
}

// retryHintFromFailed builds a new hint containing only the failed hashes of ack,
// with a fresh hint_id (preserves vLLM idempotency caching).
func (m *KvcSessionManager) retryHintFromFailed(prev *KvcHint, ack *HintAck, _ HintType) *KvcHint {
	retry := &KvcHint{
		HintID: newHintID(), Type: prev.Type, Model: prev.Model, AgentID: prev.AgentID,
		IssuedReason: prev.IssuedReason, IssuedAt: m.clock.Now(),
	}
	for _, sh := range prev.Sessions {
		var failed []int64
		for _, h := range sh.BlockHashes {
			for _, fh := range ack.FailedHashes {
				if h == fh {
					failed = append(failed, h)
					break
				}
			}
		}
		if len(failed) > 0 {
			retry.Sessions = append(retry.Sessions, SessionHint{
				SessionID: sh.SessionID, LastInstance: sh.LastInstance, BlockHashes: failed,
				SourceTier: sh.SourceTier, TargetTier: sh.TargetTier,
			})
		}
	}
	return retry
}

// enqueueRetry stores a PendingHint on each affected session for the HintRecoveryLoop (F2).
func (m *KvcSessionManager) enqueueRetry(hint *KvcHint, ack *HintAck, kind HintType) {
	retry := m.retryHintFromFailed(hint, ack, kind)
	if len(retry.Sessions) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for _, sh := range retry.Sessions {
		if s, ok := m.sessions[sh.SessionID]; ok {
			s.PendingHints = append(s.PendingHints, PendingHint{
				Hint: retry, Retries: len(s.PendingHints) + 1, NextRetryAt: now.Add(time.Second),
			})
		}
	}
}

func (m *KvcSessionManager) applyAck(hint *KvcHint, ack *HintAck) {
	if ack == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	// update block tiers from ack.BlockPlacements (learned placements)
	for h, tier := range ack.BlockPlacements {
		if bi, ok := m.blocks[h]; ok {
			bi.Tier = tier
		}
	}
	// update session states per hint type
	for _, sh := range hint.Sessions {
		s, ok := m.sessions[sh.SessionID]
		if !ok {
			continue
		}
		switch hint.Type {
		case HintOffload:
			if s.State == SessionActive {
				s.State = SessionSuspended
				t := now
				s.SuspendedAt = &t
			}
		case HintPrefetch:
			if s.State == SessionSuspended || s.State == SessionRecovering {
				s.State = SessionActive
				s.SuspendedAt = nil
				s.RecoveringAt = nil
			}
		case HintEvict:
			s.State = SessionEvicted
			// full block-ref cleanup happens in runAgingOnce (F2)
		}
	}
}

func (m *KvcSessionManager) markHintFailed(hint *KvcHint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sh := range hint.Sessions {
		if s, ok := m.sessions[sh.SessionID]; ok {
			s.HintFailed = true
		}
	}
	log.Warn().Msgf("[kvc] hint %s (%s) marked failed after retries exhausted", hint.HintID, hint.Type)
	// alarm: pkg/log AlarmPendingHintsBacklog or AlarmVllmUnreachable (wired in H1)
}

// maybeRetryFailed enqueues a retry hint containing only the failed hashes with a new
// hint_id (preserves vLLM idempotency). HintRecoveryLoop (F2) drains PendingHints.
func (m *KvcSessionManager) maybeRetryFailed(hint *KvcHint, ack *HintAck, kind HintType, _ int) {
	retry := &KvcHint{
		HintID: newHintID(), Type: kind, Model: hint.Model, AgentID: hint.AgentID,
		IssuedReason: hint.IssuedReason, IssuedAt: m.clock.Now(),
	}
	for _, sh := range hint.Sessions {
		var failed []int64
		for _, h := range sh.BlockHashes {
			for _, fh := range ack.FailedHashes {
				if h == fh {
					failed = append(failed, h)
					break
				}
			}
		}
		if len(failed) > 0 {
			retry.Sessions = append(retry.Sessions, SessionHint{
				SessionID: sh.SessionID, LastInstance: sh.LastInstance, BlockHashes: failed,
				SourceTier: sh.SourceTier, TargetTier: sh.TargetTier,
			})
		}
	}
	if len(retry.Sessions) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for _, sh := range retry.Sessions {
		if s, ok := m.sessions[sh.SessionID]; ok {
			s.PendingHints = append(s.PendingHints, PendingHint{
				Hint: retry, Retries: 1, NextRetryAt: now.Add(time.Second),
			})
		}
	}
}

// agentSessionsLocked returns shallow copies of an agent's sessions (caller holds m.mu).
func (m *KvcSessionManager) agentSessionsLocked(agentID string) []*Session {
	var out []*Session
	for _, s := range m.sessions {
		if s.AgentID == agentID {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out
}

// blocksSnapshotLocked returns a shallow copy of the blocks map (caller holds m.mu).
func (m *KvcSessionManager) blocksSnapshotLocked() map[int64]*BlockInfo {
	out := make(map[int64]*BlockInfo, len(m.blocks))
	for h, bi := range m.blocks {
		out[h] = bi
	}
	return out
}
