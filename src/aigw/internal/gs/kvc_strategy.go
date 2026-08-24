/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/stats"
)

// OffloadContext is input to OffloadStrategy.Plan.
type OffloadContext struct {
	AgentID string
	Model   string
	Reason  string    // "agent_suspected" | "session_close"
	Now     time.Time // stamp IssuedAt with this (deterministic, from mgr.clock)
}

// OffloadStrategy decides which session blocks to offload (and to which tier)
// when an agent is suspected/gone. Pure function over session/block snapshots.
type OffloadStrategy interface {
	// Plan returns one or more KvcHints (batched by batchSize). It does NOT dispatch —
	// the caller (KvcSessionManager / kvcSubscriber) does, so strategies stay side-effect-free.
	Plan(ctx OffloadContext, sessions []*Session, blocks map[int64]*BlockInfo) ([]*KvcHint, error)
	Name() string
}

// PrefetchContext is input to PrefetchStrategy.Plan.
type PrefetchContext struct {
	AgentID string
	Model   string
	Reason  string
	Now     time.Time
}

type PrefetchStrategy interface {
	Plan(ctx PrefetchContext, sessions []*Session, blocks map[int64]*BlockInfo) ([]*KvcHint, error)
	Name() string
}

// AgingContext is input to SessionAgingStrategy.Plan.
type AgingContext struct {
	Model       string
	Now         time.Time
	AgentStates map[string]agentregistry.AgentState // current agent states from AgentRegistry
}

type SessionAgingStrategy interface {
	// Plan returns Evict hints for sessions that should be evicted.
	Plan(ctx AgingContext, sessions []*Session) ([]*KvcHint, error)
	Name() string
}

// offloadAllStrategy offloads all block hashes of an agent's ACTIVE sessions.
type offloadAllStrategy struct {
	cfg base.KvcOffloadConfig
}

// NewOffloadStrategy selects an offload strategy by cfg.Mode. Default "all".
func NewOffloadStrategy(cfg base.KvcOffloadConfig) (OffloadStrategy, error) {
	switch cfg.Mode {
	case "all", "":
		return &offloadAllStrategy{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown offload strategy: %s", cfg.Mode)
	}
}

func (s *offloadAllStrategy) Name() string { return "all" }

func (s *offloadAllStrategy) Plan(ctx OffloadContext, sessions []*Session, _ map[int64]*BlockInfo) ([]*KvcHint, error) {
	// 1. filter ACTIVE sessions of this agent; exclude SUSPENDED/TERMINATED/EVICTED
	var active []*Session
	for _, sess := range sessions {
		if sess.AgentID != ctx.AgentID {
			continue
		}
		if sess.State != SessionActive {
			continue
		}
		active = append(active, sess)
	}
	if len(active) == 0 {
		return nil, nil
	}
	// 2. build SessionHints, batch by batchSize
	batch := s.cfg.BatchSize
	if batch <= 0 {
		batch = 5
	}
	var hints []*KvcHint
	for i := 0; i < len(active); i += batch {
		end := i + batch
		if end > len(active) {
			end = len(active)
		}
		var sh []SessionHint
		for _, sess := range active[i:end] {
			sh = append(sh, SessionHint{
				SessionID: sess.SessionID, LastInstance: sess.LastPrefillInstance,
				BlockHashes: sess.BlockHashes, SourceTier: "hbm", TargetTier: s.cfg.TargetTier,
			})
		}
		hints = append(hints, &KvcHint{
			HintID: newHintID(), Type: HintOffload, Model: ctx.Model, AgentID: ctx.AgentID,
			Sessions: sh, IssuedAt: ctx.Now, IssuedReason: ctx.Reason,
		})
	}
	return hints, nil
}

// ttlAgingStrategy evicts sessions whose agent is GONE+Terminated past evictGraceSec,
// or any session idle past sessionIdleEvictSec, regardless of agent state.
type ttlAgingStrategy struct {
	cfg base.KvcAgingConfig
}

func NewSessionAgingStrategy(cfg base.KvcAgingConfig) (SessionAgingStrategy, error) {
	switch cfg.Mode {
	case "ttl", "":
		return &ttlAgingStrategy{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown aging strategy: %s", cfg.Mode)
	}
}

func (s *ttlAgingStrategy) Name() string { return "ttl" }

func (s *ttlAgingStrategy) Plan(ctx AgingContext, sessions []*Session) ([]*KvcHint, error) {
	var toEvict []*Session
	grace := time.Duration(s.cfg.EvictGraceSec) * time.Second
	idle := time.Duration(s.cfg.SessionIdleEvictSec) * time.Second
	for _, sess := range sessions {
		state, ok := ctx.AgentStates[sess.AgentID]
		if ok && state == agentregistry.StateGone {
			if sess.State == SessionTerminated && sess.TerminatedAt != nil &&
				ctx.Now.Sub(*sess.TerminatedAt) > grace {
				toEvict = append(toEvict, sess)
			}
			continue
		}
		// idle eviction regardless of agent state
		if ctx.Now.Sub(sess.LastRequestAt) > idle {
			toEvict = append(toEvict, sess)
		}
	}
	if len(toEvict) == 0 {
		return nil, nil
	}
	batch := s.cfg.BatchSize
	if batch <= 0 {
		batch = 10
	}
	var hints []*KvcHint
	for i := 0; i < len(toEvict); i += batch {
		end := i + batch
		if end > len(toEvict) {
			end = len(toEvict)
		}
		var sh []SessionHint
		for _, sess := range toEvict[i:end] {
			sh = append(sh, SessionHint{SessionID: sess.SessionID, BlockHashes: sess.BlockHashes})
		}
		hints = append(hints, &KvcHint{
			HintID: newHintID(), Type: HintEvict, Model: ctx.Model, AgentID: "",
			Sessions: sh, IssuedAt: ctx.Now, IssuedReason: "aging",
		})
	}
	return hints, nil
}

func flattenSessionHashes(sessions []SessionHint) []int64 {
	var out []int64
	for _, s := range sessions {
		out = append(out, s.BlockHashes...)
	}
	return out
}

// prefetchMRUStrategy prefetches the TopN most-recently-used SUSPENDED sessions of an agent
// (by LastRequestAt desc) back to HBM.
type prefetchMRUStrategy struct {
	cfg base.KvcPrefetchConfig
}

func (s *prefetchMRUStrategy) Name() string { return "mru" }

func NewPrefetchStrategy(cfg base.KvcPrefetchConfig) (PrefetchStrategy, error) {
	switch cfg.Mode {
	case "mru", "":
		return &prefetchMRUStrategy{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown prefetch strategy: %s", cfg.Mode)
	}
}

func (s *prefetchMRUStrategy) Plan(ctx PrefetchContext, sessions []*Session, _ map[int64]*BlockInfo) ([]*KvcHint, error) {
	var suspended []*Session
	for _, sess := range sessions {
		if sess.AgentID != ctx.AgentID {
			continue
		}
		if sess.State != SessionSuspended {
			continue
		}
		suspended = append(suspended, sess)
	}
	// sort by LastRequestAt desc (most-recently-used first)
	sort.Slice(suspended, func(i, j int) bool {
		return suspended[i].LastRequestAt.After(suspended[j].LastRequestAt)
	})
	topN := s.cfg.TopN
	if topN <= 0 {
		topN = 10
	}
	if len(suspended) > topN {
		suspended = suspended[:topN]
	}
	if len(suspended) == 0 {
		return nil, nil
	}
	batch := s.cfg.BatchSize
	if batch <= 0 {
		batch = 5
	}
	var hints []*KvcHint
	for i := 0; i < len(suspended); i += batch {
		end := i + batch
		if end > len(suspended) {
			end = len(suspended)
		}
		var sh []SessionHint
		for _, sess := range suspended[i:end] {
			sh = append(sh, SessionHint{
				SessionID: sess.SessionID, LastInstance: sess.LastPrefillInstance,
				BlockHashes: sess.BlockHashes, SourceTier: "ddr", TargetTier: "hbm",
			})
		}
		hints = append(hints, &KvcHint{
			HintID: newHintID(), Type: HintPrefetch, Model: ctx.Model, AgentID: ctx.AgentID,
			Sessions: sh, IssuedAt: ctx.Now, IssuedReason: ctx.Reason,
		})
	}
	return hints, nil
}

// newHintID returns a crypto/rand-based UUID v4 (no external dep).
// Panics on rand failure: an empty hint_id would break vLLM idempotency caching.
func newHintID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// keep stats import referenced until dispatch (F1) wires the counters.
var _ = stats.StatHintsIssuedOffload
