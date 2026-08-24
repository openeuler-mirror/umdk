/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/base"
)

func TestOffloadAll_Plan_IncludesActiveExcludesSuspendedTerminated(t *testing.T) {
	clock := newFakeClock(time.UnixMilli(1000000))
	mgr, _, _ := newTestKvcMgr(t)
	mgr.SetClock(clock)
	// active session
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{10, 11})
	mgr.OnBlockStored(testBlockStored("ins1", 10, 11))
	// suspended session of the SAME agent — should be excluded by state
	mgr.SetSessionStateForAgent("s2", "a1", SessionSuspended)
	// terminated session of the SAME agent — excluded by state
	mgr.SetSessionStateForAgent("s3", "a1", SessionTerminated)

	strat, _ := NewOffloadStrategy(base.KvcOffloadConfig{Mode: "all", BatchSize: 5, TargetTier: "ddr"})
	ctx := OffloadContext{AgentID: "a1", Model: "m1", Reason: "agent_suspected", Now: clock.Now()}
	hints, err := strat.Plan(ctx, mgr.SessionsSnapshot(), mgr.BlocksSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(hints))
	}
	hashes := flattenSessionHashes(hints[0].Sessions)
	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes (only active session), got %v", hashes)
	}
	if hints[0].Type != HintOffload {
		t.Fatalf("type=%v", hints[0].Type)
	}
	if hints[0].Sessions[0].TargetTier != "ddr" {
		t.Fatalf("target=%s", hints[0].Sessions[0].TargetTier)
	}
	if !hints[0].IssuedAt.Equal(clock.Now()) {
		t.Fatalf("IssuedAt=%v want %v (deterministic from ctx.Now)", hints[0].IssuedAt, clock.Now())
	}
}

func TestOffloadAll_Plan_NoActiveSessions_ReturnsNil(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	mgr.SetSessionState("s1", SessionSuspended) // no active sessions for a1
	strat, _ := NewOffloadStrategy(base.KvcOffloadConfig{Mode: "all", BatchSize: 5, TargetTier: "ddr"})
	ctx := OffloadContext{AgentID: "a1", Model: "m1", Reason: "agent_suspected", Now: time.Now()}
	hints, err := strat.Plan(ctx, mgr.SessionsSnapshot(), mgr.BlocksSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if hints != nil {
		t.Fatalf("expected nil hints, got %d", len(hints))
	}
}

func TestOffloadAll_Plan_BatchesByBatchSize(t *testing.T) {
	clock := newFakeClock(time.UnixMilli(1000000))
	mgr, _, _ := newTestKvcMgr(t)
	mgr.SetClock(clock)
	// 7 active sessions for a1, batchSize=3 -> 3 hints (3+3+1)
	for i := 0; i < 7; i++ {
		sid := "s" + string(rune('1'+i))
		mgr.OnRequestScheduled(sid, "a1", "ins1", []int64{int64(100 + i)})
		mgr.OnBlockStored(testBlockStored("ins1", int64(100+i)))
	}
	strat, _ := NewOffloadStrategy(base.KvcOffloadConfig{Mode: "all", BatchSize: 3, TargetTier: "ddr"})
	ctx := OffloadContext{AgentID: "a1", Model: "m1", Reason: "agent_suspected", Now: clock.Now()}
	hints, _ := strat.Plan(ctx, mgr.SessionsSnapshot(), mgr.BlocksSnapshot())
	if len(hints) != 3 {
		t.Fatalf("expected 3 batched hints for 7 sessions with batchSize=3, got %d", len(hints))
	}
}

func TestPrefetchMRU_Plan_TopNByLastRequestAtDesc(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	// 3 suspended sessions with different LastRequestAt; topN=2
	mgr.SetClock(newFakeClock(time.UnixMilli(1000000)))
	mgr.AddSuspendedSession("s1", "a1", time.UnixMilli(100))
	mgr.AddSuspendedSession("s2", "a1", time.UnixMilli(300))
	mgr.AddSuspendedSession("s3", "a1", time.UnixMilli(200))

	strat, _ := NewPrefetchStrategy(base.KvcPrefetchConfig{Mode: "mru", TopN: 2, BatchSize: 5})
	ctx := PrefetchContext{AgentID: "a1", Model: "m1", Reason: "agent_recovered", Now: time.Now()}
	hints, err := strat.Plan(ctx, mgr.SessionsSnapshot(), mgr.BlocksSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	all := []SessionHint{}
	for _, h := range hints {
		all = append(all, h.Sessions...)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions prefetched, got %d", len(all))
	}
	// s2 (300) and s3 (200) are the top-2 most recent
	ids := []string{all[0].SessionID, all[1].SessionID}
	if !containsStr(ids, "s2") || !containsStr(ids, "s3") {
		t.Fatalf("expected s2,s3 ; got %v", ids)
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestTTLAging_Plan_GoneAgentAfterGrace_EvictsTerminated(t *testing.T) {
	clock := newFakeClock(time.UnixMilli(1000000))
	mgr, _, _ := newTestKvcMgr(t)
	mgr.SetClock(clock)
	// a terminated session whose TerminatedAt is > evictGraceSec (1h) ago
	mgr.AddTerminatedSession("s1", "a1", clock.Now().Add(-2*time.Hour))

	strat, _ := NewSessionAgingStrategy(base.KvcAgingConfig{Mode: "ttl", EvictGraceSec: 3600, SessionIdleEvictSec: 604800, BatchSize: 10})
	ctx := AgingContext{Model: "m1", Now: clock.Now(), AgentStates: map[string]agentregistry.AgentState{"a1": agentregistry.StateGone}}
	hints, err := strat.Plan(ctx, mgr.SessionsSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || hints[0].Type != HintEvict {
		t.Fatalf("expected 1 evict hint, got %+v", hints)
	}
}

func TestTTLAging_Plan_GracefulUnregister_ImmediateEvict(t *testing.T) {
	// unregister is an EVENT not a state. The kvcSubscriber.OnAgentUnregistered calls
	// evictAgentSessions directly (D3), bypassing the aging strategy. Covered in F1.
	t.Skip("unregister handled by evictAgentSessions, not aging strategy — covered in F1")
}
