/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"sync/atomic"
	"testing"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/kvevents"
)

func newTestKvcMgr(t *testing.T) (*KvcSessionManager, *MockKvcHintSender, *agentregistry.InMemoryAgentRegistrySubscriber) {
	t.Helper()
	clock := newFakeClock(time.UnixMilli(1000000))
	sender := &MockKvcHintSender{}
	reg := agentregistry.NewRegistry(clock, agentregistry.RegistryConfig{HeartbeatTimeoutSec: 90, RecoverWindowSec: 300, RecoverTimeoutSec: 300, GoneFinalizeSec: 3600})
	sub := &agentregistry.InMemoryAgentRegistrySubscriber{}
	reg.Subscribe(sub)
	reg.Start()
	t.Cleanup(reg.Stop)
	mgr := NewKvcSessionManager("m1", reg, sender, defaultKvcSessionConfig(), clock)
	mgr.Start()
	t.Cleanup(mgr.Stop)
	return mgr, sender, sub
}

func TestOnRequestScheduled_NewSession_CreatesActive(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{100, 101, 102})
	s, ok := mgr.GetSession("s1")
	if !ok || s.State != SessionActive || s.AgentID != "a1" {
		t.Fatalf("session=%+v ok=%v", s, ok)
	}
	if s.LastPrefillInstance != "ins1" {
		t.Fatalf("prefill instance=%s", s.LastPrefillInstance)
	}
	// pendingBlocks recorded for attribution
	if !mgr.HasPending("s1") {
		t.Fatal("pending blocks not recorded")
	}
}

func TestOnBlockStored_AttributionMatch(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{100, 101, 102})
	mgr.OnBlockStored(testBlockStored("ins1", 100))
	s, _ := mgr.GetSession("s1")
	if !containsInt64(s.BlockHashes, 100) {
		t.Fatalf("block 100 not attributed; have %v", s.BlockHashes)
	}
	bi := mgr.GetBlock(100)
	if bi == nil || !bi.Sessions["s1"] {
		t.Fatalf("block index missing session ref: %+v", bi)
	}
}

func TestOnBlockStored_AttributionMiss_RecordsBlockOnly(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	mgr.OnBlockStored(testBlockStored("ins1", 999)) // no pending session
	bi := mgr.GetBlock(999)
	if bi == nil {
		t.Fatal("block should still be indexed on miss")
	}
	if len(bi.Sessions) != 0 {
		t.Fatalf("miss block should have no sessions: %+v", bi)
	}
}

func TestOnBlockRemoved_Cleanup(t *testing.T) {
	mgr, _, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{100})
	mgr.OnBlockStored(testBlockStored("ins1", 100))
	mgr.OnBlockRemoved(testBlockRemoved("ins1", 100))
	if mgr.GetBlock(100) != nil {
		t.Fatal("block should be removed from index")
	}
	s, _ := mgr.GetSession("s1")
	if containsInt64(s.BlockHashes, 100) {
		t.Fatal("session should have block 100 removed")
	}
}

// helpers
func testBlockStored(ins string, hashes ...int64) kvevents.BlockStored {
	return kvevents.BlockStored{BlockHashes: hashes, InstanceName: ins, ModelName: "m1"}
}
func testBlockRemoved(ins string, hashes ...int64) kvevents.BlockRemoved {
	return kvevents.BlockRemoved{BlockHashes: hashes, InstanceName: ins, ModelName: "m1"}
}

func TestOnBlockStored_DegradedMode_EmptyExpectedHashes_AttributesAllFromInstance(t *testing.T) {
	// D4 degraded mode: OnRequestScheduled called with nil expectedHashes.
	// Attribution falls back to instance-only matching.
	mgr, _, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", nil) // degraded: no expected hashes
	mgr.OnBlockStored(testBlockStored("ins1", 200, 201))
	s, _ := mgr.GetSession("s1")
	if !containsInt64(s.BlockHashes, 200) || !containsInt64(s.BlockHashes, 201) {
		t.Fatalf("degraded mode should attribute all instance blocks; got %v", s.BlockHashes)
	}
}

func TestHeaderVal_CaseInsensitive(t *testing.T) {
	h := map[string]string{"X-Session-Id": "s1", "x-agent-id": "a1"}
	if headerVal(h, "x-session-id") != "s1" {
		t.Fatal("expected case-insensitive match for x-session-id")
	}
	if headerVal(h, "X-Agent-Id") != "a1" {
		t.Fatal("expected case-insensitive match for X-Agent-Id")
	}
	if headerVal(h, "x-missing") != "" {
		t.Fatal("missing key should return empty string")
	}
}

func TestOffload_Dispatch_AcceptedMarksSuspended(t *testing.T) {
	mgr, sender, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{10})
	mgr.OnBlockStored(testBlockStored("ins1", 10))
	sender.AckPolicy = func(h *KvcHint) *HintAck {
		return &HintAck{HintID: h.HintID, Status: AckAccepted, AcceptedHashes: []int64{10}, BlockPlacements: map[int64]string{10: "ddr"}}
	}
	mgr.dispatchOffloadForAgent("a1")
	s, _ := mgr.GetSession("s1")
	if s.State != SessionSuspended {
		t.Fatalf("state=%v want Suspended", s.State)
	}
	if mgr.GetBlock(10).Tier != "ddr" {
		t.Fatalf("block tier not updated to ddr: %+v", mgr.GetBlock(10))
	}
}

func TestOffload_Dispatch_InFlightNotRetried(t *testing.T) {
	mgr, sender, _ := newTestKvcMgr(t)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{10})
	mgr.OnBlockStored(testBlockStored("ins1", 10))
	sender.AckPolicy = func(h *KvcHint) *HintAck {
		return &HintAck{HintID: h.HintID, Status: AckPartial, AcceptedHashes: nil, InFlightHashes: []int64{10}}
	}
	mgr.dispatchOffloadForAgent("a1")
	if sender.SentCount() != 1 {
		t.Fatalf("in_flight must not trigger retry; calls=%d", sender.SentCount())
	}
}

func TestOffload_Dispatch_FailedRetriesThenMarksHintFailed(t *testing.T) {
	mgr, sender, _ := newTestKvcMgr(t)
	mgr.SetMaxRetries(2) // test hook
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{10})
	mgr.OnBlockStored(testBlockStored("ins1", 10))
	sender.AckPolicy = func(h *KvcHint) *HintAck {
		return &HintAck{HintID: h.HintID, Status: AckPartial, FailedHashes: []int64{10}, JobID: "j1"}
	}
	mgr.dispatchOffloadForAgent("a1")
	s, _ := mgr.GetSession("s1")
	if !s.HintFailed {
		t.Fatal("session should be marked hint_failed after retries exhausted")
	}
}

func TestHintRecoveryLoop_RetriesPendingHints(t *testing.T) {
	mgr, sender, _ := newTestKvcMgr(t)
	mgr.SetMaxRetries(0) // disable sync-retry so dispatch leaves a pending hint for the recovery loop
	mgr.SetRecoveryInterval(5 * time.Millisecond)
	mgr.OnRequestScheduled("s1", "a1", "ins1", []int64{10})
	mgr.OnBlockStored(testBlockStored("ins1", 10))
	// first dispatch fails (failed_hashes), recovery loop retries and succeeds
	var failedOnce int32
	sender.AckPolicy = func(h *KvcHint) *HintAck {
		if atomic.AddInt32(&failedOnce, 1) == 1 {
			return &HintAck{HintID: h.HintID, Status: AckPartial, FailedHashes: []int64{10}}
		}
		return &HintAck{HintID: h.HintID, Status: AckAccepted, AcceptedHashes: []int64{10}}
	}
	mgr.dispatchOffloadForAgent("a1") // leaves pending hint (maxRetries=0 -> immediate enqueue)
	time.Sleep(50 * time.Millisecond) // let recovery loop run
	if sender.SentCount() < 2 {
		t.Fatalf("recovery loop should have retried; calls=%d", sender.SentCount())
	}
}

func TestPerModelAging_EvictsAfterGrace(t *testing.T) {
	clock := newFakeClock(time.UnixMilli(1000000))
	mgr, _, _ := newTestKvcMgr(t)
	mgr.SetClock(clock)
	mgr.AddTerminatedSession("s1", "a1", clock.Now().Add(-2*time.Hour))
	mgr.ForceAgentState("a1", agentregistry.StateGone)
	mgr.SetAgingInterval(5 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	s, _ := mgr.GetSession("s1")
	if s.State != SessionEvicted {
		t.Fatalf("expected evicted, got %v", s.State)
	}
}
