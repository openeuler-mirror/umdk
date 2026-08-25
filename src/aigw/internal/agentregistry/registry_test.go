/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package agentregistry

import (
	"testing"
	"time"
)

func newTestRegistry(t *testing.T) (*agentRegistry, *FakeClock, *InMemoryAgentRegistrySubscriber) {
	t.Helper()
	clock := NewFakeClock(time.UnixMilli(1000000))
	sub := &InMemoryAgentRegistrySubscriber{}
	r := NewRegistry(clock, RegistryConfig{
		HeartbeatTimeoutSec: 90,
		RecoverWindowSec:    300,
		RecoverTimeoutSec:   300,
		GoneFinalizeSec:     3600,
		RegisterGraceSec:    30,
	}).(*agentRegistry)
	r.Subscribe(sub)
	r.Start()
	t.Cleanup(r.Stop)
	return r, clock, sub
}

func TestRegister_NewAgent_TransitionsToActiveOnHeartbeat(t *testing.T) {
	r, _, sub := newTestRegistry(t)
	if err := r.Register("a1", []string{"m1"}, nil); err != nil {
		t.Fatal(err)
	}
	if a, ok := r.Get("a1"); !ok || a.State != StateRegistered {
		t.Fatalf("state=%v want StateRegistered", a.State)
	}
	if err := r.Heartbeat("a1", []string{"m1"}, []string{"s1"}); err != nil {
		t.Fatal(err)
	}
	if a, _ := r.Get("a1"); a.State != StateActive {
		t.Fatalf("state=%v want StateActive", a.State)
	}
	if len(sub.Events) == 0 || sub.Events[0].Type != "active" {
		t.Fatalf("expected OnAgentActive broadcast, got %+v", sub.Events)
	}
}

func TestHeartbeat_SuspectedRevive_BackToActive(t *testing.T) {
	r, clock, sub := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	clock.Advance(91 * time.Second) // > 90s heartbeatTimeout -> SUSPECTED
	r.tickOnce()                    // force aging tick (test-only hook)
	if a, _ := r.Get("a1"); a.State != StateSuspected {
		t.Fatalf("state=%v want StateSuspected", a.State)
	}
	// heartbeat revives
	if err := r.Heartbeat("a1", []string{"m1"}, nil); err != nil {
		t.Fatal(err)
	}
	if a, _ := r.Get("a1"); a.State != StateActive {
		t.Fatalf("state=%v want StateActive", a.State)
	}
	last := sub.Events[len(sub.Events)-1]
	if last.Type != "recovered" {
		t.Fatalf("expected OnAgentRecovered, got %+v", last)
	}
}

func TestUnregister_Graceful_BroadcastsAndRemoves(t *testing.T) {
	r, _, sub := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	if err := r.Unregister("a1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("a1"); ok {
		t.Fatal("agent should be removed after unregister")
	}
	last := sub.Events[len(sub.Events)-1]
	if last.Type != "unregistered" {
		t.Fatalf("expected OnAgentUnregistered, got %+v", last)
	}
}

func TestRecover_AfterGone_Rejected(t *testing.T) {
	r, clock, _ := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	clock.Advance(91 * time.Second) // -> SUSPECTED
	r.tickOnce()
	clock.Advance(301 * time.Second) // > recoverWindow -> RECOVERING
	r.tickOnce()
	clock.Advance(301 * time.Second) // > recoverTimeout -> GONE
	r.tickOnce()
	if a, _ := r.Get("a1"); a.State != StateGone {
		t.Fatalf("state=%v want StateGone", a.State)
	}
	if err := r.Recover("a1", []string{"m1"}); err == nil {
		t.Fatal("Recover after GONE should error (must re-register)")
	}
}

func TestAging_FullChain_Active_Suspected_Recovering_Gone(t *testing.T) {
	r, clock, sub := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)

	clock.Advance(91 * time.Second)
	r.tickOnce()
	if a, _ := r.Get("a1"); a.State != StateSuspected {
		t.Fatalf("after 91s want Suspected, got %v", a.State)
	}

	clock.Advance(301 * time.Second) // > recoverWindow (300)
	r.tickOnce()
	if a, _ := r.Get("a1"); a.State != StateRecovering {
		t.Fatalf("after +301s want Recovering, got %v", a.State)
	}

	clock.Advance(301 * time.Second) // > recoverTimeout (300)
	r.tickOnce()
	if a, _ := r.Get("a1"); a.State != StateGone {
		t.Fatalf("after +301s want Gone, got %v", a.State)
	}
	// assert OnAgentGone broadcast happened
	last := sub.Events[len(sub.Events)-1]
	if last.Type != "gone" {
		t.Fatalf("want gone broadcast, got %+v", last)
	}
}

func TestLazyRegister_HeartbeatUnknownAgent_CreatesActive(t *testing.T) {
	r, _, sub := newTestRegistry(t)
	_ = r.Heartbeat("never-registered", []string{"m1"}, []string{"s1"})
	if a, ok := r.Get("never-registered"); !ok || a.State != StateActive {
		t.Fatalf("lazy register failed: %+v ok=%v", a, ok)
	}
	if len(sub.Events) == 0 || sub.Events[0].Type != "active" {
		t.Fatalf("expected active broadcast, got %+v", sub.Events)
	}
}

func TestRecover_SuspectedAgent_TransitionsToActive(t *testing.T) {
	r, clock, _ := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	clock.Advance(91 * time.Second) // -> SUSPECTED
	r.tickOnce()
	if err := r.Recover("a1", []string{"m1"}); err != nil {
		t.Fatalf("recover from suspected should succeed: %v", err)
	}
	if a, _ := r.Get("a1"); a.State != StateActive {
		t.Fatalf("state=%v want Active after recover", a.State)
	}
}

func TestRecover_NotFound_Error(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if err := r.Recover("nope", []string{"m1"}); err == nil {
		t.Fatal("recover on unknown agent should error")
	}
}

func TestRegistry_All_ReturnsSnapshot(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Register("a2", []string{"m1"}, nil)
	all := r.All()
	if len(all) != 2 {
		t.Fatalf("All() len=%d want 2", len(all))
	}
	// must be a snapshot: mutating the returned slice must not affect the registry
	all[0].State = StateGone
	if a, _ := r.Get("a1"); a.State == StateGone {
		t.Fatal("All() must return a copy, not a live pointer")
	}
}

func TestRegistry_Unsubscribe_StopsBroadcasts(t *testing.T) {
	r, _, sub := newTestRegistry(t)
	r.Unsubscribe(sub)
	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	if len(sub.Events) != 0 {
		t.Fatalf("unsubscribed subscriber should not receive events, got %d", len(sub.Events))
	}
}

func TestRegistry_SetAgentStateForTesting_ForceState(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	r.SetAgentStateForTesting("a1", StateSuspected)
	if a, _ := r.Get("a1"); a.State != StateSuspected {
		t.Fatalf("forced state=%v want Suspected", a.State)
	}
}
