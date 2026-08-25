/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package agentregistry

import (
	"sync"
	"testing"
	"time"
)

type fakeRedis struct {
	mu   sync.Mutex
	data map[string]map[string]string
}

func newFakeRedis() *fakeRedis { return &fakeRedis{data: make(map[string]map[string]string)} }

func (f *fakeRedis) HSet(key string, fields map[string]string, ttl int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	f.data[key] = cp
	return nil
}
func (f *fakeRedis) HGetAll(key string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string)
	for k, v := range f.data[key] {
		cp[k] = v
	}
	return cp, nil
}
func (f *fakeRedis) HDel(key string, fields ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

func TestPersistence_SaveAndRestore(t *testing.T) {
	clock := NewFakeClock(time.UnixMilli(1000000))
	redis := newFakeRedis()
	cfg := RegistryConfig{HeartbeatTimeoutSec: 90, RecoverWindowSec: 300, RecoverTimeoutSec: 300, GoneFinalizeSec: 3600}
	r := NewRegistry(clock, cfg, WithRedis(redis)).(*agentRegistry)
	r.Start()
	t.Cleanup(r.Stop)

	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)

	// simulate AIGW restart: new registry loads from same fakeRedis
	r2 := NewRegistry(clock, cfg, WithRedis(redis)).(*agentRegistry)
	r2.Start()
	t.Cleanup(r2.Stop)
	r2.loadFromRedis()
	if a, ok := r2.Get("a1"); !ok || a.State != StateActive {
		t.Fatalf("after reload state=%v ok=%v", a, ok)
	}
}

func TestGone_Finalize_RemovesAfterGrace(t *testing.T) {
	clock := NewFakeClock(time.UnixMilli(1000000))
	redis := newFakeRedis()
	cfg := RegistryConfig{HeartbeatTimeoutSec: 90, RecoverWindowSec: 1, RecoverTimeoutSec: 1, GoneFinalizeSec: 1}
	r := NewRegistry(clock, cfg, WithRedis(redis)).(*agentRegistry)
	r.Start()
	t.Cleanup(r.Stop)

	_ = r.Register("a1", []string{"m1"}, nil)
	_ = r.Heartbeat("a1", []string{"m1"}, nil)
	clock.Advance(91 * time.Second)
	r.tickOnce() // -> Suspected
	clock.Advance(2 * time.Second)
	r.tickOnce() // -> Recovering
	clock.Advance(2 * time.Second)
	r.tickOnce() // -> Gone
	// advance past goneFinalize + tick
	clock.Advance(2 * time.Second)
	r.tickOnce()
	if _, ok := r.Get("a1"); ok {
		t.Fatal("agent should be finalized (removed) after goneFinalizeSec")
	}
}
