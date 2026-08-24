/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package agentregistry

import (
	"sync"
	"time"
)

// FakeClock is a controllable clock for tests.
type FakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{t: start} }

func (fc *FakeClock) Now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.t
}

func (fc *FakeClock) Advance(d time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.t = fc.t.Add(d)
}

// AgentEvent is a recorded state-transition notification (test-only).
type AgentEvent struct {
	Type    string // "active"|"suspected"|"recovered"|"gone"|"unregistered"
	AgentID string
	Models  []string
}

// InMemoryAgentRegistrySubscriber records all broadcasts for test assertions.
type InMemoryAgentRegistrySubscriber struct {
	mu     sync.Mutex
	Events []AgentEvent
}

func (s *InMemoryAgentRegistrySubscriber) OnAgentActive(id string, m []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, AgentEvent{Type: "active", AgentID: id, Models: m})
}
func (s *InMemoryAgentRegistrySubscriber) OnAgentSuspected(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, AgentEvent{Type: "suspected", AgentID: id})
}
func (s *InMemoryAgentRegistrySubscriber) OnAgentRecovered(id string, m []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, AgentEvent{Type: "recovered", AgentID: id, Models: m})
}
func (s *InMemoryAgentRegistrySubscriber) OnAgentGone(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, AgentEvent{Type: "gone", AgentID: id})
}
func (s *InMemoryAgentRegistrySubscriber) OnAgentUnregistered(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, AgentEvent{Type: "unregistered", AgentID: id})
}
