/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// Package agentregistry tracks agent lifecycle (register/heartbeat/suspect/recover/gone)
// and broadcasts state transitions to subscribers (per-model KvcSessionManager).
// It does NOT import internal/gs (avoids import cycle). Subscribers implement Subscriber.
package agentregistry

import "time"

// AgentState is the lifecycle state of an agent.
type AgentState int

const (
	StateRegistered AgentState = iota // transient after register, awaiting first heartbeat
	StateActive                       // healthy, receiving heartbeats
	StateSuspected                    // heartbeat timeout, may have crashed
	StateRecovering                   // suspect window elapsed, awaiting recovery
	StateGone                         // final, no recovery in window
)

// Agent is the registry record for one agent.
type Agent struct {
	AgentID         string
	State           AgentState
	Models          []string
	LastHeartbeatAt time.Time
	RegisteredAt    time.Time
	SuspectedAt     *time.Time
	RecoveringAt    *time.Time
	GoneAt          *time.Time
	Metadata        map[string]string
	SessionIDs      []string
	Version         int64 // optimistic concurrency for Redis
}

// Subscriber receives agent state transitions. Implemented by per-model KvcSessionManager
// via an adapter in internal/gs/kvc_subscriber.go.
type Subscriber interface {
	OnAgentActive(agentID string, models []string)
	OnAgentSuspected(agentID string)
	OnAgentRecovered(agentID string, models []string)
	OnAgentGone(agentID string)
	OnAgentUnregistered(agentID string)
}

// Registry is the interface KvcSessionManager depends on (inverted, to avoid gs import).
type Registry interface {
	Register(agentID string, models []string, metadata map[string]string) error
	Heartbeat(agentID string, models []string, sessionIDs []string) error
	Unregister(agentID string) error
	Recover(agentID string, models []string) error
	Get(agentID string) (*Agent, bool)
	// All returns a snapshot of all registered agents (debug endpoint).
	All() []*Agent
	Subscribe(sub Subscriber)
	Unsubscribe(sub Subscriber)
	Start()
	Stop()
	// SetAgentStateForTesting forces an agent's state (test hook for aging tests).
	SetAgentStateForTesting(agentID string, state AgentState)
}

// Clock abstracts time for aging-loop tests.
type Clock interface {
	Now() time.Time
}

// realClock is the production clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// RealClock is the exported production clock (used by AigwManager wiring).
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
