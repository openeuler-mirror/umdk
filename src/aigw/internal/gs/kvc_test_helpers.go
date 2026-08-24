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
)

// fakeClock is a gs-local controllable clock for KvcSessionManager tests.
// It implements agentregistry.Clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (fc *fakeClock) Now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.t
}

func (fc *fakeClock) Advance(d time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.t = fc.t.Add(d)
}

// Compile-time check: fakeClock satisfies agentregistry.Clock.
var _ agentregistry.Clock = (*fakeClock)(nil)

// MockKvcHintSender is a test-only KvcHintSender that records sent hints and
// returns a configurable ack. Used by KvcSessionManager / HintDispatcher tests.
type MockKvcHintSender struct {
	mu        sync.Mutex
	Sent      []*KvcHint
	AckPolicy func(*KvcHint) *HintAck
	Delay     time.Duration
}

func (m *MockKvcHintSender) Send(ctx context.Context, hint *KvcHint) (*HintAck, error) {
	m.mu.Lock()
	m.Sent = append(m.Sent, hint)
	policy := m.AckPolicy
	m.mu.Unlock()
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if policy != nil {
		return policy(hint), nil
	}
	return &HintAck{HintID: hint.HintID, Status: AckAccepted, AcceptedHashes: flattenHashes(hint)}, nil
}

func (m *MockKvcHintSender) SentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Sent)
}

func flattenHashes(hint *KvcHint) []int64 {
	var out []int64
	for _, s := range hint.Sessions {
		out = append(out, s.BlockHashes...)
	}
	return out
}
