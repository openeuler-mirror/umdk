/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/state_cooldown_test.go
package apipool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState_EntersCooldownAfterThreshold(t *testing.T) {
	s := NewState(testCfg()) // FailureThreshold=3
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	assert.True(t, s.IsAvailable(k))
	s.RecordFailure(k, ErrServer5xx)
	s.RecordFailure(k, ErrServer5xx)
	assert.True(t, s.IsAvailable(k), "2 fails < threshold")
	s.RecordFailure(k, ErrServer5xx)
	assert.False(t, s.IsAvailable(k), "3 fails >= threshold -> cooldown")
}

func TestState_LazyRecovery(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrServer5xx)
	}
	assert.False(t, s.IsAvailable(k))
	// force cooldownUntil into the past
	s.forceCooldownUntil(k, 0)
	assert.True(t, s.IsAvailable(k), "expired cooldown recovers lazily")
}

func TestState_404DoesNotCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 5; i++ {
		s.RecordFailure(k, ErrNotFound)
	}
	assert.True(t, s.IsAvailable(k), "404 never triggers cooldown")
}

func TestState_4xxDoesNotCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 5; i++ {
		s.RecordFailure(k, ErrClient4xx)
	}
	assert.True(t, s.IsAvailable(k))
}

func TestState_SuccessClearsFailCount(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordFailure(k, ErrServer5xx)
	s.RecordFailure(k, ErrServer5xx)
	s.RecordSuccess(k, false, 0, 0)
	s.RecordFailure(k, ErrServer5xx)
	assert.True(t, s.IsAvailable(k), "success reset count, 1 fail < threshold")
}
