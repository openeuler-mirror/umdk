/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/state_auth_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// cooldownRemainingSec returns seconds until the entry's cooldown expires.
func (s *State) cooldownRemainingSec(k StateKey) int64 {
	e := s.getOrCreate(k)
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cooldownUntil - time.Now().Unix()
}

func TestState_401ExponentialBackoff(t *testing.T) {
	s := NewState(testCfg()) // threshold=3, auth floor=300s
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}

	// Need >= threshold consecutive fails to enter cooldown each round.
	expect := []int64{300, 600, 1200, 2400, 4800} // 5/10/20/40/80 min
	for round, want := range expect {
		for i := 0; i < 3; i++ {
			s.RecordFailure(k, ErrAuth)
		}
		got := s.cooldownRemainingSec(k)
		assert.InDelta(t, want, got, 2, "round %d", round)
		// recover for next round without clearing auth attempts: expire cooldown
		s.forceCooldownUntil(k, 0)
		assert.True(t, s.IsAvailable(k))
	}
}

func TestState_SuccessResetsAuthAttempts(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrAuth)
	}
	assert.InDelta(t, int64(300), s.cooldownRemainingSec(k), 2)
	s.forceCooldownUntil(k, 0)
	_ = s.IsAvailable(k)
	s.RecordSuccess(k, false, 0, 0) // clears auth401Attempts
	for i := 0; i < 3; i++ {
		s.RecordFailure(k, ErrAuth)
	}
	assert.InDelta(t, int64(300), s.cooldownRemainingSec(k), 2, "back to floor after success")
}
