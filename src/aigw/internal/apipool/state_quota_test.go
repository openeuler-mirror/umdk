/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/state_quota_test.go
package apipool

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func testCfg() *base.CooldownConfig {
	return &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300}
}

func TestState_RemainingTPM_Unlimited(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	assert.Equal(t, intMax, s.RemainingTPM(k, 0)) // tpm=0 means unlimited
}

func TestState_RemainingTPM_TracksTokens(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 100*time.Millisecond, 400)
	assert.Equal(t, 600, s.RemainingTPM(k, 1000))
}

func TestState_RemainingRPM_TracksRequests(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 100*time.Millisecond, 10)
	s.RecordSuccess(k, false, 100*time.Millisecond, 10)
	assert.Equal(t, 498, s.RemainingRPM(k, 500))
}

func TestState_RemainingTPM_NeverNegative(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, time.Millisecond, 2000)
	assert.Equal(t, 0, s.RemainingTPM(k, 1000))
}
