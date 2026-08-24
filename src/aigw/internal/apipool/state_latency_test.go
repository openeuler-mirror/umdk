/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/state_latency_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestState_FirstSampleAssignedDirectly(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 200*time.Millisecond, 10)
	assert.InDelta(t, 0.2, s.AvgLatency(k, false), 1e-9)
}

func TestState_EMAWithAlpha02(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, false, 200*time.Millisecond, 10) // avg=0.2
	s.RecordSuccess(k, false, 400*time.Millisecond, 10) // 0.2*0.4 + 0.8*0.2 = 0.24
	assert.InDelta(t, 0.24, s.AvgLatency(k, false), 1e-9)
}

func TestState_StreamRecordsTTFTSeparately(t *testing.T) {
	s := NewState(testCfg())
	k := StateKey{Provider: "openai", KeyFingerprint: "abc"}
	s.RecordSuccess(k, true, 50*time.Millisecond, 10)   // TTFT bucket
	s.RecordSuccess(k, false, 900*time.Millisecond, 10) // total bucket
	assert.InDelta(t, 0.05, s.AvgLatency(k, true), 1e-9)
	assert.InDelta(t, 0.9, s.AvgLatency(k, false), 1e-9)
}
