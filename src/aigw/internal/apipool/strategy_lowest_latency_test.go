/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_lowest_latency_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLowestLatency_PicksLowestTotal(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	s.RecordSuccess(deps[0].StateKey(), false, 500*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 1)
	s.RecordSuccess(deps[2].StateKey(), false, 300*time.Millisecond, 1)
	st := newLowestLatency(s, map[string]any{"explorationRatio": 0.0})
	st.rng = newSafeRand(1)
	assert.Equal(t, "b", st.Select(deps, &Context{Stream: false}).ID)
}

func TestLowestLatency_StreamUsesTTFT(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	// dep a: low TTFT, high total; dep b: high TTFT, low total
	s.RecordSuccess(deps[0].StateKey(), true, 50*time.Millisecond, 1)
	s.RecordSuccess(deps[0].StateKey(), false, 900*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), true, 400*time.Millisecond, 1)
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 1)
	s.RecordSuccess(deps[2].StateKey(), true, 600*time.Millisecond, 1)
	st := newLowestLatency(s, map[string]any{"explorationRatio": 0.0})
	st.rng = newSafeRand(1)
	assert.Equal(t, "a", st.Select(deps, &Context{Stream: true}).ID, "stream picks lowest TTFT")
}

func TestLowestLatency_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newLowestLatency(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
