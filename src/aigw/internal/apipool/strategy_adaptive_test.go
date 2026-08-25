/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_adaptive_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAdaptive_LowLatencyHighTokenWins(t *testing.T) {
	s := NewState(testCfg())
	deps := []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", TPM: 1000, RPM: 100},
		{ID: "b", Provider: "openai", APIKey: "k-b", TPM: 1000, RPM: 100},
	}
	// a: high latency, low token remaining
	s.RecordSuccess(deps[0].StateKey(), false, 2*time.Second, 950)
	// b: low latency, high token remaining
	s.RecordSuccess(deps[1].StateKey(), false, 100*time.Millisecond, 50)
	st := newAdaptive(s, nil)
	st.rng = newSafeRand(1)
	assert.Equal(t, "b", st.Select(deps, &Context{Stream: false}).ID)
}

func TestAdaptive_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newAdaptive(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}

func TestAdaptive_UnlimitedQuotaScoresOne(t *testing.T) {
	s := NewState(testCfg())
	deps := []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a"}, // TPM/RPM = 0 (unlimited)
	}
	st := newAdaptive(s, nil)
	got := st.Select(deps, &Context{})
	assert.Equal(t, "a", got.ID)
}
