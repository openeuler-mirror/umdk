/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_token_aware_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func tpmDeps() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", TPM: 1000},
		{ID: "b", Provider: "openai", APIKey: "k-b", TPM: 1000},
	}
}

func TestTokenAware_PicksMostRemaining(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 800) // a: 200 left
	s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 100) // b: 900 left
	st := newTokenAware(s, map[string]any{"tokenThreshold": 50})
	st.rng = newSafeRand(1)
	assert.Equal(t, "b", st.Select(deps, &Context{}).ID)
}

func TestTokenAware_AllBelowThresholdFallsBack(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 990) // 10 left
	s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 980) // 20 left
	st := newTokenAware(s, map[string]any{"tokenThreshold": 100})
	st.rng = newSafeRand(1)
	got := st.Select(deps, &Context{})
	assert.NotNil(t, got, "falls back to shuffle among available")
}

func TestTokenAware_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := tpmDeps()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newTokenAware(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
