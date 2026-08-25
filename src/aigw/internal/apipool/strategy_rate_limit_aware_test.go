/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_rate_limit_aware_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func rpmDeps() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a", RPM: 10},
		{ID: "b", Provider: "openai", APIKey: "k-b", RPM: 10},
	}
}

func TestRateLimitAware_PicksMostRemaining(t *testing.T) {
	s := NewState(testCfg())
	deps := rpmDeps()
	for i := 0; i < 8; i++ { // a used 8 -> 2 left
		s.RecordSuccess(deps[0].StateKey(), false, time.Millisecond, 1)
	}
	for i := 0; i < 2; i++ { // b used 2 -> 8 left
		s.RecordSuccess(deps[1].StateKey(), false, time.Millisecond, 1)
	}
	st := newRateLimitAware(s, map[string]any{"rpmThreshold": 1})
	st.rng = newSafeRand(1)
	assert.Equal(t, "b", st.Select(deps, &Context{}).ID)
}

func TestRateLimitAware_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := rpmDeps()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newRateLimitAware(s, nil)
	assert.Nil(t, st.Select(deps, &Context{}))
}
