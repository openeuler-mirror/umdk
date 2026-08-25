/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_simple_shuffle_test.go
package apipool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func depList() []*Deployment {
	return []*Deployment{
		{ID: "a", Provider: "openai", APIKey: "k-a"},
		{ID: "b", Provider: "openai", APIKey: "k-b"},
		{ID: "c", Provider: "openai", APIKey: "k-c"},
	}
}

func TestSimpleShuffle_PicksAvailable(t *testing.T) {
	s := NewState(testCfg())
	st := newSimpleShuffle(s)
	st.rng = newSafeRand(1)
	deps := depList()
	got := st.Select(deps, &Context{})
	assert.NotNil(t, got)
}

func TestSimpleShuffle_SkipsCooldown(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	// put a and b into cooldown
	for _, d := range deps[:2] {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newSimpleShuffle(s)
	st.rng = newSafeRand(1)
	for i := 0; i < 20; i++ {
		got := st.Select(deps, &Context{})
		assert.Equal(t, "c", got.ID, "only c is healthy")
	}
}

func TestSimpleShuffle_AllCooldownReturnsNil(t *testing.T) {
	s := NewState(testCfg())
	deps := depList()
	for _, d := range deps {
		for i := 0; i < 3; i++ {
			s.RecordFailure(d.StateKey(), ErrServer5xx)
		}
	}
	st := newSimpleShuffle(s)
	assert.Nil(t, st.Select(deps, &Context{}))
}

func TestFactory_CreatesSimpleShuffle(t *testing.T) {
	s := NewState(testCfg())
	st, err := CreateStrategy("simple-shuffle", s, nil)
	assert.NoError(t, err)
	assert.Equal(t, "simple-shuffle", st.Name())
}

func TestFactory_UnknownStrategy(t *testing.T) {
	s := NewState(testCfg())
	_, err := CreateStrategy("no-such", s, nil)
	assert.Error(t, err)
}
