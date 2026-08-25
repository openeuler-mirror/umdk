/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/pool_manager_test.go
package apipool

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func poolCfg() *base.ProviderPoolConfig {
	return &base.ProviderPoolConfig{
		Strategy: "simple-shuffle",
		Cooldown: testCfg(),
		Retry:    &base.RetryConfig{MaxFailoverEndpoints: 3, MaxRetriesPerEndpoint: 2},
		Deployments: []base.DeploymentConfig{
			{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "k-a", TPM: 1000, RPM: 100},
			{ID: "b", Provider: "deepseek", APIBase: "https://api.deepseek.com", APIKey: "k-b"},
		},
	}
}

func TestNewApiPoolManager_OK(t *testing.T) {
	s := NewState(testCfg())
	p, err := NewApiPoolManager("gpt-4o-mini", poolCfg(), s, NewDefaultRegistry())
	assert.NoError(t, err)
	assert.Equal(t, 3, p.MaxFailoverEndpoints())
	assert.Len(t, p.deployments, 2)
}

func TestNewApiPoolManager_UnknownProviderFails(t *testing.T) {
	s := NewState(testCfg())
	cfg := poolCfg()
	cfg.Deployments[0].Provider = "no-such"
	_, err := NewApiPoolManager("m", cfg, s, NewDefaultRegistry())
	assert.Error(t, err)
}

func TestNewApiPoolManager_UnknownStrategyFails(t *testing.T) {
	s := NewState(testCfg())
	cfg := poolCfg()
	cfg.Strategy = "no-such"
	_, err := NewApiPoolManager("m", cfg, s, NewDefaultRegistry())
	assert.Error(t, err)
}

func TestApiPoolManager_SelectExceptSkipsTried(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	first := p.Select(&Context{})
	assert.NotNil(t, first)
	tried := map[StateKey]bool{first.StateKey(): true}
	second := p.SelectExcept(&Context{}, tried)
	assert.NotNil(t, second)
	assert.NotEqual(t, first.ID, second.ID)
}

func TestApiPoolManager_OnFailureEntersCooldown(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	dep := p.deployments[0]
	for i := 0; i < 3; i++ {
		p.OnFailure(dep, 500, nil)
	}
	assert.False(t, s.IsAvailable(dep.StateKey()))
}

func TestApiPoolManager_OnSuccessRecordsLatency(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	dep := p.deployments[0]
	p.OnSuccess(dep, 200*time.Millisecond, 100)
	assert.InDelta(t, 0.2, s.AvgLatency(dep.StateKey(), false), 1e-9)
	assert.Equal(t, 900, s.RemainingTPM(dep.StateKey(), dep.TPM))
}

func TestApiPoolManager_StreamSuccessNoDoubleRPM(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	dep := p.deployments[0]
	p.OnFirstChunk(dep, 50*time.Millisecond) // records TTFT + 1 RPM
	p.OnStreamSuccess(dep, 100)              // records tokens only, no RPM
	assert.Equal(t, 99, s.RemainingRPM(dep.StateKey(), dep.RPM), "stream counts as one request")
	assert.Equal(t, 900, s.RemainingTPM(dep.StateKey(), dep.TPM))
	assert.InDelta(t, 0.05, s.AvgLatency(dep.StateKey(), true), 1e-9)
}

func TestApiPoolManager_GetAdapter(t *testing.T) {
	s := NewState(testCfg())
	p, _ := NewApiPoolManager("m", poolCfg(), s, NewDefaultRegistry())
	a, err := p.GetAdapter("openai")
	assert.NoError(t, err)
	assert.NotNil(t, a)
}
