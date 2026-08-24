/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package core

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/apipool"
	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

// Two models configured with the SAME provider+apiKey must share one StateKey,
// so token usage recorded through one model's pool decrements the quota seen by
// the other (cross-pool shared quota, spec §9).
func TestAigwManager_CrossPoolSharedQuota(t *testing.T) {
	cfg := &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model: "gpt-4o-mini", Mode: "provider",
				ProviderPool: &base.ProviderPoolConfig{
					Strategy: "simple-shuffle",
					Deployments: []base.DeploymentConfig{
						{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-shared", TPM: 1000},
					},
				},
			},
			{
				Model: "gpt-4o", Mode: "provider",
				ProviderPool: &base.ProviderPoolConfig{
					Strategy: "simple-shuffle",
					Deployments: []base.DeploymentConfig{
						{ID: "b", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-shared", TPM: 1000},
					},
				},
			},
		},
	}
	m, err := NewAigwManager(cfg)
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	defer m.Uninit()

	key := (&apipool.Deployment{Provider: "openai", APIKey: "sk-shared"}).StateKey()
	state := m.ApiPoolStateForTest()
	assert.Equal(t, 1000, state.RemainingTPM(key, 1000))

	miniPool := m.GetApiPool("gpt-4o-mini")
	depA := miniPool.Select(&apipool.Context{Model: "gpt-4o-mini"})
	assert.NotNil(t, depA)
	miniPool.OnSuccess(depA, time.Millisecond, 100)
	assert.Equal(t, 900, state.RemainingTPM(key, 1000))

	fullPool := m.GetApiPool("gpt-4o")
	depB := fullPool.Select(&apipool.Context{Model: "gpt-4o"})
	assert.NotNil(t, depB)
	fullPool.OnSuccess(depB, time.Millisecond, 100)
	assert.Equal(t, 800, state.RemainingTPM(key, 1000))
}
