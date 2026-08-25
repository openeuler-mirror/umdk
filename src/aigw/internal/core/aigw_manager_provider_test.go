/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package core

import (
	"testing"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
)

func providerConfig() *base.AigwConfig {
	return &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model: "gpt-4o-mini",
				Mode:  "provider",
				ProviderPool: &base.ProviderPoolConfig{
					Strategy: "simple-shuffle",
					Deployments: []base.DeploymentConfig{
						{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-x"},
					},
				},
			},
		},
	}
}

func TestAigwManager_GetModelMode(t *testing.T) {
	m, err := NewAigwManager(providerConfig())
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	defer m.Uninit()

	mode, err := m.GetModelMode("gpt-4o-mini")
	assert.NoError(t, err)
	assert.Equal(t, "provider", mode)

	_, err = m.GetModelMode("unknown-model")
	assert.Error(t, err)
}

func TestAigwManager_GetApiPool(t *testing.T) {
	m, _ := NewAigwManager(providerConfig())
	assert.NoError(t, m.Init())
	defer m.Uninit()
	assert.NotNil(t, m.GetApiPool("gpt-4o-mini"))
	assert.Nil(t, m.GetApiPool("unknown-model"))
}

func TestAigwManager_SdkModeProviderFailFast(t *testing.T) {
	m, err := NewAigwManager(providerConfig(), WithRuntimeMode(base.SdkMode))
	assert.NoError(t, err)
	assert.Error(t, m.Init(), "SdkMode + provider config must fail-fast")
}
