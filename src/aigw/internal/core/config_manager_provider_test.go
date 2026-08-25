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

func validProviderGsc() *base.GlobalSchedulerConfig {
	return &base.GlobalSchedulerConfig{
		Model: "gpt-4o-mini",
		Mode:  "provider",
		ProviderPool: &base.ProviderPoolConfig{
			Strategy: "adaptive",
			Deployments: []base.DeploymentConfig{
				{ID: "a", Provider: "openai", APIBase: "https://api.openai.com", APIKey: "sk-x"},
			},
		},
	}
}

func TestValidateProviderPool_OK(t *testing.T) {
	assert.NoError(t, validateProviderPool(validProviderGsc()))
}

func TestValidateProviderPool_EmptyDeployments(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments = nil
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_NilPool(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool = nil
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_UnknownProvider(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments[0].Provider = "no-such"
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_CustomNeedsAuthHeader(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Deployments[0].Provider = "custom"
	gsc.ProviderPool.Deployments[0].AuthHeaderName = ""
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateProviderPool_BadStrategy(t *testing.T) {
	gsc := validProviderGsc()
	gsc.ProviderPool.Strategy = "no-such"
	assert.Error(t, validateProviderPool(gsc))
}

func TestValidateMode_InvalidLiteral(t *testing.T) {
	gsc := &base.GlobalSchedulerConfig{Model: "m", Mode: "bogus"}
	assert.Error(t, validateModeField(gsc))
}

func TestValidateMode_EmptyIsInstance(t *testing.T) {
	gsc := &base.GlobalSchedulerConfig{Model: "m", Mode: ""}
	assert.NoError(t, validateModeField(gsc))
}
