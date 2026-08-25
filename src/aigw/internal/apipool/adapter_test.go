/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/adapter_test.go
package apipool

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenAICompatAdapter_BuildURL(t *testing.T) {
	a := newOpenAICompatAdapter("openai")
	dep := &Deployment{APIBase: "https://api.openai.com", Provider: "openai"}
	assert.Equal(t, "https://api.openai.com/v1/chat/completions",
		a.BuildURL(dep, "/v1/chat/completions", false))
}

func TestOpenAICompatAdapter_InjectAuthBearer(t *testing.T) {
	a := newOpenAICompatAdapter("openai")
	dep := &Deployment{APIKey: "sk-abc", Provider: "openai"}
	h := http.Header{}
	a.InjectAuth(h, dep)
	assert.Equal(t, "Bearer sk-abc", h.Get("Authorization"))
}

func TestOpenAICompatAdapter_CustomAuthHeader(t *testing.T) {
	a := newOpenAICompatAdapter("custom")
	dep := &Deployment{APIKey: "k1", Provider: "custom", AuthHeaderName: "X-Api-Key", AuthHeaderPrefix: ""}
	h := http.Header{}
	a.InjectAuth(h, dep)
	assert.Equal(t, "k1", h.Get("X-Api-Key"))
	assert.Empty(t, h.Get("Authorization"))
}

func TestRegistry_GetKnownProvider(t *testing.T) {
	r := NewDefaultRegistry()
	a, err := r.Get("openai")
	assert.NoError(t, err)
	assert.NotNil(t, a)
}

func TestRegistry_GetUnknownProvider(t *testing.T) {
	r := NewDefaultRegistry()
	_, err := r.Get("no-such-provider")
	assert.Error(t, err)
}

func TestRegistry_DefaultProvidersRegistered(t *testing.T) {
	r := NewDefaultRegistry()
	for _, p := range []string{"openai", "vllm", "deepseek", "dashscope", "siliconflow", "zhipu", "custom"} {
		_, err := r.Get(p)
		assert.NoError(t, err, "provider %s should be registered", p)
	}
}

func TestDashscopeAdapter_BuildURLPrefix(t *testing.T) {
	r := NewDefaultRegistry()
	a, _ := r.Get("dashscope")
	dep := &Deployment{APIBase: "https://dashscope.aliyuncs.com", Provider: "dashscope"}
	assert.Equal(t, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
		a.BuildURL(dep, "/v1/chat/completions", false))
}
