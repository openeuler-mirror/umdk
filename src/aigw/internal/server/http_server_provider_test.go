/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/proxy"

	"github.com/stretchr/testify/assert"
)

func buildProviderServer(t *testing.T, upstreamURL string) *HttpServer {
	cfg := &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{{
			Model: "gpt-4o-mini", Mode: "provider",
			ProviderPool: &base.ProviderPoolConfig{
				Strategy: "simple-shuffle",
				Cooldown: &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300},
				Retry:    &base.RetryConfig{MaxFailoverEndpoints: 3, MaxRetriesPerEndpoint: 0},
				Deployments: []base.DeploymentConfig{
					{ID: "a", Provider: "openai", APIBase: upstreamURL, APIKey: "sk-test"},
				},
			},
		}},
	}
	m, err := core.NewAigwManager(cfg)
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	t.Cleanup(m.Uninit)
	return NewHttpServer(m, "127.0.0.1", "0", proxy.NewProxyManager(context.Background(), nil))
}

func TestForwardToProvider_NonStreamSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[],"usage":{"total_tokens":42}}`))
	}))
	defer upstream.Close()

	s := buildProviderServer(t, upstream.URL)
	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "messages": []any{}})
	req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	s.forwardChatCompletions(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "total_tokens")
}

func TestForwardToProvider_AllCooldown502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	s := buildProviderServer(t, upstream.URL)

	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "messages": []any{}})
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		s.forwardChatCompletions(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}
