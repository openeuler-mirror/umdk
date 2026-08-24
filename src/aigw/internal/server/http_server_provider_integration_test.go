/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/proxy"

	"github.com/stretchr/testify/assert"
)

// newProviderServer builds a real AigwManager+HttpServer for the given schedulers.
// Cooldown counting stays deterministic regardless of proxy-level retries: each
// forwardToProvider call records exactly one OnFailure based on the final outcome.
func newProviderServer(t *testing.T, gsConfigs []base.GlobalSchedulerConfig) (*HttpServer, *core.AigwManager) {
	cfg := &base.AigwConfig{GsConfigs: gsConfigs}
	m, err := core.NewAigwManager(cfg)
	assert.NoError(t, err)
	assert.NoError(t, m.Init())
	t.Cleanup(m.Uninit)
	pm := proxy.NewProxyManager(context.Background(), nil)
	return NewHttpServer(m, "127.0.0.1", "0", pm), m
}

func providerGS(model string, deps []base.DeploymentConfig) base.GlobalSchedulerConfig {
	return base.GlobalSchedulerConfig{
		Model: model, Mode: "provider",
		ProviderPool: &base.ProviderPoolConfig{
			Strategy:    "simple-shuffle",
			Cooldown:    &base.CooldownConfig{FailureThreshold: 3, DurationSec: 1, RateLimitDurationSec: 1, Auth401FloorSec: 1},
			Retry:       &base.RetryConfig{MaxFailoverEndpoints: 3, MaxRetriesPerEndpoint: 0},
			Deployments: deps,
		},
	}
}

func dep(id, provider, apiBase string) base.DeploymentConfig {
	return base.DeploymentConfig{ID: id, Provider: provider, APIBase: apiBase, APIKey: "sk-test"}
}

func chatReq(t *testing.T, model string, stream bool) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"model": model, "stream": stream, "messages": []any{}})
	req := httptest.NewRequest("POST", "/aigw/v1/openai/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return req
}

func okUpstream(tokens int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[],"usage":{"total_tokens":%d}}`, tokens)
	}))
}

func sseUpstream(onHit func(), chunks ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onHit != nil {
			onHit()
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, c := range chunks {
			fmt.Fprintf(w, "data: %s\n\n", c)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
}

func TestProvider_TwoEndpointFailover(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	backup := okUpstream(42)
	defer backup.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{
			dep("primary", "openai", primary.URL),
			dep("backup", "openai", backup.URL),
		}),
	})

	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", false))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "total_tokens")
}

func TestProvider_CooldownThenRecovery(t *testing.T) {
	var healthy atomic.Bool // false => 500, true => 200
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[],"usage":{"total_tokens":7}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{dep("a", "openai", upstream.URL)}),
	})

	// Three failures trip the cooldown (FailureThreshold=3).
	for i := 0; i < 3; i++ {
		s.forwardChatCompletions(httptest.NewRecorder(), chatReq(t, "gpt-4o-mini", false))
	}
	// Upstream is now healthy, but the single endpoint is still cooling down.
	healthy.Store(true)
	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", false))
	assert.Equal(t, http.StatusBadGateway, rec.Code)

	// After the cooldown window (DurationSec=1) the endpoint recovers lazily.
	time.Sleep(1200 * time.Millisecond)
	rec = httptest.NewRecorder()
	s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", false))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestProvider_ClientErrorPassthroughNoFailover(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer upstream.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{dep("a", "openai", upstream.URL)}),
	})

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", false))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}
	// 400 does not count toward cooldown, so both requests reach the upstream.
	assert.Equal(t, int32(2), hits.Load())
}

func TestProvider_FailoverThenStream(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	backup := sseUpstream(nil, `{"delta":"hello"}`, "[DONE]")
	defer backup.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{
			dep("primary", "openai", primary.URL),
			dep("backup", "openai", backup.URL),
		}),
	})

	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", true))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "hello")
}

func TestProvider_StreamNoFailoverAfterStart(t *testing.T) {
	var hits atomic.Int32
	onHit := func() { hits.Add(1) }
	a := sseUpstream(onHit, `{"delta":"hi"}`, "[DONE]")
	defer a.Close()
	b := sseUpstream(onHit, `{"delta":"hi"}`, "[DONE]")
	defer b.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{
			dep("a", "openai", a.URL),
			dep("b", "openai", b.URL),
		}),
	})

	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", true))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "hi")
	// A successful stream uses exactly one endpoint; no failover after start.
	assert.Equal(t, int32(1), hits.Load())
}

func TestProvider_ContextCancelNoWrite(t *testing.T) {
	upstream := okUpstream(5)
	defer upstream.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{dep("a", "openai", upstream.URL)}),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := chatReq(t, "gpt-4o-mini", false).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.forwardChatCompletions(rec, req)
	// Loop guard returns before writing any failover/error response.
	assert.Equal(t, 0, rec.Body.Len())
}

func TestProvider_ConcurrentRequests(t *testing.T) {
	upstream := okUpstream(3)
	defer upstream.Close()

	s, _ := newProviderServer(t, []base.GlobalSchedulerConfig{
		providerGS("gpt-4o-mini", []base.DeploymentConfig{dep("a", "openai", upstream.URL)}),
	})

	const n = 100
	var ok int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			s.forwardChatCompletions(rec, chatReq(t, "gpt-4o-mini", false))
			if rec.Code == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(n), ok)
}
