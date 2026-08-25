/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Unit tests for proxy manager.
 * Create: 2026-05-11
 */

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsIdempotentMethod(t *testing.T) {
	idempotent := []string{"GET", "HEAD", "OPTIONS", "DELETE", "PUT", "TRACE"}
	nonIdempotent := []string{"POST", "PATCH"}

	for _, m := range idempotent {
		if !isIdempotentMethod(m) {
			t.Errorf("expected %s to be idempotent", m)
		}
	}

	for _, m := range nonIdempotent {
		if isIdempotentMethod(m) {
			t.Errorf("expected %s to be non-idempotent", m)
		}
	}

	// Case insensitive
	if !isIdempotentMethod("get") {
		t.Error("expected lowercase 'get' to be idempotent")
	}
}

func TestProxyManager_ForwardRequest_NonStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout: 5 * time.Second,
	})

	result, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/test",
		Headers:   http.Header{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if string(result.Body) == "" {
		t.Error("expected non-empty body")
	}
}

func TestProxyManager_ForwardRequest_Stream(t *testing.T) {
	sseData := "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(sseData))
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout: 5 * time.Second,
	})

	result, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/stream",
		Headers:   http.Header{},
		Stream:    true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StreamReader == nil {
		t.Fatal("expected StreamReader to be set")
	}

	event, err := result.StreamReader.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error reading event: %v", err)
	}
	if event.Data != `{"choices":[{"delta":{"content":"hello"}}]}` {
		t.Errorf("unexpected data: %q", event.Data)
	}
	result.StreamReader.Close()
}

func TestProxyManager_ForwardRequest_Retry(t *testing.T) {
	var attemptCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attemptCount.Add(1)
		if count < 3 {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout:           5 * time.Second,
		MaxRetry:          3,
		RetryBaseInterval: 10 * time.Millisecond,
		RetryMaxInterval:  50 * time.Millisecond,
	})

	result, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/retry",
		Headers:   http.Header{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if attemptCount.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attemptCount.Load())
	}
}

func TestProxyManager_ForwardRequest_StreamNoRetry(t *testing.T) {
	var attemptCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout:           5 * time.Second,
		MaxRetry:          3,
		RetryBaseInterval: 10 * time.Millisecond,
	})

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "POST",
		TargetURL: server.URL,
		Route:     "/stream",
		Headers:   http.Header{},
		Body:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Stream:    true,
	})

	// Should fail but not retry for streaming POST
	if err == nil {
		t.Error("expected error")
	}
	if attemptCount.Load() != 1 {
		t.Errorf("expected 1 attempt (no retry), got %d", attemptCount.Load())
	}
}

func TestProxyManager_ForwardRequest_CircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout:  5 * time.Second,
		MaxRetry: 0,
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 1,
			SuccessThreshold: 1,
			Timeout:          10 * time.Millisecond,
		},
	})

	pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/fail",
		Headers:   http.Header{},
	})

	stats := pm.GetCircuitBreakerStats()
	if stats.FailureCount != 1 {
		t.Errorf("expected 1 failure, got %d", stats.FailureCount)
	}

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/fail",
		Headers:   http.Header{},
	})
	if err == nil {
		t.Error("expected error when circuit breaker is open")
	}
}

func TestProxyManager_ForwardRequest_ContextCancel(t *testing.T) {
	blockCh := make(chan struct{})
	unblockCh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockCh
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
		close(unblockCh)
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout:           10 * time.Second,
		MaxRetry:          2,
		RetryBaseInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := pm.ForwardRequest(ctx, &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/slow",
		Headers:   http.Header{},
	})

	if err == nil {
		t.Error("expected context deadline exceeded error")
	}

	close(blockCh)
	<-unblockCh
}

func TestProxyManager_ForwardRequest_DPHeader(t *testing.T) {
	var receivedHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-data-parallel-rank")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	dpRank := 2
	pm := NewProxyManager(context.Background(), nil)

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/dp",
		Headers:   http.Header{},
		DpRank:    &dpRank,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedHeader != "2" {
		t.Errorf("expected X-data-parallel-rank '2', got %q", receivedHeader)
	}
}

func TestProxyManager_ForwardRequest_ForwardHeaders(t *testing.T) {
	authHeader := ""
	traceHeader := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		traceHeader = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), nil)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")
	headers.Set("X-Request-ID", "trace-abc")

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/headers",
		Headers:   headers,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if authHeader != "Bearer token123" {
		t.Errorf("expected Authorization header, got %q", authHeader)
	}
	if traceHeader != "trace-abc" {
		t.Errorf("expected X-Request-ID header, got %q", traceHeader)
	}
}

func TestProxyManager_ForwardRequest_Timeout(t *testing.T) {
	doneCh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		close(doneCh)
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), &ProxyConfig{
		Timeout: 50 * time.Millisecond,
	})

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "GET",
		TargetURL: server.URL,
		Route:     "/slow",
		Headers:   http.Header{},
	})

	if err == nil {
		t.Error("expected timeout error")
	}

	select {
	case <-doneCh:
		// request eventually completed
	default:
	}

	pm.Stop()
}

func TestProxyManager_DefaultConfig(t *testing.T) {
	pm := NewProxyManager(context.Background(), nil)

	if pm.maxRetry != 3 {
		t.Errorf("expected default maxRetry 3, got %d", pm.maxRetry)
	}
	if pm.timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", pm.timeout)
	}
	if pm.retryBaseInterval != 100*time.Millisecond {
		t.Errorf("expected default retryBaseInterval 100ms, got %v", pm.retryBaseInterval)
	}
}

func TestProxyManager_ContentType(t *testing.T) {
	var contentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	pm := NewProxyManager(context.Background(), nil)

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "POST",
		TargetURL: server.URL,
		Route:     "/ct",
		Headers:   http.Header{},
		Body:      []byte(`{"test":true}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}
