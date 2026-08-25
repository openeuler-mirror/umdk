/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newHint(type_ HintType, hashes ...int64) *KvcHint {
	return &KvcHint{HintID: "h1", Type: type_, Model: "m1", AgentID: "a1",
		Sessions: []SessionHint{{SessionID: "s1", BlockHashes: hashes}}, IssuedAt: time.Now()}
}

func TestVllmClient_Offload_200Accepted(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/v1/kvc/offload" || r.Method != "POST" {
			t.Fatalf("got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hint_id":"h1","status":"accepted","accepted_hashes":[10],"in_flight_hashes":[],"missing_hashes":[]}`))
	}))
	defer srv.Close()
	c := NewVllmKvcClient(srv.URL, VllmClientConfig{TimeoutMs: 1000, MaxRetries: 3})
	ack, err := c.Send(context.Background(), newHint(HintOffload, 10))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != AckAccepted || len(ack.AcceptedHashes) != 1 {
		t.Fatalf("ack=%+v", ack)
	}
}

func TestVllmClient_5xx_Retries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NewVllmKvcClient(srv.URL, VllmClientConfig{TimeoutMs: 1000, MaxRetries: 3,
		RetryBaseDelayMs: 1, RetryMaxDelayMs: 2})
	_, err := c.Send(context.Background(), newHint(HintOffload, 10))
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if got := atomic.LoadInt32(&calls); got != 4 { // 1 initial + 3 retries
		t.Fatalf("calls=%d want 4", got)
	}
}

func TestVllmClient_4xx_NoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	c := NewVllmKvcClient(srv.URL, VllmClientConfig{TimeoutMs: 1000, MaxRetries: 3})
	_, err := c.Send(context.Background(), newHint(HintOffload, 10))
	if err == nil {
		t.Fatal("expected error on 4xx")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("calls=%d want 1 (no retry on 4xx)", got)
	}
}

func TestVllmClient_Idempotent_409(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&calls) == 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"hint_id":"h1","status":"accepted","accepted_hashes":[10]}`))
		} else {
			t.Fatalf("should not retry on 409")
		}
	}))
	defer srv.Close()
	c := NewVllmKvcClient(srv.URL, VllmClientConfig{TimeoutMs: 1000, MaxRetries: 3})
	ack, err := c.Send(context.Background(), newHint(HintOffload, 10))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != AckAccepted {
		t.Fatalf("ack=%+v", ack)
	}
}

func TestVllmClient_Prefetch_SubmitThenPoll(t *testing.T) {
	state := struct {
		mu   sync.Mutex
		poll int
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/kvc/prefetch" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"hint_id":"h1","job_id":"job1","status":"accepted","accepted_hashes":[10],"missing_hashes":[]}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/kvc/jobs/job1" {
			state.mu.Lock()
			state.poll++
			running := state.poll < 2
			state.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if running {
				_, _ = w.Write([]byte(`{"job_id":"job1","status":"running","done_hashes":[]}`))
			} else {
				_, _ = w.Write([]byte(`{"job_id":"job1","status":"done","done_hashes":[10],"blocks_pinned":true}`))
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewVllmKvcClient(srv.URL, VllmClientConfig{TimeoutMs: 1000, MaxRetries: 1, RetryBaseDelayMs: 1, RetryMaxDelayMs: 2})
	c.pollInterval = 5 * time.Millisecond // test-only fast poll
	ack, err := c.Send(context.Background(), newHint(HintPrefetch, 10))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != AckAccepted {
		t.Fatalf("ack=%+v", ack)
	}
	if ack.BlockPlacements[10] != "hbm" {
		t.Fatalf("expected block 10 placement hbm after poll, got %+v", ack.BlockPlacements)
	}
}
