/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/gs"
)

// fakeVllm is a mock vLLM /v1/kvc/* server for KVC HTTP e2e tests.
type fakeVllm struct {
	mu          sync.Mutex
	srv         *httptest.Server
	offloadHits int
	evictHits   int
	lastEvict   map[int64]bool
}

func newFakeVllm() *fakeVllm {
	f := &fakeVllm{lastEvict: map[int64]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BlockHashes []int64 `json:"block_hashes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/kvc/offload":
			f.mu.Lock()
			f.offloadHits++
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"hint_id":"h","status":"accepted","accepted_hashes":[]}`))
		case r.URL.Path == "/v1/kvc/evict":
			f.mu.Lock()
			f.evictHits++
			f.lastEvict = map[int64]bool{}
			for _, h := range body.BlockHashes {
				f.lastEvict[h] = true
			}
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"hint_id":"h","status":"accepted","purged_hashes":[]}`))
		case r.URL.Path == "/v1/kvc/prefetch":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"hint_id":"h","job_id":"j","status":"accepted","accepted_hashes":[]}`))
		case r.URL.Path == "/v1/kvc/jobs/j":
			_, _ = w.Write([]byte(`{"job_id":"j","status":"done","done_hashes":[],"blocks_pinned":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return f
}

func (f *fakeVllm) offloadCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.offloadHits
}

func (f *fakeVllm) evictCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.evictHits
}

func (f *fakeVllm) lastEvictHas(h int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastEvict[h]
}

func (f *fakeVllm) close() { f.srv.Close() }

// kvcTestServer wires a real (ServiceMode) AigwManager + HttpServer with an AgentRegistry
// and per-model KvcSessionManager pointing at a mock vLLM. Built in newKvcTestServer.
type kvcTestServer struct {
	*HttpServer
	manager  *core.AigwManager
	registry agentregistry.Registry
	kvcMgr   *gs.KvcSessionManager
	fakeVllm *fakeVllm
}

func newKvcTestServer(t *testing.T) *kvcTestServer {
	t.Helper()
	clock := agentregistry.NewFakeClock(time.UnixMilli(1000000))
	fv := newFakeVllm()
	t.Cleanup(fv.close)

	reg := agentregistry.NewRegistry(clock, agentregistry.RegistryConfig{
		HeartbeatTimeoutSec: 90, RecoverWindowSec: 300, RecoverTimeoutSec: 300, GoneFinalizeSec: 3600,
	})
	reg.Start()
	t.Cleanup(reg.Stop)

	sender := gs.NewVllmKvcClient(fv.srv.URL, gs.VllmClientConfig{TimeoutMs: 1000, MaxRetries: 1, RetryBaseDelayMs: 1, RetryMaxDelayMs: 2})
	kvcMgr := gs.NewKvcSessionManager("m1", reg, sender, gs.DefaultKvcSessionConfigForTest(), clock)
	kvcMgr.Start()
	t.Cleanup(kvcMgr.Stop)

	cfg := &base.AigwConfig{GlobalConfig: base.GlobalConfig{LogLevel: "info"}, Kvc: base.DefaultKvcConfig()}
	g := &gs.GlobalSchedulerManager{}
	gs.SetKvcSessionManagerForTest(g, kvcMgr)
	mgr := core.NewAigwManagerForTest(cfg, reg, map[string]*gs.GlobalSchedulerManager{"m1": g})

	return &kvcTestServer{
		HttpServer: NewHttpServer(mgr, "127.0.0.1", "0", nil),
		manager:    mgr, registry: reg, kvcMgr: kvcMgr, fakeVllm: fv,
	}
}

// injectSessionBlock populates a session's blocks via the KvcSessionManager test hook
// (simulates a BlockStored event attributed to the session).
func (s *kvcTestServer) injectSessionBlock(sessionID, agentID, instance string, hashes []int64) {
	s.kvcMgr.InjectSessionBlockForTest(sessionID, agentID, instance, hashes)
}
