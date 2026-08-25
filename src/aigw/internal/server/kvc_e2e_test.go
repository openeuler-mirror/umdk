/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"huawei.com/aigw/internal/agentregistry"
)

// waitFor polls cond up to 2s for truth.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("waitFor: condition never became true")
}

// TestE2E_AgentLifecycle_FullFlow exercises the full agent-restart arc against a mock
// vLLM /v1/kvc/* server:
//
//	register -> heartbeat -> inject session block -> suspect (triggers offload)
//	-> recover (triggers prefetch) -> debug API shows agent.
//
// Layer 4 (HTTP e2e). NOTE: ./internal/server/ tests require the full ./build.sh
// (gs/tokenizers/lightgbm CGO) to compile; run there before merge.
func TestE2E_AgentLifecycle_FullFlow(t *testing.T) {
	srv := newKvcTestServer(t)

	// 1. register agent a1
	reg, _ := json.Marshal(map[string]interface{}{"agent_id": "a1", "models": []string{"m1"}})
	if resp := doReq(srv, http.MethodPost, "/aigw/v1/agents/register", reg); resp.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", resp.Code, resp.Body.String())
	}

	// 2. heartbeat (twice)
	hb, _ := json.Marshal(map[string]interface{}{"models": []string{"m1"}, "session_ids": []string{"s1"}})
	for i := 0; i < 2; i++ {
		if resp := doReq(srv, http.MethodPost, "/aigw/v1/agents/a1/heartbeat", hb); resp.Code != http.StatusOK {
			t.Fatalf("heartbeat #%d status=%d", i, resp.Code)
		}
	}

	// 3. populate the session's blocks (simulates a scheduled request + BlockStored)
	srv.injectSessionBlock("s1", "a1", "ins1", []int64{42})

	// 4. suspect the agent (force registry state -> SUSPECTED triggers kvcSubscriber
	//    -> offload strategy -> dispatch to mock vLLM)
	srv.registry.SetAgentStateForTesting("a1", agentregistry.StateSuspected)
	// the offload dispatch runs inline in the subscriber callback; give the HTTP call
	// to the mock vLLM a moment to land.
	waitFor(t, func() bool { return srv.fakeVllm.offloadCalls() >= 1 })
	if got := srv.fakeVllm.offloadCalls(); got < 1 {
		t.Fatalf("expected >=1 offload call to mock vLLM, got %d", got)
	}

	// 5. recover the agent -> triggers prefetch
	rec, _ := json.Marshal(map[string]interface{}{"models": []string{"m1"}})
	if resp := doReq(srv, http.MethodPost, "/aigw/v1/agents/a1/recover", rec); resp.Code != http.StatusOK {
		t.Fatalf("recover status=%d body=%s", resp.Code, resp.Body.String())
	}

	// 6. debug API: GET /aigw/v1/agents/a1 returns the agent record
	resp := doReq(srv, http.MethodGet, "/aigw/v1/agents/a1", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("debug agent detail status=%d body=%s", resp.Code, resp.Body.String())
	}
	var agent map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &agent); err != nil {
		t.Fatalf("decode agent detail: %v", err)
	}
	if agent["AgentID"] != "a1" {
		t.Fatalf("debug agent detail AgentID=%v want a1", agent["AgentID"])
	}
}
