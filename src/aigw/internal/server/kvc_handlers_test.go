/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// kvcTestServer wraps an HttpServer wired with an AgentRegistry + mock vLLM for KVC tests.
// Built in newKvcTestServer; fields exposed for test assertions.
//
// NOTE: full construction (AigwManager + mock vLLM) requires the CGO/Rust/LightGBM
// toolchain (./build.sh). Tests here run in a full build environment.

func TestAgentRegister_Heartbeat_Success(t *testing.T) {
	srv := newKvcTestServer(t) // builds AigwManager + HttpServer in-memory, ServiceMode, mock vLLM
	body, _ := json.Marshal(map[string]interface{}{"agent_id": "a1", "models": []string{"m1"}})
	resp := doReq(srv, http.MethodPost, "/aigw/v1/agents/register", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", resp.Code, resp.Body.String())
	}
	hb, _ := json.Marshal(map[string]interface{}{"models": []string{"m1"}, "session_ids": []string{"s1"}})
	resp = doReq(srv, http.MethodPost, "/aigw/v1/agents/a1/heartbeat", hb)
	if resp.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d", resp.Code)
	}
}

func TestSessionClose_Evicts(t *testing.T) {
	srv := newKvcTestServer(t)
	// register + heartbeat
	reg, _ := json.Marshal(map[string]interface{}{"agent_id": "a1", "models": []string{"m1"}})
	doReq(srv, http.MethodPost, "/aigw/v1/agents/register", reg)
	hb, _ := json.Marshal(map[string]interface{}{"models": []string{"m1"}, "session_ids": []string{"s1"}})
	doReq(srv, http.MethodPost, "/aigw/v1/agents/a1/heartbeat", hb)

	// populate the session: directly inject a block via the KvcSessionManager test hook
	srv.injectSessionBlock("s1", "a1", "ins1", []int64{42})

	resp := doReq(srv, http.MethodPost, "/aigw/v1/agents/a1/sessions/s1/close", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("close status=%d body=%s", resp.Code, resp.Body.String())
	}
	// assert mock vLLM received an evict hint carrying block 42
	if got := srv.fakeVllm.evictCalls(); got != 1 {
		t.Fatalf("evict calls=%d want 1", got)
	}
	if !srv.fakeVllm.lastEvictHas(42) {
		t.Fatal("evict hint did not carry block 42")
	}
}

func doReq(s *kvcTestServer, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.testHandler().ServeHTTP(rr, req)
	return rr
}

func TestDebug_AgentsList_Empty(t *testing.T) {
	srv := newKvcTestServer(t)
	resp := doReq(srv, http.MethodGet, "/aigw/v1/agents", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", resp.Code, resp.Body.String())
	}
	// no agents registered yet -> empty array
	if body := resp.Body.String(); body != "null" && body != "[]" {
		// json.Marshal of empty slice is "null"; accept either
		if body != "null" {
			t.Fatalf("expected null/[] for empty agents list, got %s", body)
		}
	}
}

func TestDebug_AgentDetail_NotFound(t *testing.T) {
	srv := newKvcTestServer(t)
	resp := doReq(srv, http.MethodGet, "/aigw/v1/agents/nope", nil)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown agent, got %d", resp.Code)
	}
}

func TestDebug_SessionDetail_NotFound(t *testing.T) {
	srv := newKvcTestServer(t)
	resp := doReq(srv, http.MethodGet, "/aigw/v1/models/m1/kvc/sessions/sx", nil)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown session, got %d", resp.Code)
	}
}

func TestDebug_BlockDetail_BadHash(t *testing.T) {
	srv := newKvcTestServer(t)
	resp := doReq(srv, http.MethodGet, "/aigw/v1/models/m1/kvc/blocks/notanumber", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad block hash, got %d", resp.Code)
	}
}
