/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExtractHeaders_IncludesAgentId verifies X-Agent-Id is extracted for KVC implicit heartbeat.
func TestExtractHeaders_IncludesAgentId(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/aigw/v1/openai/get-suggestion", nil)
	req.Header.Set("X-Session-Id", "s1")
	req.Header.Set("X-Agent-Id", "a1")
	req.Header.Set("X-User-Id", "u1")
	h := extractHeaders(req)
	if h["X-Agent-Id"] != "a1" {
		t.Fatalf("X-Agent-Id not extracted: %+v", h)
	}
	if h["X-Session-Id"] != "s1" {
		t.Fatalf("X-Session-Id not extracted: %+v", h)
	}
}

// TestExtractHeaders_NoAgentId verifies absent X-Agent-Id is simply omitted (not an error).
func TestExtractHeaders_NoAgentId(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/aigw/v1/openai/get-suggestion", nil)
	req.Header.Set("X-Session-Id", "s1")
	h := extractHeaders(req)
	if _, ok := h["X-Agent-Id"]; ok {
		t.Fatal("X-Agent-Id should be absent when not set")
	}
	if h["X-Session-Id"] != "s1" {
		t.Fatalf("X-Session-Id not extracted: %+v", h)
	}
}

// NOTE: the full implicit-heartbeat path (scheduleForOpenAi -> GetSuggestion ->
// reg.Heartbeat) is an integration test that requires the full ./build.sh
// (gs/tokenizers/lightgbm CGO) to construct a working scheduler + AES/HMAC.
// The wiring is in scheduleForOpenAi; the e2e assertion belongs in H2's
// full-flow HTTP e2e test.
