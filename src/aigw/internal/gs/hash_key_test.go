/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Hash key extraction test for AIGW.
 * Create: 2026-04-29
 */

package gs

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestExtractHashKey_HeaderPriority(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string]string
		wantSource    string
		wantKey       string
		wantContains  string
	}{
		{
			"x-session-id takes priority",
			map[string]string{
				"x-session-id": "session-123",
				"x-user-id":    "user-456",
			},
			"header", "x-session-id", "session-123",
		},
		{
			"x-user-id when no session-id",
			map[string]string{
				"x-user-id": "user-789",
			},
			"header", "x-user-id", "user-789",
		},
		{
			"canonical header form",
			map[string]string{
				"X-Session-Id": "canonical-form",
			},
			"header", "x-session-id", "canonical-form",
		},
		{
			"lowercase header",
			map[string]string{
				"x-session-id": "lowercase-form",
			},
			"header", "x-session-id", "lowercase-form",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for k, v := range tt.headers {
				headers.Set(k, v)
			}

			result := ExtractHashKey(headers, nil)

			if !containsSubstring(result, tt.wantContains) {
				t.Errorf("ExtractHashKey() = %q, want to contain %q", result, tt.wantContains)
			}
		})
	}
}

func TestExtractHashKey_BodyFields(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]interface{}
		wantContains string
	}{
		{
			"session_params.session_id",
			map[string]interface{}{"session_params": map[string]interface{}{"session_id": "body-session-123"}},
			"body-session-123",
		},
		{
			"user field (OpenAI format)",
			map[string]interface{}{"user": "openai-user"},
			"openai-user",
		},
		{
			"session_id",
			map[string]interface{}{"session_id": "body-session-id"},
			"body-session-id",
		},
		{
			"user_id",
			map[string]interface{}{"user_id": "body-user-id"},
			"body-user-id",
		},
		{
			"conversation_id",
			map[string]interface{}{"conversation_id": "conv-456"},
			"conv-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			result := ExtractHashKey(headers, tt.body)

			if !containsSubstring(result, tt.wantContains) {
				t.Errorf("ExtractHashKey() = %q, want to contain %q", result, tt.wantContains)
			}
		})
	}
}

func TestExtractHashKey_PriorityOrder(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-User-Id", "user-value")
	headers.Set("X-Tenant-Id", "tenant-value")

	body := map[string]interface{}{
		"user_id": "body-user-id",
		"user":    "body-user",
	}

	result := ExtractHashKey(headers, body)

	if !containsSubstring(result, "user-value") {
		t.Errorf("Header should take priority over body, got %q", result)
	}
}

func TestExtractHashKey_FallbackToContentHash(t *testing.T) {
	headers := make(http.Header)
	body := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "hello"},
		},
		"model": "gpt-4",
	}

	result := ExtractHashKey(headers, body)

	if !containsSubstring(result, "request_hash:") {
		t.Errorf("Should fallback to request hash, got %q", result)
	}
}

func TestExtractHashKey_EmptyFallback(t *testing.T) {
	headers := make(http.Header)
	body := map[string]interface{}{}

	result := ExtractHashKey(headers, body)

	if result == "fallback:empty" {
		t.Log("Correctly returned fallback:empty for empty body")
	} else if containsSubstring(result, "request_hash:") {
		t.Log("Correctly used request hash for empty body:", result)
	} else {
		t.Errorf("Unexpected result for empty body and headers: %q", result)
	}
}

func TestExtractHashKey_NilBody(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Request-Id", "req-123")

	result := ExtractHashKey(headers, nil)

	if !containsSubstring(result, "req-123") {
		t.Errorf("Should extract from header even with nil body, got %q", result)
	}
}

func TestExtractHashKeyFromBytes_Basic(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Session-Id", "session-456")

	bodyJSON := []byte(`{"user":"test-user","messages":[]}`)

	result := ExtractHashKeyFromBytes(headers, bodyJSON)

	if !containsSubstring(result, "session-456") {
		t.Errorf("Should prioritize header, got %q", result)
	}
}

func TestExtractHashKeyFromBytes_EmptyBytes(t *testing.T) {
	headers := make(http.Header)
	result := ExtractHashKeyFromBytes(headers, []byte{})

	if result != "fallback:empty" {
		t.Errorf("Empty bytes should fallback to empty, got %q", result)
	}
}

func TestExtractHashKeyFromBytes_InvalidJSON(t *testing.T) {
	headers := make(http.Header)
	invalidJSON := []byte(`{invalid json}`)

	result := ExtractHashKeyFromBytes(headers, invalidJSON)

	if !containsSubstring(result, "content_hash:") {
		t.Errorf("Invalid JSON should use content_hash, got %q", result)
	}
}

func TestExtractHashKeyFromBytes_NilBytes(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Correlation-Id", "corr-789")

	result := ExtractHashKeyFromBytes(headers, nil)

	if !containsSubstring(result, "corr-789") {
		t.Errorf("Nil bytes should check headers, got %q", result)
	}
}

func TestExtractHashKey_HeaderOverride(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Session-Id", "header-session")

	body := map[string]interface{}{
		"session_id": "body-session",
	}

	result := ExtractHashKey(headers, body)

	if containsSubstring(result, "body-session") {
		t.Errorf("Header should override body session_id, got %q", result)
	}
	if !containsSubstring(result, "header-session") {
		t.Errorf("Should use header session ID, got %q", result)
	}
}

func TestExtractHashKey_AllHeadersChecked(t *testing.T) {
	tests := []struct {
		headerName string
		headerVal  string
	}{
		{"x-session-id", "session-1"},
		{"x-user-id", "user-1"},
		{"x-tenant-id", "tenant-1"},
		{"x-correlation-id", "corr-1"},
		{"x-request-id", "req-1"},
		{"x-trace-id", "trace-1"},
	}

	for _, tt := range tests {
		t.Run(tt.headerName, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set(tt.headerName, tt.headerVal)

			result := ExtractHashKey(headers, nil)

			if !containsSubstring(result, tt.headerVal) {
				t.Errorf("Should extract %s, got %q", tt.headerName, result)
			}
		})
	}
}

func TestHashKey_String(t *testing.T) {
	hk := &HashKey{
		Source:   "header",
		Key:      "x-session-id",
		Value:    "session-123",
		Priority: 0,
	}

	result := hk.String()
	expected := "header:x-session-id:session-123"

	if result != expected {
		t.Errorf("HashKey.String() = %q, want %q", result, expected)
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstringHelper(s, substr))))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestExtractHashKey_RealWorldChatCompletion(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer sk-xxx")
	headers.Set("X-Session-Id", "chat-session-abc123")

	body := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Hello"},
		},
		"temperature": 0.7,
	}

	result := ExtractHashKey(headers, body)

	if !containsSubstring(result, "chat-session-abc123") {
		t.Errorf("Should extract session ID from header, got %q", result)
	}
}

func TestExtractHashKey_RealWorldVLLM(t *testing.T) {
	headers := make(http.Header)

	body := map[string]interface{}{
		"session_params": map[string]interface{}{
			"session_id": "vllm-session-xyz",
			"stream":     true,
		},
		"prompt": "Hello, world!",
	}

	result := ExtractHashKey(headers, body)

	if !containsSubstring(result, "vllm-session-xyz") {
		t.Errorf("Should extract from session_params.session_id, got %q", result)
	}
}

func TestExtractHashKeyFromBytes_Integration(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-User-Id", "user-abc")

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"model": "claude-3",
		"user":  "priority-user",
	})

	result := ExtractHashKeyFromBytes(headers, bodyBytes)

	if !containsSubstring(result, "user-abc") {
		t.Errorf("Should extract from header (priority over body), got %q", result)
	}
}

func TestExtractHeaderValue(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Custom-Header", "custom-value")

	tests := []struct {
		name     string
		header   string
		wantVal  string
	}{
		{"direct match", "X-Custom-Header", "custom-value"},
		{"lowercase", "x-custom-header", "custom-value"},
		{"canonical", "X-CUSTOM-HEADER", "custom-value"},
		{"missing", "X-Missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHeaderValue(headers, tt.header)
			if got != tt.wantVal {
				t.Errorf("extractHeaderValue(%q) = %q, want %q", tt.header, got, tt.wantVal)
			}
		})
	}
}