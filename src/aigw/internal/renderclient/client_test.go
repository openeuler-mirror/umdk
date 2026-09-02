/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Render client SSE/JSON body reader tests.
 */

package renderclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestReadSSEResponse_SingleLineJSONNoTrailingNewline pins the non-SSE response
// path. vLLM's /v1/chat/completions/render returns a single JSON object with no
// trailing newline (and no SSE "data:" framing) when stream mode is not used.
// bufio.Reader.ReadBytes('\n') on such a body returns (data, io.EOF)
// simultaneously; the previous implementation checked the error before writing
// the partial line to the buffer, so buf.Len()==0 on EOF and the function
// returned "failed to read response body: EOF", dropping the JSON and breaking
// every non-SSE render call.
func TestReadSSEResponse_SingleLineJSONNoTrailingNewline(t *testing.T) {
	body := []byte(`{"request_id":"abc","token_ids":[151644,8948,198]}`)
	c := &RenderClient{}

	out, err := c.readSSEResponse(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("readSSEResponse returned error for single-line JSON: %v", err)
	}
	if !bytes.Contains(out, body) {
		t.Fatalf("expected output to contain the JSON body, got: %q", out)
	}
}

// TestReadSSEResponse_SSEDataLines pins the original SSE path still works.
func TestReadSSEResponse_SSEDataLines(t *testing.T) {
	body := []byte("data: {\"token_ids\":[1,2,3]}\n\n")
	c := &RenderClient{}

	out, err := c.readSSEResponse(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("readSSEResponse returned error for SSE body: %v", err)
	}
	if !strings.Contains(string(out), "data: ") {
		t.Fatalf("expected output to retain SSE data line, got: %q", out)
	}
}

// TestReadSSEResponse_EmptyBody ensures a truly empty body still returns EOF
// (not silently returning empty data that masks a real error).
func TestReadSSEResponse_EmptyBody(t *testing.T) {
	c := &RenderClient{}
	_, err := c.readSSEResponse(bytes.NewReader(nil))
	if err == nil {
		t.Fatalf("expected error for empty body, got nil")
	}
	if err != io.EOF {
		t.Fatalf("expected io.EOF for empty body, got %v", err)
	}
}

// TestWithAuth_Forwards: a non-empty authHeader is set on the request verbatim.
func TestWithAuth_Forwards(t *testing.T) {
	c := &RenderClient{}
	req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
	c.withAuth(req, "Bearer sk-test")
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer sk-test")
	}
}

// TestWithAuth_EmptySkips: an empty authHeader sends no auth header.
func TestWithAuth_EmptySkips(t *testing.T) {
	c := &RenderClient{}
	req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
	c.withAuth(req, "")
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}

// TestRenderChat_SendsAuth: RenderChat forwards the authHeader and a 401 without
// it becomes 200 with it.
func TestRenderChat_SendsAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Non-SSE single-line JSON body (see TestReadSSEResponse_SingleLineJSONNoTrailingNewline).
		_, _ = w.Write([]byte(`{"token_ids":[1,2,3]}`))
	}))
	defer srv.Close()

	c := &RenderClient{
		config:  RenderClientConfig{MaxRetries: 0, ConnPoolSize: 1},
		baseURL: srv.URL,
		adapter: newVLLMAdapter("test"),
		client:  &http.Client{},
	}

	tokens, err := c.RenderChat(context.Background(), "test", []ChatMessage{{Role: "user", Content: "hi"}}, "Bearer sk-test")
	if err != nil {
		t.Fatalf("RenderChat returned error: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("tokens = %v, want 3", tokens)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("server received Authorization = %q, want %q", gotAuth, "Bearer sk-test")
	}
}
