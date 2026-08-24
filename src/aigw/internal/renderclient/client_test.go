/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Render client SSE/JSON body reader tests.
 */

package renderclient

import (
	"bytes"
	"io"
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
