/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatching schedule request.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import "testing"

func TestGetRequestType(t *testing.T) {
	// test ultra short request
	promptLen := 50
	if GetRequestType(promptLen) != ReqTypeUltraShort {
		t.Errorf("Expected request type to be reqTypeUltraShort for prompt length %d", promptLen)
	}

	// test short request
	promptLen = 300
	if GetRequestType(promptLen) != ReqTypeShort {
		t.Errorf("Expected request type to be reqTypeShort for prompt length %d", promptLen)
	}

	// test middle request
	promptLen = 700
	if GetRequestType(promptLen) != ReqTypeMiddle {
		t.Errorf("Expected request type to be reqTypeMiddle for prompt length %d", promptLen)
	}

	// test long request
	promptLen = 2000
	if GetRequestType(promptLen) != ReqTypeLong {
		t.Errorf("Expected request type to be reqTypeLong for prompt length %d", promptLen)
	}

	// test ultra long request
	promptLen = 5000
	if GetRequestType(promptLen) != ReqTypeUltraLong {
		t.Errorf("Expected request type to be reqTypeUltraLong for prompt length %d", promptLen)
	}
}

func TestNewLlmRequest(t *testing.T) {
	// Test with valid request
	req, err := NewLlmRequest("test-id", "test prompt")
	if err != nil {
		t.Errorf("NewLlmRequest returned unexpected error: %v", err)
	}
	if req == nil {
		t.Error("NewLlmRequest returned nil")
	}
	if req.ReqId != "test-id" {
		t.Errorf("Expected ReqId to be 'test-id', got '%s'", req.ReqId)
	}
	if req.Prompt != "test prompt" {
		t.Errorf("Expected Prompt to be 'test prompt', got '%s'", req.Prompt)
	}
	if req.TimeStamp == 0 {
		t.Error("Expected TimeStamp to be set")
	}

	// Test with empty prompt
	_, err = NewLlmRequest("test-id", "")
	if err == nil {
		t.Error("NewLlmRequest should return error for empty prompt")
	}
}

func TestLlmRequestSetPromptAttrs(t *testing.T) {
	req := &LlmRequest{}

	// Test with empty token
	req.SetPromptAttrs([]uint32{})
	if req.PromptLen != 0 {
		t.Errorf("Expected PromptLen to be 0, got %d", req.PromptLen)
	}
	if req.ReqType != ReqTypeUltraShort {
		t.Errorf("Expected ReqType to be ReqTypeUltraShort, got %v", req.ReqType)
	}

	// Test with tokens (5 tokens < 100, so should be ultra short)
	tokens := []uint32{1, 2, 3, 4, 5}
	req.SetPromptAttrs(tokens)
	if req.PromptLen != 5 {
		t.Errorf("Expected PromptLen to be 5, got %d", req.PromptLen)
	}
	if req.PromptToken == nil {
		t.Error("Expected PromptToken to be set")
	}
	if req.ReqType != ReqTypeUltraShort {
		t.Errorf("Expected ReqType to be ReqTypeUltraShort, got %v", req.ReqType)
	}

	// Test with more tokens (150 tokens >= 100 and < 500, so should be short)
	tokens2 := make([]uint32, 150)
	for i := range tokens2 {
		tokens2[i] = uint32(i)
	}
	req.SetPromptAttrs(tokens2)
	if req.ReqType != ReqTypeShort {
		t.Errorf("Expected ReqType to be ReqTypeShort, got %v", req.ReqType)
	}
}
