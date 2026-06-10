/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: huggingFace tokenizer test
 * Create: 2025-06-18
 */

// Package tokenizers provides functions of tokenization for AIGW.
package tokenizers

import (
	"testing"
)

const (
	validTestHgTokenizerModelPath = "../../test/tokenizer/DeepSeek-R1-Distill-Qwen-7B/tokenizer.json"
)

// TestNewHuggingFaceTokenizer tests the newHuggingFaceTokenizer function
func TestNewHuggingFaceTokenizer(t *testing.T) {
	// Create a new huggingFaceTokenizer instance
	tokenizer := newHuggingFaceTokenizer()
	if tokenizer == nil {
		t.Errorf("Failed to create huggingFaceTokenizer instance")
	}
}

// TestInitFromFile tests the InitFromFile method
func TestInitFromFile(t *testing.T) {
	tokenizer := newHuggingFaceTokenizer()

	// Test with a valid file path
	err := tokenizer.InitFromFile(validTestHgTokenizerModelPath)
	if err != nil {
		t.Errorf("Failed to initialize tokenizer: %v", err)
	}

	// Test with an invalid file path
	err = tokenizer.InitFromFile("invalid_file_path")
	if err == nil {
		t.Error("Expected error when initializing tokenizer with invalid file path")
	}
}

// TestUninit tests the Uninit method
func TestUninit(t *testing.T) {
	tokenizer := newHuggingFaceTokenizer()

	// Initialize tokenizer to set the handler
	err := tokenizer.InitFromFile(validTestHgTokenizerModelPath)
	if err != nil {
		t.Errorf("Failed to initialize tokenizer: %v", err)
	}

	// Uninitialize tokenizer
	tokenizer.Uninit()

	// Check if the handler is nil after uninitialization
	if tokenizer.hgTokenizerHandler != nil {
		t.Error("Tokenizer handler should be nil after uninitialization")
	}
}

// TestEncode tests the Encode method
func TestEncode(t *testing.T) {
	tokenizer := newHuggingFaceTokenizer()

	// Initialize tokenizer to set the handler
	e1 := tokenizer.InitFromFile(validTestHgTokenizerModelPath)
	if e1 != nil {
		t.Errorf("Failed to initialize tokenizer: %v", e1)
	}

	// Test with empty input
	_, err := tokenizer.Encode("")
	if err == nil {
		t.Error("Expected error when encoding empty input")
	}

	// Test with valid input
	input := "Hello, World!"
	tokenIDs, err := tokenizer.Encode(input)
	if err != nil {
		t.Errorf("Failed to Encode input: %v", err)
	}

	if len(tokenIDs) == 0 {
		t.Error("Expected non-empty token IDs, got empty")
	}
}

// TestDecode tests the Decode method
func TestDecode(t *testing.T) {
	tokenizer := newHuggingFaceTokenizer()

	// Initialize tokenizer to set the handler
	e1 := tokenizer.InitFromFile(validTestHgTokenizerModelPath)
	if e1 != nil {
		t.Errorf("Failed to initialize tokenizer: %v", e1)
	}

	// Test with empty token IDs
	_, err := tokenizer.Decode([]uint32{})
	if err == nil {
		t.Error("Expected error when decoding empty token IDs")
	}

	// Test with valid token IDs
	tokenIDs := []uint32{123, 456, 789}
	output, err := tokenizer.Decode(tokenIDs)
	if err != nil {
		t.Errorf("Failed to Decode token IDs: %v", err)
	}

	if output == "" {
		t.Error("Expected non-empty output, got empty")
	}
}
