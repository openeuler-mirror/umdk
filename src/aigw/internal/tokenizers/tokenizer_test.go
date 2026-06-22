/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: tokenizer test
 * Create: 2025-06-18
 */

// Package tokenizers provides functions of tokenization for AIGW.
package tokenizers

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestToTokenizerType tests the toTokenizerType function
func TestToTokenizerType(t *testing.T) {
	tests := []struct {
		model         string
		expectedType  tokenizerType
		expectedError error
	}{
		{
			model:         "DeepSeek-R1-Distill-Qwen-7B",
			expectedType:  huggingFaceTokenizerType,
			expectedError: nil,
		},
		{
			model:         "UnknownModel",
			expectedType:  huggingFaceTokenizerType, // Default type
			expectedError: errors.New("invalid tokenizer model"),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Model-%s", test.model), func(t *testing.T) {
			t.Logf("running test with model: %s", test.model)
			tType, err := toTokenizerType(test.model)
			if tType != test.expectedType {
				t.Errorf("Expected tokenizer type %v, got %v", test.expectedType, tType)
			}

			if err != nil && test.expectedError != nil && !strings.Contains(err.Error(), test.expectedError.Error()) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}

// TestNewTokenizer tests the NewTokenizer function
func TestNewTokenizer(t *testing.T) {
	tests := []struct {
		model         string
		expectedType  tokenizerType
		expectedError error
	}{
		{
			model:         "DeepSeek-R1-Distill-Qwen-7B",
			expectedType:  huggingFaceTokenizerType,
			expectedError: nil,
		},
		{
			model:         "CustomModel",
			expectedType:  huggingFaceTokenizerType, // Default type
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Model-%s", test.model), func(t *testing.T) {
			_, err := NewTokenizer(test.model)
			if err == nil && !errors.Is(err, test.expectedError) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
			if err != nil && test.expectedError != nil && !strings.Contains(err.Error(), test.expectedError.Error()) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}
