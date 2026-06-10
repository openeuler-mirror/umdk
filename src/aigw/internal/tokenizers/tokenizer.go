/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define the interfaces of tokenizer
 * Create: 2025-06-14
 */

// Package tokenizers provides functions of tokenization for AIGW.
package tokenizers

import (
	"errors"
	"fmt"
)

type tokenizerType int

const (
	huggingFaceTokenizerType tokenizerType = iota
)

// DefaultTokenizationRatio is the default tokenizationRatio, use to convert rune length to token length
const DefaultTokenizationRatio = 0.35

// todo: define model name as const variable
var modelToTokenizeTypeMap = map[string]tokenizerType{
	"DeepSeek-R1-Distill-Qwen-7B": huggingFaceTokenizerType,
	"DeepSeek-R1":                 huggingFaceTokenizerType,
}

func toTokenizerType(model string) (tokenizerType, error) {
	t, ok := modelToTokenizeTypeMap[model]
	if !ok {
		return huggingFaceTokenizerType, errors.New("invalid tokenizer model")
	}
	return t, nil
}

func getDefaultTokenizerType() tokenizerType {
	return huggingFaceTokenizerType
}

// Tokenizer processes some raw text as input and outputs an encoding token ids
type Tokenizer interface {
	// InitFromFile will initialize the tokenizer from file
	InitFromFile(file string) error
	// Uninit the tokenizer
	Uninit()

	// Encode input string to token ids
	Encode(input string) ([]uint32, error)
	// Decode the tokenIds to string
	Decode(tokenIDs []uint32) (string, error)
}

// NewTokenizer creates a new tokenizer with model
func NewTokenizer(model string, opts ...TokenizerOption) (Tokenizer, error) {
	t := getDefaultTokenizerType()

	switch t {
	case huggingFaceTokenizerType:
		return newHuggingFaceTokenizer(opts...), nil
	default:
		return nil, fmt.Errorf("invalid tokenizer type: %v", t)
	}
}
