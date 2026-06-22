/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatching schedule request.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"fmt"
	"time"
)

const (
	ultraShortLimit = 100
	shortLimit      = 500
	middleLimit     = 1000
	longLimit       = 4000
)

// RequestType is the type of request
type RequestType int

// definition for RequestType
const (
	ReqTypeUltraShort RequestType = iota // ultraShort[0, 100)
	ReqTypeShort                         // short[100, 500)
	ReqTypeMiddle                        // middle[500, 1000)
	ReqTypeLong                          // long[1000, 4000)
	ReqTypeUltraLong                     // ultraLong[4000, ~)
)

// LlmRequest is wrapper of inference request
type LlmRequest struct {
	Prompt  string
	ReqId   string
	ReqType RequestType

	PromptToken   []uint32
	PromptLen     int
	PrefillBlocks int // number of input blocks for prefill

	PredictTokens    int // predict total tokens, include prefill and decode
	PredictBlocks    int // predict total blocks, include prefill and decode
	PredictDecodeLen int

	PredictPrefillTime float64 // predict prefill time, unit is ms
	PrefillTimeStampMs int64   // record the start timestamp of prefill, unit is ms
	TimeStamp          int64   // unit is second
}

// GetRequestType returns the type of request
func GetRequestType(promptLen int) RequestType {
	if promptLen < ultraShortLimit {
		return ReqTypeUltraShort
	} else if promptLen < shortLimit {
		return ReqTypeShort
	} else if promptLen < middleLimit {
		return ReqTypeMiddle
	} else if promptLen < longLimit {
		return ReqTypeLong
	} else {
		return ReqTypeUltraLong
	}
}

// SetPromptAttrs sets the attributes for request
func (req *LlmRequest) SetPromptAttrs(promptToken []uint32) {
	req.PromptToken = promptToken
	req.PromptLen = len(promptToken)
	req.ReqType = GetRequestType(len(promptToken))
}

// NewLlmRequest creates the new LlmRequest
func NewLlmRequest(reqId string, prompt string) (*LlmRequest, error) {
	if len(prompt) == 0 {
		return nil, fmt.Errorf("the prompt must have a non-zero length")
	}

	return &LlmRequest{
		Prompt:             prompt,
		ReqId:              reqId,
		TimeStamp:          time.Now().UnixMilli(),
		PrefillTimeStampMs: time.Now().UnixMilli(),
	}, nil
}
