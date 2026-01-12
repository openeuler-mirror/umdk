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

type requestType int

const (
	reqTypeUltraShort requestType = iota // ultraShort[0, 100)
	reqTypeShort                         // short[100, 500)
	reqTypeMiddle                        // middle[500, 1000)
	reqTypeLong                          // long[1000, 4000)
	reqTypeUltraLong                     // ultraLong[4000, ~)
)

// LlmRequest is wrapper of inference request
type LlmRequest struct {
	Prompt  string
	ReqId   string
	reqType requestType

	promptToken      []uint32
	promptLen        int
	predictTokens    int // predict total tokens, include prefill and decode
	predictBlocks    int // predict total blocks, include prefill and decode
	predictDecodeLen int

	timeStamp int64 // unit is second
}

func getRequestType(promptLen int) requestType {
	if promptLen < ultraShortLimit {
		return reqTypeUltraShort
	} else if promptLen < shortLimit {
		return reqTypeShort
	} else if promptLen < middleLimit {
		return reqTypeMiddle
	} else if promptLen < longLimit {
		return reqTypeLong
	} else {
		return reqTypeUltraLong
	}
}

// SetPromptAttrs sets the attributes for request
func (req *LlmRequest) SetPromptAttrs(promptToken []uint32) {
	req.promptToken = promptToken
	req.promptLen = len(promptToken)
	req.reqType = getRequestType(len(promptToken))
}

// NewLlmRequest creates the new LlmRequest
func NewLlmRequest(reqId string, prompt string) (*LlmRequest, error) {
	if len(prompt) == 0 {
		return nil, fmt.Errorf("the prompt must have a non-zero length")
	}

	return &LlmRequest{
		Prompt:    prompt,
		ReqId:     reqId,
		timeStamp: time.Now().UTC().Unix(),
	}, nil
}
