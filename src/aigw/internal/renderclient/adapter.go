/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Render service request/response adapter for vLLM.
 * Create: 2026-05-21
 */

package renderclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

type vllmAdapter struct {
	model string
}

func newVLLMAdapter(model string) *vllmAdapter {
	return &vllmAdapter{model: model}
}

func (a *vllmAdapter) buildChatRequest(req RenderChatRequest) interface{} {
	chatReq := map[string]interface{}{
		"model": a.model,
	}

	messages := make([]map[string]string, 0, len(req.Messages))
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	chatReq["messages"] = messages

	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			chatReq[k] = v
		}
	}

	return chatReq
}

func (a *vllmAdapter) buildCompletionRequest(req RenderCompletionRequest) interface{} {
	cmplReq := map[string]interface{}{
		"model":  a.model,
		"prompt": req.Prompt,
	}

	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			cmplReq[k] = v
		}
	}

	return cmplReq
}

func (a *vllmAdapter) parseResponse(data []byte) (*RenderResponse, error) {
	var resp RenderResponse

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			jsonStr := strings.TrimPrefix(line, "data: ")
			if jsonStr == "[DONE]" {
				continue
			}

			if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
				continue
			}
			return &resp, nil
		}
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse render response: %w", err)
	}

	return &resp, nil
}

func (a *vllmAdapter) getChatPath() string {
	return "/v1/chat/completions/render"
}

func (a *vllmAdapter) getCompletionPath() string {
	return "/v1/completions/render"
}

func (a *vllmAdapter) supportsChat() bool {
	return true
}

func (a *vllmAdapter) supportsCompletion() bool {
	return true
}
