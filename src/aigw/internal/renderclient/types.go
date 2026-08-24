/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Render service client types.
 * Create: 2026-05-21
 */

package renderclient

type RenderChatRequest struct {
	Model     string                 `json:"model"`
	Messages  []ChatMessage          `json:"messages"`
	ExtraBody map[string]interface{} `json:"extra_body,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RenderCompletionRequest struct {
	Model     string                 `json:"model"`
	Prompt    string                 `json:"prompt"`
	ExtraBody map[string]interface{} `json:"extra_body,omitempty"`
}

type TokenizeRequest struct {
	Model            string `json:"model"`
	Prompt           string `json:"prompt"`
	AddSpecialTokens bool   `json:"add_special_tokens"`
}

type TokenizeResponse struct {
	Tokens      []int64 `json:"tokens"`
	Count       int     `json:"count"`
	MaxModelLen int     `json:"max_model_len,omitempty"`
}

type RenderResponse struct {
	Prompt      string  `json:"prompt"`
	TokenIDs    []int64 `json:"token_ids"`
	PromptLen   int     `json:"prompt_len"`
	ModelConfig struct {
		MaxModelLen int `json:"max_model_len"`
	} `json:"model_config"`
}

type RenderClientConfig struct {
	EndpointTemplate string `json:"endpointTemplate"`
	Timeout          int    `json:"timeout"`
	MaxRetries       int    `json:"maxRetries"`
	ConnPoolSize     int    `json:"connPoolSize"`
	BaseURL          string `json:"baseURL"`
}

func DefaultRenderClientConfig() RenderClientConfig {
	return RenderClientConfig{
		EndpointTemplate: "http://{ip}:8000",
		Timeout:          5000,
		MaxRetries:       3,
		ConnPoolSize:     100,
	}
}
