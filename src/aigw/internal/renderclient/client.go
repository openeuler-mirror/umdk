/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Render service HTTP client.
 * Create: 2026-05-21
 */

package renderclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"huawei.com/aigw/pkg/log"
)

type RenderClient struct {
	config  RenderClientConfig
	model   string
	adapter *vllmAdapter
	baseURL string
	client  *http.Client
}

func NewRenderClient(config RenderClientConfig, model, baseURL string) *RenderClient {
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			MaxIdleConns:        config.ConnPoolSize,
			MaxIdleConnsPerHost: config.ConnPoolSize,
		},
	}

	return &RenderClient{
		config:  config,
		model:   model,
		adapter: newVLLMAdapter(model),
		baseURL: baseURL,
		client:  client,
	}
}

// withAuth forwards the inbound Authorization header verbatim to the render
// endpoint so a vLLM started with --api-key can be authenticated without
// storing a secret in config. Empty (no inbound Authorization) => no header.
func (c *RenderClient) withAuth(req *http.Request, authHeader string) {
	if authHeader == "" {
		return
	}
	req.Header.Set("Authorization", authHeader)
}

func (c *RenderClient) RenderChat(ctx context.Context, model string, messages []ChatMessage, authHeader string) ([]int64, error) {
	req := RenderChatRequest{
		Model:    model,
		Messages: messages,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + c.adapter.getChatPath()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.withAuth(httpReq, authHeader)

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("render request failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	// Read SSE response until the terminator "\n\n"
	respBody, err := c.readSSEResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	renderResp, err := c.adapter.parseResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, body=%s", err, string(respBody))
	}

	log.Debug().Msgf("[render] chat tokenization: model=%s, tokens=%d", model, len(renderResp.TokenIDs))
	return renderResp.TokenIDs, nil
}

// TokenizePrompt tokenizes a raw prompt in the content domain (no chat
// template, no special tokens), matching the token domain used by vLLM KV
// events that report raw content tokens.
func (c *RenderClient) TokenizePrompt(ctx context.Context, model, prompt, authHeader string) ([]int64, error) {
	req := TokenizeRequest{
		Model:            model,
		Prompt:           prompt,
		AddSpecialTokens: false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + "/tokenize"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.withAuth(httpReq, authHeader)

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tokenize request failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tokenizeResp TokenizeResponse
	if err := json.Unmarshal(respBody, &tokenizeResp); err != nil {
		return nil, fmt.Errorf("failed to parse tokenize response: %w, body=%s", err, string(respBody))
	}

	log.Debug().Msgf("[render] prompt tokenization: model=%s, tokens=%d", model, len(tokenizeResp.Tokens))
	return tokenizeResp.Tokens, nil
}

func (c *RenderClient) RenderCompletion(ctx context.Context, model string, prompt, authHeader string) ([]int64, error) {
	req := RenderCompletionRequest{
		Model:  model,
		Prompt: prompt,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + c.adapter.getCompletionPath()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.withAuth(httpReq, authHeader)

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("render request failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	// Read SSE response until the terminator "\n\n"
	respBody, err := c.readSSEResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	renderResp, err := c.adapter.parseResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, body=%s", err, string(respBody))
	}

	log.Debug().Msgf("[render] completion tokenization: model=%s, tokens=%d", model, len(renderResp.TokenIDs))
	return renderResp.TokenIDs, nil
}

// readSSEResponse reads from the response body until it encounters the SSE terminator "\n\n"
func (c *RenderClient) readSSEResponse(body io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	reader := bufio.NewReader(body)
	for {
		line, err := reader.ReadBytes('\n')
		// Write whatever we got, even on a partial read. vLLM's render
		// endpoint returns a single JSON object with no trailing newline
		// (and no SSE "data:" framing) when stream mode is not used; in that
		// case ReadBytes returns (data, io.EOF) simultaneously. Writing
		// before checking err ensures we don't drop that data.
		buf.Write(line)
		if err != nil {
			if err == io.EOF && buf.Len() > 0 {
				// EOF reached but we have data, return what we have
				return buf.Bytes(), nil
			}
			return nil, err
		}
		// SSE messages are terminated by a blank line (two consecutive newlines)
		if strings.HasSuffix(buf.String(), "\n\n") {
			break
		}
		// Safety limit to prevent infinite loop
		if buf.Len() > 1<<20 { // 1MB limit
			return nil, fmt.Errorf("response too large")
		}
	}
	return buf.Bytes(), nil
}

func (c *RenderClient) doRequest(req *http.Request) (*http.Response, error) {
	var lastErr error
	for i := 0; i <= c.config.MaxRetries; i++ {
		resp, err := c.client.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if i < c.config.MaxRetries {
			time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.config.MaxRetries, lastErr)
}

func (c *RenderClient) IsHealthy(ctx context.Context) bool {
	testReq := RenderChatRequest{
		Model: c.model,
		Messages: []ChatMessage{
			{Role: "user", Content: ""},
		},
	}

	body, err := json.Marshal(testReq)
	if err != nil {
		return false
	}

	url := c.baseURL + c.adapter.getChatPath()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.withAuth(httpReq, "") // health probe: no inbound request to source auth from

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (c *RenderClient) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
