/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package renderclient

import "testing"

// TestVllmAdapter_GetChatPathPointsToRenderEndpoint 锁定 render client 必须打
// vLLM 的 /render 端点。stock vLLM 的 /v1/chat/completions 做真实生成、不返回
// token_ids;只有 /v1/chat/completions/render 返回 {"token_ids":[...]}。
func TestVllmAdapter_GetChatPathPointsToRenderEndpoint(t *testing.T) {
	a := newVLLMAdapter("Qwen3.5-9B")
	const want = "/v1/chat/completions/render"
	if got := a.getChatPath(); got != want {
		t.Fatalf("getChatPath() = %q, want %q", got, want)
	}
}

// TestVllmAdapter_ParseRenderResponse_ExtractsTokenIDs 用 vLLM 0.18
// /v1/chat/completions/render 的真实响应体(curl 录得)验证 RenderResponse 的
// json tag 与 vLLM 线格式对齐——能正确抽出 token_ids。
func TestVllmAdapter_ParseRenderResponse_ExtractsTokenIDs(t *testing.T) {
	body := []byte(`{"request_id":"chatcmpl-x","token_ids":[248045,846,198,14556,248046,198,248045,74455,198,248068,198],"features":null,"model":"Qwen3.5-9B","stream":false}`)
	a := newVLLMAdapter("Qwen3.5-9B")
	resp, err := a.parseResponse(body)
	if err != nil {
		t.Fatalf("parseResponse failed: %v", err)
	}
	want := []int64{248045, 846, 198, 14556, 248046, 198, 248045, 74455, 198, 248068, 198}
	if len(resp.TokenIDs) != len(want) {
		t.Fatalf("TokenIDs len = %d, want %d (got %v)", len(resp.TokenIDs), len(want), resp.TokenIDs)
	}
	for i := range want {
		if resp.TokenIDs[i] != want[i] {
			t.Fatalf("TokenIDs[%d] = %d, want %d", i, resp.TokenIDs[i], want[i])
		}
	}
}
