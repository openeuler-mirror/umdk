/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package base

import (
	"encoding/json"
	"testing"
)

func TestKvcConfigParsing(t *testing.T) {
	raw := `{
		"globalSchedulers": [],
		"kvc": {
			"enabled": true,
			"agent": {
				"heartbeatIntervalSec": 30,
				"heartbeatTimeoutSec": 90,
				"recoverWindowSec": 300,
				"recoverTimeoutSec": 300,
				"goneFinalizeSec": 3600,
				"registerGraceSec": 30,
				"implicitHeartbeatFromRequests": true,
				"offload":  {"mode": "all", "batchSize": 5, "targetTier": "ddr", "delayBetweenBatchesMs": 100},
				"prefetch": {"mode": "mru", "topN": 10, "batchSize": 5, "delayBetweenBatchesMs": 100},
				"aging":   {"mode": "ttl", "loopIntervalSec": 60, "evictGraceSec": 3600, "sessionIdleEvictSec": 604800, "batchSize": 10}
			},
			"session": {
				"sessionTtlSec": 86400, "blockTtlSec": 3600, "pendingBlockMatchTtlSec": 60,
				"accessFrequencyEmaWeight": 0.3, "accessFrequencyWindowSec": 600
			},
			"vllm": {
				"endpoint": "http://127.0.0.1:8000", "timeoutMs": 3000, "maxRetries": 5,
				"retryBaseDelayMs": 1000, "retryMaxDelayMs": 30000, "batchSize": 5, "hmacEnabled": false
			}
		}
	}`
	var cfg AigwConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.Kvc.Enabled {
		t.Fatal("Kvc.Enabled should be true")
	}
	if cfg.Kvc.Agent.HeartbeatTimeoutSec != 90 {
		t.Fatalf("heartbeatTimeoutSec=%d want 90", cfg.Kvc.Agent.HeartbeatTimeoutSec)
	}
	if cfg.Kvc.Vllm.Endpoint != "http://127.0.0.1:8000" {
		t.Fatalf("vllm endpoint=%q", cfg.Kvc.Vllm.Endpoint)
	}
	if cfg.Kvc.Agent.Offload.TargetTier != "ddr" {
		t.Fatalf("targetTier=%q", cfg.Kvc.Agent.Offload.TargetTier)
	}
}
