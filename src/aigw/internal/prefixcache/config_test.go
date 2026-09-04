/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Unit tests for prefix cache config JSON merge (#900).
 */

package prefixcache

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplyJSONDefaults_AllUnset(t *testing.T) {
	cfg := ApplyJSONDefaults(Config{})
	if cfg.BlockSize != defaultBlockSize {
		t.Errorf("BlockSize = %d, want default %d", cfg.BlockSize, defaultBlockSize)
	}
	if cfg.MaxContexts != defaultMaxContexts {
		t.Errorf("MaxContexts = %d, want default %d", cfg.MaxContexts, defaultMaxContexts)
	}
	if cfg.MaxPrefixesPerContext != defaultMaxPrefixesPerContext {
		t.Errorf("MaxPrefixesPerContext = %d, want default %d", cfg.MaxPrefixesPerContext, defaultMaxPrefixesPerContext)
	}
	if cfg.EvictionInterval != defaultEvictionInterval {
		t.Errorf("EvictionInterval = %v, want default %v", cfg.EvictionInterval, defaultEvictionInterval)
	}
	if cfg.EvictionDuration != defaultEvictionDuration {
		t.Errorf("EvictionDuration = %v, want default %v", cfg.EvictionDuration, defaultEvictionDuration)
	}
	if !cfg.FallbackStringMatching {
		t.Error("FallbackStringMatching must default to true")
	}
	if cfg.Seed != 0 {
		t.Errorf("Seed = %d, want 0 (random)", cfg.Seed)
	}
}

func TestApplyJSONDefaults_Overrides(t *testing.T) {
	cfg := ApplyJSONDefaults(Config{
		MaxContexts:             2000,
		MaxPrefixesPerContext:   5000,
		EvictionIntervalSeconds: 30,
		EvictionDurationMinutes: 10,
		Seed:                    42,
	})
	if cfg.MaxContexts != 2000 {
		t.Errorf("MaxContexts = %d, want 2000", cfg.MaxContexts)
	}
	if cfg.MaxPrefixesPerContext != 5000 {
		t.Errorf("MaxPrefixesPerContext = %d, want 5000", cfg.MaxPrefixesPerContext)
	}
	if cfg.EvictionInterval != 30*time.Second {
		t.Errorf("EvictionInterval = %v, want 30s", cfg.EvictionInterval)
	}
	if cfg.EvictionDuration != 10*time.Minute {
		t.Errorf("EvictionDuration = %v, want 10m", cfg.EvictionDuration)
	}
	if cfg.Seed != 42 {
		t.Errorf("Seed = %d, want 42", cfg.Seed)
	}
}

func TestPrefixCacheConfigJSONRoundTrip(t *testing.T) {
	raw := `{
		"evictionIntervalSeconds": 45,
		"evictionDurationMinutes": 15,
		"seed": 12345678901234567890,
		"maxContexts": 128
	}`
	var jsonCfg Config
	if err := json.Unmarshal([]byte(raw), &jsonCfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	cfg := ApplyJSONDefaults(jsonCfg)
	if cfg.EvictionInterval != 45*time.Second {
		t.Errorf("EvictionInterval = %v, want 45s", cfg.EvictionInterval)
	}
	if cfg.EvictionDuration != 15*time.Minute {
		t.Errorf("EvictionDuration = %v, want 15m", cfg.EvictionDuration)
	}
	if cfg.Seed != 12345678901234567890 {
		t.Errorf("Seed = %d, want 12345678901234567890", cfg.Seed)
	}
	if cfg.MaxContexts != 128 {
		t.Errorf("MaxContexts = %d, want 128", cfg.MaxContexts)
	}
}
