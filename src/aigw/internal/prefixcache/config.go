/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Prefix cache configuration.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"time"
)

const (
	defaultBlockSize              = 16
	defaultMaxContexts            = 1000
	defaultMaxPrefixesPerContext  = 10000
	defaultEvictionInterval       = 60 * time.Second
	defaultEvictionDuration       = 20 * time.Minute
	defaultFallbackStringMatching = true
)

// Config holds the prefix cache tuning knobs. Zero values mean "use the
// default", so every JSON field is optional. Seed 0 means random.
// BlockSize is driven by globalSchedulers[].blockSize (aligned with the
// vLLM --block-size), not by this struct's JSON.
type Config struct {
	BlockSize              int           `json:"-"`
	MaxContexts            int           `json:"maxContexts,omitempty"`
	MaxPrefixesPerContext  int           `json:"maxPrefixesPerContext,omitempty"`
	EvictionInterval       time.Duration `json:"-"`
	EvictionDuration       time.Duration `json:"-"`
	FallbackStringMatching bool          `json:"-"`
	Seed                   uint64        `json:"seed,omitempty"`

	EvictionIntervalSeconds int `json:"evictionIntervalSeconds,omitempty"`
	EvictionDurationMinutes int `json:"evictionDurationMinutes,omitempty"`
}

// DefaultConfig returns the built-in defaults. JSON sections that set a
// field override the corresponding default (see ApplyJSONDefaults).
func DefaultConfig() Config {
	return Config{
		BlockSize:              defaultBlockSize,
		MaxContexts:            defaultMaxContexts,
		MaxPrefixesPerContext:  defaultMaxPrefixesPerContext,
		EvictionInterval:       defaultEvictionInterval,
		EvictionDuration:       defaultEvictionDuration,
		FallbackStringMatching: defaultFallbackStringMatching,
		Seed:                   0,
	}
}

// ApplyJSONDefaults merges a JSON-unmarshalled Config (zero values = unset)
// onto the defaults: each set JSON field overrides the corresponding default.
func ApplyJSONDefaults(jsonCfg Config) Config {
	cfg := DefaultConfig()
	if jsonCfg.MaxContexts > 0 {
		cfg.MaxContexts = jsonCfg.MaxContexts
	}
	if jsonCfg.MaxPrefixesPerContext > 0 {
		cfg.MaxPrefixesPerContext = jsonCfg.MaxPrefixesPerContext
	}
	if jsonCfg.EvictionIntervalSeconds > 0 {
		cfg.EvictionInterval = time.Duration(jsonCfg.EvictionIntervalSeconds) * time.Second
	}
	if jsonCfg.EvictionDurationMinutes > 0 {
		cfg.EvictionDuration = time.Duration(jsonCfg.EvictionDurationMinutes) * time.Minute
	}
	if jsonCfg.Seed != 0 {
		cfg.Seed = jsonCfg.Seed
	}
	return cfg
}
