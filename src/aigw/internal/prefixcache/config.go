/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Prefix cache configuration.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"os"
	"strconv"
	"time"
)

const (
	defaultMaxContexts             = 1000
	defaultMaxPrefixesPerContext   = 10000
	defaultEvictionIntervalSeconds = 60
	defaultEvictionDurationMinutes = 20
	defaultBlockSize               = 16
)

func loadEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		return val == "true" || val == "1"
	}
	return defaultVal
}

func loadEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func loadEnvUint64(key string, defaultVal uint64) uint64 {
	if val := os.Getenv(key); val != "" {
		if uintVal, err := strconv.ParseUint(val, 10, 64); err == nil {
			return uintVal
		}
	}
	return defaultVal
}

var (
	envBlockSize               = loadEnvInt("AIGW_PREFIX_CACHE_BLOCK_SIZE", defaultBlockSize)
	envMaxContexts             = loadEnvInt("AIGW_PREFIX_CACHE_MAX_CONTEXTS", defaultMaxContexts)
	envMaxPrefixesPerContext   = loadEnvInt("AIGW_PREFIX_CACHE_MAX_PREFIXES_PER_CONTEXT", defaultMaxPrefixesPerContext)
	envEvictionIntervalSeconds = loadEnvInt("AIGW_PREFIX_CACHE_EVICTION_INTERVAL_SECONDS", defaultEvictionIntervalSeconds)
	envEvictionDurationMinutes = loadEnvInt("AIGW_PREFIX_CACHE_EVICTION_DURATION_MINUTES", defaultEvictionDurationMinutes)
	envFallbackStringMatching  = loadEnvBool("AIGW_PREFIX_CACHE_FALLBACK_STRING_MATCHING", true)
	envSeed                    = loadEnvUint64("AIGW_PREFIX_CACHE_SEED", 0) // 0 means random seed
)

// Config has no Enabled or MatchThreshold fields: the prefix cache is driven
// solely by selecting the prefixCache load-balancer algorithm, and partial
// prefix hits are always preferred over falling back (#900).
type Config struct {
	BlockSize              int
	MaxContexts            int
	MaxPrefixesPerContext  int
	EvictionInterval       time.Duration
	EvictionDuration       time.Duration
	FallbackStringMatching bool
	Seed                   uint64 // 0 means generate random seed
}

func DefaultConfig() Config {
	return Config{
		BlockSize:              envBlockSize,
		MaxContexts:            envMaxContexts,
		MaxPrefixesPerContext:  envMaxPrefixesPerContext,
		EvictionInterval:       time.Duration(envEvictionIntervalSeconds) * time.Second,
		EvictionDuration:       time.Duration(envEvictionDurationMinutes) * time.Minute,
		FallbackStringMatching: envFallbackStringMatching,
		Seed:                   envSeed,
	}
}
