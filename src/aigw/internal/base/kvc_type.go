/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package base

// KvcConfig is the top-level KVC management config section.
// Added in Phase 2. ServiceMode only.
type KvcConfig struct {
	Enabled bool             `json:"enabled"`
	Agent   KvcAgentConfig   `json:"agent"`
	Session KvcSessionConfig `json:"session"`
	Vllm    KvcVllmConfig    `json:"vllm"` // NOTE: design doc called this "pymotor"; pyMotor is unavailable — points at vLLM
}

// KvcAgentConfig configures agent lifecycle state machine + strategies.
type KvcAgentConfig struct {
	HeartbeatIntervalSec          int               `json:"heartbeatIntervalSec"`
	HeartbeatTimeoutSec          int               `json:"heartbeatTimeoutSec"`
	RecoverWindowSec             int               `json:"recoverWindowSec"`
	RecoverTimeoutSec            int               `json:"recoverTimeoutSec"`
	GoneFinalizeSec              int               `json:"goneFinalizeSec"`
	RegisterGraceSec             int               `json:"registerGraceSec"`
	ImplicitHeartbeatFromRequests bool             `json:"implicitHeartbeatFromRequests"`
	Offload                      KvcOffloadConfig  `json:"offload"`
	Prefetch                     KvcPrefetchConfig `json:"prefetch"`
	Aging                        KvcAgingConfig    `json:"aging"`
}

// KvcOffloadConfig configures the offload strategy.
type KvcOffloadConfig struct {
	Mode                  string `json:"mode"`
	BatchSize             int    `json:"batchSize"`
	TargetTier            string `json:"targetTier"`
	DelayBetweenBatchesMs int    `json:"delayBetweenBatchesMs"`
}

// KvcPrefetchConfig configures the prefetch strategy.
type KvcPrefetchConfig struct {
	Mode                  string `json:"mode"`
	TopN                  int    `json:"topN"`
	BatchSize             int    `json:"batchSize"`
	DelayBetweenBatchesMs int    `json:"delayBetweenBatchesMs"`
}

// KvcAgingConfig configures the session aging strategy.
type KvcAgingConfig struct {
	Mode                string `json:"mode"`
	LoopIntervalSec     int    `json:"loopIntervalSec"`
	EvictGraceSec       int    `json:"evictGraceSec"`
	SessionIdleEvictSec int    `json:"sessionIdleEvictSec"`
	BatchSize           int    `json:"batchSize"`
}

// KvcSessionConfig configures session/block index persistence.
type KvcSessionConfig struct {
	SessionTtlSec            int     `json:"sessionTtlSec"`
	BlockTtlSec              int     `json:"blockTtlSec"`
	PendingBlockMatchTtlSec  int     `json:"pendingBlockMatchTtlSec"`
	AccessFrequencyEmaWeight float64 `json:"accessFrequencyEmaWeight"`
	AccessFrequencyWindowSec int     `json:"accessFrequencyWindowSec"`
}

// KvcVllmConfig configures the HTTP client pointing at vLLM's /v1/kvc/* control plane.
// (Design doc named this "pymotor"; pyMotor is unavailable — see plan header.)
type KvcVllmConfig struct {
	Endpoint         string `json:"endpoint"`
	TimeoutMs        int    `json:"timeoutMs"`
	MaxRetries       int    `json:"maxRetries"`
	RetryBaseDelayMs int    `json:"retryBaseDelayMs"`
	RetryMaxDelayMs  int    `json:"retryMaxDelayMs"`
	BatchSize        int    `json:"batchSize"`
	HmacEnabled      bool   `json:"hmacEnabled"`
}

// DefaultKvcConfig returns disabled-by-default config (SdkMode / no-kvc deployments).
func DefaultKvcConfig() KvcConfig {
	return KvcConfig{Enabled: false}
}
