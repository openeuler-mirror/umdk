/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Prefix cache types and interfaces.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"sync"
)

type ModelContext struct {
	ModelName string
	LoraID    int64
}

// normalizeLoraID canonicalizes the LoRA identifier used as part of a
// ModelContext key. The request path passes loraID=-1 for "no lora" (the
// convention every existing test uses), but real vLLM emits BlockStored with
// a nil lora_id field, which the decoder materializes as LoraID=0 (the int64
// zero value). Without normalization the two form different ModelContext keys
// ({model,0} vs {model,-1}), so contextMap.Load misses on every real-vLLM
// lookup → "no context found" → the prefix cache never hits and every
// request falls back to least-conn. vLLM reserves lora_id 0 (and nil) for the
// base/no-lora case; real adapters get IDs ≥ 1. Map any non-positive value to
// the canonical no-lora sentinel -1 so store and lookup sides agree.
func normalizeLoraID(loraID int64) int64 {
	if loraID <= 0 {
		return -1
	}
	return loraID
}

type InstanceInfo struct {
	InstanceName   string
	LastAccessTime int64
}

type PrefixStore struct {
	prefixMap     map[uint64]map[string]*InstanceInfo
	createTime    int64
	lastAccess    int64
	totalPrefixes int64
}

type HashMapping struct {
	engineToAigw map[int64]uint64
}

type ContextData struct {
	prefixMu  sync.RWMutex
	mappingMu sync.RWMutex

	prefixStore *PrefixStore
	hashMapping *HashMapping
}

type PrefixCacheStats struct {
	TotalContexts    int32
	TotalPrefixes    int64
	TotalMappings    int64
	MemoryUsageBytes int64
}
