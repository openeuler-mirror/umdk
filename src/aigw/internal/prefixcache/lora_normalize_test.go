/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Prefix cache loraID normalization tests.
 */

package prefixcache

import (
	"strings"
	"testing"

	"huawei.com/aigw/internal/kvevents"
)

// TestMatchPrefix_LoraIDZeroStoreNegOneLookup reproduces the production
// mismatch that silently disabled prefix hits against real vLLM.
//
// Real vLLM emits BlockStored with a nil lora_id field, which aigw's decoder
// materializes as LoraID=0 (the int64 zero value). The request path, however,
// calls MatchPrefix with loraID=-1 (the codebase's "no lora" convention, used
// by every existing test). The two form different ModelContext keys
// ({model,0} vs {model,-1}), so contextMap.Load misses on every real-vLLM
// lookup → "no context found" → prefix cache never hits, every request falls
// back to least-conn. Both sides must normalize the no-lora sentinel to a
// single canonical value.
func TestMatchPrefix_LoraIDZeroStoreNegOneLookup(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokens := []byte(strings.Repeat("Hello, how are you today? ", 3))
	hashes := table.hasher.getPrefixHashes(tokens)
	if len(hashes) == 0 {
		t.Skip("not enough tokens to form a block")
	}

	// Store side: vLLM nil-lora → LoraID=0.
	if err := table.AddPrefix("test-model", 0, "instance-1", hashes); err != nil {
		t.Fatalf("AddPrefix failed: %v", err)
	}

	ready := map[string]struct{}{"instance-1": {}}
	// Lookup side: request path hardcodes loraID=-1 (no-lora convention).
	matched, _ := table.MatchPrefix("test-model", -1, tokens, ready)

	if len(matched) == 0 {
		t.Errorf("expected prefix match despite store loraID=0 vs lookup loraID=-1; "+
			"no-lora must normalize to a single canonical key. matched=%v", matched)
	}
}

// TestProcessBlockStored_LoraIDZeroStoresUnderNegOneKey covers the
// event-driven path: a real-vLLM BlockStored event carries LoraID=0 (nil
// lora_id → 0). The context must be stored under the canonical no-lora key
// {model, -1} so a subsequent MatchPrefix(loraID=-1) lookup finds it. We
// assert the contextMap key directly rather than a full hash round-trip,
// isolating the loraID normalization from block-hash alignment concerns.
func TestProcessBlockStored_LoraIDZeroStoresUnderNegOneKey(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokenBytes := make([][]byte, 2)
	for i := range tokenBytes {
		tokenBytes[i] = make([]byte, 16*8)
	}

	// vLLM event: nil lora_id → decoded LoraID=0.
	event := kvevents.BlockStored{
		BlockHashes:     []int64{100, 200},
		ParentBlockHash: nil,
		TokenIDs:        tokenBytes,
		LoraID:          0,
		ModelName:       "test-model",
		InstanceName:    "instance-1",
	}

	if err := table.ProcessBlockStored(event); err != nil {
		t.Fatalf("ProcessBlockStored failed: %v", err)
	}

	// The context must be stored under the canonical no-lora key {-1}, NOT {0}.
	normalizedCtx := ModelContext{ModelName: "test-model", LoraID: -1}
	if _, exists := table.contextMap.Load(normalizedCtx); !exists {
		t.Errorf("expected context stored under normalized key {model, -1} " +
			"after BlockStored(LoraID=0); not found (loraID not normalized)")
	}
	zeroCtx := ModelContext{ModelName: "test-model", LoraID: 0}
	if _, exists := table.contextMap.Load(zeroCtx); exists {
		t.Errorf("context must NOT be stored under raw key {model, 0}; " +
			"normalizeLoraID should have canonicalized 0 → -1")
	}
}
