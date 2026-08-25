/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Unit tests for prefix cache sync table.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"strings"
	"testing"
	"time"

	"huawei.com/aigw/internal/kvevents"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.BlockSize != defaultBlockSize {
		t.Errorf("expected BlockSize %d, got %d", defaultBlockSize, config.BlockSize)
	}

	if config.MaxContexts != defaultMaxContexts {
		t.Errorf("expected MaxContexts %d, got %d", defaultMaxContexts, config.MaxContexts)
	}

	if config.MaxPrefixesPerContext != defaultMaxPrefixesPerContext {
		t.Errorf("expected MaxPrefixesPerContext %d, got %d", defaultMaxPrefixesPerContext, config.MaxPrefixesPerContext)
	}
}

func TestNewSyncPrefixTable(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16

	table := NewSyncPrefixTable(config, nil)
	if table == nil {
		t.Fatal("expected non-nil SyncPrefixTable")
	}

	if table.seed == 0 {
		t.Error("expected non-zero seed")
	}

	if table.blockSize != 16 {
		t.Errorf("expected blockSize 16, got %d", table.blockSize)
	}

	table.Close()
}

func TestGetPrefixHashes(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"short text", "Hello", 0},
		{"exactly block size", strings.Repeat("A", 64), 1},
		{"two blocks", strings.Repeat("A", 128), 2},
		{"three blocks", strings.Repeat("A", 192), 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashes := table.hasher.getPrefixHashes([]byte(tt.text))
			if len(hashes) != tt.expected {
				t.Errorf("expected %d hashes, got %d", tt.expected, len(hashes))
			}
		})
	}
}

func TestMatchPrefix(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokens := []byte(strings.Repeat("Hello, how are you today? ", 3))
	if len(tokens) < 64 {
		t.Skip("text too short for testing")
	}

	hashes := table.hasher.getPrefixHashes(tokens)
	if len(hashes) == 0 {
		t.Skip("not enough tokens to form a block")
	}

	err := table.AddPrefix("test-model", -1, "instance-1", hashes)
	if err != nil {
		t.Fatalf("AddPrefix failed: %v", err)
	}

	readyInstances := map[string]struct{}{
		"instance-1": {},
	}

	matched, resultHashes := table.MatchPrefix("test-model", -1, tokens, readyInstances)

	if len(resultHashes) == 0 {
		t.Error("expected non-empty result hashes")
	}

	if len(matched) == 0 {
		t.Error("expected at least one matched instance")
	}

	if percent, ok := matched["instance-1"]; !ok || percent != 100 {
		t.Errorf("expected 100%% match for instance-1, got %d%%", percent)
	}
}

func TestMatchPrefixNoMatch(t *testing.T) {
	config := DefaultConfig()
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokens := []byte("Hello world")
	hashes := table.hasher.getPrefixHashes(tokens)

	table.AddPrefix("test-model", -1, "instance-1", hashes)

	differentTokens := []byte("Goodbye world")
	readyInstances := map[string]struct{}{
		"instance-1": {},
	}

	matched, _ := table.MatchPrefix("test-model", -1, differentTokens, readyInstances)

	if len(matched) > 0 {
		t.Error("expected no match for different text")
	}
}

func TestProcessBlockStored(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokenBytes := make([][]byte, 2)
	for i := range tokenBytes {
		tokenBytes[i] = make([]byte, 16*8)
	}

	event := kvevents.BlockStored{
		BlockHashes:     []int64{100, 200},
		ParentBlockHash: nil,
		TokenIDs:        tokenBytes,
		LoraID:          -1,
		ModelName:       "test-model",
		InstanceName:    "instance-1",
	}

	err := table.ProcessBlockStored(event)
	if err != nil {
		t.Fatalf("ProcessBlockStored failed: %v", err)
	}

	ctx := ModelContext{ModelName: "test-model", LoraID: -1}
	value, exists := table.contextMap.Load(ctx)
	if !exists {
		t.Fatal("expected context to be created")
	}

	contextData := value.(*ContextData)
	if len(contextData.hashMapping.engineToAigw) != 2 {
		t.Errorf("expected 2 hash mappings, got %d", len(contextData.hashMapping.engineToAigw))
	}
}

func TestProcessBlockRemoved(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokenBytes := make([][]byte, 1)
	tokenBytes[0] = make([]byte, 16*8)

	event := kvevents.BlockStored{
		BlockHashes:  []int64{100},
		TokenIDs:     tokenBytes,
		ModelName:    "test-model",
		InstanceName: "instance-1",
	}

	table.ProcessBlockStored(event)

	removeEvent := kvevents.BlockRemoved{
		BlockHashes:  []int64{100},
		ModelName:    "test-model",
		InstanceName: "instance-1",
	}

	err := table.ProcessBlockRemoved(removeEvent)
	if err != nil {
		t.Fatalf("ProcessBlockRemoved failed: %v", err)
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultConfig()
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	stats := table.GetStats()

	if stats.TotalContexts != 0 {
		t.Errorf("expected 0 contexts, got %d", stats.TotalContexts)
	}

	hashes := table.hasher.getPrefixHashes([]byte(strings.Repeat("A", 64)))
	table.AddPrefix("test-model", -1, "instance-1", hashes)

	stats = table.GetStats()
	if stats.TotalContexts != 1 {
		t.Errorf("expected 1 context, got %d", stats.TotalContexts)
	}
}

func TestTokenIDsToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []int64
		expected int
	}{
		{"empty", []int64{}, 0},
		{"single token", []int64{1}, 4},
		{"two tokens", []int64{1, 2}, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TokenIDsToBytes(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d bytes, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestGenerateSeed(t *testing.T) {
	seed1 := generateSeed()
	seed2 := generateSeed()

	if seed1 == 0 {
		t.Error("expected non-zero seed")
	}

	if seed1 == seed2 {
		t.Log("Note: seeds happened to match (rare)")
	}
}

func TestHasher(t *testing.T) {
	hasher := newHasher(12345, 16)

	hash1 := hasher.computeHash(0, []byte("test"))
	hash2 := hasher.computeHash(0, []byte("test"))

	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}

	hash3 := hasher.computeHash(0, []byte("different"))
	if hash1 == hash3 {
		t.Error("different input should produce different hash")
	}

	parentHash := hasher.computeHash(0, []byte("parent"))
	childHash := hasher.computeHash(parentHash, []byte("child"))

	if childHash == parentHash {
		t.Error("child hash should differ from parent hash")
	}
}

func TestContextDataCreation(t *testing.T) {
	config := DefaultConfig()
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	ctx := ModelContext{ModelName: "test-model", LoraID: 123}

	data1 := table.getOrCreateContextData(ctx)
	data2 := table.getOrCreateContextData(ctx)

	if data1 != data2 {
		t.Error("getOrCreateContextData should return same instance")
	}

	if data1.prefixStore == nil {
		t.Error("prefixStore should not be nil")
	}

	if data1.hashMapping == nil {
		t.Error("hashMapping should not be nil")
	}
}

func TestAddPrefixLimits(t *testing.T) {
	config := DefaultConfig()
	config.MaxPrefixesPerContext = 5
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	hashes := make([]uint64, 10)
	for i := range hashes {
		hashes[i] = uint64(i + 1)
	}

	err := table.AddPrefix("test-model", -1, "instance-1", hashes)
	if err != nil {
		t.Fatalf("AddPrefix failed: %v", err)
	}

	ctx := ModelContext{ModelName: "test-model", LoraID: -1}
	value, _ := table.contextMap.Load(ctx)
	contextData := value.(*ContextData)

	if contextData.prefixStore.totalPrefixes > int64(config.MaxPrefixesPerContext) {
		t.Errorf("totalPrefixes %d exceeds limit %d",
			contextData.prefixStore.totalPrefixes, config.MaxPrefixesPerContext)
	}
}

func TestRemoveInstance(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	hashes := table.hasher.getPrefixHashes([]byte(strings.Repeat("A", 64)))
	table.AddPrefix("test-model", -1, "instance-1", hashes)
	table.AddPrefix("test-model", -1, "instance-2", hashes)

	err := table.RemoveInstance("test-model", -1, "instance-1")
	if err != nil {
		t.Fatalf("RemoveInstance failed: %v", err)
	}

	tokens := []byte(strings.Repeat("A", 64))
	readyInstances := map[string]struct{}{
		"instance-2": {},
	}

	matched, _ := table.MatchPrefix("test-model", -1, tokens, readyInstances)

	if _, ok := matched["instance-1"]; ok {
		t.Error("instance-1 should be removed")
	}
}

func TestMatchPrefixByText(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	text := strings.Repeat("Hello, how are you today? ", 3)
	hashes := table.GetPrefixHashesByText(text)

	if len(hashes) == 0 {
		t.Skip("text too short")
	}

	table.AddPrefix("test-model", -1, "instance-1", hashes)

	readyInstances := map[string]struct{}{
		"instance-1": {},
	}

	matched, _ := table.MatchPrefixByText("test-model", -1, text, readyInstances)

	if len(matched) == 0 {
		t.Error("expected match for same text")
	}
}

func TestMatchPrefixFromTokenIDs(t *testing.T) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	tokenIDs := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	hashes := table.GetPrefixHashesFromTokenIDs(tokenIDs)

	if len(hashes) == 0 {
		t.Error("expected at least one hash")
	}

	table.AddPrefix("test-model", -1, "instance-1", hashes)

	readyInstances := map[string]struct{}{
		"instance-1": {},
	}

	matched, _ := table.MatchPrefixFromTokenIDs("test-model", -1, tokenIDs, readyInstances)

	if len(matched) == 0 {
		t.Error("expected match for same token IDs")
	}
}

func TestEvictionWorker(t *testing.T) {
	config := DefaultConfig()
	config.EvictionInterval = 100 * time.Millisecond
	config.EvictionDuration = 50 * time.Millisecond
	config.BlockSize = 16

	table := NewSyncPrefixTable(config, nil)

	hashes := table.hasher.getPrefixHashes([]byte(strings.Repeat("A", 64)))
	table.AddPrefix("test-model", -1, "instance-1", hashes)

	time.Sleep(200 * time.Millisecond)

	table.Close()

	t.Log("Eviction worker test completed")
}

func BenchmarkGetPrefixHashes(b *testing.B) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	text := make([]byte, 1000)
	for i := range text {
		text[i] = 'A'
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.hasher.getPrefixHashes(text)
	}
}

func BenchmarkMatchPrefix(b *testing.B) {
	config := DefaultConfig()
	config.BlockSize = 16
	table := NewSyncPrefixTable(config, nil)
	defer table.Close()

	text := make([]byte, 1000)
	for i := range text {
		text[i] = 'A'
	}

	hashes := table.hasher.getPrefixHashes(text)
	table.AddPrefix("test-model", -1, "instance-1", hashes)

	readyInstances := map[string]struct{}{
		"instance-1": {},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.MatchPrefix("test-model", -1, text, readyInstances)
	}
}
