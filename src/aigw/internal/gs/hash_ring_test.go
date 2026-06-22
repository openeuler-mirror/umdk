/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Consistent hash ring test for AIGW.
 * Create: 2026-04-29
 */

package gs

import (
	"testing"
)

func TestHashRing_NewHashRing(t *testing.T) {
	hr := NewHashRing()
	if hr == nil {
		t.Fatal("NewHashRing returned nil")
	}
	if hr.nodes == nil {
		t.Error("nodes slice should be initialized")
	}
	if hr.nodeMap == nil {
		t.Error("nodeMap should be initialized")
	}
	if hr.workers == nil {
		t.Error("workers map should be initialized")
	}
}

func TestHashRing_Build(t *testing.T) {
	tests := []struct {
		name         string
		workerURLs   []string
		virtualNodes int
		wantNodes    int
		wantWorkers  int
	}{
		{"empty", []string{}, 10, 0, 0},
		{"single worker", []string{"http://worker1:8000"}, 10, 10, 1},
		{"multiple workers", []string{"http://worker1:8000", "http://worker2:8000"}, 10, 20, 2},
		{"three workers", []string{"w1", "w2", "w3"}, 100, 300, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hr := NewHashRing()
			hr.Build(tt.workerURLs, tt.virtualNodes)

			if hr.Size() != tt.wantNodes {
				t.Errorf("Size() = %d, want %d", hr.Size(), tt.wantNodes)
			}
			if hr.WorkerCount() != tt.wantWorkers {
				t.Errorf("WorkerCount() = %d, want %d", hr.WorkerCount(), tt.wantWorkers)
			}
		})
	}
}

func TestHashRing_Build_SortedNodes(t *testing.T) {
	hr := NewHashRing()
	workers := []string{"http://worker1:8000", "http://worker2:8000", "http://worker3:8000"}
	hr.Build(workers, 100)

	for i := 1; i < len(hr.nodes); i++ {
		if hr.nodes[i-1].Hash >= hr.nodes[i].Hash {
			t.Errorf("nodes not sorted at index %d: %d >= %d", i, hr.nodes[i-1].Hash, hr.nodes[i].Hash)
		}
	}
}

func TestHashRing_Build_Deterministic(t *testing.T) {
	hr1 := NewHashRing()
	hr2 := NewHashRing()

	workers := []string{"http://worker1:8000", "http://worker2:8000"}
	hr1.Build(workers, 50)
	hr2.Build(workers, 50)

	if hr1.Size() != hr2.Size() {
		t.Errorf("ring sizes differ: %d vs %d", hr1.Size(), hr2.Size())
	}

	for i := range hr1.nodes {
		if hr1.nodes[i].Hash != hr2.nodes[i].Hash {
			t.Errorf("hash differs at index %d: %d vs %d", i, hr1.nodes[i].Hash, hr2.nodes[i].Hash)
		}
	}
}

func TestHashRing_Find_Empty(t *testing.T) {
	hr := NewHashRing()
	result := hr.Find(12345)
	if result != "" {
		t.Errorf("Find on empty ring returned %q, want empty string", result)
	}
}

func TestHashRing_Find_Basic(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"http://worker1:8000"}, 100)

	hashValue := hr.nodes[50].Hash
	result := hr.Find(hashValue)

	if result != "http://worker1:8000" {
		t.Errorf("Find() = %q, want %q", result, "http://worker1:8000")
	}
}

func TestHashRing_Find_Consistency(t *testing.T) {
	workers := []string{
		"http://worker1:8000",
		"http://worker2:8000",
		"http://worker3:8000",
		"http://worker4:8000",
	}

	hr := NewHashRing()
	hr.Build(workers, 160)

	testKeys := []string{"key1", "key2", "key3", "user123", "session456"}
	for _, key := range testKeys {
		hashValue := FbiHash(key)
		result := hr.Find(hashValue)

		found := false
		for _, w := range workers {
			if result == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Find(%s) = %q, not in workers %v", key, result, workers)
		}
	}
}

func TestHashRing_Find_WrapAround(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"http://worker1:8000"}, 100)

	hashValue := hr.nodes[0].Hash
	result := hr.Find(hashValue)

	if result != "http://worker1:8000" {
		t.Errorf("Find at first node = %q, want worker1", result)
	}

	result = hr.Find(0)
	if result != "http://worker1:8000" {
		t.Errorf("Find(0) = %q, want worker1", result)
	}
}

func TestHashRing_Find_AllKeysInRange(t *testing.T) {
	hr := NewHashRing()
	workers := []string{"w1", "w2", "w3", "w4", "w5"}
	hr.Build(workers, 100)

	hashes := make(map[string]int)
	for i := 0; i < 10000; i++ {
		key := string(rune(i))
		result := hr.Find(FbiHash(key))
		hashes[result]++
	}

	for worker, count := range hashes {
		if count < 1000 {
			t.Errorf("Worker %s has only %d keys, distribution may be poor", worker, count)
		}
	}
}

func TestHashRing_FindN_Empty(t *testing.T) {
	hr := NewHashRing()
	result := hr.FindN(12345, 3)
	if result != nil {
		t.Errorf("FindN on empty ring returned %v, want nil", result)
	}
}

func TestHashRing_FindN_ZeroN(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"http://worker1:8000"}, 10)
	result := hr.FindN(12345, 0)
	if result != nil {
		t.Errorf("FindN with n=0 returned %v, want nil", result)
	}
}

func TestHashRing_FindN_Basic(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"w1", "w2", "w3"}, 100)

	result := hr.FindN(FbiHash("test-key"), 3)

	if len(result) != 3 {
		t.Errorf("FindN returned %d workers, want 3", len(result))
	}

	seen := make(map[string]bool)
	for _, w := range result {
		if seen[w] {
			t.Errorf("FindN returned duplicate worker: %s", w)
		}
		seen[w] = true
	}
}

func TestHashRing_FindN_MoreThanAvailable(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"w1", "w2"}, 10)

	result := hr.FindN(FbiHash("test-key"), 10)

	if len(result) != 2 {
		t.Errorf("FindN requested 10 but only 2 workers available, got %d", len(result))
	}
}

func TestHashRing_FindN_Ordered(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"w1", "w2", "w3", "w4"}, 100)

	hashValue := FbiHash("test-key")
	result := hr.FindN(hashValue, 4)

	if len(result) != 4 {
		t.Fatalf("FindN returned %d, want 4", len(result))
	}

	seen := make(map[string]bool)
	for _, worker := range result {
		if seen[worker] {
			t.Errorf("FindN returned duplicate worker: %s", worker)
		}
		seen[worker] = true
	}

	unique := []string{}
	for _, w := range result {
		unique = append(unique, w)
	}

	if len(unique) != 4 {
		t.Errorf("FindN should return 4 unique workers, got %d", len(unique))
	}
}

func TestHashRing_GetWorkers(t *testing.T) {
	hr := NewHashRing()
	workers := []string{"w1", "w2", "w3"}
	hr.Build(workers, 100)

	result := hr.GetWorkers()
	if len(result) != 3 {
		t.Errorf("GetWorkers returned %d workers, want 3", len(result))
	}

	for _, w := range workers {
		found := false
		for _, r := range result {
			if r == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetWorkers missing worker: %s", w)
		}
	}
}

func TestHashRing_GetWorkers_Empty(t *testing.T) {
	hr := NewHashRing()
	result := hr.GetWorkers()
	if len(result) != 0 {
		t.Errorf("GetWorkers on empty ring returned %v, want empty", result)
	}
}

func TestHashRing_Size(t *testing.T) {
	hr := NewHashRing()
	if hr.Size() != 0 {
		t.Errorf("empty ring Size() = %d, want 0", hr.Size())
	}

	hr.Build([]string{"w1", "w2", "w3"}, 50)
	if hr.Size() != 150 {
		t.Errorf("Size() = %d, want 150", hr.Size())
	}
}

func TestHashRing_WorkerCount(t *testing.T) {
	hr := NewHashRing()
	if hr.WorkerCount() != 0 {
		t.Errorf("empty ring WorkerCount() = %d, want 0", hr.WorkerCount())
	}

	hr.Build([]string{"w1", "w2", "w3"}, 50)
	if hr.WorkerCount() != 3 {
		t.Errorf("WorkerCount() = %d, want 3", hr.WorkerCount())
	}
}

func TestHashRing_Rebuild(t *testing.T) {
	hr := NewHashRing()
	hr.Build([]string{"w1", "w2"}, 100)

	oldHash := hr.Find(FbiHash("test-key"))

	hr.Build([]string{"w1", "w2", "w3"}, 100)

	newSize := hr.Size()
	if newSize != 300 {
		t.Errorf("after rebuild Size() = %d, want 300", newSize)
	}

	newHash := hr.Find(FbiHash("test-key"))
	if newHash != oldHash && newHash == "w3" {
		t.Logf("key remapped from %s to %s after adding w3", oldHash, newHash)
	}
}

func TestHashRing_ThreadSafety(t *testing.T) {
	hr := NewHashRing()
	workers := []string{"w1", "w2", "w3"}
	hr.Build(workers, 100)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 1000; j++ {
				_ = hr.Find(FbiHash(string(rune(j))))
				_ = hr.FindN(FbiHash(string(rune(j))), 3)
				_ = hr.Size()
				_ = hr.WorkerCount()
				_ = hr.GetWorkers()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestVirtualNodeKey(t *testing.T) {
	tests := []struct {
		worker string
		index  int
		want   string
	}{
		{"worker1", 0, "worker1:0"},
		{"worker1", 1, "worker1:1"},
		{"http://worker:8000", 100, "http://worker:8000:100"},
	}

	for _, tt := range tests {
		got := virtualNodeKey(tt.worker, tt.index)
		if got != tt.want {
			t.Errorf("virtualNodeKey(%q, %d) = %q, want %q", tt.worker, tt.index, got, tt.want)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		i    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{99, "99"},
		{100, "100"},
		{999, "999"},
		{1000, "1000"},
		{-1, "-1"},
		{-10, "-10"},
		{-100, "-100"},
	}

	for _, tt := range tests {
		got := itoa(tt.i)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.i, got, tt.want)
		}
	}
}

func TestHashRing_Distribution(t *testing.T) {
	hr := NewHashRing()
	workers := []string{
		"http://worker1:8000",
		"http://worker2:8000",
		"http://worker3:8000",
	}
	hr.Build(workers, 160)

	counts := map[string]int{
		"http://worker1:8000": 0,
		"http://worker2:8000": 0,
		"http://worker3:8000": 0,
	}

	n := 10000
	for i := 0; i < n; i++ {
		key := string(rune(i)) + "some-request-data"
		result := hr.Find(FbiHash(key))
		counts[result]++
	}

	expected := float64(n) / float64(len(workers))
	tolerance := 0.2

	for worker, count := range counts {
		ratio := float64(count) / expected
		if ratio < 1-tolerance || ratio > 1+tolerance {
			t.Errorf("Worker %s has %d/%d (ratio %.2f), expected ~%.2f ±20%%",
				worker, count, n, ratio, expected)
		}
	}
}

func TestHashRing_MinimalRemapOnNodeChange(t *testing.T) {
	workers := []string{"w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10"}

	hr := NewHashRing()
	hr.Build(workers, 160)

	keys := make([]string, 1000)
	results := make([]string, len(keys))
	for i := range keys {
		keys[i] = string(rune(i)) + "-key-for-consistency-test"
		results[i] = hr.Find(FbiHash(keys[i]))
	}

	hr.Build(append(workers, "w11"), 160)

	remapped := 0
	for i := range keys {
		newResult := hr.Find(FbiHash(keys[i]))
		if newResult != results[i] {
			remapped++
		}
	}

	remapRatio := float64(remapped) / float64(len(keys))
	if remapRatio > 0.15 {
		t.Errorf("Remap ratio %.2f%% is higher than expected ~10%% for consistent hash", remapRatio*100)
	} else {
		t.Logf("Remap ratio: %.2f%% (expected ~10%%)", remapRatio*100)
	}
}