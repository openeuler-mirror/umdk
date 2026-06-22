/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Consistent hash ring implementation for AIGW.
 * Create: 2026-04-29
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"sort"
	"sync"
)

// VirtualNode represents a virtual node in the hash ring.
// Each physical worker has multiple virtual nodes for balanced distribution.
type VirtualNode struct {
	Hash      uint64 // Hash value of the virtual node
	WorkerURL string // Worker URL (may include @rank for DP-aware workers)
	Index     int    // Virtual node index (0, 1, 2, ..., virtualNodes-1)
}

// HashRing represents a consistent hash ring with virtual nodes.
// Uses BTreeMap-like structure (sorted slice) for O(log n) lookups.
type HashRing struct {
	mu      sync.RWMutex
	nodes   []*VirtualNode        // Sorted virtual nodes by hash
	nodeMap map[uint64]string     // Hash -> WorkerURL for quick lookup
	workers map[string]int        // WorkerURL -> count of virtual nodes
}

// NewHashRing creates a new hash ring.
func NewHashRing() *HashRing {
	return &HashRing{
		nodes:   make([]*VirtualNode, 0),
		nodeMap: make(map[uint64]string),
		workers: make(map[string]int),
	}
}

// Build builds the hash ring with the given worker URLs and virtual node count.
// Each worker gets virtualNodes virtual nodes for balanced distribution.
func (hr *HashRing) Build(workerURLs []string, virtualNodes int) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	newNodes := make([]*VirtualNode, 0, len(workerURLs)*virtualNodes)
	newNodeMap := make(map[uint64]string)
	newWorkers := make(map[string]int)

	for _, workerURL := range workerURLs {
		// Create virtual nodes for each worker
		for i := 0; i < virtualNodes; i++ {
			virtualKey := virtualNodeKey(workerURL, i)
			hashValue := FbiHash(virtualKey)

			node := &VirtualNode{
				Hash:      hashValue,
				WorkerURL: workerURL,
				Index:     i,
			}
			newNodes = append(newNodes, node)
			newNodeMap[hashValue] = workerURL
		}
		newWorkers[workerURL] = virtualNodes
	}

	// Sort by hash value for binary search
	sort.Slice(newNodes, func(i, j int) bool {
		return newNodes[i].Hash < newNodes[j].Hash
	})

	hr.nodes = newNodes
	hr.nodeMap = newNodeMap
	hr.workers = newWorkers
}

// Find finds the worker responsible for the given hash value.
// Returns the worker URL whose virtual node is closest to the hash value.
// If no workers exist, returns empty string.
func (hr *HashRing) Find(hashValue uint64) string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	if len(hr.nodes) == 0 {
		return ""
	}

	// Binary search for the first node with hash >= hashValue
	idx := sort.Search(len(hr.nodes), func(i int) bool {
		return hr.nodes[i].Hash >= hashValue
	})

	// Wrap around to the first node if needed
	if idx >= len(hr.nodes) {
		idx = 0
	}

	return hr.nodes[idx].WorkerURL
}

// FindN finds the N closest workers to the given hash value.
// Used for fallback when the primary worker is unhealthy.
// Returns deduplicated worker URLs.
func (hr *HashRing) FindN(hashValue uint64, n int) []string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	if len(hr.nodes) == 0 || n <= 0 {
		return nil
	}

	// Binary search for the starting position
	idx := sort.Search(len(hr.nodes), func(i int) bool {
		return hr.nodes[i].Hash >= hashValue
	})

	result := make([]string, 0, n)
	seen := make(map[string]bool)

	// Iterate around the ring to find N unique workers
	for i := 0; i < len(hr.nodes) && len(result) < n; i++ {
		pos := (idx + i) % len(hr.nodes)
		workerURL := hr.nodes[pos].WorkerURL

		// Deduplicate
		if !seen[workerURL] {
			seen[workerURL] = true
			result = append(result, workerURL)
		}
	}

	return result
}

// GetWorkers returns all current workers in the ring.
func (hr *HashRing) GetWorkers() []string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	workers := make([]string, 0, len(hr.workers))
	for workerURL := range hr.workers {
		workers = append(workers, workerURL)
	}
	return workers
}

// Size returns the number of virtual nodes in the ring.
func (hr *HashRing) Size() int {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	return len(hr.nodes)
}

// WorkerCount returns the number of physical workers in the ring.
func (hr *HashRing) WorkerCount() int {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	return len(hr.workers)
}

// virtualNodeKey generates the key for a virtual node.
// Format: "workerURL:index"
func virtualNodeKey(workerURL string, index int) string {
	// Using simple concatenation to avoid fmt overhead
	// This is called frequently during hash ring building
	return workerURL + ":" + itoa(index)
}

// itoa converts int to string without fmt for performance.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	neg := i < 0
	if neg {
		i = -i
	}

	var b [20]byte
	bp := len(b) - 1
	for i >= 10 {
		q := i / 10
		b[bp] = byte(i - q*10 + '0')
		bp--
		i = q
	}
	b[bp] = byte(i + '0')

	if neg {
		bp--
		b[bp] = '-'
	}

	return string(b[bp:])
}
