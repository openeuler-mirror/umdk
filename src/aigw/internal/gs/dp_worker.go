/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: DP (Data Parallel) aware worker support.
 * Create: 2026-04-29
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"fmt"
	"strconv"
	"strings"

	"huawei.com/aigw/internal/base"
)

// DPAwareWorker represents a DP-aware worker with rank information.
// Each physical worker can be expanded into multiple DP-aware workers,
// each with a different DP rank for fine-grained load balancing.
type DPAwareWorker struct {
	BaseURL  string            // Base URL without @rank suffix (e.g., "http://worker:8000")
	DpRank   int               // DP rank (0, 1, 2, ...)
	DpSize   int               // Total DP size (number of virtual workers per physical worker)
	InsRole  base.InstanceRole // Instance role
	GroupID  string            // Group ID
}

// NewDPAwareWorker creates a new DP-aware worker.
func NewDPAwareWorker(baseURL string, dpRank, dpSize int, role base.InstanceRole, groupID string) *DPAwareWorker {
	return &DPAwareWorker{
		DpRank:  dpRank,
		DpSize:  dpSize,
		BaseURL: baseURL,
		InsRole: role,
		GroupID: groupID,
	}
}

// URL returns the identifier URL with @rank suffix.
// This is used for consistent hash routing and identification.
// Example: "http://worker:8000@2"
func (dw *DPAwareWorker) URL() string {
	return fmt.Sprintf("%s@%d", dw.BaseURL, dw.DpRank)
}

// BaseURL2 returns the base URL without @rank suffix.
// This is used for actual HTTP requests.
// Example: "http://worker:8000"
func (dw *DPAwareWorker) BaseURL2() string {
	return dw.BaseURL
}

// EndpointURL returns the actual request URL by appending the route.
// This is the URL used for sending HTTP requests (no @rank).
// Example: "http://worker:8000/v1/chat/completions"
func (dw *DPAwareWorker) EndpointURL(route string) string {
	return fmt.Sprintf("%s%s", dw.BaseURL, route)
}

// DpRankOpt returns the DP rank as an optional pointer.
// Returns nil if DP is not enabled (DpSize <= 1).
func (dw *DPAwareWorker) DpRankOpt() *int {
	if dw.DpSize <= 1 {
		return nil
	}
	return &dw.DpRank
}

// DPAwareSnapshot represents a snapshot of a DP-aware worker's metrics.
type DPAwareSnapshot struct {
	InsUrl      string  // Identifier URL with @rank
	BaseURL     string  // Base URL without @rank
	DpRank      int     // DP rank
	DpSize      int     // DP size
	FreeBlocks  int     // Available blocks
	TokenNum    int     // Total tokens processed
	TBT         float64 // Time between tokens (ms)
	TTFT        float64 // Time to first token (ms)
	InsRole     base.InstanceRole
	GroupID     string
}

// DPAwareMetric represents metrics for a DP-aware worker.
type DPAwareMetric struct {
	InsUrl     string  // Identifier URL with @rank
	BaseURL    string  // Base URL without @rank
	DpRank     int     // DP rank
	FreeBlocks int     // Available blocks
	TokenNum   int     // Total tokens processed
	TBT        float64 // Time between tokens (ms)
	TTFT       float64 // Time to first token (ms)
	GroupID    string
}

// ParseDPAwareWorkerURL parses a DP-aware worker URL.
// Returns the base URL, DP rank, and whether a rank was present.
// Example: "http://worker:8000@2" -> ("http://worker:8000", 2, true)
// Example: "http://worker:8000" -> ("http://worker:8000", 0, false)
func ParseDPAwareWorkerURL(url string) (baseURL string, dpRank int, hasRank bool) {
	parts := strings.Split(url, "@")
	if len(parts) == 2 {
		rank, err := strconv.Atoi(parts[1])
		if err == nil {
			return parts[0], rank, true
		}
	}
	return url, 0, false
}

// ExtractDpRank extracts the DP rank from a worker URL.
// Returns the base URL, DP rank pointer, and error.
// Example: "http://worker:8000@2" -> ("http://worker:8000", &2, nil)
// Example: "http://worker:8000" -> ("http://worker:8000", nil, nil)
func ExtractDpRank(workerURL string) (baseURL string, dpRank *int, err error) {
	parts := strings.Split(workerURL, "@")
	if len(parts) != 2 {
		// No DP rank present
		return workerURL, nil, nil
	}

	rank, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("invalid dp rank: %s", parts[1])
	}

	return parts[0], &rank, nil
}

// GetDPAwareWorkers expands worker URLs into DP-aware format.
// Each physical worker URL is expanded into dpSize DP-aware worker URLs.
// Example: (["http://worker:8000"], 3) -> ["http://worker:8000@0", "http://worker:8000@1", "http://worker:8000@2"]
func GetDPAwareWorkers(workerURLs []string, dpSize int) []string {
	if dpSize <= 1 {
		// No DP expansion needed
		return workerURLs
	}

	var dpAwareWorkers []string
	for _, url := range workerURLs {
		// Expand each physical worker into dpSize DP-aware workers
		for rank := 0; rank < dpSize; rank++ {
			dpAwareWorkers = append(dpAwareWorkers, fmt.Sprintf("%s@%d", url, rank))
		}
	}
	return dpAwareWorkers
}
