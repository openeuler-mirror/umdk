/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Consistent hash load balancer for AIGW.
 * Create: 2026-04-29
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"net/http"
	"sync"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

// ConsistentHashLB implements consistent hash load balancing for session affinity.
// Supports DP-aware workers with virtual nodes for balanced distribution.
type ConsistentHashLB struct {
	baseLoadBalancer
	hashRing     *HashRing
	virtualNodes int
	mu           sync.RWMutex
	lastWorkers  []string
	dpSize       int
	fallbackNum  int // Number of fallback workers to try on failure
}

// newConsistentHashLB creates a new consistent hash load balancer.
func newConsistentHashLB(metricProvider MetricProvider, params *AlgorithmParams) (*ConsistentHashLB, error) {
	log.Info().Msgf("[ConsistentHash] Init ConsistentHash loadbalancer.")

	virtualNodes := VirtualNodesPerWorker
	if params.VirtualNodes > 0 {
		virtualNodes = params.VirtualNodes
	}

	fallbackNum := 3 // Default: try 3 workers on failure
	if params.FallbackNum > 0 {
		fallbackNum = params.FallbackNum
	}

	return &ConsistentHashLB{
		baseLoadBalancer: baseLoadBalancer{
			metricProvider:    metricProvider,
			instanceRoleType:  params.InstanceRoleType,
		},
		hashRing:     NewHashRing(),
		virtualNodes: virtualNodes,
		dpSize:       params.DpSize,
		fallbackNum:  fallbackNum,
	}, nil
}

// schedule implements the loadBalancer interface for consistent hash.
func (lb *ConsistentHashLB) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	// 1. Extract hash key from request
	hashKey := lb.extractHashKeyFromRequest(request)

	// 2. Calculate hash value
	hashValue := FbiHash(hashKey)

	// 3. Get worker metrics
	queryOpts := lb.buildQueryOptions(options)
	metrics, err := lb.metricProvider.GetInstanceMetrics(nil, queryOpts)
	if err != nil {
		log.Error().Msgf("[ConsistentHash] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	if len(metrics) == 0 {
		log.Debug().Msg("[ConsistentHash] no instances available for scheduling")
		return createEmptyScheduleResult()
	}

	// 4. Get DP-aware worker URLs
	workerURLs := lb.getWorkerURLs(metrics)

	// 5. Update hash ring if workers changed
	lb.updateHashRingIfNeeded(workerURLs)

	// 6. Find target worker
	targetWorkerURL := lb.hashRing.Find(hashValue)
	if targetWorkerURL == "" {
		log.Error().Msgf("[ConsistentHash] hash ring is empty")
		return createEmptyScheduleResult()
	}

	// 7. Check health and find fallback if needed
	targetMetric := lb.findMetricByURL(metrics, targetWorkerURL)
	if targetMetric == nil || !lb.isHealthy(targetMetric) {
		// Try fallback workers
		fallbackURLs := lb.hashRing.FindN(hashValue, lb.fallbackNum)
		for _, url := range fallbackURLs {
			if metric := lb.findMetricByURL(metrics, url); metric != nil && lb.isHealthy(metric) {
				targetWorkerURL = url
				targetMetric = metric
				break
			}
		}

		if targetMetric == nil {
			log.Debug().Msgf("[ConsistentHash] no healthy workers found for hash key: %s", hashKey)
			return createEmptyScheduleResult()
		}
	}

	// 8. Parse DP info from worker URL
	baseURL, dpRank, hasRank := ParseDPAwareWorkerURL(targetWorkerURL)

	// 9. Build schedule result
	result := &ScheduleResult{
		ResultType:     DispatchRequest,
		PrefillUrl:     baseURL,
		PrefillGroupID: targetMetric.GroupID,
	}

	if hasRank {
		result.DpRank = &dpRank
	}

	log.Debug().Msgf("[ConsistentHash] req %v scheduled to ins %v (hash_key=%s)",
		request.Request.ReqId, targetWorkerURL, hashKey)

	return result
}

// extractHashKeyFromRequest extracts hash key from schedule request.
func (lb *ConsistentHashLB) extractHashKeyFromRequest(request *ScheduleRequestMsg) string {
	// Convert headers to http.Header
	headers := make(http.Header)
	for k, v := range request.Headers {
		headers.Set(k, v)
	}

	// Extract hash key
	return ExtractHashKey(headers, request.Body)
}

// getWorkerURLs extracts worker URLs from metrics.
// If DP is enabled, expands each physical worker into dpSize DP-aware workers.
func (lb *ConsistentHashLB) getWorkerURLs(metrics []*InstanceMetric) []string {
	if lb.dpSize <= 1 {
		// No DP expansion
		urls := make([]string, len(metrics))
		for i, m := range metrics {
			urls[i] = m.InsUrl
		}
		return urls
	}

	// Expand to DP-aware workers
	return GetDPAwareWorkers(getMetricURLs(metrics), lb.dpSize)
}

// getMetricURLs extracts URLs from InstanceMetric slice.
func getMetricURLs(metrics []*InstanceMetric) []string {
	urls := make([]string, len(metrics))
	for i, m := range metrics {
		urls[i] = m.InsUrl
	}
	return urls
}

// updateHashRingIfNeeded updates the hash ring if the worker list has changed.
func (lb *ConsistentHashLB) updateHashRingIfNeeded(workerURLs []string) {
	lb.mu.RLock()
	workersChanged := !equalStringSlices(lb.lastWorkers, workerURLs)
	lb.mu.RUnlock()

	if !workersChanged {
		return
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	// Double check after acquiring write lock
	if equalStringSlices(lb.lastWorkers, workerURLs) {
		return
	}

	// Rebuild hash ring
	lb.hashRing.Build(workerURLs, lb.virtualNodes)
	lb.lastWorkers = workerURLs

	log.Info().Msgf("[ConsistentHash] rebuilt hash ring with %d workers, %d virtual nodes",
		len(workerURLs), len(workerURLs)*lb.virtualNodes)
}

// findMetricByURL finds a metric by worker URL (handles DP-aware URLs).
func (lb *ConsistentHashLB) findMetricByURL(metrics []*InstanceMetric, workerURL string) *InstanceMetric {
	// First try exact match with the full workerURL
	for _, m := range metrics {
		if m.InsUrl == workerURL {
			return m
		}
	}

	// Parse DP info for fallback
	baseURL, _, hasRank := ParseDPAwareWorkerURL(workerURL)

	// For DP-aware URLs, find by base URL if exact match fails
	if hasRank {
		for _, m := range metrics {
			if m.InsUrl == baseURL {
				return m
			}
		}
	}
	return nil
}

// isHealthy checks if a worker is healthy based on its metrics.
func (lb *ConsistentHashLB) isHealthy(metric *InstanceMetric) bool {
	// When skipInstanceConnection is enabled, consider all workers healthy
	if lb.instanceRoleType == base.MixedRoleInstance {
		return true
	}
	// Basic health check: worker has free capacity
	// Can be extended with latency thresholds
	return metric.FreeBlocks > 0
}

// equalStringSlices checks if two string slices are equal.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// contains checks if a string is in a slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
