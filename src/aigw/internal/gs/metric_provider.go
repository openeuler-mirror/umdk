/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: define the functions of metric provider for AIGW.
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for AIGW.
package gs

import "huawei.com/aigw/internal/base"

// InstanceContext encapsulates instance identification and provider flag information
type InstanceContext struct {
	InstanceID       string
	GroupID          string
	DecodeInstanceID string
}

// MetricProvider defines the interface for providing instance metrics
type MetricProvider interface {
	// GetInstanceMetrics retrieves instance metrics based on the specified criteria
	// instanceIDs: list of instance IDs to retrieve, empty slice means all instances
	// options: optional filtering criteria, nil means no filtering
	GetInstanceMetrics(instanceIDs []string, options *MetricQueryOptions) ([]*InstanceMetric, error)

	// RangeMetrics iterates over instance metrics without allocating a new slice
	// instanceIDs: list of instance IDs to iterate over, empty slice means all instances
	// options: optional filtering criteria, nil means no filtering
	// fn: callback function for each metric, return false to stop iteration
	RangeMetrics(instanceIDs []string, options *MetricQueryOptions, fn func(*InstanceMetric) bool) error

	// AddRequest adds a request to track its resource usage on instances.
	// The actual behavior depends on the provider implementation:
	// - InstanceMetricProvider: adds request to the specified instance (InstanceID),
	//   and if DecodeInstanceID is set, also adds it to the decode instance.
	// - CacheMetricProvider: forwards request to cache manager for cache-aware tracking.
	// req: the LLM request to add
	// ctx: instance context containing instance ID, group ID, and optional decode instance ID
	AddRequest(req *LlmRequest, ctx *InstanceContext) error

	// RemoveRequest removes a request from the specified instance
	// req: the LLM request to remove
	// ctx: instance context containing instance ID, group ID, and role
	RemoveRequest(req *LlmRequest, ctx *InstanceContext) error

	// PredictTokensByEMA predicts total tokens using EMA algorithm
	PredictTokensByEMA(req *LlmRequest) int

	// GetDPAwareMetrics retrieves DP-aware instance metrics.
	// Each physical instance is expanded into dpSize DP-aware workers.
	// options: optional filtering criteria, nil means no filtering
	// dpSize: number of DP-aware workers per physical worker
	GetDPAwareMetrics(options *MetricQueryOptions, dpSize int) ([]*DPAwareMetric, error)
}

// MetricQueryOptions defines the filtering criteria for querying instance metrics
type MetricQueryOptions struct {
	Role            *base.InstanceRole // instance role filter, nil means no filtering
	GroupID         string             // group ID filter, empty string means no filtering
	ExcludeGroupIDs map[string]bool    // group IDs to exclude, nil means no exclusion
}

// InstanceMetric represents the unified data structure for instance metrics
type InstanceMetric struct {
	// Static instance information
	InsUrl  string
	Role    base.InstanceRole
	GroupID string

	// Dynamic metrics
	TokenNum       int
	PrefillTime    float64
	FreeBlocks     int
	PreBlocks      int
	TBT            float64
	TTFT           float64
	QueueLength    int
	AvgWaitingTime float64
	ReqNum         int
	PrefillTokens  int

	// Request information
	HeadReq *LlmRequest
}
