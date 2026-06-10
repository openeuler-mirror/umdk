/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cache metric provider implementation for AIGW.
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"errors"
	"fmt"

	"huawei.com/aigw/internal/cachecenter"
)

// CacheMetricProvider provides instance metrics based on CacheManager
type CacheMetricProvider struct {
	cacheManager *cachecenter.CacheManager
}

// NewCacheMetricProvider creates a new cache metric provider
func NewCacheMetricProvider(cacheMgr *cachecenter.CacheManager) *CacheMetricProvider {
	return &CacheMetricProvider{cacheManager: cacheMgr}
}

// filterAndConvertMetrics filters and converts metrics based on the given criteria
// Returns true to continue iteration, false to stop
func (p *CacheMetricProvider) filterAndConvertMetrics(instanceIDs []string,
	options *MetricQueryOptions, fn func(*InstanceMetric) bool) {
	// Optimize: convert instanceIDs to map for O(1) lookup
	idSet := make(map[string]bool, len(instanceIDs))
	for _, id := range instanceIDs {
		idSet[id] = true
	}

	p.cacheManager.RangeMetrics(func(instanceID string, metric *cachecenter.InstanceMetrics) bool {
		// Filter by instanceIDs
		if len(idSet) > 0 && !idSet[instanceID] {
			return true
		}

		// Filter by options
		if options != nil {
			if options.Role != nil && metric.Role != *options.Role {
				return true
			}
			if options.GroupID != "" && metric.GroupID != options.GroupID {
				return true
			}
			if options.ExcludeGroupIDs != nil && options.ExcludeGroupIDs[metric.GroupID] {
				return true
			}
		}

		metricCopy := metric.Copy()
		instanceMetric := &InstanceMetric{
			// Static instance information
			InsUrl:  instanceID,
			Role:    metricCopy.Role,
			GroupID: metricCopy.GroupID,

			// Dynamic metrics
			TokenNum:    metricCopy.TokenLoad,
			PrefillTime: metricCopy.QueueTime,

			// Request information
			HeadReq: convertToLlmRequest(metricCopy.HeadReq),
		}

		return fn(instanceMetric)
	})
}

// GetInstanceMetrics retrieves instance metrics based on the specified criteria
func (p *CacheMetricProvider) GetInstanceMetrics(instanceIDs []string,
	options *MetricQueryOptions) ([]*InstanceMetric, error) {
	var metrics []*InstanceMetric
	p.filterAndConvertMetrics(instanceIDs, options, func(instanceMetric *InstanceMetric) bool {
		metrics = append(metrics, instanceMetric)
		return true
	})
	return metrics, nil
}

// RangeMetrics iterates over instance metrics without allocating a new slice
func (p *CacheMetricProvider) RangeMetrics(instanceIDs []string,
	options *MetricQueryOptions, fn func(*InstanceMetric) bool) error {
	p.filterAndConvertMetrics(instanceIDs, options, func(instanceMetric *InstanceMetric) bool {
		return fn(instanceMetric)
	})
	return nil
}

// AddRequest adds a request to the specified instance
func (p *CacheMetricProvider) AddRequest(req *LlmRequest, ctx *InstanceContext) error {
	if ctx == nil {
		return errors.New("context is nil")
	}

	// Convert LlmRequest to RequestInfo for CacheManager
	reqInfo := &cachecenter.RequestInfo{
		ReqId:              req.ReqId,
		PrefillInstance:    ctx.InstanceID,
		DecodeInstance:     ctx.DecodeInstanceID,
		IsPrefill:          true, // Default to prefill, will be updated by cache manager
		PromptTokenLen:     req.PromptLen,
		DecodeTokenLen:     req.PredictDecodeLen,
		PredictPrefillTime: req.PredictPrefillTime,
		PrefillStartTimeMs: req.PrefillTimeStampMs,
		TimeStamp:          req.TimeStamp,
		GroupID:            ctx.GroupID,
	}

	return p.cacheManager.AddRequest(reqInfo)
}

// RemoveRequest removes a request from the specified instance
func (p *CacheMetricProvider) RemoveRequest(req *LlmRequest, ctx *InstanceContext) error {
	return p.cacheManager.RemoveRequest(req.ReqId)
}

// PredictTokensByEMA predicts total tokens using EMA algorithm
// CacheMetricProvider doesn't support EMA prediction, returns prompt length
func (p *CacheMetricProvider) PredictTokensByEMA(req *LlmRequest) int {
	return req.PromptLen
}

// GetDPAwareMetrics retrieves DP-aware instance metrics.
// Each physical instance is expanded into dpSize DP-aware workers.
func (p *CacheMetricProvider) GetDPAwareMetrics(options *MetricQueryOptions, dpSize int) ([]*DPAwareMetric, error) {
	if dpSize <= 1 {
		// No DP expansion, return regular metrics with empty DP info
		metrics, err := p.GetInstanceMetrics(nil, options)
		if err != nil {
			return nil, err
		}
		result := make([]*DPAwareMetric, len(metrics))
		for i, m := range metrics {
			result[i] = &DPAwareMetric{
				InsUrl:     m.InsUrl,
				BaseURL:    m.InsUrl,
				DpRank:     0,
				FreeBlocks: m.FreeBlocks,
				TokenNum:   m.TokenNum,
				TBT:        m.TBT,
				TTFT:       m.TTFT,
				GroupID:    m.GroupID,
			}
		}
		return result, nil
	}

	var dpMetrics []*DPAwareMetric
	p.filterAndConvertMetrics(nil, options, func(instanceMetric *InstanceMetric) bool {
		// Expand each physical instance into dpSize DP-aware workers
		for rank := 0; rank < dpSize; rank++ {
			dpMetric := &DPAwareMetric{
				InsUrl:     fmt.Sprintf("%s@%d", instanceMetric.InsUrl, rank),
				BaseURL:    instanceMetric.InsUrl,
				DpRank:     rank,
				FreeBlocks: instanceMetric.FreeBlocks,
				TokenNum:   instanceMetric.TokenNum,
				TBT:        instanceMetric.TBT,
				TTFT:       instanceMetric.TTFT,
				GroupID:    instanceMetric.GroupID,
			}
			dpMetrics = append(dpMetrics, dpMetric)
		}
		return true
	})
	return dpMetrics, nil
}

// convertToLlmRequest converts cachecenter.RequestInfo to gs.LlmRequest
func convertToLlmRequest(reqInfo *cachecenter.RequestInfo) *LlmRequest {
	if reqInfo == nil {
		return nil
	}
	return &LlmRequest{
		ReqId:              reqInfo.ReqId,
		PromptLen:          reqInfo.PromptTokenLen,
		PredictDecodeLen:   reqInfo.DecodeTokenLen,
		PredictPrefillTime: reqInfo.PredictPrefillTime,
		PrefillTimeStampMs: reqInfo.PrefillStartTimeMs,
		TimeStamp:          reqInfo.TimeStamp,
	}
}
