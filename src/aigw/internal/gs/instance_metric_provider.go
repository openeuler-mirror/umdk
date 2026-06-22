/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: instance metric provider implementation for AIGW.
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"fmt"
)

// InstanceMetricProvider provides instance metrics based on instance objects
type InstanceMetricProvider struct {
	insManager *InstanceManager
}

// NewInstanceMetricProvider creates a new instance metric provider
func NewInstanceMetricProvider(insMgr *InstanceManager) *InstanceMetricProvider {
	return &InstanceMetricProvider{insManager: insMgr}
}

// buildInstanceMetric creates an InstanceMetric from an instance
func (p *InstanceMetricProvider) buildInstanceMetric(ins *instance) *InstanceMetric {
	// Get head request from reqQueue (consistent with getSnapShot behavior)
	var headReq *LlmRequest
	if ins.reqQueue != nil {
		head := ins.reqQueue.getHeadReq()
		if head != nil {
			headReq = &LlmRequest{
				ReqId:              head.ReqId,
				PredictPrefillTime: head.PredictPrefillTime,
				PrefillTimeStampMs: head.PrefillTimeStampMs,
			}
		}
	}

	// When skipInstanceConnection is enabled, set a default FreeBlocks value to make instances appear healthy
	freeBlocks := ins.freeBlocks
	if ins.insMgr != nil && ins.insMgr.skipInstanceConnection && freeBlocks == 0 {
		freeBlocks = 100 // Default capacity for skipConnection mode
	}

	return &InstanceMetric{
		// Static instance information
		InsUrl:  ins.insUrl,
		Role:    ins.insRole,
		GroupID: ins.groupID,

		// Dynamic metrics
		TokenNum:       ins.tokenNum,
		PrefillTime:    ins.prefillTime,
		FreeBlocks:     freeBlocks,
		PreBlocks:      ins.preBlocks,
		TBT:            ins.tbt,
		TTFT:           ins.ttft,
		QueueLength:    ins.queueLength,
		AvgWaitingTime: ins.avgWaitingTime,
		ReqNum:         ins.reqNum,
		PrefillTokens:  ins.prefillTokens,

		// Request information
		HeadReq: headReq,
	}
}

// filterInstance checks if an instance matches the given criteria
func (p *InstanceMetricProvider) filterInstance(ins *instance, idSet map[string]bool,
	options *MetricQueryOptions) bool {
	// filter by status - skip health check if skipInstanceConnection is enabled
	if ins.insMgr != nil && ins.insMgr.skipInstanceConnection {
		// When skipInstanceConnection is enabled, consider all registered instances as healthy
	} else if ins.insWatcher != nil && !ins.insWatcher.isHealth() {
		return false
	}

	// Filter by instanceIDs
	if len(idSet) > 0 && !idSet[ins.insUrl] {
		return false
	}

	// Filter by options
	if options != nil {
		if options.Role != nil && ins.insRole != *options.Role {
			return false
		}
		if options.GroupID != "" && ins.groupID != options.GroupID {
			return false
		}
		if options.ExcludeGroupIDs != nil && options.ExcludeGroupIDs[ins.groupID] {
			return false
		}
	}

	return true
}

// iterateMetrics iterates over instances and calls the callback for each matching instance
func (p *InstanceMetricProvider) iterateMetrics(instanceIDs []string, options *MetricQueryOptions,
	fn func(*InstanceMetric) bool) error {
	p.insManager.poolRWLock.RLock()
	defer p.insManager.poolRWLock.RUnlock()

	// Optimize: convert instanceIDs to map for O(1) lookup
	idSet := make(map[string]bool, len(instanceIDs))
	for _, id := range instanceIDs {
		idSet[id] = true
	}

	for _, ins := range p.insManager.insPool {
		if !p.filterInstance(ins, idSet, options) {
			continue
		}

		ins.rwLock.RLock()
		metric := p.buildInstanceMetric(ins)
		ins.rwLock.RUnlock()

		if !fn(metric) {
			return nil
		}
	}

	return nil
}

// GetInstanceMetrics retrieves instance metrics based on the specified criteria
func (p *InstanceMetricProvider) GetInstanceMetrics(instanceIDs []string,
	options *MetricQueryOptions) ([]*InstanceMetric, error) {
	var metrics []*InstanceMetric
	err := p.iterateMetrics(instanceIDs, options, func(metric *InstanceMetric) bool {
		metrics = append(metrics, metric)
		return true
	})
	return metrics, err
}

// RangeMetrics iterates over instance metrics without allocating a new slice
func (p *InstanceMetricProvider) RangeMetrics(instanceIDs []string,
	options *MetricQueryOptions, fn func(*InstanceMetric) bool) error {
	return p.iterateMetrics(instanceIDs, options, fn)
}

// AddRequest adds a request to the specified instance
func (p *InstanceMetricProvider) AddRequest(req *LlmRequest, ctx *InstanceContext) error {
	p.insManager.addReq(ctx.InstanceID, req)
	if ctx.DecodeInstanceID != "" {
		p.insManager.addReq(ctx.DecodeInstanceID, req)
	}
	return nil
}

// RemoveRequest removes a request from the specified instance
func (p *InstanceMetricProvider) RemoveRequest(req *LlmRequest, ctx *InstanceContext) error {
	if e := p.RemoveRequestFromInstance(req, ctx.InstanceID); e != nil {
		return e
	}

	if ctx.DecodeInstanceID != "" {
		if e := p.RemoveRequestFromInstance(req, ctx.DecodeInstanceID); e != nil {
			p.insManager.addReq(ctx.InstanceID, req)
			return e
		}
	}

	return nil
}

// RemoveRequestFromInstance removes a request from the specified instance with instanceID
func (p *InstanceMetricProvider) RemoveRequestFromInstance(req *LlmRequest, instanceID string) error {
	p.insManager.poolRWLock.RLock()
	ins, exists := p.insManager.insPool[instanceID]
	p.insManager.poolRWLock.RUnlock()
	if !exists {
		return fmt.Errorf("instance %v not found when removing request", instanceID)
	}

	ins.delReq(req, true)
	return nil
}

// PredictTokensByEMA predicts total tokens using EMA algorithm
func (p *InstanceMetricProvider) PredictTokensByEMA(req *LlmRequest) int {
	return p.insManager.predictTokensByEMA(req)
}

// GetDPAwareMetrics retrieves DP-aware instance metrics.
// Each physical instance is expanded into dpSize DP-aware workers.
func (p *InstanceMetricProvider) GetDPAwareMetrics(options *MetricQueryOptions, dpSize int) ([]*DPAwareMetric, error) {
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
	err := p.iterateMetrics(nil, options, func(instanceMetric *InstanceMetric) bool {
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
	return dpMetrics, err
}
