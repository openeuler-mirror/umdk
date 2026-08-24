/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: define the functions of central cache.
 * Create: 2026-01-20
 */

// Package cachecenter implements metadata operations using Redis via injected CacheDriverOps.
package cachecenter

import (
	"sync"
	"sync/atomic"
	"time"

	"huawei.com/aigw/internal/base"
)

type cacheHolder struct {
	metrics    *sync.Map // map[string]*InstanceMetrics
	requestMap *sync.Map // map[string]*RequestInfo
}

type localCache struct {
	holder atomic.Pointer[cacheHolder]
}

// newLocalCache creates a new thread-safe local cache instance
func newLocalCache() *localCache {
	lc := &localCache{}
	lc.holder.Store(&cacheHolder{
		metrics:    &sync.Map{},
		requestMap: &sync.Map{},
	})
	return lc
}

type instanceKey struct {
	address string
	role    base.InstanceRole
}

// incrementalMerge performs incremental merge without replacing the entire holder
func (lc *localCache) incrementalMerge(mergedRequests []*RequestInfo) {
	holder := lc.holder.Load()
	if holder == nil {
		return
	}

	// 1. Update or add requests from merged result
	for _, req := range mergedRequests {
		holder.requestMap.Store(req.ReqId, req)
	}

	// 2. Rebuild metrics for all instances (iterate all requests)
	instanceGroups := make(map[instanceKey][]*RequestInfo)
	holder.requestMap.Range(func(key, value interface{}) bool {
		req, ok := value.(*RequestInfo)
		if !ok || req == nil {
			return true
		}
		pKey := instanceKey{address: req.PrefillInstance, role: base.PrefillRoleInstance}
		dKey := instanceKey{address: req.DecodeInstance, role: base.DecodeRoleInstance}
		if pKey.address != "" && req.IsPrefill {
			instanceGroups[pKey] = append(instanceGroups[pKey], req)
		}
		if dKey.address != "" && !req.IsPrefill {
			instanceGroups[dKey] = append(instanceGroups[dKey], req)
		}
		return true
	})

	// 3. Update metrics for all instances that have requests
	for key, reqs := range instanceGroups {
		headReq := findEarliestRequest(key.role, reqs)
		tokenLoad := calculateTokenLoad(key.role, reqs)
		queueTime := calculateQueueTime(key.role, reqs)

		groupID := ""
		if len(reqs) > 0 {
			groupID = reqs[0].GroupID
		}

		// Preserve LastActiveTime from existing metrics, default to now for new metrics
		var lastActiveTime time.Time
		if existing, ok := holder.metrics.Load(key.address); ok {
			if existingMetric, ok := existing.(*InstanceMetrics); ok && existingMetric != nil {
				lastActiveTime = existingMetric.LastActiveTime
			}
		}
		if lastActiveTime.IsZero() {
			lastActiveTime = time.Now()
		}

		holder.metrics.Store(key.address, &InstanceMetrics{
			Role:           key.role,
			HeadReq:        headReq,
			TokenLoad:      tokenLoad,
			QueueTime:      queueTime,
			GroupID:        groupID,
			LastActiveTime: lastActiveTime,
		})
	}
}

// swapInNewState rebuilds the entire cache from parsed requests
func (lc *localCache) swapInNewState(requests []*RequestInfo) {
	newRequestMap := &sync.Map{}
	newMetrics := &sync.Map{}

	instanceGroups := make(map[instanceKey][]*RequestInfo)

	// rebuild requestMap
	for _, req := range requests {
		newRequestMap.Store(req.ReqId, req)
		pKey := instanceKey{address: req.PrefillInstance, role: base.PrefillRoleInstance}
		dKey := instanceKey{address: req.DecodeInstance, role: base.DecodeRoleInstance}
		if pKey.address != "" && req.IsPrefill {
			instanceGroups[pKey] = append(instanceGroups[pKey], req)
		}
		if dKey.address != "" && !req.IsPrefill {
			instanceGroups[dKey] = append(instanceGroups[dKey], req)
		}
	}

	// rebuild metrics
	for key, reqs := range instanceGroups {
		headReq := findEarliestRequest(key.role, reqs)
		tokenLoad := calculateTokenLoad(key.role, reqs)
		queueTime := calculateQueueTime(key.role, reqs)

		// Get GroupID from the first request in the group
		groupID := ""
		if len(reqs) > 0 {
			groupID = reqs[0].GroupID
		}

		newMetrics.Store(key.address, &InstanceMetrics{
			Role:           key.role,
			HeadReq:        headReq,
			TokenLoad:      tokenLoad,
			QueueTime:      queueTime,
			GroupID:        groupID,
			LastActiveTime: time.Now(),
		})
	}

	lc.holder.Store(&cacheHolder{
		metrics:    newMetrics,
		requestMap: newRequestMap,
	})
}

// findEarliestRequest returns the request with the smallest TimeStamp
func findEarliestRequest(role base.InstanceRole, requests []*RequestInfo) *RequestInfo {
	if role != base.PrefillRoleInstance || len(requests) == 0 {
		return nil
	}
	earliest := requests[0]
	for _, r := range requests {
		if r.TimeStamp < earliest.TimeStamp {
			earliest = r
		}
	}
	return earliest
}

// calculateTokenLoad returns total prompt + decode tokens
func calculateTokenLoad(role base.InstanceRole, requests []*RequestInfo) int {
	total := 0
	for _, r := range requests {
		if role == base.PrefillRoleInstance {
			total += r.PromptTokenLen
		} else {
			total += r.PromptTokenLen + r.DecodeTokenLen
		}

	}
	return total
}

// calculateQueueTime returns total predict prefill time
func calculateQueueTime(role base.InstanceRole, requests []*RequestInfo) float64 {
	if role != base.PrefillRoleInstance || len(requests) == 0 {
		return 0.0
	}
	var total float64 = 0
	for _, r := range requests {
		total += r.PredictPrefillTime
	}
	return total
}
