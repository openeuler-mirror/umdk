/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description:Unit tests for local cache.
 * Create: 2026-01-20
 */

// Package cachecenter implements metadata operations using Redis via injected CacheDriverOps.
package cachecenter

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"huawei.com/aigw/internal/base"
)

func getMapLength(sm *sync.Map) int {
	count := 0
	sm.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Helper: create a mock RequestInfo
func newTestRequest(reqID string, prefillIns, decodeIns string, promptTokens, decodeTokens int, prefillTime float64, timeStamp int64) *RequestInfo {
	return &RequestInfo{
		ReqId:              reqID,
		PrefillInstance:    prefillIns,
		DecodeInstance:     decodeIns,
		PromptTokenLen:     promptTokens,
		DecodeTokenLen:     decodeTokens,
		PredictPrefillTime: prefillTime,
		TimeStamp:          timeStamp,
	}
}

// Test swapInNewState: normal case
func TestLocalCache_SwapInNewState_Normal(t *testing.T) {
	cache := newLocalCache()

	// Create test data
	// Note: IsPrefill=true means request is in prefill stage (uses prefill instance)
	// IsPrefill=false means request is in decode stage (uses decode instance)
	req1 := newTestRequest("req1", "ins-A", "ins-B", 100, 50, 10.5, 1000)
	req1.IsPrefill = true                                                // req1 is in prefill stage, uses ins-A
	req2 := newTestRequest("req2", "ins-A", "ins-C", 200, 30, 20.3, 900) // earlier timestamp
	req2.IsPrefill = true                                                // req2 is in prefill stage, uses ins-A
	req3 := newTestRequest("req3", "ins-D", "ins-B", 150, 40, 15.0, 1100)
	req3.IsPrefill = false // req3 is in decode stage, uses ins-B

	requests := []*RequestInfo{req1, req2, req3}

	cache.swapInNewState(requests)
	c := cache.holder.Load()
	// Test requestMap
	assert.Equal(t, 3, getMapLength(c.requestMap))
	value, _ := c.requestMap.Load("req1")
	reqInfo := value.(*RequestInfo)
	assert.Equal(t, req1, reqInfo)
	value, _ = c.requestMap.Load("req2")
	reqInfo = value.(*RequestInfo)
	assert.Equal(t, req2, reqInfo)
	value, _ = c.requestMap.Load("req3")
	reqInfo = value.(*RequestInfo)
	assert.Equal(t, req3, reqInfo)

	// Test metrics
	// ins-A: req1 + req2 (both in prefill stage)
	// ins-B: req3 (in decode stage)
	// ins-C: none (req2 is in prefill stage, not decode)
	// ins-D: none (req3 is in decode stage, not prefill)
	assert.Equal(t, 2, getMapLength(c.metrics)) // ins-A, ins-B

	// ins-A: req1 + req2 (both prefill)
	value, _ = c.metrics.Load("ins-A")
	metricA := value.(*InstanceMetrics)
	assert.Equal(t, 100+200, metricA.TokenLoad) // prompt tokens only for prefill
	assert.InDelta(t, 10.5+20.3, metricA.QueueTime, 1e-6)
	assert.Equal(t, "req2", metricA.HeadReq.ReqId) // earliest timestamp

	// ins-B: req3 (decode)
	value, _ = c.metrics.Load("ins-B")
	metricB := value.(*InstanceMetrics)
	assert.Equal(t, 150+40, metricB.TokenLoad)      // prompt + decode tokens for decode
	assert.InDelta(t, 0.0, metricB.QueueTime, 1e-6) // no queue time for decode
	assert.Nil(t, metricB.HeadReq)                  // no head request for decode role
}

// Test swapInNewState: empty requests
func TestLocalCache_SwapInNewState_Empty(t *testing.T) {
	cache := newLocalCache()
	cache.swapInNewState([]*RequestInfo{})
	c := cache.holder.Load()
	assert.Equal(t, 0, getMapLength(c.requestMap))
	assert.Equal(t, 0, getMapLength(c.metrics))
}

// Test swapInNewState: nil requests
func TestLocalCache_SwapInNewState_Nil(t *testing.T) {
	cache := newLocalCache()
	cache.swapInNewState(nil)
	c := cache.holder.Load()
	assert.Equal(t, 0, getMapLength(c.requestMap))
	assert.Equal(t, 0, getMapLength(c.metrics))
}

// Test findEarliestRequest
func TestFindEarliestRequest(t *testing.T) {
	req1 := newTestRequest("req1", "", "", 0, 0, 0, 1000)
	req2 := newTestRequest("req2", "", "", 0, 0, 0, 800)
	req3 := newTestRequest("req3", "", "", 0, 0, 0, 1200)

	// Normal case
	earliest := findEarliestRequest(base.PrefillRoleInstance, []*RequestInfo{req1, req2, req3})
	assert.Equal(t, "req2", earliest.ReqId)

	// Single request
	earliest = findEarliestRequest(base.PrefillRoleInstance, []*RequestInfo{req1})
	assert.Equal(t, "req1", earliest.ReqId)

	// Empty
	earliest = findEarliestRequest(base.PrefillRoleInstance, []*RequestInfo{})
	assert.Nil(t, earliest)
}

// Test calculateTokenLoad
func TestCalculateTokenLoad(t *testing.T) {
	req1 := newTestRequest("req1", "", "", 100, 50, 0, 0)
	req2 := newTestRequest("req2", "", "", 200, 30, 0, 0)

	total := calculateTokenLoad(base.DecodeRoleInstance, []*RequestInfo{req1, req2})
	assert.Equal(t, 100+50+200+30, total)

	// Empty
	assert.Equal(t, 0, calculateTokenLoad(base.DecodeRoleInstance, []*RequestInfo{}))
}

// Test calculateQueueTime
func TestCalculateQueueTime(t *testing.T) {
	req1 := newTestRequest("req1", "", "", 0, 0, 10.5, 0)
	req2 := newTestRequest("req2", "", "", 0, 0, 20.3, 0)

	total := calculateQueueTime(base.PrefillRoleInstance, []*RequestInfo{req1, req2})
	assert.InDelta(t, 30.8, total, 1e-6)

	// Empty
	assert.InDelta(t, 0.0, calculateQueueTime(base.PrefillRoleInstance, []*RequestInfo{}), 1e-6)
}

// Test concurrent access: RWMutex is working
func TestLocalCache_ConcurrentAccess(t *testing.T) {
	cache := newLocalCache()

	// Simulate initial state
	reqs := []*RequestInfo{
		newTestRequest("req1", "ins-A", "ins-B", 100, 50, 10.0, 1000),
	}
	cache.swapInNewState(reqs)
	c := cache.holder.Load()
	var wg sync.WaitGroup

	// Start multiple readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = getMapLength(c.requestMap)
				_ = getMapLength(c.metrics)
				if _, ok := c.metrics.Load("ins-A"); ok {
					continue
				}
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Start one writer (swapInNewState is write)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			newReqs := []*RequestInfo{
				newTestRequest("req2", "ins-C", "ins-D", 200, 60, 15.0, 900),
			}
			cache.swapInNewState(newReqs)
			time.Sleep(50 * time.Microsecond)
		}
	}()

	wg.Wait()
}
