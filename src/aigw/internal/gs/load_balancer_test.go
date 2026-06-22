/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: schedule implementation.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/stats"
)

// TestNewLoadBalancer tests newLoadBalancer
func TestNewLoadBalancer(t *testing.T) {
	instanceManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	metricProvider := NewInstanceMetricProvider(instanceManager)

	// RR
	config := &AlgorithmParams{
		PdMode:    MixedDeployment,
		PdMixedLB: LoadBalancerRoundRobin,
		BatchSize: 10,
	}

	lb, err := newLoadBalancer(metricProvider, config)
	assert.NoError(t, err)
	assert.IsType(t, &rrLoadBalancer{}, lb)

	// leastConn
	config = &AlgorithmParams{
		PdMode:    MixedDeployment,
		PdMixedLB: LoadBalancerLeastConn,
		BatchSize: 10,
	}

	lb, err = newLoadBalancer(metricProvider, config)
	assert.NoError(t, err)
	assert.IsType(t, &leastConnLoadBalancer{}, lb)

	// capacity
	config = &AlgorithmParams{
		PdMode:            MixedDeployment,
		PdMixedLB:         LoadBalancerCapacity,
		MinBlockThreshold: 10,
		TbtThreshold:      10,
		TtftThreshold:     10,
	}

	lb, err = newLoadBalancer(metricProvider, config)
	assert.NoError(t, err)
	assert.IsType(t, &capacityLoadBalancer{}, lb)

	// token
	config = &AlgorithmParams{
		PdMode:        MixedDeployment,
		PdMixedLB:     LoadBalancerToken,
		TbtThreshold:  10,
		TtftThreshold: 10,
	}

	lb, err = newLoadBalancer(metricProvider, config)
	assert.NoError(t, err)
	assert.IsType(t, &tokenLoadBalancer{}, lb)

	// pdLoadBalancer: {prefillTimeAware, decode}
	config = &AlgorithmParams{
		PdMode:        SeparatedDeployment,
		PrefillLB:     LoadBalancerPrefillTimeAware,
		DecodeLB:      LoadBalancerDecode,
		TbtThreshold:  10,
		TtftThreshold: 10,
	}

	lb, err = newLoadBalancer(metricProvider, config)
	assert.NoError(t, err)
	assert.IsType(t, &pdLoadBalancer{}, lb)

	// invalid deployment
	config = &AlgorithmParams{
		PdMode:        DeploymentPolicy(-1),
		PdMixedLB:     LoadBalancerType(-1),
		TbtThreshold:  10,
		TtftThreshold: 10,
	}
	lb, err = newLoadBalancer(metricProvider, config)
	assert.Error(t, err)
}

func TestRoundRobinLoadBalancer_Schedule(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
		insSnapshots: []*insSnapshot{
			{insUrl: "http://instance1", reqNum: 0},
			{insUrl: "http://instance2", reqNum: 0},
			{insUrl: "http://instance3", reqNum: 0},
		},
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue()}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue()}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue()}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	metricProvider := NewInstanceMetricProvider(insManager)

	_, e1 := newRoundRobinLB(metricProvider, &AlgorithmParams{BatchSize: -1})
	assert.Error(t, e1)

	lb, _ := newRoundRobinLB(metricProvider, &AlgorithmParams{BatchSize: 2})

	requests := make([]*ScheduleRequestMsg, 4)
	for i := 0; i < 4; i++ {
		requests[i] = &ScheduleRequestMsg{
			Request: &LlmRequest{
				ReqId:  fmt.Sprintf("req_%d", i+1),
				Prompt: "hi",
			},
		}
	}

	result1 := lb.schedule(requests[0], nil)
	if result1.PrefillUrl != "http://instance1" {
		t.Errorf("First request should be scheduled to instance1, got %v", result1.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(requests[0].Request, &InstanceContext{
		InstanceID: result1.PrefillUrl,
		GroupID:    result1.PrefillGroupID,
	})

	result2 := lb.schedule(requests[1], nil)
	if result2.PrefillUrl != "http://instance2" {
		t.Errorf("Second request should be scheduled to instance2, got %v", result2.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(requests[1].Request, &InstanceContext{
		InstanceID: result2.PrefillUrl,
		GroupID:    result2.PrefillGroupID,
	})

	result3 := lb.schedule(requests[2], nil)
	if result3.PrefillUrl != "http://instance3" {
		t.Errorf("Third request should be scheduled to instance3, got %v", result3.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(requests[2].Request, &InstanceContext{
		InstanceID: result3.PrefillUrl,
		GroupID:    result3.PrefillGroupID,
	})

	result4 := lb.schedule(requests[3], nil)
	if result4.PrefillUrl != "http://instance1" {
		t.Errorf("Fourth request should be scheduled to instance1, got %v", result4.PrefillUrl)
	}
}

func TestLeastConnLoadBalancer_Schedule(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
		insSnapshots: []*insSnapshot{
			{insUrl: "http://instance1", reqNum: 1},
			{insUrl: "http://instance2", reqNum: 0},
			{insUrl: "http://instance3", reqNum: 2},
		},
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), reqNum: 1}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), reqNum: 0}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), reqNum: 2}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	metricProvider := NewInstanceMetricProvider(insManager)

	_, e1 := newLeastConnLB(metricProvider, &AlgorithmParams{BatchSize: -1})
	assert.Error(t, e1)

	lb, _ := newLeastConnLB(metricProvider, &AlgorithmParams{BatchSize: 2})

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:  "req_1",
			Prompt: "hi",
		},
	}

	result := lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance2" {
		t.Errorf("Expected prefillUrl to be http://instance2, got %v", result.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

}

func TestCapacityLoadBalancer_Schedule(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
		insSnapshots: []*insSnapshot{
			{insUrl: "http://instance1", freeBlocks: 595, tbt: 20, ttft: 100},
			{insUrl: "http://instance2", freeBlocks: 400, tbt: 20, ttft: 100},
			{insUrl: "http://instance3", freeBlocks: 600, tbt: 20, ttft: 100},
		},
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), freeBlocks: 595, tbt: 20}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), freeBlocks: 400, tbt: 20}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), freeBlocks: 600, tbt: 20}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	metricProvider := NewInstanceMetricProvider(insManager)

	_, e1 := newCapacityLB(metricProvider, &AlgorithmParams{BatchSize: -1})
	assert.Error(t, e1)

	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result := lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance3" {
		t.Errorf("Expected prefillUrl to be http://instance3, got %v", result.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	request = &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance1" {
		t.Errorf("Expected prefillUrl to be http://instance1, got %v", result.PrefillUrl)
	}
}

func TestTokenLoadBalancer_Schedule(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 300, tbt: 20, ttft: 100}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 200, tbt: 20, ttft: 100}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 100, tbt: 20, ttft: 100}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	metricProvider := NewInstanceMetricProvider(insManager)

	// Test with invalid parameters
	_, e1 := newTokenLB(metricProvider, &AlgorithmParams{BatchSize: -1})
	assert.Error(t, e1)

	// Test with valid parameters
	config := &AlgorithmParams{
		TbtThreshold:  50,
		TtftThreshold: 200,
		BlockSize:     128,
		PredictType:   0,
	}
	lb, _ := newTokenLB(metricProvider, config)
	lb.statsFunc = func(statType stats.StatType) {}

	// Test with a request
	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1000,
		},
	}
	result := lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance3" {
		t.Errorf("Expected prefillUrl to be http://instance3, got %v", result.PrefillUrl)
	}
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with another request
	request = &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req2",
			PromptLen: 500,
		},
	}
	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance2" {
		t.Errorf("Expected prefillUrl to be http://instance2, got %v", result.PrefillUrl)
	}

	// Test with all instances exceeding tbtThreshold

	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 300, tbt: 60, ttft: 100}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 200, tbt: 60, ttft: 100}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 100, tbt: 60, ttft: 100}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "" {
		t.Errorf("Expected prefillUrl to be empty, got %v", result.PrefillUrl)
	}

	// Test with all instances exceeding ttftThreshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 300, tbt: 20, ttft: 300}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 200, tbt: 20, ttft: 300}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 100, tbt: 20, ttft: 300}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "" {
		t.Errorf("Expected prefillUrl to be empty, got %v", result.PrefillUrl)
	}

	// Test with one instance exceeding tbtThreshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 300, tbt: 60, ttft: 100}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 200, tbt: 20, ttft: 100}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 100, tbt: 20, ttft: 100}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance3" {
		t.Errorf("Expected prefillUrl to be http://instance3, got %v", result.PrefillUrl)
	}

	// Test with one instance exceeding ttftThreshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 300, tbt: 20, ttft: 300}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 200, tbt: 20, ttft: 100}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		tokenNum: 100, tbt: 20, ttft: 100}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance3" {
		t.Errorf("Expected prefillUrl to be http://instance3, got %v", result.PrefillUrl)
	}
}

func TestCapacityLoadBalancer_NoAvailableInstancesDueToFreeBlocks(t *testing.T) {
	statsCalled := false
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 30, tbt: 20}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 25, tbt: 20}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 28, tbt: 20}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	metricProvider := NewInstanceMetricProvider(insManager)
	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
		StatsFunc: func(statType stats.StatType) {
			if statType == stats.CapacityLbInsufficientFreeBlocks {
				statsCalled = true
			}
		},
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result := lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, "", result.PrefillUrl)
	assert.True(t, statsCalled, "Expected CapacityLbInsufficientFreeBlocks stat to be called")
}

func TestCapacityLoadBalancer_InstanceExcludedDueToLatency(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 60}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 20}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 400, tbt: 20}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	metricProvider := NewInstanceMetricProvider(insManager)
	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result := lb.schedule(request, nil)
	assert.Equal(t, "http://instance2", result.PrefillUrl, "Should select instance with highest free blocks under latency threshold")
}

func TestCapacityLoadBalancer_PowerOfTwoSelection(t *testing.T) {
	originalRand := globalRandom
	defer func() { globalRandom = originalRand }()
	globalRandom = rand.New(rand.NewSource(1)) // 固定随机种子

	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 20}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 20}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 700, tbt: 20}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	metricProvider := NewInstanceMetricProvider(insManager)
	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
		PowerOfTwo:        true,
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result := lb.schedule(request, nil)
	assert.Equal(t, "http://instance3", result.PrefillUrl, "Should select instance with highest free blocks using power-of-two")
}

func TestCapacityLoadBalancer_BlockCalculationEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		promptLen      int
		expectedBlocks int
	}{
		{"ExactBlockSize", 128, 1},
		{"OneOverBlockSize", 129, 2},
		{"OneLessThanDouble", 255, 2},
		{"DoubleBlockSize", 256, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insManager := &InstanceManager{
				insPool: make(map[string]*instance),
			}
			ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
				reqQueue: newRequestQueue(), freeBlocks: 1000, tbt: 20}
			insManager.insPool["http://instance1"] = ins1
			metricProvider := NewInstanceMetricProvider(insManager)
			config := &AlgorithmParams{
				MinBlockThreshold: 32,
				TbtThreshold:      50,
				TtftThreshold:     200,
				BlockSize:         128,
				PredictType:       PredictTypeNone,
			}
			lb, _ := newCapacityLB(metricProvider, config)

			request := &ScheduleRequestMsg{
				Request: &LlmRequest{
					ReqId:     "req1",
					PromptLen: tt.promptLen,
				},
			}

			lb.schedule(request, nil)

			// Add request to metric provider after scheduling to update instance state
			metricProvider.AddRequest(request.Request, &InstanceContext{
				InstanceID: "http://instance1",
				GroupID:    "",
			})

			// Verify block calculation by checking instance metrics
			metrics, err := metricProvider.GetInstanceMetrics([]string{"http://instance1"}, nil)
			assert.NoError(t, err)
			assert.Len(t, metrics, 1)

			actualBlocks := 1000 - metrics[0].FreeBlocks
			assert.Equal(t, tt.expectedBlocks, actualBlocks, "Block calculation mismatch for case: %s", tt.name)
		})
	}
}

func TestCapacityLoadBalancer_AllInstancesLatencyExceeded(t *testing.T) {
	statsCalled := false
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 60}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 55}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2

	metricProvider := NewInstanceMetricProvider(insManager)
	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
		StatsFunc: func(statType stats.StatType) {
			if statType == stats.CapacityLbLatencyOverLimit {
				statsCalled = true
			}
		},
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}

	result := lb.schedule(request, nil)
	assert.Equal(t, "", result.PrefillUrl, "Should return empty result when all instances exceed latency thresholds")
	assert.True(t, statsCalled, "Should trigger latency over limit stat")
}

func TestCapacityLoadBalancer_ExactBlockThreshold(t *testing.T) {
	statsCalled := false
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 32, tbt: 20}
	insManager.insPool["http://instance1"] = ins1
	metricProvider := NewInstanceMetricProvider(insManager)
	config := &AlgorithmParams{
		MinBlockThreshold: 32,
		TbtThreshold:      50,
		TtftThreshold:     200,
		BlockSize:         128,
		StatsFunc: func(statType stats.StatType) {
			if statType == stats.CapacityLbInsufficientFreeBlocks {
				statsCalled = true
			}
		},
	}
	lb, _ := newCapacityLB(metricProvider, config)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 128,
		},
	}

	result := lb.schedule(request, nil)
	assert.Equal(t, "", result.PrefillUrl, "Should reject when free blocks exactly equal threshold")
	assert.True(t, statsCalled, "Should trigger insufficient blocks stat")
}

// TestPrefillTimeLoadBalancer_Schedule test the schedule method of prefillTimeLoadBalancer
func TestPrefillTimeLoadBalancer_Schedule(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "ttft_test_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	testData := "50,0,50.0\n100,0,100.0\n150,0,150.0\n200,0,200.0\n250,0,250.0\n"
	_, err = tmpFile.WriteString(testData)
	assert.NoError(t, err)
	err = tmpFile.Close()
	assert.NoError(t, err)

	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), tbt: 20, prefillTime: 0}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), tbt: 20, prefillTime: 50}

	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	metricProvider := NewInstanceMetricProvider(insManager)

	requestFirst := &ScheduleRequestMsg{
		Request: &LlmRequest{
			PromptLen: 50,
			ReqId:     "req0",
		},
	}

	ins2.addReq(requestFirst.Request)

	config := &AlgorithmParams{
		TbtThreshold:     50,
		TtftThreshold:    500,
		StatsFunc:        func(statType stats.StatType) {},
		PretrainTTFTPath: tmpFile.Name(),
	}

	lb, err := newPrefillTimeLB(metricProvider, config)
	assert.NoError(t, err)

	// Test with a req1
	req1 := &LlmRequest{
		ReqId:              "req1",
		PromptLen:          100,
		PrefillTimeStampMs: time.Now().UnixMilli(),
	}
	request := &ScheduleRequestMsg{
		Request: req1,
	}
	result := lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance1", result.PrefillUrl)
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with req2
	req2 := &LlmRequest{
		ReqId:              "req2",
		PromptLen:          200,
		PrefillTimeStampMs: time.Now().UnixMilli(),
	}
	request = &ScheduleRequestMsg{
		Request: req2,
	}
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with req3
	req3 := &LlmRequest{
		ReqId:              "req3",
		PromptLen:          100,
		PrefillTimeStampMs: time.Now().UnixMilli(),
	}
	request = &ScheduleRequestMsg{
		Request: req3,
	}
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance1", result.PrefillUrl)
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with all instances exceeding tbtThreshold
	config = &AlgorithmParams{
		TbtThreshold:     50,
		TtftThreshold:    200,
		StatsFunc:        func(statType stats.StatType) {},
		PretrainTTFTPath: tmpFile.Name(),
	}
	lb, _ = newPrefillTimeLB(metricProvider, config)
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), tbt: 60, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), tbt: 60, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "", result.PrefillUrl)

	// Test with all instance exceeding ttftThreshold
	config = &AlgorithmParams{
		TbtThreshold:     50,
		TtftThreshold:    200,
		StatsFunc:        func(statType stats.StatType) {},
		PretrainTTFTPath: tmpFile.Name(),
	}
	lb, _ = newPrefillTimeLB(metricProvider, config)
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 500, tbt: 20, prefillTime: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 500, tbt: 20, prefillTime: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "", result.PrefillUrl)

	// Test with one instance exceeding tbtThreshold
	config = &AlgorithmParams{
		TbtThreshold:     50,
		TtftThreshold:    200,
		StatsFunc:        func(statType stats.StatType) {},
		PretrainTTFTPath: tmpFile.Name(),
	}
	lb, _ = newPrefillTimeLB(metricProvider, config)
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 10, tbt: 60, prefillTime: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 10, tbt: 20, prefillTime: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)

	// Test with one instance exceeding ttftThreshold
	config = &AlgorithmParams{
		TbtThreshold:     50,
		TtftThreshold:    200,
		StatsFunc:        func(statType stats.StatType) {},
		PretrainTTFTPath: tmpFile.Name(),
	}
	lb, _ = newPrefillTimeLB(metricProvider, config)
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 500, tbt: 20, prefillTime: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(), ttft: 10, tbt: 20, prefillTime: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)

}

// TestDecodeLoadBalancer_Schedule tests the schedule method of decodeLoadBalancer.
func TestDecodeLoadBalancer_Schedule(t *testing.T) {
	insManager := &InstanceManager{
		insPool: make(map[string]*instance),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 20, preBlocks: 0}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 598, tbt: 20, preBlocks: 0}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 596, tbt: 20, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	metricProvider := NewInstanceMetricProvider(insManager)

	config := &AlgorithmParams{
		TbtThreshold:      50,
		TtftThreshold:     200,
		MinBlockThreshold: 32,
		BlockSize:         128,
		PredictType:       0,
		PowerOfTwo:        false,
		StatsFunc:         func(statType stats.StatType) {},
	}
	lb, _ := newDecodeLB(metricProvider, config)

	// Test with a request
	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:     "req1",
			PromptLen: 1280,
		},
	}
	result := lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance1", result.PrefillUrl)
	// Add request to metric provider after scheduling to update instance state
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with another request
	request = &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:         "req2",
			PredictBlocks: 5,
		},
	}
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)
	// Add request to metric provider after scheduling
	metricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID: result.PrefillUrl,
		GroupID:    result.PrefillGroupID,
	})

	// Test with all instances exceeding tbtThreshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 60, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 60, preBlocks: 0}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 400, tbt: 60, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "", result.PrefillUrl)

	// Test with all instances exceeding freeBlocks threshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 30, tbt: 20, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 25, tbt: 20, preBlocks: 0}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 28, tbt: 20, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "", result.PrefillUrl)

	// Test with one instance exceeding tbtThreshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 60, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 20, preBlocks: 0}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 400, tbt: 20, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)

	// Test with one instance exceeding freeBlocks threshold
	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 30, tbt: 20, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 20, preBlocks: 0}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 400, tbt: 20, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance2", result.PrefillUrl)

	// Test with power-of-two selection
	originalRand := globalRandom
	defer func() { globalRandom = originalRand }()
	globalRandom = rand.New(rand.NewSource(1)) // 固定随机种子

	ins1 = &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 600, tbt: 20, preBlocks: 0}
	ins2 = &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 500, tbt: 20, preBlocks: 0}
	ins3 = &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		freeBlocks: 400, tbt: 20, preBlocks: 0}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3
	result = lb.schedule(request, nil)
	assert.NotNil(t, result)
	assert.Equal(t, DispatchRequest, result.ResultType)
	assert.Equal(t, "http://instance1", result.PrefillUrl)
}

func TestPDLoadBalancer_ScheduleWithRR(t *testing.T) {
	pInsManager := &InstanceManager{
		insPool: make(map[string]*instance),

		cacheManager: cachecenter.NewCacheManager(context.Background(), "test"),
	}
	ins1 := &instance{insUrl: "http://instance1", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		reqNum: 1, insRole: base.PrefillRoleInstance}
	ins2 := &instance{insUrl: "http://instance2", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		reqNum: 0, insRole: base.DecodeRoleInstance}
	ins3 := &instance{insUrl: "http://instance3", reqSet: make(map[string]*LlmRequest), reqQueue: newRequestQueue(),
		reqNum: 8, insRole: base.PrefillRoleInstance}
	pInsManager.insPool["http://instance1"] = ins1
	pInsManager.insPool["http://instance2"] = ins2
	pInsManager.insPool["http://instance3"] = ins3
	pMetricProvider := NewInstanceMetricProvider(pInsManager)

	// Create PD load balancer
	pdLB, err := newPDLoadBalancer(pMetricProvider, &AlgorithmParams{
		PdMode:            SeparatedDeployment,
		PrefillLB:         LoadBalancerRoundRobin,
		DecodeLB:          LoadBalancerRoundRobin,
		BlockSize:         128,
		BatchSize:         2,
		MinBlockThreshold: 30,
		TbtThreshold:      50,
		TtftThreshold:     200,
		PredictType:       PredictTypeNone,
	})

	assert.Equal(t, err, nil)

	// Test with a request
	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:  "req_1",
			Prompt: "hi",
		},
	}

	// First schedule should find a prefill and decode instance
	result := pdLB.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "http://instance1" {
		t.Errorf("Expected prefillUrl to be http://instance1, got %v", result.PrefillUrl)
	}
	if result.DecodeUrl != "http://instance2" {
		t.Errorf("Expected decodeUrl to be http://instance1, got %v", result.DecodeUrl)
	}
	// Add request to metric provider after scheduling
	pMetricProvider.AddRequest(request.Request, &InstanceContext{
		InstanceID:       result.PrefillUrl,
		GroupID:          result.PrefillGroupID,
		DecodeInstanceID: result.DecodeUrl,
	})

	// reqNum of instance1 == batchSize, second schedule result should be empty
	request = &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId:  "req_2",
			Prompt: "hello",
		},
	}
	result = pdLB.schedule(request, nil)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ResultType != DispatchRequest {
		t.Errorf("Expected dispatchRequest, got %v", result.ResultType)
	}
	if result.PrefillUrl != "" {
		t.Errorf("Expected prefillUrl to be “”, got %v", result.PrefillUrl)
	}
	if result.DecodeUrl != "" {
		t.Errorf("Expected decodeUrl to be “”, got %v", result.DecodeUrl)
	}
}
