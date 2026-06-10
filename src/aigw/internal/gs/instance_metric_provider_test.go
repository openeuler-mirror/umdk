/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: metric provider test
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"sync"
	"testing"

	"huawei.com/aigw/internal/base"
)

// TestGetInstanceMetricsEmptyPool tests GetInstanceMetrics with empty instance pool
func TestGetInstanceMetricsEmptyPool(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	provider := NewInstanceMetricProvider(insManager)

	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("Expected 0 metrics, got %d", len(metrics))
	}
}

// TestGetInstanceMetricsWithNilReqQueue tests GetInstanceMetrics with nil reqQueue
func TestGetInstanceMetricsWithNilReqQueue(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    nil, // nil reqQueue
		headReq:     nil,
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].HeadReq != nil {
		t.Error("Expected HeadReq to be nil when reqQueue is nil and headReq is nil")
	}
}

// TestGetInstanceMetricsWithEmptyReqQueue tests GetInstanceMetrics with empty reqQueue
func TestGetInstanceMetricsWithEmptyReqQueue(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(), // empty reqQueue
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].HeadReq != nil {
		t.Error("Expected HeadReq to be nil when reqQueue is empty")
	}
}

// TestGetInstanceMetricsWithHeadRequest tests GetInstanceMetrics with head request in queue
func TestGetInstanceMetricsWithHeadRequest(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	reqQueue := newRequestQueue()
	headReq := &LlmRequest{
		ReqId:              "head-req",
		PredictPrefillTime: 100.0,
		PrefillTimeStampMs: 1000,
	}
	reqQueue.enqueue(headReq)

	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    reqQueue,
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].HeadReq == nil {
		t.Error("Expected HeadReq to be non-nil")
	}
	if metrics[0].HeadReq.ReqId != "head-req" {
		t.Errorf("Expected ReqId 'head-req', got '%s'", metrics[0].HeadReq.ReqId)
	}
}

// TestGetInstanceMetricsAllFilters tests GetInstanceMetrics with all filter combinations
func TestGetInstanceMetricsAllFilters(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group2",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins3 := &instance{
		insUrl:      "http://instance3",
		insRole:     base.DecodeRoleInstance,
		groupID:     "group1",
		tokenNum:    150,
		prefillTime: 75.0,
		freeBlocks:  8,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	provider := NewInstanceMetricProvider(insManager)

	// Test 1: Get all metrics
	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 3 {
		t.Errorf("Expected 3 metrics, got %d", len(metrics))
	}

	// Test 2: Filter by instance IDs
	metrics, err = provider.GetInstanceMetrics([]string{"http://instance1", "http://instance3"}, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("Expected 2 metrics, got %d", len(metrics))
	}

	// Test 3: Filter by role
	role := base.PrefillRoleInstance
	metrics, err = provider.GetInstanceMetrics(nil, &MetricQueryOptions{Role: &role})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric for prefill role, got %d", len(metrics))
	}
	if metrics[0].InsUrl != "http://instance2" {
		t.Errorf("Expected instance2, got %s", metrics[0].InsUrl)
	}

	// Test 4: Filter by group ID
	metrics, err = provider.GetInstanceMetrics(nil, &MetricQueryOptions{GroupID: "group1"})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("Expected 2 metrics for group1, got %d", len(metrics))
	}

	// Test 5: Filter by exclude group IDs
	excludeGroups := map[string]bool{"group1": true}
	metrics, err = provider.GetInstanceMetrics(nil, &MetricQueryOptions{ExcludeGroupIDs: excludeGroups})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric after excluding group1, got %d", len(metrics))
	}
	if metrics[0].InsUrl != "http://instance2" {
		t.Errorf("Expected instance2, got %s", metrics[0].InsUrl)
	}

	// Test 6: Combine filters - instance IDs and role
	metrics, err = provider.GetInstanceMetrics([]string{"http://instance1", "http://instance2"}, &MetricQueryOptions{Role: &role})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric for combined filters, got %d", len(metrics))
	}
	if metrics[0].InsUrl != "http://instance2" {
		t.Errorf("Expected instance2, got %s", metrics[0].InsUrl)
	}

	// Test 7: Combine filters - group ID and exclude group IDs (should return empty)
	metrics, err = provider.GetInstanceMetrics(nil, &MetricQueryOptions{GroupID: "group1", ExcludeGroupIDs: excludeGroups})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("Expected 0 metrics for conflicting filters, got %d", len(metrics))
	}
}

// TestRangeMetricsEmptyPool tests RangeMetrics with empty instance pool
func TestRangeMetricsEmptyPool(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	provider := NewInstanceMetricProvider(insManager)

	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 metrics, got %d", count)
	}
}

// TestRangeMetricsWithNilReqQueue tests RangeMetrics with nil reqQueue
func TestRangeMetricsWithNilReqQueue(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    nil, // nil reqQueue
		headReq:     nil,
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		if m.HeadReq != nil {
			t.Error("Expected HeadReq to be nil when reqQueue is nil and headReq is nil")
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric, got %d", count)
	}
}

// TestRangeMetricsWithHeadRequest tests RangeMetrics with head request in queue
func TestRangeMetricsWithHeadRequest(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	reqQueue := newRequestQueue()
	headReq := &LlmRequest{
		ReqId:              "head-req",
		PredictPrefillTime: 100.0,
		PrefillTimeStampMs: 1000,
	}
	reqQueue.enqueue(headReq)

	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    reqQueue,
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		if m.HeadReq == nil {
			t.Error("Expected HeadReq to be non-nil")
		}
		if m.HeadReq.ReqId != "head-req" {
			t.Errorf("Expected ReqId 'head-req', got '%s'", m.HeadReq.ReqId)
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric, got %d", count)
	}
}

// TestRangeMetricsEarlyTermination tests RangeMetrics with early termination
func TestRangeMetricsEarlyTermination(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group2",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins3 := &instance{
		insUrl:      "http://instance3",
		insRole:     base.DecodeRoleInstance,
		groupID:     "group1",
		tokenNum:    150,
		prefillTime: 75.0,
		freeBlocks:  8,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	provider := NewInstanceMetricProvider(insManager)

	// Test early termination after first instance
	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		return false // Stop after first
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric (early termination), got %d", count)
	}

	// Test early termination after second instance
	count = 0
	err = provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		return count < 2 // Stop after second
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 metrics (early termination), got %d", count)
	}
}

// TestRangeMetricsWithFilters tests RangeMetrics with filters
func TestRangeMetricsWithFilters(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group2",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins3 := &instance{
		insUrl:      "http://instance3",
		insRole:     base.DecodeRoleInstance,
		groupID:     "group1",
		tokenNum:    150,
		prefillTime: 75.0,
		freeBlocks:  8,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	provider := NewInstanceMetricProvider(insManager)

	// Test 1: Filter by instance IDs
	count := 0
	err := provider.RangeMetrics([]string{"http://instance1", "http://instance3"}, nil, func(m *InstanceMetric) bool {
		count++
		if m.InsUrl != "http://instance1" && m.InsUrl != "http://instance3" {
			t.Errorf("Expected instance1 or instance3, got %s", m.InsUrl)
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 metrics, got %d", count)
	}

	// Test 2: Filter by role
	role := base.PrefillRoleInstance
	count = 0
	err = provider.RangeMetrics(nil, &MetricQueryOptions{Role: &role}, func(m *InstanceMetric) bool {
		count++
		if m.InsUrl != "http://instance2" {
			t.Errorf("Expected instance2, got %s", m.InsUrl)
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric for prefill role, got %d", count)
	}

	// Test 3: Filter by group ID
	count = 0
	err = provider.RangeMetrics(nil, &MetricQueryOptions{GroupID: "group1"}, func(m *InstanceMetric) bool {
		count++
		if m.InsUrl != "http://instance1" && m.InsUrl != "http://instance3" {
			t.Errorf("Expected instance1 or instance3, got %s", m.InsUrl)
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 metrics for group1, got %d", count)
	}

	// Test 4: Filter by exclude group IDs
	excludeGroups := map[string]bool{"group1": true}
	count = 0
	err = provider.RangeMetrics(nil, &MetricQueryOptions{ExcludeGroupIDs: excludeGroups}, func(m *InstanceMetric) bool {
		count++
		if m.InsUrl != "http://instance2" {
			t.Errorf("Expected instance2, got %s", m.InsUrl)
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric after excluding group1, got %d", count)
	}
}

// TestAddRequest tests adding a request to an instance
func TestAddRequest(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instance
	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictTokens:      200,
		PredictBlocks:      10,
		PredictPrefillTime: 50.0,
	}

	err := provider.AddRequest(req, &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
	if err != nil {
		t.Errorf("AddRequest returned error: %v", err)
	}

	// Verify request was added
	if _, exists := ins.reqSet["test-req"]; !exists {
		t.Error("Request was not added to reqSet")
	}
	if ins.reqQueue.len() != 1 {
		t.Errorf("Expected queue size 1, got %d", ins.reqQueue.len())
	}
	if ins.freeBlocks != 0 {
		t.Errorf("Expected freeBlocks 0, got %d", ins.freeBlocks)
	}
}

// TestAddRequestNonExistentInstance tests adding request to non-existent instance
func TestAddRequestNonExistentInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	provider := NewInstanceMetricProvider(insManager)

	req := &LlmRequest{
		ReqId:  "test-req",
		Prompt: "test prompt",
	}

	// AddRequest doesn't return error for non-existent instance, it just logs
	provider.AddRequest(req, &InstanceContext{
		InstanceID:       "http://non-existent",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
}

// TestRemoveRequest tests removing a request from an instance
func TestRemoveRequest(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instance with request
	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictTokens:      200,
		PredictBlocks:      10,
		PredictPrefillTime: 50.0,
	}
	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  0,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	ins.reqSet["test-req"] = req
	ins.reqQueue.enqueue(req)
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	err := provider.RemoveRequest(req, &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
	if err != nil {
		t.Errorf("RemoveRequest returned error: %v", err)
	}

	// Verify request was removed
	if _, exists := ins.reqSet["test-req"]; exists {
		t.Error("Request was not removed from reqSet")
	}
	if ins.reqQueue.len() != 0 {
		t.Errorf("Expected queue size 0, got %d", ins.reqQueue.len())
	}
	if ins.freeBlocks != 10 {
		t.Errorf("Expected freeBlocks 10, got %d", ins.freeBlocks)
	}
}

// TestRemoveRequestNonExistentInstance tests removing request from non-existent instance
func TestRemoveRequestNonExistentInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	provider := NewInstanceMetricProvider(insManager)

	req := &LlmRequest{
		ReqId:  "test-req",
		Prompt: "test prompt",
	}

	// RemoveRequest should return error for non-existent instance
	err := provider.RemoveRequest(req, &InstanceContext{
		InstanceID:       "http://non-existent",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
	if err == nil {
		t.Error("RemoveRequest should return error for non-existent instance")
	}
}

// TestRemoveRequestNonExistentRequest tests removing non-existent request
func TestRemoveRequestNonExistentRequest(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instance
	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	req := &LlmRequest{
		ReqId:  "test-req",
		Prompt: "test prompt",
	}

	err := provider.RemoveRequest(req, &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
	if err != nil {
		t.Errorf("RemoveRequest returned error: %v", err)
	}

	// Verify no changes
	if len(ins.reqSet) != 0 {
		t.Errorf("Expected 0 requests in reqSet, got %d", len(ins.reqSet))
	}
}

// TestGetInstanceMetricsWithUnhealthyInstance tests filtering out unhealthy instances
func TestGetInstanceMetricsWithUnhealthyInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Create a mock unhealthy watcher
	unhealthyWatcher := &mockWatcher{healthy: false}

	// Add test instances - one healthy, one unhealthy, one without watcher
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: true}, // healthy
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group1",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  unhealthyWatcher, // unhealthy
	}
	ins3 := &instance{
		insUrl:      "http://instance3",
		insRole:     base.DecodeRoleInstance,
		groupID:     "group1",
		tokenNum:    150,
		prefillTime: 75.0,
		freeBlocks:  8,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  nil, // no watcher
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	provider := NewInstanceMetricProvider(insManager)

	// Get all metrics - unhealthy instance should be filtered out
	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	// Should return 2 metrics (healthy instance and instance without watcher)
	if len(metrics) != 2 {
		t.Errorf("Expected 2 metrics (healthy + no watcher), got %d", len(metrics))
	}

	// Verify the unhealthy instance is not in the results
	for _, m := range metrics {
		if m.InsUrl == "http://instance2" {
			t.Error("Unhealthy instance should be filtered out")
		}
	}
}

// TestRangeMetricsWithUnhealthyInstance tests filtering out unhealthy instances in RangeMetrics
func TestRangeMetricsWithUnhealthyInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances with different health statuses
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: true},
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group1",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: false}, // unhealthy
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2

	provider := NewInstanceMetricProvider(insManager)

	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		if m.InsUrl == "http://instance2" {
			t.Error("Unhealthy instance should be filtered out in RangeMetrics")
		}
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 metric (healthy only), got %d", count)
	}
}

// TestGetInstanceMetricsWithHealthAndRoleFilter tests combining health filter with role filter
func TestGetInstanceMetricsWithHealthAndRoleFilter(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: true},
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group1",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: false}, // unhealthy
	}
	ins3 := &instance{
		insUrl:      "http://instance3",
		insRole:     base.DecodeRoleInstance,
		groupID:     "group1",
		tokenNum:    150,
		prefillTime: 75.0,
		freeBlocks:  8,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: true},
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2
	insManager.insPool["http://instance3"] = ins3

	provider := NewInstanceMetricProvider(insManager)

	// Filter by prefill role - should only return healthy prefill instance
	role := base.PrefillRoleInstance
	metrics, err := provider.GetInstanceMetrics(nil, &MetricQueryOptions{Role: &role})
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric (healthy prefill), got %d", len(metrics))
	}
	if metrics[0].InsUrl != "http://instance1" {
		t.Errorf("Expected instance1, got %s", metrics[0].InsUrl)
	}
}

// TestGetInstanceMetricsAllUnhealthy tests when all instances are unhealthy
func TestGetInstanceMetricsAllUnhealthy(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instances - all unhealthy
	ins1 := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: false},
	}
	ins2 := &instance{
		insUrl:      "http://instance2",
		insRole:     base.PrefillRoleInstance,
		groupID:     "group1",
		tokenNum:    200,
		prefillTime: 100.0,
		freeBlocks:  5,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
		insWatcher:  &mockWatcher{healthy: false},
	}
	insManager.insPool["http://instance1"] = ins1
	insManager.insPool["http://instance2"] = ins2

	provider := NewInstanceMetricProvider(insManager)

	// Get all metrics - all instances should be filtered out
	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("Expected 0 metrics (all unhealthy), got %d", len(metrics))
	}
}

// mockWatcher is a mock implementation of instanceWatcher for testing
type mockWatcher struct {
	healthy bool
}

func (w *mockWatcher) connect() error {
	return nil
}

func (w *mockWatcher) run(wg *sync.WaitGroup) {
	wg.Done()
}

func (w *mockWatcher) connectWithRetry() error {
	return nil
}

func (w *mockWatcher) checkConnAndRetry() error {
	return nil
}

func (w *mockWatcher) isHealth() bool {
	return w.healthy
}

func (w *mockWatcher) setHealth() {
	w.healthy = true
}

// TestInstanceMetricProviderAddRequestToPrefillDecode tests that AddRequest adds request to instance
func TestInstanceMetricProviderAddRequestToPrefillDecode(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add test instance
	ins := &instance{
		insUrl:      "http://instance1",
		insRole:     base.MixedRoleInstance,
		groupID:     "group1",
		tokenNum:    100,
		prefillTime: 50.0,
		freeBlocks:  10,
		reqSet:      make(map[string]*LlmRequest),
		reqQueue:    newRequestQueue(),
	}
	insManager.insPool["http://instance1"] = ins

	provider := NewInstanceMetricProvider(insManager)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictTokens:      200,
		PredictBlocks:      10,
		PredictPrefillTime: 50.0,
	}

	// AddRequest should add the request to the instance
	err := provider.AddRequest(req, &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "http://decode-instance1",
	})
	if err != nil {
		t.Errorf("AddRequest returned error: %v", err)
	}

	// Verify request was added to the instance
	if _, exists := ins.reqSet["test-req"]; !exists {
		t.Error("Request should be added to reqSet by AddRequest")
	}
	if ins.reqQueue.len() != 1 {
		t.Errorf("Expected queue size 1, got %d", ins.reqQueue.len())
	}
	// Note: DecodeInstanceID is ignored by InstanceMetricProvider, only InstanceID is used
	// Note: freeBlocks is not updated by AddRequest, it's updated by instance metrics
}
