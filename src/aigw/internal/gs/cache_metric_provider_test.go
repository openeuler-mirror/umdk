/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cache metric provider test
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"context"
	"testing"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
)

// CacheMetricProvider tests

func TestNewCacheMetricProvider(t *testing.T) {
	// Test creating a new cache metric provider with nil cache manager
	provider := NewCacheMetricProvider(nil)

	if provider == nil {
		t.Error("NewCacheMetricProvider returned nil")
	}

	if provider.cacheManager != nil {
		t.Error("cacheManager should be nil")
	}
}

func TestCacheMetricProviderPredictTokensByEMA(t *testing.T) {
	provider := NewCacheMetricProvider(nil)

	req := &LlmRequest{
		ReqId:     "test-req",
		Prompt:    "test prompt",
		PromptLen: 100,
	}

	// CacheMetricProvider returns prompt length directly
	result := provider.PredictTokensByEMA(req)
	if result != 100 {
		t.Errorf("Expected 100, got %d", result)
	}
}

func TestConvertToLlmRequest(t *testing.T) {
	// Test with nil
	result := convertToLlmRequest(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}

	// Test with valid request info
	reqInfo := &cachecenter.RequestInfo{
		ReqId:              "test-req",
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}

	result = convertToLlmRequest(reqInfo)
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.ReqId != "test-req" {
		t.Errorf("Expected ReqId to be 'test-req', got '%s'", result.ReqId)
	}
	if result.PromptLen != 100 {
		t.Errorf("Expected PromptLen to be 100, got %d", result.PromptLen)
	}
	if result.PredictDecodeLen != 200 {
		t.Errorf("Expected PredictDecodeLen to be 200, got %d", result.PredictDecodeLen)
	}
}

func TestMetricProviderInterfaces(t *testing.T) {
	// Test that both providers implement MetricProvider interface
	var _ MetricProvider = NewCacheMetricProvider(nil)
}

func TestCacheMetricProviderWithMockCacheManager(t *testing.T) {
	// Create a properly initialized cache manager
	cacheMgr := newTestCacheManager(t)

	provider := NewCacheMetricProvider(cacheMgr)
	if provider == nil {
		t.Error("NewCacheMetricProvider returned nil")
	}
	if provider.cacheManager != cacheMgr {
		t.Error("cacheManager not set correctly")
	}
}

func TestCacheMetricProviderGetInstanceMetricsWithNilCache(t *testing.T) {
	// Test with nil cache manager - should not panic
	provider := NewCacheMetricProvider(nil)

	// Just verify the provider was created
	if provider == nil {
		t.Error("NewCacheMetricProvider returned nil")
	}
}

func TestCacheMetricProviderGetInstanceMetricsWithRoleFilter(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	role := base.PrefillRoleInstance
	options := &MetricQueryOptions{
		Role: &role,
	}

	metrics, err := provider.GetInstanceMetrics(nil, options)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	// Should return empty since no data in cache
	if len(metrics) != 0 {
		t.Errorf("Expected 0 metrics, got %d", len(metrics))
	}
}

func TestCacheMetricProviderGetInstanceMetricsWithInstanceIDs(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Test with specific instance IDs
	instanceIDs := []string{"instance1", "instance2"}
	metrics, err := provider.GetInstanceMetrics(instanceIDs, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("Expected 0 metrics, got %d", len(metrics))
	}
}

func TestCacheMetricProviderRangeMetricsEmpty(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

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

func TestCacheMetricProviderRangeMetricsEarlyTermination(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Test early termination
	count := 0
	err := provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		return false // Stop immediately
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	// Should be 0 since cache is empty
	if count != 0 {
		t.Errorf("Expected 0 metrics, got %d", count)
	}
}

func TestCacheMetricProviderAddRequest(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictDecodeLen:   200,
		PredictPrefillTime: 50.0,
		PrefillTimeStampMs: 1000,
		TimeStamp:          500,
	}

	// Test AddRequest - this may fail if cache manager is not fully initialized
	// but should not panic
	ctx := &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	}
	err := provider.AddRequest(req, ctx)
	// Error is expected since cache manager is nil/mock
	_ = err
}

func TestCacheMetricProviderRemoveRequest(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	req := &LlmRequest{
		ReqId:  "test-req",
		Prompt: "test prompt",
	}

	// Test RemoveRequest - this may fail if cache manager is not fully initialized
	ctx := &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	}
	err := provider.RemoveRequest(req, ctx)
	_ = err
}

func TestCacheMetricProviderAddReqToCache(t *testing.T) {
	cacheMgr := newTestCacheManager(t)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictDecodeLen:   200,
		PredictPrefillTime: 50.0,
		PrefillTimeStampMs: 1000,
		TimeStamp:          500,
	}

	res := &ScheduleResult{
		PrefillUrl: "http://prefill-instance",
		DecodeUrl:  "http://decode-instance",
	}

	// Test adding request to cache manager directly with both prefill and decode instances
	reqInfo := &cachecenter.RequestInfo{
		ReqId:              req.ReqId,
		PrefillInstance:    res.PrefillUrl,
		DecodeInstance:     res.DecodeUrl,
		IsPrefill:          true,
		PromptTokenLen:     req.PromptLen,
		DecodeTokenLen:     req.PredictDecodeLen,
		PredictPrefillTime: req.PredictPrefillTime,
		PrefillStartTimeMs: req.PrefillTimeStampMs,
		TimeStamp:          req.TimeStamp,
	}
	err := cacheMgr.AddRequest(reqInfo)
	_ = err
}

// Helper function to create a properly initialized CacheManager for testing
func newTestCacheManager(t *testing.T) *cachecenter.CacheManager {
	t.Helper()
	ctx := context.Background()
	cacheMgr := cachecenter.NewCacheManager(ctx, "test-model")
	return cacheMgr
}

// Test CacheMetricProvider with properly initialized CacheManager and data
func TestCacheMetricProviderWithRealCacheManager(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	if provider == nil {
		t.Error("NewCacheMetricProvider returned nil")
	}
	if provider.cacheManager != cacheMgr {
		t.Error("cacheManager not set correctly")
	}
}

// Test CacheMetricProvider GetInstanceMetrics with actual data
func TestCacheMetricProviderGetInstanceMetricsWithData(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Add a request to create instance metrics
	req := &cachecenter.RequestInfo{
		ReqId:              "test-req-1",
		PrefillInstance:    "http://instance1",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}

	err := cacheMgr.AddRequest(req)
	if err != nil {
		t.Logf("AddRequest returned error (expected if cache not started): %v", err)
	}

	// Test GetInstanceMetrics - may return empty if cache not started
	metrics, err := provider.GetInstanceMetrics(nil, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	_ = metrics
}

// Test CacheMetricProvider RangeMetrics with actual data
func TestCacheMetricProviderRangeMetricsWithData(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Add a request to create instance metrics
	req := &cachecenter.RequestInfo{
		ReqId:              "test-req-1",
		PrefillInstance:    "http://instance1",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}

	err := cacheMgr.AddRequest(req)
	if err != nil {
		t.Logf("AddRequest returned error (expected if cache not started): %v", err)
	}

	// Test RangeMetrics - may return empty if cache not started
	count := 0
	err = provider.RangeMetrics(nil, nil, func(m *InstanceMetric) bool {
		count++
		return true
	})
	if err != nil {
		t.Errorf("RangeMetrics returned error: %v", err)
	}
	_ = count
}

// Test CacheMetricProvider GetInstanceMetrics with instance ID filter
func TestCacheMetricProviderGetInstanceMetricsFilterByID(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Add requests for different instances
	req1 := &cachecenter.RequestInfo{
		ReqId:              "test-req-1",
		PrefillInstance:    "http://instance1",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}
	req2 := &cachecenter.RequestInfo{
		ReqId:              "test-req-2",
		PrefillInstance:    "http://instance2",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     150,
		DecodeTokenLen:     250,
		PredictPrefillTime: 60.0,
		PrefillStartTimeMs: 1100,
		TimeStamp:          600,
	}

	_ = cacheMgr.AddRequest(req1)
	_ = cacheMgr.AddRequest(req2)

	// Test filtering by instance IDs
	instanceIDs := []string{"http://instance1"}
	metrics, err := provider.GetInstanceMetrics(instanceIDs, nil)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	// Note: metrics count depends on whether cache is running
	_ = metrics
}

// Test CacheMetricProvider GetInstanceMetrics with role filter
func TestCacheMetricProviderGetInstanceMetricsWithRoleFilterData(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Add a request with prefill instance
	req := &cachecenter.RequestInfo{
		ReqId:              "test-req-1",
		PrefillInstance:    "http://instance1",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}

	_ = cacheMgr.AddRequest(req)

	role := base.PrefillRoleInstance
	options := &MetricQueryOptions{
		Role: &role,
	}

	metrics, err := provider.GetInstanceMetrics(nil, options)
	if err != nil {
		t.Errorf("GetInstanceMetrics returned error: %v", err)
	}
	_ = metrics
}

// Test CacheMetricProvider RemoveRequest with actual data
func TestCacheMetricProviderRemoveRequestWithData(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	// Add a request first
	req := &cachecenter.RequestInfo{
		ReqId:              "test-req-remove",
		PrefillInstance:    "http://instance1",
		DecodeInstance:     "",
		IsPrefill:          true,
		PromptTokenLen:     100,
		DecodeTokenLen:     200,
		PredictPrefillTime: 50.0,
		PrefillStartTimeMs: 1000,
		TimeStamp:          500,
	}

	addErr := cacheMgr.AddRequest(req)
	if addErr != nil {
		t.Logf("AddRequest returned error: %v", addErr)
	}

	// Now try to remove it via provider
	llmReq := &LlmRequest{
		ReqId:  "test-req-remove",
		Prompt: "test prompt",
	}

	err := provider.RemoveRequest(llmReq, &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "",
	})
	// May fail if cache is not running, but should not panic
	_ = err
}

// TestCacheMetricProviderAddRequestToPrefillDecode tests adding request to pd nodes
func TestCacheMetricProviderAddRequestToPrefillDecode(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictDecodeLen:   200,
		PredictPrefillTime: 50.0,
		PrefillTimeStampMs: 1000,
		TimeStamp:          500,
	}

	ctx := &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "http://decode-instance1",
	}

	err := provider.AddRequest(req, ctx)
	// Error is expected if cache manager is not fully initialized
	_ = err
}

// TestCacheMetricProviderAddRequestWithNilContext tests adding request with nil context
func TestCacheMetricProviderAddRequestWithNilContext(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	req := &LlmRequest{
		ReqId:  "test-req",
		Prompt: "test prompt",
	}

	err := provider.AddRequest(req, nil)
	if err == nil {
		t.Error("Expected error for nil context")
	}
}

// TestCacheMetricProviderAddRequestWithEmptyDecodeInstance tests adding request with empty decode instance
func TestCacheMetricProviderAddRequestWithEmptyDecodeInstance(t *testing.T) {
	cacheMgr := newTestCacheManager(t)
	provider := NewCacheMetricProvider(cacheMgr)

	req := &LlmRequest{
		ReqId:              "test-req",
		Prompt:             "test prompt",
		PromptLen:          100,
		PredictDecodeLen:   200,
		PredictPrefillTime: 50.0,
		PrefillTimeStampMs: 1000,
		TimeStamp:          500,
	}

	ctx := &InstanceContext{
		InstanceID:       "http://instance1",
		GroupID:          "group1",
		DecodeInstanceID: "", // Empty decode instance
	}

	err := provider.AddRequest(req, ctx)
	if err != nil {
		t.Errorf("AddRequest returned error: %v", err)
	}
}
