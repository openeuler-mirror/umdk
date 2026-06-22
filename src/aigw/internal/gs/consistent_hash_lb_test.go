/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Consistent hash load balancer test for AIGW.
 * Create: 2026-04-29
 */

package gs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"huawei.com/aigw/internal/base"
)

type mockMetricProvider struct {
	metrics []*InstanceMetric
}

func (m *mockMetricProvider) GetInstanceMetrics(_ []string, _ *MetricQueryOptions) ([]*InstanceMetric, error) {
	return m.metrics, nil
}

func (m *mockMetricProvider) RangeMetrics(_ []string, _ *MetricQueryOptions, fn func(*InstanceMetric) bool) error {
	for _, metric := range m.metrics {
		if !fn(metric) {
			break
		}
	}
	return nil
}

func (m *mockMetricProvider) AddRequest(_ *LlmRequest, _ *InstanceContext) error {
	return nil
}

func (m *mockMetricProvider) RemoveRequest(_ *LlmRequest, _ *InstanceContext) error {
	return nil
}

func (m *mockMetricProvider) PredictTokensByEMA(_ *LlmRequest) int {
	return 100
}

func (m *mockMetricProvider) GetDPAwareMetrics(_ *MetricQueryOptions, _ int) ([]*DPAwareMetric, error) {
	result := make([]*DPAwareMetric, len(m.metrics))
	for i, metric := range m.metrics {
		result[i] = &DPAwareMetric{
			InsUrl:     metric.InsUrl,
			BaseURL:    metric.InsUrl,
			DpRank:     0,
			FreeBlocks: metric.FreeBlocks,
			TokenNum:   0,
			TBT:        0,
			TTFT:       0,
			GroupID:    metric.GroupID,
		}
	}
	return result, nil
}

func newMockMetricProvider(urls []string) *mockMetricProvider {
	metrics := make([]*InstanceMetric, len(urls))
	for i, url := range urls {
		metrics[i] = &InstanceMetric{
			InsUrl:     url,
			FreeBlocks: 100,
			ReqNum:     0,
		}
	}
	return &mockMetricProvider{metrics: metrics}
}

func TestNewConsistentHashLB(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2"})
	lb, err := newConsistentHashLB(provider, &AlgorithmParams{})

	assert.NoError(t, err)
	assert.NotNil(t, lb)
	assert.Equal(t, VirtualNodesPerWorker, lb.virtualNodes)
}

func TestNewConsistentHashLB_CustomParams(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1"})
	params := &AlgorithmParams{
		VirtualNodes: 50,
		FallbackNum:  5,
		DpSize:       2,
	}

	lb, err := newConsistentHashLB(provider, params)

	assert.NoError(t, err)
	assert.Equal(t, 50, lb.virtualNodes)
	assert.Equal(t, 5, lb.fallbackNum)
	assert.Equal(t, 2, lb.dpSize)
}

func TestConsistentHashLB_Schedule_SessionAffinity(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 100})

	headers := map[string]string{
		"X-Session-Id": "consistent-session-123",
	}

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{
			ReqId: "req1",
		},
		Headers: headers,
	}

	results := make([]string, 10)
	for i := 0; i < 10; i++ {
		result := lb.schedule(request, nil)
		results[i] = result.PrefillUrl
	}

	for _, url := range results {
		if url == "" {
			t.Error("Schedule returned empty URL")
		}
		first := results[0]
		if url != first {
			t.Errorf("Same session routed to different workers: first=%s, current=%s", first, url)
		}
	}
}

func TestConsistentHashLB_Schedule_DifferentSessions(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 100})

	session1 := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "session-A"},
	}

	session2 := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req2"},
		Headers: map[string]string{"X-Session-Id": "session-B"},
	}

	result1 := lb.schedule(session1, nil)
	result2 := lb.schedule(session2, nil)

	t.Logf("Session A -> %s", result1.PrefillUrl)
	t.Logf("Session B -> %s", result2.PrefillUrl)
}

func TestConsistentHashLB_Schedule_NoHealthyWorkers(t *testing.T) {
	provider := &mockMetricProvider{metrics: []*InstanceMetric{}}
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{})

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "session-123"},
	}

	result := lb.schedule(request, nil)

	assert.Equal(t, "", result.PrefillUrl)
}

func TestConsistentHashLB_Schedule_AllWorkersUnhealthy(t *testing.T) {
	metrics := []*InstanceMetric{
		{InsUrl: "w1", FreeBlocks: 0},
		{InsUrl: "w2", FreeBlocks: 0},
	}
	provider := &mockMetricProvider{metrics: metrics}

	params := &AlgorithmParams{
		InstanceRoleType: base.MixedRoleInstance,
	}
	lb, _ := newConsistentHashLB(provider, params)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "session-123"},
	}

	result := lb.schedule(request, nil)

	assert.NotEmpty(t, result.PrefillUrl)
}

func TestConsistentHashLB_Schedule_FallbackOnUnhealthy(t *testing.T) {
	metrics := []*InstanceMetric{
		{InsUrl: "w1", FreeBlocks: 0},
		{InsUrl: "w2", FreeBlocks: 100},
		{InsUrl: "w3", FreeBlocks: 0},
	}
	provider := &mockMetricProvider{metrics: metrics}

	params := &AlgorithmParams{
		VirtualNodes:    100,
		FallbackNum:     3,
		InstanceRoleType: base.MixedRoleInstance,
	}
	lb, _ := newConsistentHashLB(provider, params)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "session-123"},
	}

	result := lb.schedule(request, nil)

	assert.NotEmpty(t, result.PrefillUrl)
}

func TestConsistentHashLB_Schedule_HashRingRebuild(t *testing.T) {
	metrics := []*InstanceMetric{
		{InsUrl: "w1", FreeBlocks: 100},
		{InsUrl: "w2", FreeBlocks: 100},
	}
	provider := &mockMetricProvider{metrics: metrics}
	params := &AlgorithmParams{
		VirtualNodes:     100,
		InstanceRoleType: base.MixedRoleInstance,
	}
	lb, _ := newConsistentHashLB(provider, params)

	lb.mu.RLock()
	initialWorkers := len(lb.lastWorkers)
	lb.mu.RUnlock()

	assert.Equal(t, 0, initialWorkers)

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "session-123"},
	}

	lb.schedule(request, nil)

	lb.mu.RLock()
	workersAfterFirst := len(lb.lastWorkers)
	lb.mu.RUnlock()

	assert.Equal(t, 2, workersAfterFirst)

	provider.metrics = append(provider.metrics, &InstanceMetric{
		InsUrl:     "w3",
		FreeBlocks: 100,
	})

	lb.schedule(request, nil)

	lb.mu.RLock()
	newWorkers := len(lb.lastWorkers)
	lb.mu.RUnlock()

	assert.Equal(t, 3, newWorkers)
}

func TestConsistentHashLB_Schedule_Distribution(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3", "w4", "w5"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 160})

	counts := map[string]int{
		"w1": 0, "w2": 0, "w3": 0, "w4": 0, "w5": 0,
	}

	n := 1000
	for i := 0; i < n; i++ {
		request := &ScheduleRequestMsg{
			Request: &LlmRequest{ReqId: fmt.Sprintf("req-%d", i)},
			Headers: map[string]string{"X-Session-Id": fmt.Sprintf("session-%d", i)},
		}

		result := lb.schedule(request, nil)
		if result.PrefillUrl != "" {
			counts[result.PrefillUrl]++
		}
	}

	total := 0
	for _, c := range counts {
		total += c
	}

	expected := float64(n) / float64(len(counts))
	tolerance := 0.3

	for worker, count := range counts {
		ratio := float64(count) / expected
		t.Logf("Worker %s: %d requests (ratio %.2f)", worker, count, ratio)
		if ratio < 1-tolerance || ratio > 1+tolerance {
			t.Errorf("Worker %s distribution %.2f outside tolerance [%.2f, %.2f]",
				worker, ratio, 1-tolerance, 1+tolerance)
		}
	}

	t.Logf("Total requests scheduled: %d/%d", total, n)
}

func TestConsistentHashLB_Schedule_PriorityHeaders(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 100})

	sessionA := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: map[string]string{"X-Session-Id": "sess-A"},
	}

	sessionB := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req2"},
		Headers: map[string]string{"X-User-Id": "user-B"},
	}

	resultA := lb.schedule(sessionA, nil)
	resultB := lb.schedule(sessionB, nil)

	t.Logf("Session-A -> %s", resultA.PrefillUrl)
	t.Logf("User-B -> %s", resultB.PrefillUrl)
}

func TestConsistentHashLB_Schedule_BodyHashKey(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 100})

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Body: map[string]interface{}{
			"session_params": map[string]interface{}{
				"session_id": "body-session-xyz",
			},
		},
	}

	result := lb.schedule(request, nil)

	assert.NotEmpty(t, result.PrefillUrl)
}

func TestConsistentHashLB_ExtractHashKey(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{})

	headers := map[string]string{
		"X-Session-Id": "test-session",
		"X-User-Id":    "test-user",
	}

	request := &ScheduleRequestMsg{
		Request: &LlmRequest{ReqId: "req1"},
		Headers: headers,
		Body: map[string]interface{}{
			"session_id": "body-session",
		},
	}

	hashKey := lb.extractHashKeyFromRequest(request)

	if hashKey == "" {
		t.Error("extractHashKeyFromRequest returned empty string")
	}

	if hashKey == "fallback:empty" {
		t.Error("Should have extracted session ID, got fallback")
	}
}

func TestConsistentHashLB_IsHealthy(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{
		InstanceRoleType: base.DecodeRoleInstance,
	})

	healthy := &InstanceMetric{FreeBlocks: 10}
	unhealthy := &InstanceMetric{FreeBlocks: 0}

	assert.True(t, lb.isHealthy(healthy))
	assert.False(t, lb.isHealthy(unhealthy))
}

func TestConsistentHashLB_IsHealthy_MixedRole(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{
		InstanceRoleType: base.MixedRoleInstance,
	})

	unhealthy := &InstanceMetric{FreeBlocks: 0}

	assert.True(t, lb.isHealthy(unhealthy))
}

func TestConsistentHashLB_FindMetricByURL(t *testing.T) {
	metrics := []*InstanceMetric{
		{InsUrl: "http://w1:8000", FreeBlocks: 100},
		{InsUrl: "http://w2:8000", FreeBlocks: 100},
	}
	provider := &mockMetricProvider{metrics: metrics}
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{})

	t.Run("exact match", func(t *testing.T) {
		result := lb.findMetricByURL(metrics, "http://w1:8000")
		assert.NotNil(t, result)
		assert.Equal(t, "http://w1:8000", result.InsUrl)
	})

	t.Run("DP-aware URL", func(t *testing.T) {
		result := lb.findMetricByURL(metrics, "http://w1:8000@0")
		assert.NotNil(t, result)
	})

	t.Run("not found", func(t *testing.T) {
		result := lb.findMetricByURL(metrics, "http://w3:8000")
		assert.Nil(t, result)
	})
}

func TestConsistentHashLB_GetWorkerURLs(t *testing.T) {
	metrics := []*InstanceMetric{
		{InsUrl: "http://w1:8000", FreeBlocks: 100},
		{InsUrl: "http://w2:8000", FreeBlocks: 100},
	}
	provider := &mockMetricProvider{metrics: metrics}

	t.Run("no DP expansion", func(t *testing.T) {
		lb, _ := newConsistentHashLB(provider, &AlgorithmParams{DpSize: 1})
		urls := lb.getWorkerURLs(metrics)
		assert.Equal(t, 2, len(urls))
	})

	t.Run("with DP expansion", func(t *testing.T) {
		lb, _ := newConsistentHashLB(provider, &AlgorithmParams{DpSize: 4})
		urls := lb.getWorkerURLs(metrics)
		assert.Equal(t, 8, len(urls))
	})
}

func TestConsistentHashLB_EqualStringSlices(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different order", []string{"a", "b"}, []string{"b", "a"}, false},
		{"different len", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a"}, []string{"b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := equalStringSlices(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConsistentHashLB_Contains(t *testing.T) {
	slice := []string{"a", "b", "c"}

	assert.True(t, contains(slice, "b"))
	assert.False(t, contains(slice, "d"))
	assert.False(t, contains([]string{}, "a"))
}

func TestConsistentHashLB_ConsistencyUnderLoad(t *testing.T) {
	provider := newMockMetricProvider([]string{"w1", "w2", "w3"})
	lb, _ := newConsistentHashLB(provider, &AlgorithmParams{VirtualNodes: 160})

	sessionID := "stress-test-session-12345"

	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		request := &ScheduleRequestMsg{
			Request: &LlmRequest{ReqId: fmt.Sprintf("req-%d", i)},
			Headers: map[string]string{"X-Session-Id": sessionID},
		}
		result := lb.schedule(request, nil)
		results[i] = result.PrefillUrl
	}

	first := results[0]
	for i, url := range results {
		if url != first {
			t.Errorf("Inconsistent routing at iteration %d: expected %s, got %s", i, first, url)
		}
	}
}