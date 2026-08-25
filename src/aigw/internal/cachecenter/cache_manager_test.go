/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package cachecenter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"huawei.com/aigw/internal/base"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRedisOps simulates Redis operations
type mockRedisOps struct {
	data map[string]map[string]string
	mu   sync.RWMutex
}

func newMockRedisOps() *mockRedisOps {
	return &mockRedisOps{
		data: make(map[string]map[string]string),
	}
}

func (m *mockRedisOps) HGetAll(key string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, exists := m.data[key]; exists {
		clone := make(map[string]string, len(data))
		for k, v := range data {
			clone[k] = v
		}
		return clone, nil
	}
	return make(map[string]string), nil
}

func (m *mockRedisOps) HSet(key string, fields map[string]string, ttl int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.data[key]; !exists {
		m.data[key] = make(map[string]string)
	}
	for k, v := range fields {
		m.data[key][k] = v
	}
	return nil
}

func (m *mockRedisOps) HDel(key string, fields ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if data, exists := m.data[key]; exists {
		for _, field := range fields {
			delete(data, field)
		}
	}
	return nil
}

func (m *mockRedisOps) HGetAllBatch(keys []string) ([]map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value := make([]map[string]string, 0)
	for _, key := range keys {
		if data, exists := m.data[key]; exists {
			value = append(value, data)
		}
	}
	return value, nil
}

// createTestRequest creates a test RequestInfo
func createTestRequest(reqID string, prefillIns, decodeIns string, promptLen, decodeLen int, prefillTime float64, timestamp int64) RequestInfo {
	return RequestInfo{
		ReqId:              reqID,
		PrefillInstance:    prefillIns,
		DecodeInstance:     decodeIns,
		PromptTokenLen:     promptLen,
		DecodeTokenLen:     decodeLen,
		PredictPrefillTime: prefillTime,
		PrefillStartTimeMs: 0,
		TimeStamp:          timestamp,
	}
}

// mockJSON serializes RequestInfo without ReqId (due to json:"-")
func mockJSON(req RequestInfo) string {
	tmp := struct {
		PrefillInstance    string  `json:"pi"`
		DecodeInstance     string  `json:"di"`
		IsPrefill          bool    `json:"isp"`
		PromptTokenLen     int     `json:"ptl"`
		DecodeTokenLen     int     `json:"dtl"`
		PredictPrefillTime float64 `json:"ppt"`
		PrefillStartTimeMs int64   `json:"pst"`
		TimeStamp          int64   `json:"ts"`
		GroupID            string  `json:"gp"`
		LastModifiedTime   int64   `json:"lmt"`
	}{
		PrefillInstance:    req.PrefillInstance,
		DecodeInstance:     req.DecodeInstance,
		IsPrefill:          req.IsPrefill,
		PromptTokenLen:     req.PromptTokenLen,
		DecodeTokenLen:     req.DecodeTokenLen,
		PredictPrefillTime: req.PredictPrefillTime,
		PrefillStartTimeMs: req.PrefillStartTimeMs,
		TimeStamp:          req.TimeStamp,
		GroupID:            req.GroupID,
		LastModifiedTime:   req.LastModifiedTime,
	}
	data, _ := json.Marshal(tmp)
	return string(data)
}

// newTestRedisCache creates a mock Redis cache for testing
func newTestRedisCache() (*mockRedisOps, *RedisCacheCenter) {
	mockOps := newMockRedisOps()
	redisCache := NewRedisCacheCenter(&CacheDriverOps{
		HGetAll:      mockOps.HGetAll,
		HSet:         mockOps.HSet,
		HDel:         mockOps.HDel,
		HGetAllBatch: mockOps.HGetAllBatch,
	}, 0)
	return mockOps, redisCache
}

// TestCacheManager_FullWorkflow tests full lifecycle
func TestCacheManager_FullWorkflow(t *testing.T) {
	mockOps, redisCache := newTestRedisCache()

	modelName := "test_model"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cm := NewCacheManager(ctx, modelName, WithRemoteCache(redisCache))
	require.NotNil(t, cm)

	cm.Start()
	time.Sleep(10 * time.Millisecond)

	t.Run("AddRequest should sync to remote and update metrics", func(t *testing.T) {
		req := createTestRequest("req1", "ins1", "ins2", 100, 50, 200.0, time.Now().UnixNano())
		err := cm.AddRequest(&req)
		assert.NoError(t, err)
		cache := cm.cache.holder.Load()
		time.Sleep(10 * time.Millisecond)
		value, exists := cache.metrics.Load("ins1")
		assert.True(t, exists)
		insMetric := value.(*InstanceMetrics)
		assert.Equal(t, 100, insMetric.TokenLoad)
		assert.Equal(t, 200.0, insMetric.QueueTime)

		value, exists = cache.metrics.Load("ins2")
		assert.True(t, exists)
		insMetric = value.(*InstanceMetrics)
		assert.Equal(t, 150, insMetric.TokenLoad)

		// Check remote data is stored in instance-based key
		key := fmt.Sprintf(InstanceRequestInfo, modelName, "ins1")
		mockOps.mu.RLock()
		remote, exists := mockOps.data[key]
		mockOps.mu.RUnlock()
		assert.True(t, exists)
		assert.Contains(t, remote, "req1")
		// Verify key fields match; lmt is dynamic so check presence separately
		var stored, expected map[string]interface{}
		json.Unmarshal([]byte(remote["req1"]), &stored)
		json.Unmarshal([]byte(mockJSON(req)), &expected)
		assert.Equal(t, expected["pi"], stored["pi"])
		assert.Equal(t, expected["di"], stored["di"])
		assert.Equal(t, expected["isp"], stored["isp"])
		assert.Equal(t, expected["ptl"], stored["ptl"])
		assert.Equal(t, expected["dtl"], stored["dtl"])
		assert.Equal(t, expected["ppt"], stored["ppt"])
		assert.Equal(t, expected["pst"], stored["pst"])
		assert.Equal(t, expected["gp"], stored["gp"])
		assert.Contains(t, stored, "lmt")
		assert.Greater(t, stored["lmt"].(float64), float64(0))
	})

	t.Run("UpdateRequestOnPrefillFinished should promote next head", func(t *testing.T) {
		// after update req1, no headReq
		err := cm.UpdateRequestOnPrefillFinished("req1")
		assert.NoError(t, err)
		time.Sleep(10 * time.Millisecond)

		cache := cm.cache.holder.Load()
		value, _ := cache.metrics.Load("ins1")
		head := value.(*InstanceMetrics).HeadReq
		assert.Nil(t, head)

		// add req1 req2 then update req2, expect headReq is req3
		req2 := createTestRequest("req2", "ins1", "ins3", 80, 40, 150.0, time.Now().UnixNano()-1e8)
		err = cm.AddRequest(&req2)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)

		req3 := createTestRequest("req3", "ins1", "ins3", 80, 40, 150.0, time.Now().UnixNano()-1e8)
		err = cm.AddRequest(&req3)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)

		err = cm.UpdateRequestOnPrefillFinished("req2")
		assert.NoError(t, err)
		time.Sleep(10 * time.Millisecond)

		value, _ = cache.metrics.Load("ins1")
		insMetric := value.(*InstanceMetrics)
		head = insMetric.HeadReq
		assert.NotNil(t, head)
		assert.Equal(t, "req3", head.ReqId)

		v, _ := cache.requestMap.Load("req3")
		updatedReq2 := v.(*RequestInfo)
		assert.True(t, updatedReq2.PrefillStartTimeMs > 0)
	})

	t.Run("RemoveRequest should delete and sync", func(t *testing.T) {
		err := cm.RemoveRequest("req2")
		assert.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		cache := cm.cache.holder.Load()
		value, exists := cache.requestMap.Load("req2")
		assert.False(t, exists)

		value, _ = cache.metrics.Load("ins1")
		insMetric := value.(*InstanceMetrics)
		assert.NotNil(t, insMetric.HeadReq)

		// Check remote data is stored in instance-based key
		key := fmt.Sprintf(InstanceRequestInfo, modelName, "ins1")
		mockOps.mu.RLock()
		remote, _ := mockOps.data[key]
		mockOps.mu.RUnlock()
		assert.NotContains(t, remote, "req2")
	})

	t.Run("rebuildCache recovers from remote state", func(t *testing.T) {
		req4 := createTestRequest("req4", "ins4", "ins5", 60, 30, 100.0, time.Now().UnixNano())
		req4.IsPrefill = true // Set IsPrefill to true so it gets added to prefill instance group
		key := fmt.Sprintf(InstanceRequestInfo, modelName, "ins4")
		mockOps.mu.Lock()
		if mockOps.data[key] == nil {
			mockOps.data[key] = make(map[string]string)
		}
		mockOps.data[key]["req4"] = mockJSON(req4)
		mockOps.mu.Unlock()

		// Add instance to activeInstances so rebuildCache can find it
		cm.activeInstances.Store("ins4", true)

		err := cm.rebuildCache()
		assert.NoError(t, err)
		cache := cm.cache.holder.Load()
		value, exists := cache.metrics.Load("ins4")
		assert.True(t, exists)
		insMetric := value.(*InstanceMetrics)
		assert.Equal(t, 60, insMetric.TokenLoad)
		assert.Equal(t, 100.0, insMetric.QueueTime)

		_, exists = cache.requestMap.Load("req3")
		assert.True(t, exists)
	})

	t.Run("Stop should gracefully shutdown", func(t *testing.T) {
		cm.Stop()

		select {
		case <-cm.ctx.Done():
			// expected
		default:
			t.Fatal("context should be cancelled")
		}
	})
}

// TestCacheManager_RebuildCache_InvalidData handles invalid JSON data
func TestCacheManager_RebuildCache_InvalidData(t *testing.T) {
	mockOps := newMockRedisOps()
	key := fmt.Sprintf(InstanceRequestInfo, "test_model", "ins1")
	mockOps.data[key] = map[string]string{
		"valid":   `{"pi":"ins1","di":"","ptl":50,"dtl":0,"ppt":100,"pst":0,"ts":123}`,
		"invalid": `{invalid json}`,
		"empty":   "",
	}

	redisCache := NewRedisCacheCenter(&CacheDriverOps{
		HGetAll:      mockOps.HGetAll,
		HSet:         mockOps.HSet,
		HDel:         mockOps.HDel,
		HGetAllBatch: mockOps.HGetAllBatch,
	}, 0)

	cm := NewCacheManager(context.Background(), "test_model", WithRemoteCache(redisCache))
	cm.Start()
	defer cm.Stop()

	// Add instance to activeInstances so rebuildCache can find it
	cm.activeInstances.Store("ins1", true)

	time.Sleep(10 * time.Millisecond)

	err := cm.rebuildCache()
	assert.NoError(t, err)
}

// TestCacheManager_RebuildCache_LocalRequestProtection verifies that rebuildCache
// does not mistakenly delete activeInstances when local requests exist but Redis
// has not been synced yet.
func TestCacheManager_RebuildCache_LocalRequestProtection(t *testing.T) {
	t.Run("sync incomplete - activeInstances preserved", func(t *testing.T) {
		// Use empty Redis mock (no data) to simulate sync task not completed
		_, redisCache := newTestRedisCache()

		// Create CacheManager WITHOUT Start() so sync tasks are not processed
		cm := NewCacheManager(context.Background(), "test_model", WithRemoteCache(redisCache))
		require.NotNil(t, cm)

		// Add a request — this stores to local cache and activeInstances,
		// but sync task stays in channel (not processed)
		req := createTestRequest("req_local", "ins_local", "ins_decode", 100, 50, 200.0, time.Now().UnixNano())
		req.IsPrefill = true
		err := cm.AddRequest(&req)
		require.NoError(t, err)

		// Verify activeInstances has the instance
		_, exists := cm.activeInstances.Load("ins_local")
		assert.True(t, exists, "ins_local should be in activeInstances after AddRequest")

		// Rebuild cache — Redis has no data for ins_local (sync not completed)
		err = cm.rebuildCache()
		assert.NoError(t, err)

		// Verify activeInstances still retains ins_local (local request protection)
		_, exists = cm.activeInstances.Load("ins_local")
		assert.True(t, exists, "ins_local should NOT be deleted from activeInstances when local request exists")
	})

	t.Run("no local requests - activeInstances cleaned up", func(t *testing.T) {
		_, redisCache := newTestRedisCache()

		cm := NewCacheManager(context.Background(), "test_model", WithRemoteCache(redisCache))
		require.NotNil(t, cm)

		// Manually add an instance to activeInstances without any local request
		cm.activeInstances.Store("ins_orphan", true)

		// Rebuild cache — no Redis data and no local request for ins_orphan
		err := cm.rebuildCache()
		assert.NoError(t, err)

		// Verify ins_orphan is cleaned up
		_, exists := cm.activeInstances.Load("ins_orphan")
		assert.False(t, exists, "ins_orphan should be deleted from activeInstances when no local request and no Redis data")
	})

	t.Run("decode instance with local request not preserved", func(t *testing.T) {
		_, redisCache := newTestRedisCache()

		cm := NewCacheManager(context.Background(), "test_model", WithRemoteCache(redisCache))
		require.NotNil(t, cm)

		// Register a decode-role instance via EnsureInstanceMetrics
		cm.EnsureInstanceMetrics("ins_decode", base.DecodeRoleInstance, "group1")
		_, exists := cm.activeInstances.Load("ins_decode")
		assert.True(t, exists, "ins_decode should be in activeInstances after EnsureInstanceMetrics")

		// Add a local request where ins_decode is the DecodeInstance
		req := createTestRequest("req_decode", "ins_prefill", "ins_decode", 80, 40, 150.0, time.Now().UnixNano())
		req.IsPrefill = false
		err := cm.AddRequest(&req)
		require.NoError(t, err)

		// Rebuild cache — no Redis data for ins_decode
		err = cm.rebuildCache()
		assert.NoError(t, err)

		// Verify ins_decode is preserved (local request references it via DecodeInstance)
		_, exists = cm.activeInstances.Load("ins_decode")
		assert.False(t, exists, "ins_decode should be preserved when local request references it via DecodeInstance")
	})
}
