/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Unit tests for RedisCacheCenter.
 * Create: 2026-01-20
 */

package cachecenter

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper: create test RequestInfo
func newTestRequestInfo(reqID string) *RequestInfo {
	return &RequestInfo{
		ReqId:              reqID,
		PrefillInstance:    "ins-A",
		DecodeInstance:     "ins-B",
		PromptTokenLen:     100,
		DecodeTokenLen:     50,
		PredictPrefillTime: 10.5,
		TimeStamp:          1000,
	}
}

// Test instanceRequestsInfoKey
func TestRedisCacheCenter_instanceRequestsInfoKey(t *testing.T) {
	rcc := NewRedisCacheCenter(&CacheDriverOps{}, 0)
	key := rcc.instanceRequestsInfoKey("gpt-3.5", "ins-A")
	assert.Equal(t, "model:gpt-3.5:instance:ins-A:requests_info", key)
}

// Test AddRequest success
func TestRedisCacheCenter_AddRequest_Success(t *testing.T) {
	var capturedKey string
	var capturedFields map[string]string

	ops := &CacheDriverOps{
		HSet: func(key string, fields map[string]string, ttl int) error {
			capturedKey = key
			capturedFields = fields
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	model := "gpt-3.5"
	instanceID := "ins-A"
	info := newTestRequestInfo("req1")

	err := rcc.AddRequest(model, instanceID, []*RequestInfo{info})

	assert.NoError(t, err)
	assert.Equal(t, "model:gpt-3.5:instance:ins-A:requests_info", capturedKey)
	assert.Equal(t, 1, len(capturedFields))
	assert.Equal(t, info.StringWithoutId(), capturedFields["req1"])
}

// Test AddRequest failure
func TestRedisCacheCenter_AddRequest_Failure(t *testing.T) {
	ops := &CacheDriverOps{
		HSet: func(key string, fields map[string]string, ttl int) error {
			return errors.New("redis write failed")
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	info := newTestRequestInfo("req1")

	err := rcc.AddRequest("gpt-3.5", "ins-A", []*RequestInfo{info})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis write failed")
}

// Test RemoveRequest success
func TestRedisCacheCenter_RemoveRequest_Success(t *testing.T) {
	var capturedKey, capturedField string
	ops := &CacheDriverOps{
		HDel: func(key string, field ...string) error {
			capturedKey = key
			capturedField = field[0]
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	err := rcc.RemoveRequest("gpt-3", "ins-A", []*RequestInfo{{ReqId: "req1"}})

	assert.NoError(t, err)
	assert.Equal(t, "model:gpt-3:instance:ins-A:requests_info", capturedKey)
	assert.Equal(t, "req1", capturedField)
}

// Test RemoveRequest failure
func TestRedisCacheCenter_RemoveRequest_Failure(t *testing.T) {
	ops := &CacheDriverOps{
		HDel: func(key string, field ...string) error {
			return errors.New("redis delete failed")
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	err := rcc.RemoveRequest("gpt-3", "ins-A", []*RequestInfo{{ReqId: "req3"}})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete metadata")
	assert.Contains(t, err.Error(), "redis delete failed")
}

// Test UpdateRequest with non-nil info
func TestRedisCacheCenter_UpdateRequest_Success(t *testing.T) {
	var capturedKey string
	var capturedFields map[string]string

	ops := &CacheDriverOps{
		HSet: func(key string, fields map[string]string, ttl int) error {
			capturedKey = key
			capturedFields = fields
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	info := newTestRequestInfo("req1")

	err := rcc.UpdateRequest("gpt-3", "ins-A", []*RequestInfo{info})

	assert.NoError(t, err)
	assert.Equal(t, "model:gpt-3:instance:ins-A:requests_info", capturedKey)
	assert.Equal(t, 1, len(capturedFields))
	assert.Equal(t, info.StringWithoutId(), capturedFields["req1"])
}

// Test UpdateRequest with nil info (should return nil)
func TestRedisCacheCenter_UpdateRequest_NilInfo(t *testing.T) {
	// HSet should not be called
	called := false
	ops := &CacheDriverOps{
		HSet: func(key string, fields map[string]string, ttl int) error {
			called = true
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	err := rcc.UpdateRequest("gpt-3", "ins-A", nil)

	assert.Error(t, err)
	assert.False(t, called)
}

// Test FetchRequestsInfoByInstance success
func TestRedisCacheCenter_FetchRequestsInfoByInstance_Success(t *testing.T) {
	expectedResult := map[string]string{
		"req1": "{decodeLength:123}",
		"req2": "{decodeLength:456}",
	}
	ops := &CacheDriverOps{
		HGetAll: func(key string) (map[string]string, error) {
			assert.Equal(t, "model:gpt-3.5:instance:ins-A:requests_info", key)
			return expectedResult, nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	result, err := rcc.FetchRequestsInfoByInstance("gpt-3.5", "ins-A")

	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

// Test FetchRequestsInfoByInstance failure
func TestRedisCacheCenter_FetchRequestsInfoByInstance_Failure(t *testing.T) {
	ops := &CacheDriverOps{
		HGetAll: func(key string) (map[string]string, error) {
			return nil, errors.New("redis connection lost")
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)
	result, err := rcc.FetchRequestsInfoByInstance("gpt-3.5", "ins-A")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "redis connection lost")
}

// Test NewRedisCacheCenter tests constructor
func TestRedisCacheCenter_NewRedisCacheCenter(t *testing.T) {
	ops := &CacheDriverOps{
		HGetAll: func(key string) (map[string]string, error) {
			return nil, nil
		},
		HSet: func(key string, fields map[string]string, ttl int) error {
			return nil
		},
		HDel: func(key string, fields ...string) error {
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 3600)

	assert.NotNil(t, rcc)
	assert.Equal(t, ops, rcc.ops)
	assert.Equal(t, 3600, rcc.reqTtl)
}

// Test AddRequest and UpdateRequest with empty list
func TestRedisCacheCenter_AddUpdate_EmptyList(t *testing.T) {
	ops := &CacheDriverOps{
		HSet: func(key string, fields map[string]string, ttl int) error {
			return nil
		},
	}

	rcc := NewRedisCacheCenter(ops, 0)

	// Test AddRequest with empty list
	err := rcc.AddRequest("gpt-3.5", "ins-A", []*RequestInfo{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty RequestInfo list")

	// Test UpdateRequest with empty list
	err = rcc.UpdateRequest("gpt-3.5", "ins-A", []*RequestInfo{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty RequestInfo list")
}
