/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Unit tests for types.
 * Create: 2026-01-20
 */

package cachecenter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRequestInfo_String verifies that RequestInfo.String() returns valid JSON.
func TestRequestInfo_String(t *testing.T) {
	// Arrange
	req := &RequestInfo{
		ReqId:              "req-123",
		PrefillInstance:    "prefill-01:8080",
		DecodeInstance:     "decode-01:8080",
		PromptTokenLen:     512,
		DecodeTokenLen:     256,
		PredictPrefillTime: 12.34,
		PrefillStartTimeMs: 1712345678000,
		TimeStamp:          1712345678000,
	}

	// Act
	result := req.String()

	// Assert: Unmarshal to verify structure
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, "prefill-01:8080", output["prefillInstance"])
	assert.Equal(t, float64(512), output["promptTokenLen"]) // JSON unmarshals int as float64
	assert.Equal(t, float64(12.34), output["predictPrefillTime"])
	assert.Equal(t, "req-123", req.ReqId) // ReqId is not in JSON but should remain intact
}

// TestRequestInfo_String_Empty ensures empty RequestInfo still produces valid JSON.
func TestRequestInfo_String_Empty(t *testing.T) {
	// Arrange
	req := &RequestInfo{}

	// Act
	result := req.String()

	// Assert
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, float64(0), output["promptTokenLen"])
	assert.Equal(t, "", output["prefillInstance"])
}

// TestInstanceMetrics_String tests JSON output when InstanceMetrics has a head request.
func TestInstanceMetrics_String(t *testing.T) {
	// Arrange
	req := &RequestInfo{
		ReqId:              "req-456",
		PrefillInstance:    "ins-1",
		PromptTokenLen:     100,
		DecodeTokenLen:     50,
		PredictPrefillTime: 5.5,
		PrefillStartTimeMs: 1712345678000,
		TimeStamp:          1712345678000,
	}
	metrics := &InstanceMetrics{
		HeadReq:   req,
		TokenLoad: 150,
		QueueTime: 2.3,
	}

	// Act
	result := metrics.String()

	// Assert
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, float64(150), output["tokenLoad"])
	headReq := output["headReq"].(map[string]interface{})
	assert.Equal(t, "ins-1", headReq["pi"])
	assert.Equal(t, float64(100), headReq["ptl"])
}

func TestInstanceMetrics_UpdateMetric(t *testing.T) {
	t.Run("update fields successfully", func(t *testing.T) {
		im := &InstanceMetrics{
			TokenLoad: 10,
			QueueTime: 5.0,
		}

		im.updateMetric(func() {
			im.TokenLoad = 20
			im.QueueTime = 10.0
			im.HeadReq = &RequestInfo{
				ReqId:           "test-req",
				PrefillInstance: "prefill-1",
			}
		})

		if im.TokenLoad != 20 {
			t.Errorf("expected TokenLoad 20, got %d", im.TokenLoad)
		}
		if im.QueueTime != 10.0 {
			t.Errorf("expected QueueTime 10.0, got %f", im.QueueTime)
		}
		if im.HeadReq == nil || im.HeadReq.ReqId != "test-req" {
			t.Errorf("expected HeadReq with ReqId 'test-req', got %+v", im.HeadReq)
		}
	})

	t.Run("set head request to nil", func(t *testing.T) {
		im := &InstanceMetrics{
			HeadReq: &RequestInfo{ReqId: "test"},
		}

		im.updateMetric(func() {
			im.HeadReq = nil
		})

		if im.HeadReq != nil {
			t.Errorf("expected HeadReq to be nil, got %+v", im.HeadReq)
		}
	})
}

func TestInstanceMetrics_Copy(t *testing.T) {
	t.Run("copy with all fields populated", func(t *testing.T) {
		original := &InstanceMetrics{}
		original.updateMetric(func() {
			original.HeadReq = &RequestInfo{
				ReqId:              "test-req",
				PrefillInstance:    "prefill-1",
				DecodeInstance:     "decode-1",
				PromptTokenLen:     100,
				DecodeTokenLen:     50,
				PredictPrefillTime: 2.5,
				PrefillStartTimeMs: 1000,
				TimeStamp:          2000,
			}
			original.TokenLoad = 15
			original.QueueTime = 3.14
		})

		copied := original.Copy()

		// Check all fields are copied correctly
		if copied.TokenLoad != 15 {
			t.Errorf("expected TokenLoad 15, got %d", copied.TokenLoad)
		}
		if copied.QueueTime != 3.14 {
			t.Errorf("expected QueueTime 3.14, got %f", copied.QueueTime)
		}
		if copied.HeadReq == nil {
			t.Fatal("expected HeadReq not to be nil")
		}
		if copied.HeadReq.ReqId != "test-req" {
			t.Errorf("expected HeadReq.ReqId 'test-req', got '%s'", copied.HeadReq.ReqId)
		}
		if copied.HeadReq.PrefillInstance != "prefill-1" {
			t.Errorf("expected HeadReq.PrefillInstance 'prefill-1', got '%s'", copied.HeadReq.PrefillInstance)
		}
		if copied.HeadReq.PromptTokenLen != 100 {
			t.Errorf("expected HeadReq.PromptTokenLen 100, got %d", copied.HeadReq.PromptTokenLen)
		}
	})

	t.Run("copy with nil HeadReq", func(t *testing.T) {
		original := &InstanceMetrics{}
		original.updateMetric(func() {
			original.HeadReq = nil
			original.TokenLoad = 20
			original.QueueTime = 5.5
		})

		copied := original.Copy()

		if copied.HeadReq != nil {
			t.Errorf("expected HeadReq to be nil, got %+v", copied.HeadReq)
		}
		if copied.TokenLoad != 20 {
			t.Errorf("expected TokenLoad 20, got %d", copied.TokenLoad)
		}
		if copied.QueueTime != 5.5 {
			t.Errorf("expected QueueTime 5.5, got %f", copied.QueueTime)
		}
	})

	t.Run("copy safety - modifying copy doesn't affect original", func(t *testing.T) {
		original := &InstanceMetrics{}
		original.updateMetric(func() {
			original.HeadReq = &RequestInfo{
				ReqId:           "original-req",
				PrefillInstance: "original-prefill",
			}
			original.TokenLoad = 10
			original.QueueTime = 2.0
		})

		copied := original.Copy()

		// Modify the copy
		copied.TokenLoad = 99
		copied.QueueTime = 99.9
		if copied.HeadReq != nil {
			copied.HeadReq.ReqId = "modified-req"
			copied.HeadReq.PrefillInstance = "modified-prefill"
		}

		// Original should remain unchanged
		if original.TokenLoad != 10 {
			t.Errorf("original TokenLoad was modified, expected 10, got %d", original.TokenLoad)
		}
		if original.QueueTime != 2.0 {
			t.Errorf("original QueueTime was modified, expected 2.0, got %f", original.QueueTime)
		}
		if original.HeadReq.ReqId != "original-req" {
			t.Errorf("original HeadReq.ReqId was modified, expected 'original-req', got '%s'", original.HeadReq.ReqId)
		}
		if original.HeadReq.PrefillInstance != "original-prefill" {
			t.Errorf("original HeadReq.PrefillInstance was modified, expected 'original-prefill', got '%s'", original.HeadReq.PrefillInstance)
		}
	})

	t.Run("copy with empty RequestInfo", func(t *testing.T) {
		original := &InstanceMetrics{}
		original.updateMetric(func() {
			original.HeadReq = &RequestInfo{}
			original.TokenLoad = 0
			original.QueueTime = 0.0
		})

		copied := original.Copy()

		if copied.HeadReq == nil {
			t.Error("expected HeadReq not to be nil even when empty")
		}
		if copied.TokenLoad != 0 {
			t.Errorf("expected TokenLoad 0, got %d", copied.TokenLoad)
		}
		if copied.QueueTime != 0.0 {
			t.Errorf("expected QueueTime 0.0, got %f", copied.QueueTime)
		}
	})
}

// TestInstanceMetrics_String_NilHeadReq ensures HeadReq omission in JSON when nil.
func TestInstanceMetrics_String_NilHeadReq(t *testing.T) {
	// Arrange
	metrics := &InstanceMetrics{
		TokenLoad: 100,
		QueueTime: 1.2,
		HeadReq:   nil,
	}

	// Act
	result := metrics.String()

	// Assert
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, float64(100), output["tokenLoad"])
	assert.Nil(t, output["headReq"]) // should be omitted due to omitempty
}

// TestInstanceMetrics_String_Nil ensures nil InstanceMetrics returns "null".
func TestInstanceMetrics_String_Nil(t *testing.T) {
	// Arrange
	var metrics *InstanceMetrics

	// Act
	result := metrics.String()

	// Assert
	assert.Equal(t, "null", result)
}

// TestSyncTask_String tests that syncTask.String() produces correct JSON.
func TestSyncTask_String(t *testing.T) {
	// Arrange
	req1 := &RequestInfo{
		ReqId:              "req-001",
		PrefillInstance:    "ins-1",
		PromptTokenLen:     64,
		DecodeTokenLen:     32,
		PredictPrefillTime: 1.1,
		PrefillStartTimeMs: 1712345678000,
		TimeStamp:          1712345678000,
	}
	req2 := &RequestInfo{
		ReqId:              "req-002",
		PrefillInstance:    "ins-2",
		PromptTokenLen:     128,
		DecodeTokenLen:     64,
		PredictPrefillTime: 2.2,
		PrefillStartTimeMs: 1712345678001,
		TimeStamp:          1712345678001,
	}

	task := &syncTask{
		TaskType:  TaskAddRequest,
		ModelName: "llama-3",
		Info:      []*RequestInfo{req1, req2},
	}

	// Act
	result := task.String()

	// Assert
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, TaskAddRequest, output["taskType"])
	assert.Equal(t, "llama-3", output["modelName"])
	requests := output["requests"].([]interface{})
	assert.Len(t, requests, 2)
	first := requests[0].(map[string]interface{})
	assert.Equal(t, "ins-1", first["prefillInstance"])
}

// TestSyncTask_String_EmptyInfo ensures empty Info slice is serialized as [].
func TestSyncTask_String_EmptyInfo(t *testing.T) {
	// Arrange
	task := &syncTask{
		TaskType:  TaskDeleteRequest,
		ModelName: "test-model",
		Info:      []*RequestInfo{},
	}

	// Act
	result := task.String()

	// Assert
	var output map[string]interface{}
	err := json.Unmarshal([]byte(result), &output)
	assert.NoError(t, err)
	assert.Equal(t, TaskDeleteRequest, output["taskType"])
	assert.Equal(t, "test-model", output["modelName"])
	assert.Equal(t, []interface{}{}, output["requests"])
}

// TestSyncTask_String_Nil ensures nil syncTask returns "null".
func TestSyncTask_String_Nil(t *testing.T) {
	// Arrange
	var task *syncTask

	// Act
	result := task.String()

	// Assert
	assert.Equal(t, "null", result)
}

// BenchmarkRequestInfo_String benchmarks the performance of String() method.
func BenchmarkRequestInfo_String(b *testing.B) {
	req := &RequestInfo{
		ReqId:              "req-123",
		PrefillInstance:    "ins-1",
		PromptTokenLen:     100,
		DecodeTokenLen:     50,
		PredictPrefillTime: 1.5,
		PrefillStartTimeMs: time.Now().UnixMilli(),
		TimeStamp:          time.Now().UnixMilli(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = req.String()
	}
}

// BenchmarkInstanceMetrics_String benchmarks InstanceMetrics.String().
func BenchmarkInstanceMetrics_String(b *testing.B) {
	metrics := &InstanceMetrics{
		HeadReq: &RequestInfo{
			ReqId:          "req-123",
			PromptTokenLen: 100,
		},
		TokenLoad: 100,
		QueueTime: 1.0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = metrics.String()
	}
}
