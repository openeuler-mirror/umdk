/*
 * SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
* Description: inference instance management.
* Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"huawei.com/aigw/internal/base"
)

func TestNewInstance(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.MixedRoleInstance, "", reqStatusChan, insMgr)

	if ins.insUrl != "localhost:8080" {
		t.Error("Expected localhost:8080")
	}
	if ins.insRole != base.MixedRoleInstance {
		t.Error("Expected mixedRoleInstance")
	}
	if ins.freeBlocks != 0 {
		t.Error("Expected0")
	}
	if ins.preBlocks != 0 {
		t.Error("Expected 0")
	}
	if len(ins.reqSet) != 0 {
		t.Error("Expected 0")
	}
	if len(ins.preloadMap) != 0 {
		t.Error("Expected 0")
	}
	if ins.ctx == nil {
		t.Error("Expected non-nil result")
	}
	if ins.cancel == nil {
		t.Error("Expected non-nil result")
	}
	if ins.reqStatusChan == nil {
		t.Error("Expected non-nil result")
	}
}

func TestInstanceRole(t *testing.T) {
	role, err := base.ToInstanceRole("mixed")
	assert.NoError(t, err)
	assert.Equal(t, base.MixedRoleInstance, role)

	role, err = base.ToInstanceRole("prefill")
	assert.NoError(t, err)
	assert.Equal(t, base.PrefillRoleInstance, role)

	role, err = base.ToInstanceRole("decode")
	assert.NoError(t, err)
	assert.Equal(t, base.DecodeRoleInstance, role)

	role, err = base.ToInstanceRole("invalid")
	assert.Error(t, err)
	assert.Equal(t, base.InvalidRoleInstance, role)
	assert.EqualError(t, err, "invalid is not a valid instance role")
}

func TestAddReqToMixIns(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.MixedRoleInstance, "", reqStatusChan, insMgr)

	req := &LlmRequest{ReqId: "test-req", PredictBlocks: 1}
	ins.addReq(req)

	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	insReq, exists := ins.reqSet["test-req"]
	if !exists {
		t.Error("Expected exists")
	}
	if insReq != req {
		t.Error("Expected equal")
	}
}

func TestAddReqToDecodeIns(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	reqStatusChan := make(chan *ControlMessage, 1)
	initBlocks := 10
	decodeIns, _ := newInstance("localhost:8081", base.DecodeRoleInstance, "", reqStatusChan, insMgr)
	decodeIns.preBlocks = initBlocks
	decodeReq := &LlmRequest{ReqId: "decode-req", PredictBlocks: 3}
	decodeIns.addReq(decodeReq)

	decodeIns.rwLock.Lock()
	defer decodeIns.rwLock.Unlock()
	load, exists := decodeIns.preloadMap["decode-req"]
	if !exists {
		t.Error("Expected exists")
	}
	if load != decodeReq.PredictBlocks {
		t.Error("Expected req load is 3")
	}
	if decodeIns.preBlocks != (initBlocks + decodeReq.PredictBlocks) {
		t.Error("Expected preBlocks is 13")
	}
}

func TestProcessReqStatusWithReqIsFinished(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	insManager := newInstanceManager()
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.MixedRoleInstance, "", reqStatusChan, insMgr)
	ins.insMgr = insManager

	req := &LlmRequest{ReqId: "finish-req", ReqType: ReqTypeUltraShort}
	ins.reqSet["finish-req"] = req
	data := ReqStatusData{Event: "REQUEST_IS_FINISHED", ReqId: "finish-req", DecodeLen: 10}
	ins.processReqStatus(data)
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	_, exists := ins.reqSet["finish-req"]
	if exists {
		t.Error("Expected not exists")
	}
}

func TestProcessReqStatusWithDecodeReceivedKvc(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	insManager := newInstanceManager()
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.DecodeRoleInstance, "", reqStatusChan, insMgr)
	ins.insMgr = insManager
	ins.preloadMap["test-req"] = 5
	ins.preBlocks = 5
	ins.reqSet["test-req"] = nil

	data := ReqStatusData{Event: "DECODE_RECEIVED_KVC", ReqId: "test-req"}
	ins.processReqStatus(data)
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	_, exists := ins.reqSet["test-req"]
	if !exists {
		t.Error("Expected exists")
	}
	_, exists = ins.preloadMap["test-req"]
	if exists {
		t.Error("Expected not exists")
	}
	if ins.preBlocks != 0 {
		t.Error("Expected preBlocks is 0")
	}
}

func TestProcessMetric(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.MixedRoleInstance, "", reqStatusChan, insMgr)

	data := MetricData{
		FreeBlocks:     5,
		AvgWaitingTime: 100.0,
		TBT:            20.0,
		QueueLength:    3,
		TTFT:           150.0,
	}

	ins.processMetric(data)
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()

	if ins.freeBlocks != data.FreeBlocks {
		t.Error("Expected freeBlocks is 5")
	}
	if ins.avgWaitingTime != data.AvgWaitingTime {
		t.Error("Expected avgWaitingTime is 100")
	}
	if ins.tbt != data.TBT {
		t.Error("Expected tbt is 20")
	}
	if ins.queueLength != data.QueueLength {
		t.Error("Expected queueLength is 3")
	}
	if ins.ttft != data.TTFT {
		t.Error("Expected ttft is 150")
	}
}

func TestProcessSSEWithMetricEvent(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	reqStatusChan := make(chan *ControlMessage, 1)
	ins, _ := newInstance("localhost:8080", base.MixedRoleInstance, "", reqStatusChan, insMgr)

	// test metric_event
	metricData := MetricData{
		TotalBlocks: 10,
		FreeBlocks:  5,
	}
	data, err1 := json.Marshal(metricData)
	if err1 != nil {
		t.Error("json marshal error")
	}
	metricEvent := InsEvent{
		EventType: "metric_event",
		Data:      data,
	}
	metricJSON, err2 := json.Marshal(metricEvent)
	if err2 != nil {
		t.Error("json marshal error")
	}
	ins.processInsData(string(metricJSON))
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	if ins.freeBlocks != metricData.FreeBlocks {
		t.Error("Expected ins.freeBlocks is 5")
	}
}

func TestDecodeUpdateReq(t *testing.T) {
	// Setup test context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	insMgr := newInstanceManager()
	// Create a test instance
	ins := &instance{
		insUrl:     "test-instance",
		insRole:    base.DecodeRoleInstance,
		preloadMap: make(map[string]int),
		reqSet:     make(map[string]*LlmRequest),
		reqQueue:   newRequestQueue(),
		ctx:        ctx,
		insWg:      new(sync.WaitGroup),
		insMgr:     insMgr,
	}

	// Test case 1: DECODE_RECEIVED_KVC event with existing request
	t.Run("DECODE_RECEIVED_KVC with existing request", func(t *testing.T) {
		reqID := "test-req-1"
		ins.preloadMap[reqID] = 5
		ins.preBlocks = 5

		data := ReqStatusData{
			Event: "DECODE_RECEIVED_KVC",
			ReqId: reqID,
		}

		ins.decodeUpdateReq(data)

		// Assert that the request is removed from preloadMap and preBlocks is updated
		_, exists := ins.preloadMap[reqID]
		if exists {
			t.Error("expected not exist")
		}
		if ins.preBlocks != 0 {
			t.Error("expected preBlocks == 0")
		}

	})

	// Test case 2: REQUEST_IS_FINISHED event with existing request
	t.Run("REQUEST_IS_FINISHED with existing request", func(t *testing.T) {
		reqID := "test-req-2"
		req := &LlmRequest{
			ReqId:         reqID,
			ReqType:       ReqTypeUltraShort,
			PredictBlocks: 3,
		}
		ins.reqSet[reqID] = req
		ins.reqNum = 1

		data := ReqStatusData{
			Event:     "REQUEST_IS_FINISHED",
			ReqId:     reqID,
			DecodeLen: 10,
		}

		ins.decodeUpdateReq(data)

		// Assert that the request is removed from reqSet and reqNum is updated
		_, exists := ins.reqSet[reqID]

		if exists {
			t.Error("expected not exist")
		}
		if ins.reqNum != 0 {
			t.Error("expected reqNum == 0")
		}
	})

	// Test case 3: REQUEST_IS_FINISHED event with non-existing request
	t.Run("REQUEST_IS_FINISHED with non-existing request", func(t *testing.T) {
		reqID := "test-req-3"
		data := ReqStatusData{
			Event: "REQUEST_IS_FINISHED",
			ReqId: reqID,
		}

		ins.decodeUpdateReq(data)

		// Assert that no changes are made
		_, exists := ins.reqSet[reqID]
		if exists {
			t.Error("expected not exists")
		}
	})

	// Test case 4: Invalid event type
	t.Run("Invalid event type", func(t *testing.T) {
		reqID := "test-req-4"
		data := ReqStatusData{
			Event: "INVALID_EVENT",
			ReqId: reqID,
		}

		ins.decodeUpdateReq(data)

		// Assert that no changes are made
		_, exists := ins.reqSet[reqID]
		if exists {
			t.Error("expected not exists")
		}
	})
}

func TestProcessInsData_TableDriven(t *testing.T) {
	// 初始化通用测试依赖
	baseInsMgr := newInstanceManager()
	// 定义测试用例表
	testCases := []struct {
		name     string
		setup    func() *instance                  // 测试前置准备
		input    string                            // 输入数据
		validate func(t *testing.T, ins *instance) // 验证函数
	}{
		{
			name: "MetricEvent",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"metric_event","data":{
					"totalKvBlocks":100,
					"freeKvBlocks":1,
					"timeToFirstToken":1,
					"timeBetweenTokens":1,
					"queueLength":5,
					"avgWaitingTime":3.0
					}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()

				if ins.freeBlocks != 1 {
					t.Errorf("Expected freeBlocks 1, got %d", ins.freeBlocks)
				}
				if ins.ttft != 1 {
					t.Errorf("Expected ttft 1, got %f", ins.ttft)
				}
				if ins.tbt != 1 {
					t.Errorf("Expected tbt 1, got %f", ins.tbt)
				}
			},
		},
		{
			name: "ReqEventMixedRole",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "", make(chan *ControlMessage, 10), baseInsMgr)
				req := &LlmRequest{ReqId: "req1", PredictTokens: 1, PredictBlocks: 1}
				ins.reqSet[req.ReqId] = req
				ins.reqNum = 1
				ins.tokenNum = 1
				return ins
			},
			input: `{"eventType":"req_event","data":{
					"event":"REQUEST_IS_FINISHED",
					"requestId":"req1",
					"decodeLen":5,
					"promptTokens":[1,2,3]
					}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()

				if _, exists := ins.reqSet["req1"]; exists {
					t.Error("Request should be removed from reqSet")
				}
				if ins.reqNum != 0 {
					t.Errorf("Expected reqNum 0, got %d", ins.reqNum)
				}
			},
		},
		{
			name: "UnknownEventType",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"unknown_event","data":{}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.freeBlocks != 0 { // 初始值为0
					t.Error("Instance state should not change for unknown event type")
				}
			},
		},
		{
			name: "InvalidJSON",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "", nil, baseInsMgr)
				return ins
			},
			input: `{invalid json}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.freeBlocks != 0 { // 初始值为0
					t.Error("Instance state should not change with invalid JSON")
				}
			},
		},
		{
			name: "DecodeInstanceReqEvent",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.DecodeRoleInstance, "", nil, baseInsMgr)
				req := &LlmRequest{ReqId: "req1", PredictTokens: 1, PredictBlocks: 1}
				ins.reqSet[req.ReqId] = req
				ins.preloadMap[req.ReqId] = 1
				ins.preBlocks = 1
				return ins
			},
			input: `{"eventType":"req_event","data":{
					"event":"DECODE_RECEIVED_KVC",
					"requestId":"req1",
					"decodeLen":5,
					"promptTokens":[1,2,3]
					}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()

				if ins.preBlocks != 0 {
					t.Errorf("Expected preBlocks 0, got %d", ins.preBlocks)
				}
				if _, exists := ins.preloadMap["req1"]; exists {
					t.Error("Preload should be removed for DECODE_RECEIVED_KVC event")
				}
			},
		},
		{
			name: "KVCGeneratedEventMixedRole",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "test", nil, baseInsMgr)
				req := &LlmRequest{ReqId: "req1", PredictTokens: 1, PredictBlocks: 1}
				ins.reqSet[req.ReqId] = req
				ins.reqNum = 1
				ins.tokenNum = 1
				return ins
			},
			input: `{"eventType":"req_event","data":{
					"event":"KVC_GENERATED",
					"requestId":"req1"
					}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()

				if _, exists := ins.reqSet["req1"]; !exists {
					t.Error("Request should still be in reqSet")
				}
			},
		},
		{
			name: "KVCGeneratedEventPrefillRole",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.PrefillRoleInstance, "test", nil, baseInsMgr)
				req := &LlmRequest{ReqId: "req1", PredictTokens: 1, PredictBlocks: 1}
				ins.reqSet[req.ReqId] = req
				ins.reqNum = 1
				ins.tokenNum = 1
				return ins
			},
			input: `{"eventType":"req_event","data":{
					"event":"KVC_GENERATED",
					"requestId":"req1"
					}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()

				if _, exists := ins.reqSet["req1"]; exists {
					t.Error("Request should be removed from reqSet")
				}
				if ins.reqNum != 0 {
					t.Errorf("Expected reqNum 0, got %d", ins.reqNum)
				}
			},
		},
		{
			name: "InvalidReqStatusData",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "test", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"req_event","data":{}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.reqNum != 0 {
					t.Errorf("Expected reqNum 0, got %d", ins.reqNum)
				}
			},
		},
		{
			name: "EmptyReqStatusData",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "test", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"req_event","data":null}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.reqNum != 0 {
					t.Errorf("Expected reqNum 0, got %d", ins.reqNum)
				}
			},
		},
		{
			name: "InvalidMetricData",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "test", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"metric_event","data":{}}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.freeBlocks != 0 {
					t.Errorf("Expected freeBlocks 0, got %d", ins.freeBlocks)
				}
			},
		},
		{
			name: "EmptyMetricData",
			setup: func() *instance {
				ins, _ := newInstance("test-url", base.MixedRoleInstance, "test", nil, baseInsMgr)
				return ins
			},
			input: `{"eventType":"metric_event","data":null}`,
			validate: func(t *testing.T, ins *instance) {
				ins.rwLock.RLock()
				defer ins.rwLock.RUnlock()
				if ins.freeBlocks != 0 {
					t.Errorf("Expected freeBlocks 0, got %d", ins.freeBlocks)
				}
			},
		},
	}

	// 执行所有测试用例
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ins := tc.setup()
			ins.processInsData(tc.input)
			tc.validate(t, ins)
		})
	}

	// 单独处理并发测试
	t.Run("ConcurrentAccess", func(t *testing.T) {
		ins, _ := newInstance("test-url", base.MixedRoleInstance, "", nil, baseInsMgr)
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			ins.processInsData(`{"eventType":"metric_event","data":{
										"totalKvBlocks":1024,
										"freeKvBlocks":1024,
										"timeToFirstToken":10.5,
										"timeBetweenTokens":2.0,
										"queueLength":5,
										"avgWaitingTime":3.0
										}}`)
		}()

		go func() {
			defer wg.Done()
			ins.processInsData(`{"eventType":"metric_event","data":{
										"totalKvBlocks":200,
										"freeKvBlocks":1,
										"timeToFirstToken":20.5,
										"timeBetweenTokens":3.0,
										"queueLength":10,
										"avgWaitingTime":6.0
										}}`)
		}()

		wg.Wait()

		ins.rwLock.RLock()
		defer ins.rwLock.RUnlock()
		if ins.freeBlocks != 1 && ins.freeBlocks != 1024 {
			t.Errorf("Unexpected freeBlocks value: %d", ins.freeBlocks)
		}
	})
}

func TestPrefillUpdateReq(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*instance) // 测试前置操作
		input       ReqStatusData   // 输入数据
		wantReqNum  int             // 期望的请求数
		wantReqSize int             // 期望的请求集合大小
	}{
		{
			name: "KVCGenerated_ExistingRequest",
			setup: func(ins *instance) {
				ins.reqSet["test-request"] = &LlmRequest{ReqId: "test-request", Prompt: "test"}
				ins.reqQueue = newRequestQueue()
				ins.reqQueue.enqueue(&LlmRequest{ReqId: "test-request", Prompt: "test"})
				ins.reqNum = 1
			},
			input: ReqStatusData{
				Event: "KVC_GENERATED",
				ReqId: "test-request",
			},
			wantReqNum:  0,
			wantReqSize: 0,
		},
		{
			name: "KVCGenerated_NonExistingRequest",
			setup: func(ins *instance) {
				// 空初始化
			},
			input: ReqStatusData{
				Event: "KVC_GENERATED",
				ReqId: "non-existent-request",
			},
			wantReqNum:  0,
			wantReqSize: 0,
		},
		{
			name: "InvalidEvent_ShouldIgnore",
			setup: func(ins *instance) {
				ins.reqSet["test-request"] = &LlmRequest{ReqId: "test-request", Prompt: "test"}
				ins.reqNum = 1
			},
			input: ReqStatusData{
				Event: "INVALID_EVENT",
				ReqId: "test-request",
			},
			wantReqNum:  1,
			wantReqSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 初始化实例
			ins := &instance{
				insRole:  base.PrefillRoleInstance,
				reqSet:   make(map[string]*LlmRequest),
				reqQueue: newRequestQueue(),
				rwLock:   sync.RWMutex{},
			}

			// 执行前置操作
			if tt.setup != nil {
				tt.setup(ins)
			}

			// 执行测试方法
			ins.prefillUpdateReq(tt.input)

			// 验证结果
			if len(ins.reqSet) != tt.wantReqSize {
				t.Errorf("reqSet size got = %d, want %d", len(ins.reqSet), tt.wantReqSize)
			}
			if ins.reqNum != tt.wantReqNum {
				t.Errorf("reqNum got = %d, want %d", ins.reqNum, tt.wantReqNum)
			}
		})
	}
}

func TestProcessPrefillEvents(t *testing.T) {
	tests := []struct {
		name         string
		aesEnabled   bool            // AES是否启用
		buildEvent   func() string   // 构建事件数据
		setup        func(*instance) // 测试前置操作
		wantReqNum   int             // 期望的请求数
		wantReqSize  int             // 期望的请求集合大小
		expectErrors bool            // 是否预期出错
	}{
		{
			name:       "KVCGenerated_WithAESDisabled",
			aesEnabled: false,
			buildEvent: func() string {
				event := InsEvent{
					EventType: "req_event",
					Data:      json.RawMessage(`{"event":"KVC_GENERATED","requestId":"test-req-123"}`),
				}
				data, err := json.Marshal(event)
				if err != nil {
					return err.Error()
				}
				return string(data)
			},
			setup: func(ins *instance) {
				ins.reqSet["test-req-123"] = &LlmRequest{ReqId: "test-req-123", Prompt: "test"}
				ins.reqNum = 1
			},
			wantReqNum:   0,
			wantReqSize:  0,
			expectErrors: false,
		},
		{
			name:       "InvalidJSON_ShouldHandleGracefully",
			aesEnabled: false,
			buildEvent: func() string {
				return `{"eventType":"req_event","data":{invalid-json}}`
			},
			setup:        func(ins *instance) {},
			wantReqNum:   0,
			wantReqSize:  0,
			expectErrors: true,
		},
		{
			name:       "UnknownEventType_ShouldIgnore",
			aesEnabled: false,
			buildEvent: func() string {
				event := InsEvent{
					EventType: "unknown_event",
					Data:      json.RawMessage(`{}`),
				}
				data, err := json.Marshal(event)
				if err != nil {
					return err.Error()
				}
				return string(data)
			},
			setup:        func(ins *instance) {},
			wantReqNum:   0,
			wantReqSize:  0,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 初始化实例管理器
			insMgr := newInstanceManager()

			// 创建测试实例
			ins, _ := newInstance(
				"http://test-instance",
				base.PrefillRoleInstance,
				"",
				make(chan *ControlMessage, 1),
				insMgr,
			)

			// 执行前置操作
			tt.setup(ins)

			// 构建事件数据
			eventData := tt.buildEvent()

			// 执行处理方法
			ins.processInsData(eventData)

			// 验证结果
			if len(ins.reqSet) != tt.wantReqSize {
				t.Errorf("reqSet size got = %d, want %d", len(ins.reqSet), tt.wantReqSize)
			}
			if ins.reqNum != tt.wantReqNum {
				t.Errorf("reqNum got = %d, want %d", ins.reqNum, tt.wantReqNum)
			}
		})
	}
}

// 测试正常删除存在的请求
func TestDelReq_NormalCase(t *testing.T) {
	// 初始化实例，角色为mixed
	ins := &instance{
		reqSet:     make(map[string]*LlmRequest),
		reqQueue:   newRequestQueue(),
		preloadMap: make(map[string]int),
		insRole:    base.DecodeRoleInstance, // 测试decode角色下的preload处理
		rwLock:     sync.RWMutex{},
	}

	// 添加一个请求
	req := &LlmRequest{
		ReqId:         "req1",
		PredictTokens: 100,
		PredictBlocks: 5,
	}
	ins.reqSet[req.ReqId] = req
	ins.reqNum = 1
	ins.tokenNum = 100
	ins.preloadMap[req.ReqId] = 5
	ins.preBlocks = 5

	// 删除请求
	ins.delReq(req, false)

	// 验证请求是否被删除
	assert.NotContains(t, ins.reqSet, req.ReqId)
	assert.Equal(t, 0, ins.reqNum)
	assert.Equal(t, 0, ins.tokenNum)
	assert.Equal(t, 0, ins.preBlocks)
	assert.NotContains(t, ins.preloadMap, req.ReqId)
}

// 测试删除不存在的请求
func TestDelReq_NonExistentRequest(t *testing.T) {
	ins := &instance{
		reqSet:     make(map[string]*LlmRequest),
		reqQueue:   newRequestQueue(),
		preloadMap: make(map[string]int),
		rwLock:     sync.RWMutex{},
	}

	// 删除一个不存在的请求
	req, err := NewLlmRequest("testID", "test_prompt")
	if err != nil {
		t.Errorf("%v", err.Error())
	}
	ins.delReq(req, false)

	// 验证状态未变化
	assert.Empty(t, ins.reqSet)
	assert.Equal(t, 0, ins.reqNum)
	assert.Equal(t, 0, ins.tokenNum)
}

// 测试decodeInstance角色下的删除操作
func TestDelReq_DecodeInstanceRole(t *testing.T) {
	ins := &instance{
		reqSet:     make(map[string]*LlmRequest),
		reqQueue:   newRequestQueue(),
		preloadMap: make(map[string]int),
		insRole:    base.DecodeRoleInstance,
		rwLock:     sync.RWMutex{},
	}

	// 添加请求到decode实例
	req := &LlmRequest{
		ReqId:         "req1",
		PredictTokens: 50,
		PredictBlocks: 3,
	}
	ins.reqSet[req.ReqId] = req
	ins.reqNum = 1
	ins.tokenNum = 50
	ins.preloadMap[req.ReqId] = 3
	ins.preBlocks = 3

	ins.delReq(req, false)

	// 验证preload相关字段
	assert.Equal(t, 0, ins.preBlocks)
	assert.NotContains(t, ins.preloadMap, req.ReqId)
}

// TestNewRequestQueue test create a reqeustQueue
func TestNewRequestQueue(t *testing.T) {
	queue := newRequestQueue()

	if queue.reqList == nil {
		t.Error("Expected reqList to be initialized, got nil")
	}
	if queue.reqMap == nil {
		t.Error("Expected reqMap to be initialized, got nil")
	}
	if queue.len() != 0 {
		t.Errorf("Expected initial length to be 0, got %d", queue.len())
	}
}

// TestRequestQueue_Enqueue test req enqueue
func TestRequestQueue_Enqueue(t *testing.T) {
	queue := newRequestQueue()

	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: 1000}
	queue.enqueue(req1)

	if queue.len() != 1 {
		t.Errorf("Expected length after enqueue to be 1, got %d", queue.len())
	}

	frontReq := queue.getHeadReq()

	if frontReq.ReqId != "req1" {
		t.Errorf("Expected front request ID to be 'req1', got %s", frontReq.ReqId)
	}
}

// TestRequestQueue_Dequeue test dequeue end request
func TestRequestQueue_DequeueTail(t *testing.T) {
	queue := newRequestQueue()

	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: 1000}
	req2 := &LlmRequest{ReqId: "req2", PrefillTimeStampMs: 2000}
	queue.enqueue(req1)
	queue.enqueue(req2)

	// test deque second queue
	queue.dequeue("req2")

	if queue.len() != 1 {
		t.Errorf("Expected length after dequeueing tail to be 1, got %d", queue.len())
	}

	frontReq := queue.getHeadReq()
	if frontReq.ReqId != "req1" {
		t.Errorf("Expected front request ID to be 'req1', got %s", frontReq.ReqId)
	}
}

// TestRequestQueue_DequeueHead test dequeue head request
func TestRequestQueue_DequeueHead(t *testing.T) {
	queue := newRequestQueue()

	originalTime := time.Now().UnixMilli()
	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: originalTime}
	req2 := &LlmRequest{ReqId: "req2", PrefillTimeStampMs: originalTime}
	queue.enqueue(req1)
	queue.enqueue(req2)

	// wait for a while
	time.Sleep(10 * time.Millisecond)

	// dequeue head request req1 , this will cause updating timestamps
	queue.dequeue("req1")

	if queue.len() != 1 {
		t.Errorf("Expected length after dequeueing head to be 1, got %d", queue.len())
	}

	frontReq := queue.getHeadReq()
	if frontReq == nil {
		t.Error("Expected to get front element after dequeueing head")
	}
	if frontReq.ReqId != "req2" {
		t.Errorf("Expected front request ID to be 'req2', got %s", frontReq.ReqId)
	}
	// Verify that the timestamp of the new head was updated
	if frontReq.PrefillTimeStampMs <= originalTime {
		t.Errorf("Expected new head's prefillTimeStampMs to be updated (>%d), got %d",
			originalTime, frontReq.PrefillTimeStampMs)
	}
}

// TestRequestQueue_DequeueNonExistent test delete non-exist element
func TestRequestQueue_DequeueNonExistent(t *testing.T) {
	queue := newRequestQueue()

	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: 1000}
	queue.enqueue(req1)

	originalLength := queue.len()

	// try dequeue non-exist request
	queue.dequeue("non_existent")

	if queue.len() != originalLength {
		t.Errorf("Expected length to remain unchanged after deleting non-existent item, got %d", queue.len())
	}

}

// TestRequestQueue_Len test length method
func TestRequestQueue_Len(t *testing.T) {
	queue := newRequestQueue()

	if queue.len() != 0 {
		t.Errorf("Expected initial length to be 0, got %d", queue.len())
	}

	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: 1000}
	queue.enqueue(req1)

	if queue.len() != 1 {
		t.Errorf("Expected length after first enqueue to be 1, got %d", queue.len())
	}

	req2 := &LlmRequest{ReqId: "req2", PrefillTimeStampMs: 2000}
	queue.enqueue(req2)

	if queue.len() != 2 {
		t.Errorf("Expected length after second enqueue to be 2, got %d", queue.len())
	}

	queue.dequeue("req1")

	if queue.len() != 1 {
		t.Errorf("Expected length after first dequeue to be 1, got %d", queue.len())
	}

	queue.dequeue("req2")

	if queue.len() != 0 {
		t.Errorf("Expected length after last dequeue to be 0, got %d", queue.len())
	}
}

// TestRequestQueue_GetHeadReq test get head request
func TestRequestQueue_GetHeadReq(t *testing.T) {
	queue := newRequestQueue()

	// test empty requeue
	head := queue.getHeadReq()
	if head != nil {
		t.Error("Expected getHeadReq() on empty queue to return false")
	}

	req1 := &LlmRequest{ReqId: "req1", PrefillTimeStampMs: 1000}
	req2 := &LlmRequest{ReqId: "req2", PrefillTimeStampMs: 2000}
	queue.enqueue(req1)
	queue.enqueue(req2)

	frontReq := queue.getHeadReq()
	if frontReq == nil {
		t.Error("Expected getHeadReq() on non-empty queue to return true")
	}
	if frontReq.ReqId != "req1" {
		t.Errorf("Expected front request ID to be 'req1', got %s", frontReq.ReqId)
	}

	// 队头元素不应被取出
	if queue.len() != 2 {
		t.Errorf("Expected length to remain 2 after getHeadReq(), got %d", queue.len())
	}

	// 删除队头后，getHeadReq() 应该返回新的队头
	queue.dequeue("req1")
	frontReq = queue.getHeadReq()
	if frontReq == nil {
		t.Error("Expected getHeadReq() after head removal to return true")
	}
	if frontReq.ReqId != "req2" {
		t.Errorf("Expected new front request ID to be 'req2', got %s", frontReq.ReqId)
	}
}

// TestRequestQueueMultipleOperations test multiple operations
func TestRequestQueueMultipleOperations(t *testing.T) {
	queue := newRequestQueue()

	for i := 0; i < 5; i++ {
		req := &LlmRequest{ReqId: "req" + string(rune('0'+i)), PrefillTimeStampMs: int64(i)}
		queue.enqueue(req)
	}

	if queue.len() != 5 {
		t.Fatalf("Expected length 5 after enqueuing 5 items, got %d", queue.len())
	}

	// check head requeue
	front := queue.getHeadReq()
	if front == nil || front.ReqId != "req0" {
		t.Errorf("Expected front to be 'req0', got %s", front.ReqId)
	}

	// 连续出队
	for i := 0; i < 5; i++ {
		idToDequeue := "req" + string(rune('0'+i))
		queue.dequeue(idToDequeue)

		expectedLen := 5 - i - 1
		if queue.len() != expectedLen {
			t.Errorf("Expected length %d after dequeuing '%s', got %d", expectedLen, idToDequeue, queue.len())
		}

		if expectedLen > 0 {
			front = queue.getHeadReq()
			if front == nil {
				t.Errorf("Expected front to exist when len is %d", expectedLen)
			}
			expectedFrontID := "req" + string(rune('0'+i+1))
			if front.ReqId != expectedFrontID {
				t.Errorf("Expected front to be '%s', got %s", expectedFrontID, front.ReqId)
			}
		}
	}

	if queue.len() != 0 {
		t.Errorf("Expected final len to be 0, got %d", queue.len())
	}
}
