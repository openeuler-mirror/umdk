/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: instance manager extended test
 * Create: 2026-03-31
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"testing"
	"time"

	"huawei.com/aigw/internal/base"
)

func TestPredictTokensByEMAExt(t *testing.T) {
	insManager := newInstanceManager()

	// Test when EMA prediction exists
	insManager.emaRWLock.Lock()
	insManager.emaPredictLen[ReqTypeShort] = 100
	insManager.emaRWLock.Unlock()

	req := &LlmRequest{
		ReqId:     "test-req",
		Prompt:    "test prompt",
		ReqType:   ReqTypeShort,
		PromptLen: 50,
	}

	result := insManager.predictTokensByEMA(req)
	if result != 150 {
		t.Errorf("Expected 150, got %d", result)
	}

	// Test when EMA prediction does not exist
	req2 := &LlmRequest{
		ReqId:     "test-req-2",
		Prompt:    "test prompt",
		ReqType:   ReqTypeUltraLong,
		PromptLen: 5000,
	}

	result2 := insManager.predictTokensByEMA(req2)
	if result2 != 5000 {
		t.Errorf("Expected 5000, got %d", result2)
	}
}

func TestIsReqExistsExt(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add an instance with a request
	ins := &instance{
		insUrl:   "http://test-instance",
		reqSet:   make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(),
	}
	ins.reqSet["existing-req"] = &LlmRequest{
		ReqId: "existing-req",
	}
	insManager.insPool["http://test-instance"] = ins

	// Test existing request
	if !insManager.isReqExists("existing-req") {
		t.Error("Expected request to exist")
	}

	// Test non-existing request
	if insManager.isReqExists("non-existing-req") {
		t.Error("Expected request to not exist")
	}
}

func TestGetInsNumExt(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Initially empty
	if insManager.getInsNum() != 0 {
		t.Errorf("Expected 0, got %d", insManager.getInsNum())
	}

	// Add instances
	insManager.insPool["ins1"] = &instance{insUrl: "ins1"}
	insManager.insPool["ins2"] = &instance{insUrl: "ins2"}

	if insManager.getInsNum() != 2 {
		t.Errorf("Expected 2, got %d", insManager.getInsNum())
	}
}

func TestCheckReqSurvivalExt(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insPool = make(map[string]*instance)

	// Add an instance with an old request
	oldReq := &LlmRequest{
		ReqId:     "old-req",
		TimeStamp: time.Now().Add(-20 * time.Second).UnixMilli(),
	}
	ins := &instance{
		insUrl:   "http://test-instance",
		reqSet:   make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(),
	}
	ins.reqSet["old-req"] = oldReq
	insManager.insPool["http://test-instance"] = ins

	// Check with 10 second timeout
	insManager.checkReqSurvival(10 * time.Second)

	// Request should be deleted
	ins.rwLock.RLock()
	_, exists := ins.reqSet["old-req"]
	ins.rwLock.RUnlock()
	if exists {
		t.Error("Expected old request to be deleted")
	}
}

func TestSnapshotThrottlingExt(t *testing.T) {
	insManager := newInstanceManager()

	// Test snapshot update interval
	if insManager.insSnapShotFreq != time.Duration(defaultFreq)*time.Second {
		t.Errorf("Expected %v, got %v", time.Duration(defaultFreq)*time.Second, insManager.insSnapShotFreq)
	}

	// Test that snapshot update works
	insManager.updatePoolShot()
	if len(insManager.insSnapshots) != 0 {
		t.Errorf("Expected 0 snapshots, got %d", len(insManager.insSnapshots))
	}
}

func TestUpdateEmaPredictLenExt(t *testing.T) {
	insManager := newInstanceManager()

	// Test update
	insManager.updateEmaPredictLen(ReqTypeShort, 150)

	insManager.emaRWLock.RLock()
	defer insManager.emaRWLock.RUnlock()
	if insManager.emaPredictLen[ReqTypeShort] != 150 {
		t.Errorf("Expected 150, got %d", insManager.emaPredictLen[ReqTypeShort])
	}
}

func TestToInstanceRoleExt(t *testing.T) {
	tests := []struct {
		input    string
		expected base.InstanceRole
		wantErr  bool
	}{
		{"mixed", base.MixedRoleInstance, false},
		{"prefill", base.PrefillRoleInstance, false},
		{"decode", base.DecodeRoleInstance, false},
		{"invalid", base.InvalidRoleInstance, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			role, err := base.ToInstanceRole(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToInstanceRole() error = %v, wantErr %v", err, tt.wantErr)
			}
			if role != tt.expected {
				t.Errorf("ToInstanceRole() = %v, want %v", role, tt.expected)
			}
		})
	}
}
