/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatcher test
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"context"
	"testing"
	"time"
)

func TestNewGlobalScheduleDispatcher(t *testing.T) {
	ctx := context.Background()
	dispatcher := newGlobalScheduleDispatcher(ctx)

	if dispatcher == nil {
		t.Error("newGlobalScheduleDispatcher returned nil")
	}

	if dispatcher.dispatchChan == nil {
		t.Error("dispatchChan is nil")
	}

	if dispatcher.wg == nil {
		t.Error("wg is nil")
	}
}

func TestGlobalScheduleDispatcherStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher := newGlobalScheduleDispatcher(ctx)
	dispatcher.start()

	// Give some time for the dispatcher to start
	time.Sleep(10 * time.Millisecond)

	dispatcher.stop()
}

func TestGlobalScheduleDispatcherExecuteDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher := newGlobalScheduleDispatcher(ctx)
	dispatcher.start()
	defer dispatcher.stop()

	// Test with nil result
	response := make(chan interface{}, 1)
	msg := &ControlMessage{
		Request:  &ExecuteDispatchMsg{Result: nil},
		Response: response,
	}
	dispatcher.dispatchChan <- msg

	select {
	case result := <-response:
		if result == nil {
			t.Error("Expected non-nil result")
		}
		resultMsg, ok := result.(*SuggestionResultMsg)
		if !ok {
			t.Errorf("Expected SuggestionResultMsg, got %T", result)
		}
		if resultMsg.PrefillUrl != "" {
			t.Error("Expected empty prefill URL for nil result")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for response")
	}
}

func TestGlobalScheduleDispatcherExecuteDispatchingWithResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher := newGlobalScheduleDispatcher(ctx)
	dispatcher.start()
	defer dispatcher.stop()

	// Test with valid result
	response := make(chan interface{}, 1)
	result := &ScheduleResult{
		PrefillUrl: "http://instance1",
		DecodeUrl:  "http://instance2",
	}
	msg := &ControlMessage{
		Request:  &ExecuteDispatchMsg{Result: result},
		Response: response,
	}
	dispatcher.dispatchChan <- msg

	select {
	case res := <-response:
		resultMsg, ok := res.(*SuggestionResultMsg)
		if !ok {
			t.Errorf("Expected SuggestionResultMsg, got %T", res)
		}
		if resultMsg.PrefillUrl != "http://instance1" {
			t.Errorf("Expected prefill URL http://instance1, got %s", resultMsg.PrefillUrl)
		}
		if resultMsg.DecodeUrl != "http://instance2" {
			t.Errorf("Expected decode URL http://instance2, got %s", resultMsg.DecodeUrl)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for response")
	}
}

func TestDispatchTypeValues(t *testing.T) {
	tests := []struct {
		dt       DispatchType
		expected int
	}{
		{DispatchRequest, 0},
		{DispatchMigration, 1},
		{DispatchKvcCopy, 2},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := int(tt.dt)
			if result != tt.expected {
				t.Errorf("DispatchType = %v, want %v", result, tt.expected)
			}
		})
	}
}