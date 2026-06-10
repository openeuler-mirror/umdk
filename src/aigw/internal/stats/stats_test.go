/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: definitions of types for AIGW core.
 * Create: 2025-08-01
 */

// Package stats contains the core functions for Aigw's stats.
package stats

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestNewStats(t *testing.T) {
	stats := NewDataPlaneStats()
	if stats == nil {
		t.Error("NewDataPlaneStats return nil")
	}
	if len(stats.Counts) != int(TypeCount) {
		t.Errorf("the length of counts should be %v, but get %v", TypeCount, len(stats.Counts))
	}
	for i := 0; i < int(TypeCount); i++ {
		if stats.Counts[i] != 0 {
			t.Errorf("counts[%v] expected 0, got %v", i, stats.Counts[i])
		}
	}
}

func TestRecord(t *testing.T) {
	tests := []struct {
		name        string
		statsType   StatType
		initial     uint64
		expected    uint64
		expectError bool
	}{
		{
			name:        "recordScheduleSuccess",
			statsType:   ScheduleSuccess,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "recordScheduleFailure",
			statsType:   ScheduleFailure,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "TokenizerEncodeError",
			statsType:   TokenizerEncodeError,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "LightGbmVectorizeError",
			statsType:   LightGbmVectorizeError,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "LightGbmPredictError",
			statsType:   LightGbmPredictError,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "CapacityLbInsufficientFreeBlocks",
			statsType:   CapacityLbInsufficientFreeBlocks,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "CapacityLbLatencyOverLimit",
			statsType:   CapacityLbLatencyOverLimit,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "TokenLbLatencyOverLimit",
			statsType:   TokenLbLatencyOverLimit,
			initial:     0,
			expected:    1,
			expectError: false,
		},
		{
			name:        "InvalidStatType",
			statsType:   TypeCount,
			initial:     0,
			expected:    0,
			expectError: true,
		},
		{
			name:        "InvalidStatType-1",
			statsType:   -1,
			initial:     0,
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewDataPlaneStats()
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectError {
						t.Errorf("expected no panic, but got one")
					}
				} else if tt.expectError {
					t.Errorf("expected panic, but none occurred")
				}
			}()
			stats.Record(tt.statsType)
			actual := atomic.LoadUint64(&stats.Counts[tt.statsType])
			if actual != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}

func TestGetStatsMap(t *testing.T) {
	tests := []struct {
		name     string
		records  []StatType
		expected map[string]uint64
	}{
		{
			name:    "noRecords",
			records: []StatType{},
			expected: map[string]uint64{
				"ScheduleSuccess":                  0,
				"ScheduleFailure":                  0,
				"TokenizerEncodeError":             0,
				"LightGbmVectorizeError":           0,
				"LightGbmPredictError":             0,
				"CapacityLbInsufficientFreeBlocks": 0,
				"CapacityLbLatencyOverLimit":       0,
				"TokenLbLatencyOverLimit":          0,
				"LbNoInstances":                    0,
			},
		},
		{
			name: "withRecords",
			records: []StatType{ScheduleSuccess, ScheduleFailure,
				CapacityLbLatencyOverLimit, ScheduleSuccess,
				CapacityLbInsufficientFreeBlocks, LightGbmPredictError,
				LightGbmVectorizeError, TokenizerEncodeError,
				TokenLbLatencyOverLimit, LbNoInstances},
			expected: map[string]uint64{
				"ScheduleSuccess":                  2,
				"ScheduleFailure":                  1,
				"TokenizerEncodeError":             1,
				"LightGbmVectorizeError":           1,
				"LightGbmPredictError":             1,
				"CapacityLbInsufficientFreeBlocks": 1,
				"CapacityLbLatencyOverLimit":       1,
				"TokenLbLatencyOverLimit":          1,
				"LbNoInstances":                    1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewDataPlaneStats()
			for _, st := range tt.records {
				stats.Record(st)
			}
			result := stats.GetStatsMap()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestStatTypeString test StatType's String method
func TestStatTypeString(t *testing.T) {
	testCases := []struct {
		statType StatType
		expected string
	}{
		{ScheduleSuccess, "ScheduleSuccess"},
		{ScheduleFailure, "ScheduleFailure"},
		{TokenizerEncodeError, "TokenizerEncodeError"},
		{LightGbmVectorizeError, "LightGbmVectorizeError"},
		{LightGbmPredictError, "LightGbmPredictError"},
		{CapacityLbInsufficientFreeBlocks, "CapacityLbInsufficientFreeBlocks"},
		{CapacityLbLatencyOverLimit, "CapacityLbLatencyOverLimit"},
		{TokenLbLatencyOverLimit, "TokenLbLatencyOverLimit"},
		{LbNoInstances, "LbNoInstances"},
		{TypeCount, "TypeCount"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("StatType%d", tc.statType), func(t *testing.T) {
			result := tc.statType.String()
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}

	// test invalid StatType method
	invalidCount := 100
	invalidStatType := StatType(invalidCount)
	expectedInvalid := "StatType(100)"
	resultInvalid := invalidStatType.String()
	if resultInvalid != expectedInvalid {
		t.Errorf("Expected %q, got %q", expectedInvalid, resultInvalid)
	}
}
