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
	"sync/atomic"
)

// StatType means the stat type of aigw in dataplane
//
//go:generate stringer -type StatType
type StatType int

// Stat type
const (
	// ScheduleSuccess indicates successful scheduling.
	ScheduleSuccess StatType = iota
	// ScheduleFailure indicates failed scheduling.
	ScheduleFailure
	// TokenizerEncodeError indicates tokenizer encoding failures, which may be the cause of scheduling failure.
	TokenizerEncodeError
	// LightGbmVectorizeError indicates lightgbm vectorize failures, which may be the cause of scheduling failure.
	LightGbmVectorizeError
	// LightGbmPredictError indicates lightgbm predicting failures, which may be the cause of scheduling failure.
	LightGbmPredictError
	// CapacityLbInsufficientFreeBlocks indicates all instances lack sufficient free blocks under CapacityL LB strategy,
	// which may be the cause of scheduling failure.
	CapacityLbInsufficientFreeBlocks
	// CapacityLbLatencyOverLimit indicates all instances' latency metrics(ttft or tbt) exceed the threshold
	// under Capacity LB strategy, which may be the cause of scheduling failure.
	CapacityLbLatencyOverLimit
	// TokenLbLatencyOverLimit indicates all instances' latency metrics(ttft or tbt) exceed the threshold
	// under Token Lb strategy, which may be the cause of scheduling failure.
	TokenLbLatencyOverLimit
	// LbNoInstances indicates there is no instances registered
	LbNoInstances
	TypeCount
)

// DataPlaneStats means the stat of global scheduler in dataplane
type DataPlaneStats struct {
	Counts [TypeCount]uint64
}

// NewDataPlaneStats returns a new stats instance
func NewDataPlaneStats() *DataPlaneStats {
	return &DataPlaneStats{}
}

// Record means incrementing the corresponding stats-type counter by one.
func (s *DataPlaneStats) Record(statsType StatType) {
	if statsType >= 0 && int(statsType) < len(s.Counts) {
		atomic.AddUint64(&s.Counts[statsType], 1)
	}
}

// GetStatsMap returns a map of stats that maps each type to its count.
func (s *DataPlaneStats) GetStatsMap() map[string]uint64 {
	stats := make(map[string]uint64)
	for i, count := range s.Counts {
		name := fmt.Sprintf("%s", StatType(i).String())
		stats[name] = atomic.LoadUint64(&count)
	}
	return stats
}
