/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: inference instance management.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"huawei.com/aigw/pkg/utils"
	"testing"
)

// TestCheckMetricData 测试 CheckMetricData 函数
func TestCheckMetricData(t *testing.T) {
	tests := []struct {
		name    string
		data    MetricData
		wantErr bool
	}{
		{
			name: "valid metric data",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     50,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: false,
		},
		{
			name: "invalid total blocks <= 0",
			data: MetricData{
				TotalBlocks:    0,
				FreeBlocks:     50,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
		{
			name: "invalid free blocks < 0",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     -1,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
		{
			name: "invalid TTFT < 0",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     50,
				TTFT:           -1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
		{
			name: "invalid TBT < 0",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     50,
				TTFT:           0.1,
				TBT:            -1,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
		{
			name: "invalid queue length < 0",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     50,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    -1,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
		{
			name: "invalid avg waiting time < 0",
			data: MetricData{
				TotalBlocks:    100,
				FreeBlocks:     50,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid free blocks > total blocks",
			data: MetricData{
				TotalBlocks:    50,
				FreeBlocks:     100,
				TTFT:           0.1,
				TBT:            0.05,
				QueueLength:    10,
				AvgWaitingTime: 0.2,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckMetricData(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("CheckMetricData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckReqStatusData 测试 CheckReqStatusData 函数
func TestCheckReqStatusData(t *testing.T) {
	tests := []struct {
		name    string
		data    ReqStatusData
		wantErr bool
	}{
		{
			name: "valid req status data",
			data: ReqStatusData{
				Event:        "test_event",
				ReqId:        "test_request_id",
				DecodeLen:    100,
				PromptTokens: []int{1, 2, 3},
			},
			wantErr: false,
		},
		{
			name: "invalid req id length",
			data: ReqStatusData{
				Event:        "test_event",
				ReqId:        "",
				DecodeLen:    100,
				PromptTokens: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "invalid event length",
			data: ReqStatusData{
				Event:        "",
				ReqId:        "test_request_id",
				DecodeLen:    100,
				PromptTokens: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "invalid decode len < 0",
			data: ReqStatusData{
				Event:        "test_event",
				ReqId:        "test_request_id",
				DecodeLen:    -1,
				PromptTokens: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "invalid prompt tokens length",
			data: ReqStatusData{
				Event:        "test_event",
				ReqId:        "test_request_id",
				DecodeLen:    100,
				PromptTokens: make([]int, utils.MaxMessageLength+1),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckReqStatusData(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("CheckReqStatusData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
