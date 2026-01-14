/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: inference instance management.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"encoding/json"
	"fmt"

	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

// InsEvent eventType can be metric、reqStatus
type InsEvent struct {
	EventType string          `json:"eventType"`
	Data      json.RawMessage `json:"data"`
}

// MetricData metric数据结构
type MetricData struct {
	TotalBlocks    int     `json:"totalKvBlocks"`
	FreeBlocks     int     `json:"freeKvBlocks"`
	TTFT           float64 `json:"timeToFirstToken"`
	TBT            float64 `json:"timeBetweenTokens"`
	QueueLength    int     `json:"queueLength"`
	AvgWaitingTime float64 `json:"avgWaitingTime"`
}

// ReqStatusData 请求状态数据结构
type ReqStatusData struct {
	Event        string `json:"event"`
	ReqId        string `json:"requestId"`
	DecodeLen    int    `json:"decodeLen"`
	PromptTokens []int  `json:"promptTokens"`
}

// CheckMetricData Check Metric Data
func CheckMetricData(data MetricData) error {
	if data.TotalBlocks <= 0 {
		log.Error().Msgf("[CheckMetricData]TotalBlocks %v should bigger than 0.", data.TotalBlocks)
		return fmt.Errorf("[CheckMetricData]TotalBlocks %v should bigger than 0", data.TotalBlocks)
	}
	if data.FreeBlocks < 0 {
		log.Error().Msgf("[CheckMetricData]FreeBlocks %v is less than 0.", data.FreeBlocks)
		return fmt.Errorf("[CheckMetricData]FreeBlocks %v is less than 0", data.FreeBlocks)
	}
	if data.TTFT < 0 {
		log.Error().Msgf("[CheckMetricData]TTFT %v is less than 0.", data.TTFT)
		return fmt.Errorf("[CheckMetricData]TTFT %v is less than 0", data.TTFT)
	}
	if data.TBT < 0 {
		log.Error().Msgf("[CheckMetricData]TBT %v is less than 0.", data.TBT)
		return fmt.Errorf("[CheckMetricData]TBT %v is less than 0", data.TBT)
	}
	if data.QueueLength < 0 {
		log.Error().Msgf("[CheckMetricData]QueueLength %v is less than 0.", data.QueueLength)
		return fmt.Errorf("[CheckMetricData]QueueLength %v is less than 0", data.QueueLength)
	}
	if data.AvgWaitingTime < 0 {
		log.Error().Msgf("[CheckMetricData]AvgWaitingTime %v is less than 0.", data.AvgWaitingTime)
		return fmt.Errorf("[CheckMetricData]AvgWaitingTime %v is less than 0", data.AvgWaitingTime)
	}
	if data.FreeBlocks > data.TotalBlocks {
		log.Error().Msgf("[CheckMetricData]TotalBlocks %v should bigger than FreeBlocks %v.",
			data.TotalBlocks, data.FreeBlocks)
		return fmt.Errorf("[CheckMetricData]TotalBlocks %v should bigger than FreeBlocks %v",
			data.TotalBlocks, data.FreeBlocks)
	}
	return nil
}

// CheckReqStatusData Check ReqStatus Data
func CheckReqStatusData(data ReqStatusData) error {
	err := utils.CheckStringLength(data.ReqId)
	if err != nil {
		log.Error().Msgf("[CheckReqStatusData]The length of ReqId is invalid.%v", err)
		return fmt.Errorf("[CheckReqStatusData]The length of ReqId is invalid.%v", err)
	}
	err = utils.CheckStringLength(data.Event)
	if err != nil {
		log.Error().Msgf("[CheckReqStatusData]The length of Req.Event is invalid.%v", err)
		return fmt.Errorf("[CheckReqStatusData]The length of Req.Event is invalid.%v", err)
	}
	if data.DecodeLen < 0 {
		log.Error().Msgf("[CheckReqStatusData]The length of decodelen %v is less than 0.", data.DecodeLen)
		return fmt.Errorf("[CheckReqStatusData]The length of decodelen %v is less than 0", data.DecodeLen)
	}
	if data.PromptTokens != nil && len(data.PromptTokens) > utils.MaxMessageLength {
		log.Error().Msgf("[CheckReqStatusData]The length of promptToken %v is too long.", len(data.PromptTokens))
		return fmt.Errorf("[CheckReqStatusData]The length of promptToken %v is too long", len(data.PromptTokens))
	}
	return nil
}
