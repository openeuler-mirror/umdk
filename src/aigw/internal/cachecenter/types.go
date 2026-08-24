/*
 * SPDX-License-Identifier: MIT
 * Copyright (i) Huawei Technologies Co., Ltd. 2025-2026 All rights reserved.
 * Description: define the functions of central cache.
 * Create: 2026-01-20
 */

// Package cachecenter provides base type of cachecenter for AIGW.
package cachecenter

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
)

// Task types
const (
	TaskAddRequest    = "ADD"
	TaskDeleteRequest = "DELETE"
	TaskUpdateRequest = "UPDATE"
)

// RequestInfo holds metadata for a single request
type RequestInfo struct {
	ReqId              string  `json:"-"`
	PrefillInstance    string  `json:"pi"`
	DecodeInstance     string  `json:"di"`
	IsPrefill          bool    `json:"isp"`
	PromptTokenLen     int     `json:"ptl"`
	DecodeTokenLen     int     `json:"dtl"`
	PredictPrefillTime float64 `json:"ppt"`
	PrefillStartTimeMs int64   `json:"pst"`
	TimeStamp          int64   `json:"ts"`
	GroupID            string  `json:"gp"`
	// LastModifiedTime is used for incremental merge during cache rebuild.
	// When rebuilding local cache from Redis, requests with larger LastModifiedTime
	// are considered newer and will overwrite older ones. This prevents local updates
	// from being overwritten by stale Redis data when async write hasn't completed.
	LastModifiedTime int64 `json:"lmt,omitempty"`
}

func (r *RequestInfo) String() string {
	data, err := json.Marshal(struct {
		ReqId              string  `json:"reqId"`
		PrefillInstance    string  `json:"prefillInstance"`
		DecodeInstance     string  `json:"decodeInstance"`
		IsPrefill          bool    `json:"isPrefill"`
		PromptTokenLen     int     `json:"promptTokenLen"`
		DecodeTokenLen     int     `json:"decodeTokenLen"`
		PredictPrefillTime float64 `json:"predictPrefillTime"`
		PrefillStartTimeMs int64   `json:"prefillStartTimeMs"`
		TimeStamp          int64   `json:"timeStamp"`
		GroupID            string  `json:"groupId"`
	}{
		ReqId:              r.ReqId,
		PrefillInstance:    r.PrefillInstance,
		DecodeInstance:     r.DecodeInstance,
		IsPrefill:          r.IsPrefill,
		PromptTokenLen:     r.PromptTokenLen,
		DecodeTokenLen:     r.DecodeTokenLen,
		PredictPrefillTime: r.PredictPrefillTime,
		PrefillStartTimeMs: r.PrefillStartTimeMs,
		TimeStamp:          r.TimeStamp,
		GroupID:            r.GroupID,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

// StringWithoutId return a request's json string format without requestId
func (r *RequestInfo) StringWithoutId() string {
	data, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(data)
}

// InstanceMetrics holds metrics for a single instance
type InstanceMetrics struct {
	mu sync.RWMutex

	Role           base.InstanceRole `json:"role"`
	HeadReq        *RequestInfo      `json:"headReq,omitempty"`
	TokenLoad      int               `json:"tokenLoad"`
	QueueTime      float64           `json:"queueTime"`
	GroupID        string            `json:"groupId"`
	LastActiveTime time.Time         `json:"lastActiveTime"` // last active time, used for metric aging
}

// DeletedRequest records a recently deleted request for tombstone tracking.
// This prevents resurrected requests when local deletion hasn't synced to Redis yet.
type DeletedRequest struct {
	DeletedAt int64 // UnixNano timestamp when deleted
}

func (im *InstanceMetrics) updateMetric(cb func()) {
	im.mu.Lock()
	defer im.mu.Unlock()
	cb()
}

// Copy return a copy of instanceMetrics
func (im *InstanceMetrics) Copy() InstanceMetrics {
	im.mu.RLock()
	defer im.mu.RUnlock()

	var head *RequestInfo
	if im.HeadReq != nil {
		head = &RequestInfo{}
		*head = *im.HeadReq
	}

	return InstanceMetrics{
		Role:           im.Role,
		HeadReq:        head,
		TokenLoad:      im.TokenLoad,
		QueueTime:      im.QueueTime,
		GroupID:        im.GroupID,
		LastActiveTime: im.LastActiveTime,
	}
}

// String returns the JSON representation of InstanceMetrics.
func (im *InstanceMetrics) String() string {
	if im == nil {
		return "null"
	}
	data, err := json.Marshal(im)
	if err != nil {
		return "null"
	}
	return string(data)
}

// syncTask represents a task to sync with remote db
type syncTask struct {
	TaskType   string         `json:"taskType"`
	ModelName  string         `json:"modelName"`
	InstanceID string         `json:"instanceId"`
	Info       []*RequestInfo `json:"requests"`
}

// String returns the JSON string representation of syncTask.
func (st *syncTask) String() string {
	if st == nil {
		return "null"
	}
	baseJSON := fmt.Sprintf(`{"taskType":"%s","modelName":"%s","instanceId":"%s"}`,
		st.TaskType, st.ModelName, st.InstanceID)

	var requests []string
	for _, req := range st.Info {
		if req != nil {
			requests = append(requests, req.String())
		}
	}

	requestsStr := "[" + strings.Join(requests, ",") + "]"
	result := baseJSON[:len(baseJSON)-1] + `, "requests":` + requestsStr + "}"

	return result
}
