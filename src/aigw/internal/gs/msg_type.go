/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: definitions for messages of GS manager.
 * Create: 2025-06-06
 */

// Package gs is the global scheduler for gateway.
package gs

// ControlMessage is base struct for control plane message.
type ControlMessage struct {
	Request  interface{}
	Response chan<- interface{}
}

// RegisterInstanceMsg is the message used for registering new instance.
type RegisterInstanceMsg struct {
	Name    string
	Model   string
	IP      string
	Port    string
	Role    string
	GroupID string
}

// UnregisterInstanceMsg is the message used for unregistering instance.
type UnregisterInstanceMsg struct {
	Model string
	IP    string
	Port  string
}

// ScheduleRequestMsg is used to issue schedule request.
type ScheduleRequestMsg struct {
	Request *LlmRequest
}

// ExecuteDispatchMsg is used for dispatching schedule request.
type ExecuteDispatchMsg struct {
	Result *scheduleResult
}

// SuggestionResultMsg is the message return to caller.
type SuggestionResultMsg struct {
	PrefillUrl string
	DecodeUrl  string
}
