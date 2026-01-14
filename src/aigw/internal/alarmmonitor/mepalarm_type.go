/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package monitor provides the management monitor client for AIGW.
 * Create: 2025-08-1
 */

// Package alarmmonitor provides the management monitor client for AIGW.
package alarmmonitor

import (
	"encoding/json"
)

const (
	mepAlarmRecoverModeAuto   = "AUTO"   // Mep alarm auto recover
	mepAlarmRecoverModeManual = "MANUAL" // Mep alarm manual recover
)

const (
	mepAlarmLevelFatal    = "FATAL"
	mepAlarmLevelCritical = "CRITICAL"
	mepAlarmLevelWarn     = "WARN"
	mepAlarmLevelNormal   = "NORMAL"
	mepAlarmLevelSuggest  = "SUGGEST"
	mepAlarmLevelNotify   = "NOTIFY"
	mepAlarmLevelClear    = "CLEAR"
)
const (
	mepAlarmReportModeRepeat   = "REPEAT"
	mepAlarmReportModeUnique   = "UNIQUE"
	mepAlarmReportModeOverride = "OVERRIDE"
)

// AlarmMsg is the Mep format alarm msg
type AlarmMsg struct {
	AlarmType   string `json:"alarmType"`   // MEP alarm type
	Source      string `json:"source"`      // MEP alarm source
	AlarmTarget string `json:"alarmTarget"` // MEP alarm source details
	BusinessId  string `json:"businessId"`  // MEP tenet Id
	Level       string `json:"level"`       // MEP alarm level
	Content     string `json:"content"`     // MEP alarm content
	Dimension   string `json:"dimension"`   // Invalid field
	Mode        string `json:"mode"`        // MEP alarm report mode: REPEAT;UNIQUE;OVERRIDE
	RecoverMode string `json:"recoverMode"` // MEP alarm recover mode
	ReportIP    string `json:"reportIP"`    // MEP alarm source's host ip
}

// MepAlarmData is the Mep format alarm data
type MepAlarmData struct {
	Alarms []AlarmMsg `json:"alarms"`
}

// MepAlarm is the Mep format alarm
type MepAlarm struct {
	Version string       `json:"version"`
	Data    MepAlarmData `json:"data"`
}

// String return the json format string of MepAlarm
func (a *MepAlarm) String() string {
	jsonStr, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return string(jsonStr)
}
