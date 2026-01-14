/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: alarm main file
 * Create: 2025-08-1
 */

// Package log use for init alarm logger format
package log

// AlarmLogEntry is AIGW's alarm entry
type AlarmLogEntry struct {
	AlarmType   string `json:"alarmType"`
	Service     string `json:"source"`
	AlarmAction string `json:"alarmAction"`
	Content     string `json:"content"`
}
