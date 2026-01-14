/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log main file
 * Create: 2025-08-1
 */

// Package log use for init alarm logger format
package log

import (
	"fmt"
	"path"

	"github.com/sirupsen/logrus"
)

const alarmCallDepth = 4

// AlarmBlocking is the log blocking alarm
const AlarmBlocking = "AlarmBlocking"

// ZooKeeper related alarm
const (
	ZKConnectionTimeout  = "ZKConnectionTimeout"  // zk connection timeout
	ZKPathCreationFailed = "ZKPathCreationFailed" // zk create path failed
	ZKPathNotExist       = "ZKPathNotExist"       // zk path is not exist
	ZKDisconnected       = "ZKDisconnected"       // zk session is expired
)

// Instance related alarm
const (
	InstanceConnTimeout   = "InstanceConnTimeout"   // Instance connection timeout
	InstanceReconnTimeout = "InstanceReconnTimeout" // Instance reconnection timeout
)

// Datasync related alarm
const (
	DataSyncFetchFailed = "DataSyncFetchFailed" // Fetch model info from dataSync failed
)

// Specification limit related alert
const (
	GlobalGSInstancesLimitExceeded         = "GlobalGSInstancesLimitExceeded"
	PerGSInstanceLimitExceeded             = "PerGSInstanceLimitExceeded"
	DataSyncModelRegistrationLimitExceeded = "DataSyncModelRegistrationLimitExceeded"
)

const (
	alarmFormat = "Service:Aigw,AlarmType:%v,AlarmAction:%v,AlarmInfo:%v"
)

const (
	// Report alarm
	Report = "report"
	// Clear alarm
	Clear = "clear"
)

func alarmMsgf(logFunc func(format string, args ...interface{}), alarmType, alarmAction, alarmContent string) {
	logFunc(alarmContent)
	msg := fmt.Sprintf(alarmFormat, alarmType, alarmAction, alarmContent)

	if loggerM.alarmCbFunc != nil {
		alarmLogEntry := &AlarmLogEntry{
			AlarmType:   alarmType,
			Service:     "AIGW",
			AlarmAction: alarmAction,
			Content:     alarmContent,
		}
		loggerM.alarmCbFunc(alarmLogEntry)
	}
	loggerM.processAlarmEntry(msg)
}

// WarnAlarmMsgf outputs logger alarm msg at warning level
func WarnAlarmMsgf(alarmType, alarmAction, alarmContent string) {
	e := Warn()
	e.callDepth = alarmCallDepth
	alarmMsgf(e.Msgf, alarmType, alarmAction, alarmContent)
}

// ErrorAlarmMsgf outputs logger alarm msg at error level
func ErrorAlarmMsgf(alarmType, alarmAction, alarmContent string) {
	e := Error()
	e.callDepth = alarmCallDepth
	alarmMsgf(e.Msgf, alarmType, alarmAction, alarmContent)
}

func newAlarmLogger(formatter *Formatter) {
	alarmLogger = &logrus.Logger{
		Formatter: formatter,
		Out: &RotateWriter{
			Filename:   path.Join(config.Directory, alarmFile),
			MaxSize:    defaultAlarmSize,
			MaxBackups: defaultAlarmBackUps,
		},
		Level: WarnLevel,
	}
	alarmLogger.SetNoLock()
}

// SetAlarmLogCb Sets the callback function for handling alarm log events.
func SetAlarmLogCb(cb alarmCbFunc) {
	loggerM.alarmCbFunc = cb
}
