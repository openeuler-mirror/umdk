/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log main file
 * Create: 2025-08-1
 */

// Package log use for init alarm logger format
package log

import (
	"path"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewAlarmLogger tests newAlarmLogger
func TestNewAlarmLogger(t *testing.T) {
	formatter := &Formatter{}
	newAlarmLogger(formatter)

	// test alarmLogger init
	assert.NotNil(t, alarmLogger)
	assert.Equal(t, formatter, alarmLogger.Formatter)
	assert.Equal(t, WarnLevel, alarmLogger.Level)
	assert.IsType(t, &RotateWriter{}, alarmLogger.Out)

	// test RotateWriter init
	writer, ok := alarmLogger.Out.(*RotateWriter)
	assert.True(t, ok)
	assert.Equal(t, path.Join(config.Directory, alarmFile), writer.Filename)
	assert.Equal(t, defaultAlarmSize, int(writer.MaxSize))
	assert.Equal(t, defaultAlarmBackUps, writer.MaxBackups)

	// test SetNoLock is called
	assert.False(t, alarmLogger.Hooks != nil)
}

// TestSetAlarmCb tests SetAlarmLogCb
func TestSetAlarmLogCb(t *testing.T) {
	cb := func(entry *AlarmLogEntry) {
		// do nothing
	}

	SetAlarmLogCb(cb)

	assert.NotNil(t, loggerM.alarmCbFunc)
	assert.False(t, reflect.DeepEqual(cb, loggerM.alarmCbFunc))
}
