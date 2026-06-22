/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log container test
 * Create: 2025-7-26
 */

// Package log use for init logger format
package log

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	int8Num  = 123
	int16Num = 12345
	int32Num = 1234567890
	int64Num = 1234567890123456789
	fpNum    = 123.456
)

func TestSetGlobalLevel(t *testing.T) {
	SetGlobalLevel(DebugLevel)
	assert.Equal(t, DebugLevel, logger.GetLevel())
}

func TestDisableLog(t *testing.T) {
	DisableLog()
	assert.Equal(t, io.Discard, logger.Out)
}

func TestFormatter_Format(t *testing.T) {
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(os.Stdout)

	formatter := &Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		Separator:       " | ",
		FormatTimestamp: func(i interface{}) string {
			return fmt.Sprintf("[%s]", i)
		},
		FormatLevel: func(i interface{}) string {
			return fmt.Sprintf("[%s]", i)
		},
		FormatField: func(k string, i interface{}) string {
			return k + "=" + fmt.Sprintf("%v", i)
		},
		FormatCaller: func(file, function, line string) string {
			return file + ":" + function + ":" + line
		},
	}

	logger.SetFormatter(formatter)

	assert.Equal(t, false, loggerM.blocked, "logger should be not blocked")
	cnt := len(loggerM.logCh)

	entry := Info()
	entry.Str("key", "value").Msg("test message")
	entry.Msg("test message")

	assert.Equal(t, false, loggerM.blocked, "logger should be not blocked")
	assert.Greater(t, len(loggerM.logCh), cnt)

	// clear the cached entry
	select {
	case f := <-loggerM.logCh:
		f()
	case <-time.After(time.Second):
		break
	}

	entry1 := Info()
	entry1.Str("key", "value").Msgf("test message: %s", "formatted")
	entry1.Msgf("test message: %s", "formatted")

	assert.Equal(t, false, loggerM.blocked, "logger should be not blocked")
	assert.Greater(t, len(loggerM.logCh), cnt)
}

func TestEntry_isLevelEnabled(t *testing.T) {
	SetGlobalLevel(DebugLevel)

	entry := Info()
	assert.True(t, entry.isLevelEnabled())

	entry = Debug()
	assert.True(t, entry.isLevelEnabled())

	entry = Trace()
	assert.False(t, entry.isLevelEnabled())
}

func TestFormatterCaller(t *testing.T) {
	formatter := &Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		Separator:       " | ",
		FormatTimestamp: func(i interface{}) string {
			return fmt.Sprintf("[%s]", i)
		},
		FormatLevel: func(i interface{}) string {
			return fmt.Sprintf("[%s]", i)
		},
		FormatField: func(k string, i interface{}) string {
			return k + "=" + fmt.Sprintf("%v", i)
		},
		FormatCaller: func(file, function, line string) string {
			return file + ":" + function + ":" + line
		},
	}

	s1, _, _ := formatter.Caller()
	assert.NotEmpty(t, s1)
}

// TestInitEntry tests the initEntry method
func TestInitEntry(t *testing.T) {
	entry := &Entry{}
	entry.initEntry(logrus.InfoLevel)

	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.level != logrus.InfoLevel {
		t.Errorf("level should be InfoLevel, but got %v", entry.level)
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestNewLogger tests the newLogger function
func TestNewLogger(t *testing.T) {
	entry := newLogger(logrus.DebugLevel)

	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.level != logrus.DebugLevel {
		t.Errorf("level should be DebugLevel, but got %v", entry.level)
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestBool tests the Bool method
func TestBool(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Bool("key", true)

	expected := map[string]interface{}{
		"key": true,
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestStr tests the Str method
func TestStr(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Str("key", "value")

	expected := map[string]interface{}{
		"key": "value",
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestInt tests the Int method
func TestInt(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Int("key", int8Num)

	expected := map[string]interface{}{
		"key": int8Num,
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestInt64 tests the Int64 method
func TestInt64(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Int64("key", int64Num)

	expected := map[string]interface{}{
		"key": int64(int64Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestInt8 tests the Int8 method
func TestInt8(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Int8("key", int8Num)

	expected := map[string]interface{}{
		"key": int64(int8Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestInt16 tests the Int16 method
func TestInt16(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Int16("key", int16Num)

	expected := map[string]interface{}{
		"key": int64(int16Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestInt32 tests the Int32 method
func TestInt32(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Int32("key", int32Num)

	expected := map[string]interface{}{
		"key": int64(int32Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestUint64 tests the Uint64 method
func TestUint64(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Uint64("key", int64Num)

	expected := map[string]interface{}{
		"key": uint64(int64Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestUint8 tests the Uint8 method
func TestUint8(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Uint8("key", int8Num)

	expected := map[string]interface{}{
		"key": uint64(int8Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestUint16 tests the Uint16 method
func TestUint16(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Uint16("key", int16Num)

	expected := map[string]interface{}{
		"key": uint64(int16Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestUint tests the Uint method
func TestUint(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Uint("key", int32Num)

	expected := map[string]interface{}{
		"key": uint64(int32Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestUint32 tests the Uint32 method
func TestUint32(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Uint32("key", int32Num)

	expected := map[string]interface{}{
		"key": uint64(int32Num),
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestFloat64 tests the Float64 method
func TestFloat64(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Float64("key", fpNum)

	expected := map[string]interface{}{
		"key": fpNum,
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestFloat32 tests the Float32 method
func TestFloat32(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	entry.Float32("key", fpNum)

	assert.Greater(t, len(entry.fields), 0)
}

// TestAnErr tests the AnErr method
func TestAnErr(t *testing.T) {
	entry := newLogger(logrus.InfoLevel)
	err := errors.New("test error")
	entry.AnErr("key", err)

	expected := map[string]interface{}{
		"key": "test error",
	}
	if !reflect.DeepEqual(entry.fields, expected) {
		t.Errorf("fields should be %v, but got %v", expected, entry.fields)
	}
}

// TestWarn tests the Warn function
func TestWarn(t *testing.T) {
	entry := Warn()

	if entry.level != logrus.WarnLevel {
		t.Errorf("level should be WarnLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestError tests the Error function
func TestError(t *testing.T) {
	entry := Error()

	if entry.level != logrus.ErrorLevel {
		t.Errorf("level should be ErrorLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestFatal tests the Fatal function
func TestFatal(t *testing.T) {
	entry := Fatal()

	if entry.level != logrus.FatalLevel {
		t.Errorf("level should be FatalLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestPanic tests the Panic function
func TestPanic(t *testing.T) {
	entry := Panic()

	if entry.level != logrus.PanicLevel {
		t.Errorf("level should be PanicLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestTrace tests the Trace function
func TestTrace(t *testing.T) {
	entry := Trace()

	if entry.level != logrus.TraceLevel {
		t.Errorf("level should be TraceLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}

// TestDebug tests the Debug function
func TestDebug(t *testing.T) {
	entry := Debug()

	if entry.level != logrus.DebugLevel {
		t.Errorf("level should be DebugLevel, but got %v", entry.level)
	}
	if entry.fields == nil {
		t.Errorf("fields should be initialized, but got nil")
	}
	if entry.msg != "" {
		t.Errorf("msg should be empty, but got %v", entry.msg)
	}
}
