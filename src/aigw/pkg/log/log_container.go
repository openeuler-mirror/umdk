/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Create: 2025-05-30
 */

// Package log use for init logger format
package log

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const callerFiledName = "__caller__"

const defaultDepth = 2

const (
	// PanicLevel level.
	PanicLevel = logrus.PanicLevel
	// FatalLevel level.
	FatalLevel = logrus.FatalLevel
	// ErrorLevel level.
	ErrorLevel = logrus.ErrorLevel
	// WarnLevel level.
	WarnLevel = logrus.WarnLevel
	// InfoLevel level.
	// application.
	InfoLevel = logrus.InfoLevel
	// DebugLevel level.
	DebugLevel = logrus.DebugLevel
	// TraceLevel level.
	TraceLevel = logrus.TraceLevel
)

var (
	logger       = logrus.New()
	alarmLogger  = logrus.New()
	logEntryPool = &sync.Pool{
		New: func() interface{} {
			return &Entry{}
		},
	}
)

// Formatter defines custom log isFormat
type Formatter struct {
	FormatTimestamp func(i interface{}) string
	FormatLevel     func(i interface{}) string
	FormatField     func(k string, i interface{}) string
	FormatCaller    func(file, function, line string) string
	TimestampFormat string
	Separator       string
}

// Caller get the file, line, function of caller
func (c *Formatter) Caller() (string, string, string) {
	if pc, file, line, ok := runtime.Caller(defaultDepth); ok {
		function := runtime.FuncForPC(pc).Name()
		return file, function, strconv.Itoa(line)
	}
	return "", "", ""
}

// Format generates log content and returns it as bytes
func (c *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	var res []byte
	timeStr := entry.Time.Format(time.RFC3339Nano)
	if c.TimestampFormat != "" {
		timeStr = entry.Time.Format(c.TimestampFormat)
	}
	if c.Separator == "" {
		c.Separator = " "
	}
	appendStr := func(res *[]byte) func(strs ...string) {
		return func(strs ...string) {
			for _, s := range strs {
				*res = append(*res, s...)
			}
		}
	}(&res)
	appendStr(c.FormatTimestamp(timeStr))
	appendStr(c.Separator, c.FormatLevel(strconv.Itoa(os.Getpid())))
	appendStr(c.Separator, c.FormatLevel(entry.Level))
	call, ok := entry.Data[callerFiledName].(caller)
	if ok {
		appendStr(c.Separator, c.FormatCaller(call.file, call.function, call.line))
		delete(entry.Data, callerFiledName)
	}
	appendStr(c.Separator, entry.Message)
	for k, v := range entry.Data {
		appendStr(c.Separator, c.FormatField(k, v))
	}
	appendStr("\n")
	return res, nil
}

// Entry defines a log container for logrus
type Entry struct {
	fields    map[string]interface{}
	level     logrus.Level
	msg       string
	callDepth int
}

func (l *Entry) initEntry(level logrus.Level) *Entry {
	l.fields = make(map[string]interface{})
	l.level = level
	l.msg = ""
	l.callDepth = defaultDepth
	return l
}

func newLogger(level logrus.Level) *Entry {
	var log *Entry
	log, ok := logEntryPool.Get().(*Entry)
	if !ok {
		log = new(Entry)
	}
	return log.initEntry(level)
}

// Bool adds bool value to Fields
func (l *Entry) Bool(k string, v bool) *Entry {
	l.fields[k] = v
	return l
}

// Str adds string value to Fields
func (l *Entry) Str(k, v string) *Entry {
	l.fields[k] = v
	return l
}

// Int adds int value to Fields
func (l *Entry) Int(k string, v int) *Entry {
	l.fields[k] = v
	return l
}

// Int64 adds int64 value to Fields
func (l *Entry) Int64(k string, v int64) *Entry {
	l.fields[k] = v
	return l
}

// Int8 adds int8 value to Fields
func (l *Entry) Int8(k string, v int8) *Entry {
	return l.Int64(k, int64(v))
}

// Int16 adds int16 value to Fields
func (l *Entry) Int16(k string, v int16) *Entry {
	return l.Int64(k, int64(v))
}

// Int32 adds int32 value to Fields
func (l *Entry) Int32(k string, v int32) *Entry {
	return l.Int64(k, int64(v))
}

// Uint64 adds uint64 value to Fields
func (l *Entry) Uint64(k string, v uint64) *Entry {
	l.fields[k] = v
	return l
}

// Uint8 adds uint8 value to Fields
func (l *Entry) Uint8(k string, v uint8) *Entry {
	return l.Uint64(k, uint64(v))
}

// Uint16 adds uint16 value to Fields
func (l *Entry) Uint16(k string, v uint16) *Entry {
	return l.Uint64(k, uint64(v))
}

// Uint adds uint value to Fields
func (l *Entry) Uint(k string, v uint) *Entry {
	return l.Uint64(k, uint64(v))
}

// Uint32 adds uint32 value to Fields
func (l *Entry) Uint32(k string, v uint32) *Entry {
	return l.Uint64(k, uint64(v))
}

// Float64 adds uint32 value to Fields
func (l *Entry) Float64(k string, v float64) *Entry {
	l.fields[k] = v
	return l
}

// Float32 adds float32 value to Fields
func (l *Entry) Float32(k string, v float32) *Entry {
	return l.Float64(k, float64(v))
}

// AnErr adds an error to Fields
func (l *Entry) AnErr(k string, e error) *Entry {
	if e != nil {
		l.fields[k] = e.Error()
	}
	return l
}

const defaultErrKey = "error"

// Err adds an error to Fields
func (l *Entry) Err(e error) *Entry {
	if e != nil {
		l.fields[defaultErrKey] = e.Error()
	}
	return l
}

// Status returns status of logger
func Status() *StatusInfo {
	return loggerM.processReqStatus()
}

// Info sets logger type with info
func Info() *Entry {
	return newLogger(InfoLevel)
}

// Warn sets logger type with warn
func Warn() *Entry {
	return newLogger(WarnLevel)
}

// Error sets logger type with error
func Error() *Entry {
	return newLogger(ErrorLevel)
}

// Fatal sets logger type with fatal
func Fatal() *Entry {
	return newLogger(FatalLevel)
}

// Panic sets logger type with panic
func Panic() *Entry {
	return newLogger(PanicLevel)
}

// Trace sets logger type with trace
func Trace() *Entry {
	return newLogger(TraceLevel)
}

// Debug sets logger type with debug
func Debug() *Entry {
	return newLogger(DebugLevel)
}

// SetGlobalLevel set lowest level
func SetGlobalLevel(l logrus.Level) {
	logger.SetLevel(l)
}

// DisableLog disable the logger
func DisableLog() {
	logger.SetOutput(io.Discard)
}

func (l *Entry) isLevelEnabled() bool {
	return logger.GetLevel() >= l.level
}

type caller struct {
	file, function, line string
}

func (l *Entry) getCaller() (string, string, string) {
	if pc, file, line, ok := runtime.Caller(l.callDepth); ok {
		function := runtime.FuncForPC(pc).Name()
		return file, function, strconv.Itoa(line)
	}
	return "", "", ""
}

// Msg outputs logger msg
func (l *Entry) Msg(args ...interface{}) {
	if !l.isLevelEnabled() {
		return
	}
	file, function, line := l.getCaller()
	l.fields[callerFiledName] = caller{file: file, function: function, line: line}
	l.msg = fmt.Sprint(args...)
	loggerM.addEntry(l)
}

// Msgf outputs logger msg with isFormat
func (l *Entry) Msgf(format string, args ...interface{}) {
	if !l.isLevelEnabled() {
		return
	}
	file, function, line := l.getCaller()
	l.fields[callerFiledName] = caller{file: file, function: function, line: line}
	l.msg = fmt.Sprintf(format, args...)
	loggerM.addEntry(l)
}
