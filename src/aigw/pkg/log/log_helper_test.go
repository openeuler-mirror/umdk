/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log helper test
 * Create: 2025-7-26
 */

package log

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	logHelperTestDelay = 100 * time.Millisecond
	defaultLogBufSize  = logBufSize * 8
)

// TestLogManager tests the logManager methods
func TestLogManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lm := newLogManager(ctx)

	// Test start and stop
	lm.start()
	time.Sleep(logHelperTestDelay) // Give some time for the goroutines to start
	lm.stop()

	// Test addEntry
	entry := &Entry{level: InfoLevel, msg: "test message", fields: logrus.Fields{"key": "value"}}
	lm.addEntry(entry)

	// Test isBlocked
	assert.False(t, lm.isBlocked())

	// Test addCachedLog
	lm.addCachedLog("cached log message")
	assert.Equal(t, uint32(1), lm.status.CachedMsgNum)
	assert.Equal(t, "cached log message", lm.status.CachedLogs[0])

	logFunc := lm.recordFunc(entry)
	logFunc()

	// Test setFormatter
	var formatter = &Formatter{TimestampFormat: time.RFC3339Nano}
	formatter.FormatTimestamp = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatLevel = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatField = func(k string, i interface{}) string {
		return fmt.Sprintf("%v:%v", k, i)
	}
	formatter.FormatCaller = func(file, function, line string) string {
		return fmt.Sprintf("[%s:%s] [%s]", filepath.Base(file), line, filepath.Base(function))
	}
	lm.setFormatter(formatter)

	// Test formatLog
	formattedLog := lm.formatLog(entry, "reason")

	assert.Equal(t, true, strings.Contains(formattedLog, "__reason__:reason"))

	// Test processInLogEntry
	lm.processInLogEntry(entry)

	// Test processReqStatus
	status := lm.processReqStatus()
	assert.Equal(t, uint32(1), status.CachedMsgNum)
	assert.Equal(t, "cached log message", status.CachedLogs[0])
	assert.Equal(t, uint32(defaultLogBufSize), status.BufferSize)
	assert.False(t, status.Blocked)
}

// TestLogManagerMonitor tests the monitor method
func TestLogManagerMonitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lm := newLogManager(ctx)
	lm.start()

	// Wait for the monitor to start
	time.Sleep(logHelperTestDelay)

	// Send a keep-alive message
	lm.kaCh <- struct{}{}

	// Wait for the monitor to reset the timer
	time.Sleep(logHelperTestDelay)

	// Check if blocked is false
	assert.False(t, lm.isBlocked())

	lm.stop()
}

func TestLogManagerFunc(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lm := newLogManager(ctx)
	assert.NotNil(t, lm)
	entry := newLogger(logrus.ErrorLevel)
	f := lm.recordFunc(entry)
	f()

	entry = newLogger(logrus.WarnLevel)
	f = lm.recordFunc(entry)
	f()

	entry = newLogger(logrus.DebugLevel)
	f = lm.recordFunc(entry)
	f()

	entry = newLogger(logrus.TraceLevel)
	f = lm.recordFunc(entry)
	f()
}

func TestProcessInLogEntry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lm := newLogManager(ctx)
	assert.NotNil(t, lm)

	var formatter = &Formatter{TimestampFormat: time.RFC3339Nano}
	formatter.FormatTimestamp = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatLevel = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatField = func(k string, i interface{}) string {
		return fmt.Sprintf("%v:%v", k, i)
	}
	formatter.FormatCaller = func(file, function, line string) string {
		return fmt.Sprintf("[%s:%s] [%s]", filepath.Base(file), line, filepath.Base(function))
	}
	lm.setFormatter(formatter)

	entry := newLogger(logrus.ErrorLevel)
	lm.blocked = true
	lm.processInLogEntry(entry)

	lm.blocked = false
	lm.logCh = make(chan func(), 0)
	lm.processInLogEntry(entry)
	assert.Greater(t, lm.status.BlockedNum, uint32(0))
}
