/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: implementation of async log manager
 * Create: 2025-5-30
 */

// Package log use for init logger format
package log

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	logBufSize      = 1024
	alarmLogBufSize = 8192
)

// StatusInfo log status
type StatusInfo struct {
	SuccessNum        uint32
	FailedNum         uint32
	CachedMsgNum      uint32
	BlockedNum        uint32
	BufferLen         uint32
	BufferSize        uint32
	SuccessUpdateTime time.Time
	FailedUpdateTime  time.Time
	BlockUpdateTime   time.Time
	Blocked           bool
	CachedLogs        []string
}

type alarmCbFunc = func(*AlarmLogEntry)

type logManager struct {
	wg *sync.WaitGroup
	sync.Mutex
	status      *StatusInfo
	formatter   *Formatter
	ctx         context.Context
	cancel      context.CancelFunc
	logCh       chan func()
	alarmCh     chan func()
	kaCh        chan struct{}
	alarmCbFunc alarmCbFunc
	blocked     bool
}

func (l *logManager) start() {
	l.wg.Add(1)
	go l.printLoop()
	l.wg.Add(1)
	go l.monitor()
}

func (l *logManager) stop() {
	l.cancel()
	l.wg.Wait()
}

func (l *logManager) setBlocked(b bool) {
	l.Lock()
	defer l.Unlock()
	l.blocked = b
}

func (l *logManager) getBlocked() bool {
	l.Lock()
	defer l.Unlock()
	return l.blocked
}

func (l *logManager) printLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(time.Second * 4) // 4 keep alive
	for {
		select {
		case <-ticker.C:
			l.kaCh <- struct{}{}

		case logFunc := <-l.logCh:
			if logFunc == nil {
				continue
			}
			logFunc()
			l.status.SuccessNum++
			l.status.SuccessUpdateTime = time.Now()
		case alarmFunc := <-l.alarmCh:
			if alarmFunc == nil {
				continue
			}
			alarmFunc()

		case <-l.ctx.Done():
			return
		}
	}
}

func (l *logManager) monitor() {
	defer l.wg.Done()
	duration := time.Second * 15 // 15 timeout
	timer := time.NewTimer(duration)

	for {
		select {
		case <-timer.C:
			l.setBlocked(true)

		case _, _ = <-l.kaCh:
			l.setBlocked(false)
			if !timer.Stop() {
				<-timer.C
			}

		case <-l.ctx.Done():
			return
		}
		timer.Reset(duration)
	}
}

func (l *logManager) addEntry(entry *Entry) {
	l.processInLogEntry(entry)
}

func (l *logManager) isBlocked() bool {
	return l.getBlocked()
}

func (l *logManager) addCachedLog(msg string) {
	l.Lock()
	defer l.Unlock()
	l.status.CachedLogs = append([]string{msg}, l.status.CachedLogs...)
	if l.status.CachedMsgNum == logBufSize {
		l.status.CachedLogs = l.status.CachedLogs[:l.status.CachedMsgNum]
		return
	}
	l.status.CachedMsgNum++
}

func (l *logManager) recordFunc(entry *Entry) func() {
	return func() {
		defer logEntryPool.Put(entry)
		switch entry.level {
		case PanicLevel:
			logger.WithFields(entry.fields).Panic(entry.msg)
		case FatalLevel:
			logger.WithFields(entry.fields).Fatal(entry.msg)
		case ErrorLevel:
			logger.WithFields(entry.fields).Error(entry.msg)
		case WarnLevel:
			logger.WithFields(entry.fields).Warn(entry.msg)
		case InfoLevel:
			logger.WithFields(entry.fields).Info(entry.msg)
		case DebugLevel:
			logger.WithFields(entry.fields).Debug(entry.msg)
		case TraceLevel:
			logger.WithFields(entry.fields).Trace(entry.msg)
		default:
			break
		}
	}
}

func (l *logManager) alarmFunc(msg string) func() {
	return func() {
		alarmLogger.WithFields(map[string]interface{}{}).Warn(msg)
	}
}

func (l *logManager) setFormatter(formatter *Formatter) {
	l.formatter = formatter
}

func (l *logManager) formatLog(entry *Entry, reason string) string {
	e := &logrus.Entry{
		Data:    entry.fields,
		Time:    time.Now(),
		Level:   entry.level,
		Message: entry.msg,
	}
	b, err := l.formatter.Format(e)
	if err != nil {
		return ""
	}
	sb := strings.Builder{}
	if len(b) > 0 {
		sb.Write(b[:len(b)-1])
	}
	sb.WriteString(" __reason__:" + reason)
	return sb.String()
}

func (l *logManager) processAlarmEntry(msg string) {
	select {
	case l.alarmCh <- l.alarmFunc(msg):
	default: // alarm is not blocked, may write slow
		reason := fmt.Sprintf(alarmFormat, AlarmBlocking, Report, "alarm buffer is full")
		// Reads the latest alarmCh message.
		<-l.alarmCh
		// write the alarm blocking alarmCh message.
		l.alarmCh <- l.alarmFunc(reason)
		// Reads the latest alarmCh message.
		<-l.alarmCh
		// write the alarm msg alarmCh message.
		l.alarmCh <- l.alarmFunc(msg)
	}
}

func (l *logManager) processInLogEntry(entry *Entry) {
	if l.getBlocked() { // log is blocked
		l.status.BlockedNum++
		l.addCachedLog(l.formatLog(entry, "log process is blocked"))
		l.status.BlockUpdateTime = time.Now()
		return
	}

	select {
	case l.logCh <- l.recordFunc(entry):
	default: // log is not blocked, may write slow
		l.status.FailedNum++
		l.addCachedLog(l.formatLog(entry, "log buffer is full"))
		l.status.FailedUpdateTime = time.Now()
	}
}

func (l *logManager) processReqStatus() *StatusInfo {
	s := &StatusInfo{}
	*s = *l.status
	tmpCache := s.CachedLogs[:]
	if len(tmpCache) > logBufSize {
		tmpCache = tmpCache[:logBufSize]
	}
	s.CachedLogs = make([]string, len(tmpCache))
	for i := 0; i < len(tmpCache); i++ {
		s.CachedLogs[i] = tmpCache[i]
	}
	s.BufferSize = uint32(cap(l.logCh))
	s.BufferLen = uint32(len(l.logCh))
	s.Blocked = l.isBlocked()
	return s
}

func newLogManager(c context.Context) *logManager {
	ctx, cancel := context.WithCancel(c)
	return &logManager{
		logCh:   make(chan func(), logBufSize*8), // logBufSize*8
		alarmCh: make(chan func(), alarmLogBufSize),
		kaCh:    make(chan struct{}, 1),
		status:  &StatusInfo{},
		ctx:     ctx,
		cancel:  cancel,
		wg:      &sync.WaitGroup{},
	}
}
