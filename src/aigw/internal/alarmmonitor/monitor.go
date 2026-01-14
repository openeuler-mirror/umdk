/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package monitor provides the management monitor client for AIGW.
 * Create: 2025-08-1
 */

// Package alarmmonitor provides the management monitor client for AIGW.
package alarmmonitor

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	msgChanBufferSize   = 2048
	msgWriteChanTimeout = 50 * time.Millisecond
	httpTimeout         = 1 * time.Second
	maxRetries          = 3
	maxDelay            = 16
)

// MonitorManager provides the management of the alarm to monitor
type MonitorManager struct {
	config       *base.MonitorConfig
	ctx          context.Context
	cancelFunc   context.CancelFunc
	wg           *sync.WaitGroup
	client       *http.Client
	alarmMsgChan chan *MepAlarm
	hostIP       string
	service      string
	url          string
	hmacMgr      *crypto.HmacManager
}

// NewMonitorManger return a AlarmClientManger
func NewMonitorManger(cfg *base.MonitorConfig, opts ...AlarmClientOption) (*MonitorManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("monitor cfg is nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &MonitorManager{
		config:       cfg,
		ctx:          ctx,
		cancelFunc:   cancel,
		wg:           new(sync.WaitGroup),
		alarmMsgChan: make(chan *MepAlarm, msgChanBufferSize),
		client:       &http.Client{Timeout: httpTimeout},
		url:          "http://" + cfg.Address + cfg.AlarmPath,
		hmacMgr:      crypto.NewHmacManager(nil),
	}
	for _, opt := range opts {
		if err := opt(mgr); err != nil {
			return nil, err
		}
	}
	return mgr, nil
}
func (m *MonitorManager) checkMonitorApiAvailable() error {
	log.Info().Msgf("start checking if the monitor api is available")
	req, err := http.NewRequest("POST", m.url, nil)
	if err != nil {
		log.Error().Msgf("failed to create the request for the monitor API check, err : %v", err)
		return err
	}
	rsp, err := m.client.Do(req)

	// network is unreachable
	if err != nil {
		log.Error().Msgf("monitor api %v is unavailable, err: %v", m.url, err)
		return err
	}
	defer rsp.Body.Close()

	// check response code (404 means http api is unavailable)
	if rsp.StatusCode == http.StatusNotFound {
		err := fmt.Errorf("monitor api %v is unavailable, got http response status code %v", m.url, rsp.StatusCode)
		log.Error().Msgf("%v", err)
		return err
	}
	return nil
}

// Start background alarm routines
func (m *MonitorManager) Start() error {
	log.Info().Msgf("starting alarm client manager")
	if err := m.checkMonitorApiAvailable(); err != nil {
		return err
	}
	m.ctx, m.cancelFunc = context.WithCancel(context.Background())
	m.wg.Add(1)
	go m.alarmLoop()

	log.Info().Msgf("alarm client manger has been started successfully")
	return nil
}

// Stop Monitor manger graceful shutdown and cleanup
func (m *MonitorManager) Stop() {
	log.Info().Msgf("start to stop alarm client manger")

	m.cancelFunc()
	m.wg.Wait()
	log.Info().Msgf("alarm client manger stopped")
}

// PutAlarmMessage is put msg to Monitor server
func (m *MonitorManager) PutAlarmMessage(aEntry *log.AlarmLogEntry) {
	level := mepAlarmLevelWarn
	if aEntry.AlarmAction == log.Clear {
		level = mepAlarmLevelClear
	}
	a := &MepAlarm{
		Version: "1.0.0",
		Data: MepAlarmData{
			[]AlarmMsg{
				{
					AlarmType:   aEntry.AlarmType,
					Source:      aEntry.Service,
					BusinessId:  m.config.BusinessId,
					AlarmTarget: fmt.Sprintf("%s@%s", m.config.ServiceName, m.config.Version),
					Level:       level,
					Content:     aEntry.Content,
					Mode:        mepAlarmReportModeOverride,
					RecoverMode: mepAlarmRecoverModeAuto,
					ReportIP:    m.hostIP,
				},
			},
		},
	}
	select {
	case m.alarmMsgChan <- a:
	case <-time.After(msgWriteChanTimeout):
		log.Debug().Msgf("Monitor putAlarmMessage timeout, alarm message %s", a.String())
		// Read the earliest alam message
		<-m.alarmMsgChan
		// write the latest alam message
		m.alarmMsgChan <- a

	case <-m.ctx.Done():
		log.Warn().Msgf("Monitor Client putAlarmMessage cancelled")
	}
}

func (m *MonitorManager) alarmLoop() {
	defer m.wg.Done()
	for {
		select {
		case msg := <-m.alarmMsgChan:
			m.postAlarmRequest(msg)
		case <-m.ctx.Done():
			log.Info().Msgf("alarm loop stopped")
			return
		}
	}
}

func (m *MonitorManager) generateAlarmRequest(msg *MepAlarm) (*http.Request, error) {
	req, err := http.NewRequest("POST", m.url, strings.NewReader(msg.String()))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if m.hmacMgr.EnableHmac() {
		if err := m.hmacMgr.AddHmacSign(req, msg.String()); err != nil {
			return nil, fmt.Errorf("create hmac signature failed: %v", err)
		}
	}
	return req, nil
}

// postAlarmRequest post HTTP request to monitor server
func (m *MonitorManager) postAlarmRequest(msg *MepAlarm) {
	var lastErr error
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		req, err := m.generateAlarmRequest(msg)
		if err != nil {
			log.Error().Msgf("Failed to send POST request: %v", err)
			break
		}
		resp, err := m.client.Do(req)
		if err != nil {
			lastErr = err
			log.Error().Msgf("Failed to send POST request: %v", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Error().Msgf("POST request failed with status code %v, retrying...", resp.StatusCode)
			lastErr = fmt.Errorf("HTTP status code %v", resp.StatusCode)

			backoff := utils.GetExpBackoffDelay(uint32(retryCount), maxDelay)
			utils.SleepWithContext(m.ctx, backoff)
			continue
		}

		log.Info().Msgf("POST request succeeded, HTTP status code: %v", resp.StatusCode)
		return
	}

	log.Error().Msgf("Failed to send alarm message after %d retries: %v", maxRetries, lastErr)
}
