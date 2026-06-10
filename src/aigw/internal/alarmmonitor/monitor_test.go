/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package monitor provides the management monitor client for AIGW.
 * Create: 2025-08-1
 */

// Package alarmmonitor provides the management monitor client for AIGW.
package alarmmonitor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
)

const sleepTime = 10 * time.Millisecond

// mockRoundTripper is a mock HTTP RoundTripper for testing
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return m.resp, m.err
}

// TestNewMonitorManger tests the NewMonitorManger function
func TestNewMonitorManger(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *base.MonitorConfig
		hostIp  string
		mgr     *crypto.HmacManager
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			hostIp:  "",
			mgr:     nil,
			wantErr: true,
		},
		{
			name: "valid config1",
			cfg: &base.MonitorConfig{
				Address:     "localhost:8080",
				AlarmPath:   "/alarm",
				ServiceName: "test-service",
				Version:     "1.0.0",
			},
			hostIp:  "1.2.3.4",
			mgr:     nil,
			wantErr: false,
		},
		{
			name: "valid config2",
			cfg: &base.MonitorConfig{
				Address:     "localhost:8080",
				AlarmPath:   "/alarm",
				ServiceName: "test-service",
				Version:     "1.0.0",
			},
			hostIp:  "",
			mgr:     &crypto.HmacManager{},
			wantErr: false,
		},
		{
			name: "valid config3",
			cfg: &base.MonitorConfig{
				Address:     "localhost:8080",
				AlarmPath:   "/alarm",
				ServiceName: "test-service",
				Version:     "1.0.0",
			},
			hostIp:  "1.2.3.4",
			mgr:     &crypto.HmacManager{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewMonitorManger(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMonitorManger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mgr == nil {
				t.Errorf("NewMonitorManger() returned nil")
			}
		})
	}
}

// TestStartStop tests the Start and Stop methods
func TestStartStop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &base.MonitorConfig{
		Address:     strings.TrimPrefix(ts.URL, "http://"),
		AlarmPath:   "/alarm",
		ServiceName: "test-service",
		Version:     "1.0.0",
	}
	mgr, err := NewMonitorManger(cfg)
	if err != nil {
		t.Fatalf("create monitor failed: %v", err)
	}

	// Test Start
	if err := mgr.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(sleepTime) // wait for goroutine to start

	// Test Stop
	mgr.Stop()
	time.Sleep(sleepTime) // wait for goroutine to exit

	// Check if context is canceled
	select {
	case <-mgr.ctx.Done():
	default:
		t.Errorf("context should be done after Stop()")
	}
}

// TestPutAlarmMessage tests the PutAlarmMessage method
func TestPutAlarmMessage(t *testing.T) {
	cfg := &base.MonitorConfig{
		Address:     "localhost:8080",
		AlarmPath:   "/alarm",
		ServiceName: "test-service",
		Version:     "1.0.0",
	}
	mgr, _ := NewMonitorManger(cfg)

	// create alarm
	alarm := &log.AlarmLogEntry{
		AlarmType:   "TestAlarm",
		Service:     "test-service",
		Content:     "Test content",
		AlarmAction: log.Report,
	}

	// put 2 message
	expecteMsgNum := 2
	mgr.PutAlarmMessage(&log.AlarmLogEntry{})
	mgr.PutAlarmMessage(&log.AlarmLogEntry{})
	if len(mgr.alarmMsgChan) != expecteMsgNum {
		t.Errorf("expected 2 message in chanel, but got%d", len(mgr.alarmMsgChan))
	}
	<-mgr.alarmMsgChan
	<-mgr.alarmMsgChan

	// Put an alarm message with AlarmAction is report
	mgr.PutAlarmMessage(alarm)

	select {
	case msg := <-mgr.alarmMsgChan:
		assert.Equal(t, mepAlarmLevelWarn, msg.Data.Alarms[0].Level)
	default:
		t.Errorf("should get an alarm msg from alarmMsgChan")
	}

	// Put an alarm message with AlarmAction is clear
	alarm.AlarmAction = log.Clear
	mgr.PutAlarmMessage(alarm)

	select {
	case msg := <-mgr.alarmMsgChan:
		assert.Equal(t, mepAlarmLevelClear, msg.Data.Alarms[0].Level)
	default:
		t.Errorf("should get an alarm msg from alarmMsgChan")
	}

	// no alarm msg in alarmMsgChan anymore
	select {
	case <-mgr.alarmMsgChan:
		t.Errorf("should not get an alarm msg from alarmMsgChan")
	default:
	}

	// Put an alarm message with cancellation
	mgr.cancelFunc()
	mgr.PutAlarmMessage(alarm)
}

// TestPostAlarmRequest tests the postAlarmRequest method
func TestPostAlarmRequest(t *testing.T) {
	cfg := &base.MonitorConfig{
		Address:     "localhost:8080",
		AlarmPath:   "/alarm",
		ServiceName: "test-service",
		Version:     "1.0.0",
	}
	mgr, _ := NewMonitorManger(cfg)

	// Mock HTTP client
	mgr.client = &http.Client{
		Transport: &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
			},
		},
	}

	// Build test message
	alarm := &MepAlarm{
		Version: "1.0.0",
		Data: MepAlarmData{
			[]AlarmMsg{
				{
					AlarmType:   "TestAlarm",
					Source:      "test-service",
					AlarmTarget: "test-service@1.0.0",
					Level:       mepAlarmLevelWarn,
					Content:     "Test content",
					Mode:        mepAlarmReportModeOverride,
					RecoverMode: mepAlarmRecoverModeAuto,
					ReportIP:    "127.0.0.1",
				},
			},
		},
	}

	// Success case
	mgr.postAlarmRequest(alarm)

	// Simulate failure
	mgr.client.Transport = &mockRoundTripper{
		err: fmt.Errorf("network error"),
	}
	mgr.postAlarmRequest(alarm)

	// Simulate non-200 status code
	mgr.client.Transport = &mockRoundTripper{
		resp: &http.Response{
			StatusCode: http.StatusInternalServerError,
		},
	}
	mgr.postAlarmRequest(alarm)
}

// TestMonitorMainFlow tests the monitor main flow
func TestMonitorMainFlow(t *testing.T) {
	cfg := &base.MonitorConfig{
		Address:     "localhost:8080",
		AlarmPath:   "/alarm",
		ServiceName: "test-service",
		Version:     "1.0.0",
	}
	mgr, _ := NewMonitorManger(cfg)

	// Start alarm loop
	mgr.Start()
	defer mgr.Stop()

	// Send test message
	alarm := &MepAlarm{
		Version: "1.0.0",
		Data: MepAlarmData{
			[]AlarmMsg{
				{
					AlarmType:   "TestAlarm",
					Source:      "test-service",
					AlarmTarget: "test-service@1.0.0",
					Level:       mepAlarmLevelWarn,
					Content:     "Test content",
					Mode:        mepAlarmReportModeOverride,
					RecoverMode: mepAlarmRecoverModeAuto,
					ReportIP:    "127.0.0.1",
				},
			},
		},
	}
	mgr.alarmMsgChan <- alarm

	// Wait for processing
	time.Sleep(sleepTime)
}

// TestWithServiceAddress tests the WithServiceAddress option
func TestWithServiceAddress(t *testing.T) {
	// Create a new MonitorManager
	mgr := &MonitorManager{}

	// Apply the WithServiceAddress option
	err := WithServiceAddress("192.168.1.1")(mgr)
	if err != nil {
		t.Errorf("WithServiceAddress returned an error: %v", err)
	}

	// Check if the hostIP is set correctly
	if mgr.hostIP != "192.168.1.1" {
		t.Errorf("expected hostIP to be '192.168.1.1', got '%s'", mgr.hostIP)
	}
}

// TestWithHmac tests the WithHmac option
func TestWithHmac(t *testing.T) {
	// Create a mock HmacManager
	hmacMgr := &crypto.HmacManager{}

	// Create a new MonitorManager
	mgr := &MonitorManager{}

	// Apply the WithHmac option
	err := WithHmac(hmacMgr)(mgr)
	if err != nil {
		t.Errorf("WithHmac returned an error: %v", err)
	}

	// Check if the hmacMgr is set correctly
	if mgr.hmacMgr != hmacMgr {
		t.Errorf("expected hmacMgr to be set to the provided HmacManager, got nil")
	}
}

// generateAlarmRequest测试
func TestGenerateAlarmRequest(t *testing.T) {
	testCases := []struct {
		name    string
		hmacKey []byte
		msg     *MepAlarm
		wantErr bool
	}{
		{
			name:    "with hmac and with alarm message",
			hmacKey: []byte("hmacKey"),
			msg: &MepAlarm{
				Version: "version",
				Data:    MepAlarmData{},
			},
			wantErr: false,
		},
		{
			name:    "with hmac and without alarm message",
			hmacKey: []byte("hmacKey"),
			msg:     nil,
			wantErr: false,
		},
		{
			name:    "with hmac and with empty alarm message",
			hmacKey: []byte("hmacKey"),
			msg:     &MepAlarm{},
			wantErr: false,
		},
		{
			name:    "without hmac and with alarm message",
			hmacKey: []byte("hmacKey"),
			msg: &MepAlarm{
				Version: "version",
				Data:    MepAlarmData{},
			},
			wantErr: false,
		},
		{
			name:    "without hmac and without alarm message",
			hmacKey: []byte("hmacKey"),
			msg:     &MepAlarm{},
			wantErr: false,
		},
		{
			name:    "without hmac and with empty alarm message",
			hmacKey: []byte("hmacKey"),
			msg:     nil,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &MonitorManager{
				hmacMgr: &crypto.HmacManager{},
				url:     "http://test",
			}

			_, err := mgr.generateAlarmRequest(tc.msg)
			if (err != nil) != tc.wantErr {
				t.Errorf("expected: %v got: %v", tc.wantErr, err)
			}

		})
	}
}

// TestMepAlarmStringFormat tests the string representation of an alarm.
func TestMepAlarmStringFormat(t *testing.T) {
	tests := []struct {
		name     string
		alarm    *MepAlarm
		expected string
	}{
		{
			name: "normal case1",
			alarm: &MepAlarm{
				Version: "1.0",
				Data: MepAlarmData{
					Alarms: []AlarmMsg{
						{
							AlarmType:   "alarmType",
							Source:      "source",
							AlarmTarget: "alarmTarget",
							BusinessId:  "businessId",
							Level:       mepAlarmLevelWarn,
							Content:     "alarm content",
							Dimension:   "dimension",
							Mode:        mepAlarmReportModeOverride,
							RecoverMode: mepAlarmRecoverModeAuto,
							ReportIP:    "192.168.1.1",
						},
					},
				},
			},
			expected: `{"version":"1.0","data":{"alarms":[{"alarmType":"alarmType","source":"source",` +
				`"alarmTarget":"alarmTarget","businessId":"businessId","level":"WARN","content":` +
				`"alarm content","dimension":"dimension","mode":"OVERRIDE",` +
				`"recoverMode":"AUTO","reportIP":"192.168.1.1"}]}}`,
		},
		{
			name: "normal case2",
			alarm: &MepAlarm{
				Version: "1.0",
				Data: MepAlarmData{
					Alarms: []AlarmMsg{
						{
							AlarmType:   "alarmType",
							Source:      "source",
							AlarmTarget: "alarmTarget",
							BusinessId:  "",
							Level:       mepAlarmLevelClear,
							Content:     "alarm content",
							Dimension:   "",
							Mode:        mepAlarmReportModeOverride,
							RecoverMode: mepAlarmRecoverModeAuto,
							ReportIP:    "192.168.1.1",
						},
					},
				},
			},
			expected: `{"version":"1.0","data":{"alarms":[{"alarmType":"alarmType","source":"source",` +
				`"alarmTarget":"alarmTarget","businessId":"","level":"CLEAR","content":` +
				`"alarm content","dimension":"","mode":"OVERRIDE",` +
				`"recoverMode":"AUTO","reportIP":"192.168.1.1"}]}}`,
		},
		{
			name:     "nil pointer",
			alarm:    nil,
			expected: "null",
		},
		{
			name: "empty fields",
			alarm: &MepAlarm{
				Version: "",
				Data: MepAlarmData{
					Alarms: []AlarmMsg{},
				},
			},
			expected: `{"version":"","data":{"alarms":[]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alarm.String()
			if result != tt.expected {
				t.Errorf("expected: %q, got: %q", tt.expected, result)
			}
		})
	}
}

// TestCheckMonitorApiAvailable tests the checkMonitorApiAvailable function
func TestCheckMonitorApiAvailable1(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		mockResponse   *http.Response
		mockError      error
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name: "valid monitor api",
			url:  "http://localhost:8080/valid",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			mockError:      nil,
			expectedError:  false,
			expectedErrMsg: "",
		},
		{
			name:           "network unreachable",
			url:            "http://localhost:8080/unreachable",
			mockResponse:   nil,
			mockError:      fmt.Errorf("network unreachable"),
			expectedError:  true,
			expectedErrMsg: "network unreachable",
		},
		{
			name: "HTTP 404 error",
			url:  "http://localhost:8080/notfound",
			mockResponse: &http.Response{
				StatusCode: http.StatusNotFound,
			},
			mockError:      nil,
			expectedError:  true,
			expectedErrMsg: "unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock server
			var server *httptest.Server
			if tt.mockResponse != nil && tt.mockError == nil {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.mockResponse.StatusCode)
				}))
				defer server.Close()
				tt.url = server.URL
			}

			// Create a MonitorManager with the mock server URL
			cfg := &base.MonitorConfig{
				Address:     strings.TrimPrefix(tt.url, "http://"),
				AlarmPath:   "/alarm",
				ServiceName: "test-service",
				Version:     "1.0.0",
			}
			mgr, _ := NewMonitorManger(cfg)

			// Mock HTTP client
			if tt.mockError != nil {
				mgr.client = &http.Client{
					Transport: &mockRoundTripper{
						err: tt.mockError,
					},
				}
			}

			// Call the function to test
			err := mgr.checkMonitorApiAvailable()

			// Check the result
			if (err != nil) != tt.expectedError {
				t.Errorf("checkMonitorApiAvailable() error = %v, expectedError %v", err, tt.expectedError)
			}
			if tt.expectedError && !strings.Contains(err.Error(), tt.expectedErrMsg) {
				t.Errorf("checkMonitorApiAvailable() expected error message = %v, got %v", tt.expectedErrMsg, err.Error())
			}
		})
	}
}
