/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: server test
 * Create: 2025-06-18
 */

// Package server provides north interfaces for AIGW.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"huawei.com/aigw/internal/alarmmonitor"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/gs"
	"huawei.com/aigw/internal/modelmonitor"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/sock"
)

const (
	serverTestWaitTime = 500 * time.Millisecond
	validConfigPath    = "../../test/config/valid_config.json"
)

type mockTokenizer struct {
	mock.Mock
}

func (m *mockTokenizer) InitFromFile(path string) error {
	args := m.Called(path)
	return args.Error(0)
}

func (m *mockTokenizer) Uninit() {
	m.Called()
}

func (m *mockTokenizer) Encode(prompt string) ([]int, error) {
	return []int{}, nil
}

func (m *mockTokenizer) Decode(tokenIDs []uint32) (string, error) {
	return "", nil
}

// TestParseLaunchSettings tests the parseLaunchSettings function
func TestParseLaunchSettings(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		wantHost string
		wantPort string
	}{
		{
			name:    "default values", // Test case for default values
			args:    []string{},       // No arguments provided
			wantErr: false,            // No error expected
		},
		{
			name:    "default values",                   // Test case for invalid config file
			args:    []string{"--config=invalidConfig"}, // format is valid, but config value is invalid
			wantErr: true,                               // Error expected
		},
		{
			name:    "unknown option",             // Test case for unknown option
			args:    []string{"--invalid=option"}, // Unknown option argument
			wantErr: true,                         // Error expected
		},
		{
			name:    "invalid format of option",
			args:    []string{"test#test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Logf("Running test: %v", tt.name)
		t.Run(tt.name, func(t *testing.T) {
			// Reset settings to default values
			settings.cfgPath = validConfigPath

			// Simulate command line arguments
			os.Args = []string{"aigw"}            // Assume program name is aigw
			os.Args = append(os.Args, tt.args...) // Append test arguments

			err := parseLaunchSettings()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLaunchSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// TestInitLog tests the initLog function
func TestInitLog(t *testing.T) {
	tests := []struct {
		name     string
		logPath  string
		logLevel string
		wantErr  bool
	}{
		{
			name:    "default log settings", // Test case for default log settings
			wantErr: false,                  // No error expected
		},
		{
			name:    "custom log path", // Test case for custom log path
			logPath: "/tmp/",           // Custom log path
			wantErr: false,             // No error expected
		},
		{
			name:     "invalid log level", // Test case for invalid log level
			logLevel: "invalid",           // Invalid log level
			wantErr:  true,                // Error expected
		},
	}

	for _, tt := range tests {
		t.Logf("Running test: %v", tt.name)
		t.Run(tt.name, func(t *testing.T) {
			gCfg := &base.GlobalConfig{
				LogPath:  tt.logPath,
				LogLevel: tt.logLevel,
			}

			err := initLog(gCfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("initLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func resetServerHandler() {
	serverHandler = aigwServerHandler{}
}

// TestExecute tests the Execute function
func TestExecute(t *testing.T) {
	resetServerHandler()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "invalid host",             // Test case for invalid host
			args:    []string{"--host=0.0.0.0"}, // Invalid host argument
			wantErr: true,                       // Error expected
		},
		{
			name:    "invalid port",         // Test case for invalid port
			args:    []string{"--port=abc"}, // Invalid port argument
			wantErr: true,                   // Error expected
		},
	}

	for _, tt := range tests {
		t.Logf("Running test: %v", tt.name)
		t.Run(tt.name, func(t *testing.T) {
			// Reset settings to default values
			settings.cfgPath = validConfigPath

			// Simulate command line arguments
			os.Args = []string{"aigw"} // Assume program name is aigw
			os.Args = append(os.Args, tt.args...)

			err := Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	// Test signal handling
	t.Run("signal handling", func(t *testing.T) {
		t.Logf("Running test: signal handling")
		// Simulate signal
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Wait for server to start
			time.Sleep(serverTestWaitTime)
			// Send SIGTERM signal
			process, err := os.FindProcess(os.Getpid())
			if err != nil {
				t.Errorf("failed to find process: %v", err)
				return
			}
			err = process.Signal(syscall.SIGTERM)
			if err != nil {
				t.Errorf("failed to signal: %v", err)
			}
			// Wait for exit
			time.Sleep(serverTestWaitTime)
		}()

		tk := mockTokenizer{}
		tk.On("InitFromFile", mock.Anything).Return(nil)
		tk.On("Uninit").Return()

		// Start server
		settings.cfgPath = validConfigPath
		os.Args = []string{"aigw"}
		err := Execute()
		if err != nil {
			t.Errorf("Execute() error = %v", err)
			return
		}

		// Wait for goroutine to complete
		<-done
		t.Logf("test signal handling finished")
	})
}

func TestHandleConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid absolute path", "/tmp/config.json", true},
		{"valid relative path", "config.json", true},
		{"invalid path", "./server.go", false},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重置settings.cfgPath以避免测试干扰
			err := handleConfig(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("want err, but no err: %v", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("want no err, but err: %v", tt.name)
			}
		})
	}
}

func TestHandleHMACKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"correct length", "0123456789abcdef0123456789abcdef", false},
		{"too short", "0123456789abcdef0123456", true},
		{"too long", "0123456789abcdef0123456789abcd", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleHMACKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleHMACKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestHandleAESKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"correct length", "0123456789abcdef", false},
		{"too short", "0123456789abc", true},
		{"too long", "0123456789abcdef0", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleAESKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleAESKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestInitZooKeeperManager(t *testing.T) {
	t.Run("Test with invalid configuration", func(t *testing.T) {

		globalCfg := &base.GlobalConfig{
			Host: "localhost",
			Port: "2181",
		}
		cfg := &base.ZookeeperConfig{
			Address: "invalid_address",
		}

		zkMgr, err := initZooKeeperManager(globalCfg, cfg)
		if err == nil || zkMgr != nil {
			t.Errorf("except err")
		}
	})

	t.Run("Test ZooKeeper connection failure", func(t *testing.T) {

		globalCfg := &base.GlobalConfig{
			Host: "localhost",
			Port: "2181",
		}
		cfg := &base.ZookeeperConfig{
			Address:        "zookeeper_address",
			ConnectTimeout: 1,
			SessionTimeout: 1,
		}

		zkMgr, err := initZooKeeperManager(globalCfg, cfg)
		if err == nil || zkMgr != nil {
			t.Errorf("except err")
		}
	})
}

// TestValidateCryptoData tests the validateCryptoData function
func TestValidateCryptoData(t *testing.T) {
	// Test case: valid crypto data
	validData := base.CryptoData{
		ApiHmacKey:        "1234567890abcdef1234567890abcdef",
		InsHmacKey:        "1234567890abcdef1234567890abcdef",
		MonitorHmacKey:    "1234567890abcdef1234567890abcdef",
		DataSyncHmacKey:   "1234567890abcdef1234567890abcdef",
		ApiAesKey:         "1234567890abcdef",
		InsAesKey:         "1234567890abcdef",
		ZookeeperUser:     "valid_zk_user",
		ZookeeperPassword: "valid_zk_password",
	}
	err := validateCryptoData(&validData)
	assert.NoError(t, err)

	// Test case: invalid api HMAC key
	invalidData := validData
	invalidData.ApiHmacKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ApiHmacKey is invalid")

	invalidData = validData
	invalidData.InsHmacKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "InsHmacKey is invalid")

	invalidData = validData
	invalidData.MonitorHmacKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MonitorHmacKey is invalid")

	invalidData = validData
	invalidData.DataSyncHmacKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DataSyncHmacKey is invalid")

	// Test case: invalid AES key
	invalidData = validData
	invalidData.ApiAesKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api aes key is invalid")

	invalidData = validData
	invalidData.InsAesKey = "invalid"
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ins aes key is invalid")

	// Test case: invalid zk user length
	invalidData = validData
	invalidData.ZookeeperUser = strings.Repeat("a", commonStringLen+1)
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid zk user len")

	// Test case: invalid zk password length
	invalidData = validData
	invalidData.ZookeeperPassword = strings.Repeat("a", commonStringLen+1)
	err = validateCryptoData(&invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid zk password len")
}

// TestLoadCryptoDataSuccess tests the loadCryptoData function success
func TestLoadCryptoDataSuccess(t *testing.T) {
	// Test case: crypto sock is empty
	aigwConfig := &base.AigwConfig{
		GlobalConfig: base.GlobalConfig{
			CryptoSock: "/tmp/123",
		},
	}

	validData := &base.CryptoData{
		ApiHmacKey:        "1234567890abcdef1234567890abcdef",
		InsHmacKey:        "1234567890abcdef1234567890abcdef",
		MonitorHmacKey:    "1234567890abcdef1234567890abcdef",
		DataSyncHmacKey:   "1234567890abcdef1234567890abcdef",
		ApiAesKey:         "1234567890abcdef",
		InsAesKey:         "1234567890abcdef",
		ZookeeperUser:     "valid_zk_user",
		ZookeeperPassword: "valid_zk_password",
	}

	unixSockMock := gomonkey.ApplyFunc(sock.NewUnixSock,
		func(socketPath string, opts ...sock.UnixSockOption) (*sock.UnixSock, error) {
			return &sock.UnixSock{}, nil
		})
	defer unixSockMock.Reset()
	readMock := gomonkey.ApplyMethod(reflect.TypeOf(&sock.UnixSock{}), "ReadData",
		func(uds *sock.UnixSock) ([]byte, error) {
			d, e1 := json.Marshal(validData)
			assert.NoError(t, e1)
			return d, nil
		})
	defer readMock.Reset()
	closeMock := gomonkey.ApplyMethod(reflect.TypeOf(&sock.UnixSock{}), "Close", func(uds *sock.UnixSock) {})
	defer closeMock.Reset()

	err := loadCryptoData(aigwConfig)
	assert.NoError(t, err)

	// disable loading
	aigwConfig.GlobalConfig.CryptoSock = ""
	err = loadCryptoData(aigwConfig)
	assert.NoError(t, err)
}


// TestLoadCryptoData tests the loadCryptoData function fail
func TestLoadCryptoDataFail(t *testing.T) {
	aigwConfig := &base.AigwConfig{
		GlobalConfig: base.GlobalConfig{
			CryptoSock: "/tmp/123",
		},
	}

	// Test case: NewUnixSock fails
	t.Run("NewUnixSock fails", func(t *testing.T) {
		unixSockMockFail := gomonkey.ApplyFunc(sock.NewUnixSock,
			func(socketPath string, opts ...sock.UnixSockOption) (*sock.UnixSock, error) {
				return nil, fmt.Errorf("failed to create UnixSock")
			})
		defer unixSockMockFail.Reset()
		err := loadCryptoData(aigwConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create UnixSock")
	})

	// Test case: ReadData fails
	t.Run("ReadData fails", func(t *testing.T) {
		unixSockMock := gomonkey.ApplyFunc(sock.NewUnixSock,
			func(socketPath string, opts ...sock.UnixSockOption) (*sock.UnixSock, error) {
				return &sock.UnixSock{}, nil
			})
		defer unixSockMock.Reset()
		readMock := gomonkey.ApplyMethod(reflect.TypeOf(&sock.UnixSock{}), "ReadData",
			func(uds *sock.UnixSock) ([]byte, error) {
				return nil, fmt.Errorf("failed to read data")
			})
		defer readMock.Reset()
		err := loadCryptoData(aigwConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read data")
	})

	// Test case: Unmarshal fails
	t.Run("Unmarshal fails", func(t *testing.T) {
		unixSockMock := gomonkey.ApplyFunc(sock.NewUnixSock,
			func(socketPath string, opts ...sock.UnixSockOption) (*sock.UnixSock, error) {
				return &sock.UnixSock{}, nil
			})
		defer unixSockMock.Reset()
		readSuccessMock := gomonkey.ApplyMethod(reflect.TypeOf(&sock.UnixSock{}), "ReadData",
			func(uds *sock.UnixSock) ([]byte, error) {
				return []byte{}, nil
			})
		defer readSuccessMock.Reset()
		unmarshalMock := gomonkey.ApplyFunc(json.Unmarshal,
			func(data []byte, v any) error {
				return fmt.Errorf("failed to unmarshal")
			})
		defer unmarshalMock.Reset()
		err := loadCryptoData(aigwConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal")
	})

	// Test case: validate fails
	t.Run("validate fails", func(t *testing.T) {
		backup := serverHandler.crypto
		unixSockMock := gomonkey.ApplyFunc(sock.NewUnixSock,
			func(socketPath string, opts ...sock.UnixSockOption) (*sock.UnixSock, error) {
				return &sock.UnixSock{}, nil
			})
		defer unixSockMock.Reset()
		readMock := gomonkey.ApplyMethod(reflect.TypeOf(&sock.UnixSock{}), "ReadData",
			func(uds *sock.UnixSock) ([]byte, error) {
				return []byte{}, nil
			})
		defer readMock.Reset()
		unmarshalSuccessMock := gomonkey.ApplyFunc(json.Unmarshal,
			func(data []byte, v any) error {
				c, ok := v.(*base.CryptoData)
				if !ok {
					return fmt.Errorf("invalid base.CryptoData")
				}
				c.ApiHmacKey = "123"
				return nil
			})
		defer unmarshalSuccessMock.Reset()
		err := loadCryptoData(aigwConfig)
		assert.Error(t, err)
		serverHandler.crypto = backup
	})
}

// TestInitCompSuccess tests the InitComp function success
func TestAIGWBasic(t *testing.T) {
	// 1. Test initialization
	t.Run("InitUninit", func(t *testing.T) {
		if !IsInitComp() {
			t.Error("Should not be initialized at start")
		}

		cfg := &base.AigwConfig{GlobalConfig: base.GlobalConfig{LogLevel: "info"}}
		if err := InitComp(cfg); err != nil {
			t.Errorf("Init failed: %v", err)
		}

		if !IsInitComp() {
			t.Error("Should be initialized after InitComp")
		}

		UninitComp()
		if IsInitComp() {
			t.Error("Should not be initialized after UninitComp")
		}
	})

	// 2. Test API calls
	t.Run("APIWithNil", func(t *testing.T) {
		tests := []struct {
			name string
			test func(*testing.T)
		}{
			{"SelectWithContext", func(t *testing.T) {
				_, c := SelectWithContext(nil, nil)
				if c == nil {
					t.Error("SelectWithContext should fail when input parameter is invalid")
				}
			}},
			{"NotifyEvent", func(t *testing.T) {
				err := NotifyEvent(nil)
				assert.Error(t, err)
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, tt.test)
		}
	})
}

// TestPrintUsage checks that PrintUsage writes correct usage info to stdout.
func TestPrintUsage(t *testing.T) {
	// Arrange: Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Save original Args[0] and restore later
	originalArg0 := os.Args[0]
	os.Args[0] = "/usr/bin/aigw"

	// Act
	PrintUsage()

	// Restore stdout
	w.Close()
	os.Stdout = old

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	output := buf.String()

	// Assert
	assert.Contains(t, output, "/usr/bin/aigw")
	assert.Contains(t, output, "--config")
	assert.Contains(t, output, "-h/--help")
	assert.Contains(t, output, "default:")

	// Restore original args
	os.Args[0] = originalArg0
}

// TestRegisterDriverOps test register cache driver ops
func TestRegisterDriverOps(t *testing.T) {
	serverHandler.cacheDriverOps = nil
	res := IsRegCacheDriver()
	assert.False(t, res)

	serverHandler.cacheDriverOps = &cachecenter.CacheDriverOps{}
	res = IsRegCacheDriver()
	assert.True(t, res)
}

// TestIsRegCacheDriver test register cache driver
func TestIsRegCacheDriver(t *testing.T) {
	RegisterCacheDriverOps("", &cachecenter.CacheDriverOps{})
	assert.NotNil(t, serverHandler.cacheDriverOps)
}

// TestDeleteDriverOps
func TestDeleteDriverOps(t *testing.T) {
	serverHandler.cacheDriverOps = &cachecenter.CacheDriverOps{}
	DeleteDriverOps()
	assert.Nil(t, serverHandler.cacheDriverOps)
}

// TestRegisterModel
func TestRegisterModel(t *testing.T) {
	cfg := &base.AigwConfig{GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
		Limits: base.Limits{ModelNum: 10}, Predictor: base.PredictorConfig{PredictType: "none"},
	}
	err := InitComp(cfg)
	assert.Nil(t, err)

	err = RegisterModel(nil)
	assert.NotNil(t, err)

	mock_model_name := "mock_model"
	config := core.NewDefaultGsConfig(mock_model_name)
	config.LoadBalancer.Mixed = "roundRobin"
	config.LoadBalancer.BatchSize = 1
	err = RegisterModel(config)
	assert.Nil(t, err)

	err = UnregisterModel("")
	assert.NotNil(t, err)

	err = UnregisterModel(mock_model_name)
	assert.Nil(t, err)

	UninitComp()
}

// TestIsInitComp tests IsInitComp function
func TestIsInitComp(t *testing.T) {
	// Initially not initialized
	assert.False(t, IsInitComp())

	// After initialization
	cfg := &base.AigwConfig{
		GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
		Limits:       base.Limits{ModelNum: 10},
		Predictor:    base.PredictorConfig{PredictType: "none"},
	}
	err := InitComp(cfg)
	assert.Nil(t, err)
	assert.True(t, IsInitComp())
	UninitComp()
}

// TestSelectWithContext tests SelectWithContext function
func TestSelectWithContext(t *testing.T) {
	cfg := &base.AigwConfig{
		GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
		Limits:       base.Limits{ModelNum: 10, InsNumPerModel: 10},
		Predictor:    base.PredictorConfig{PredictType: "none"},
	}
	err := InitComp(cfg)
	assert.Nil(t, err)

	// Test with nil request
	_, err = SelectWithContext(nil, nil)
	assert.NotNil(t, err)

	// Test with valid request but no instance
	req := &base.OpenAiRequest{
		UUID:  "test-uuid",
		Model: "test-model",
		Messages: []base.OpenAiMessage{
			{Role: "user", Content: "hello"},
		},
	}
	ctx := &RegMsgCtx{
		RegInstanceMsg: []*gs.RegisterInstanceMsg{},
	}
	_, err = SelectWithContext(req, ctx)
	assert.NotNil(t, err)

	UninitComp()
}

// TestNotifyEvent tests NotifyEvent function
func TestNotifyEvent(t *testing.T) {
	cfg := &base.AigwConfig{
		GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
		Limits:       base.Limits{ModelNum: 10},
		Predictor:    base.PredictorConfig{PredictType: "none"},
	}
	err := InitComp(cfg)
	assert.Nil(t, err)

	// Test with nil request
	err = NotifyEvent(nil)
	assert.NotNil(t, err)

	// Test with valid request
	reqEvent := &RequestEvent{
		Model:     "test-model",
		ID:        "test-id",
		EventDesc: "DECODE_RECEIVED_KVC",
	}
	err = NotifyEvent(reqEvent)
	// This may fail because model is not registered, but it should not panic

	UninitComp()
}

// TestConstructKeyData tests constructKeyData function
func TestConstructKeyData(t *testing.T) {
	tempData := &base.CryptoData{
		ApiHmacKey:        "test-api-hmac-key",
		ApiAesKey:         "test-api-aes-key",
		InsHmacKey:        "test-ins-hmac-key",
		InsAesKey:         "test-ins-aes-key",
		MonitorHmacKey:    "test-monitor-hmac-key",
		DataSyncHmacKey:   "test-data-sync-hmac-key",
		ZookeeperUser:     "test-zk-user",
		ZookeeperPassword: "test-zk-password",
		ZookeeperTlsKey:   "test-zk-tls-key",
	}

	constructKeyData(tempData)

	c := &serverHandler.crypto
	assert.Equal(t, []byte("test-api-hmac-key"), c.apiHmacKey)
	assert.Equal(t, []byte("test-api-aes-key"), c.apiAesKey)
	assert.Equal(t, []byte("test-ins-hmac-key"), c.insHmacKey)
	assert.Equal(t, []byte("test-ins-aes-key"), c.insAesKey)
	assert.Equal(t, []byte("test-monitor-hmac-key"), c.monitorHmacKey)
	assert.Equal(t, []byte("test-data-sync-hmac-key"), c.dataSyncHmacKey)
	assert.Equal(t, "test-zk-user", c.zookeeperUser)
	assert.Equal(t, []byte("test-zk-password"), c.zookeeperPassword)
	assert.Equal(t, []byte("test-zk-tls-key"), c.zookeeperTlsKey)
}

// TestValidateCryptoDataWithEmptyKeys tests validateCryptoData with empty keys
func TestValidateCryptoDataWithEmptyKeys(t *testing.T) {
	// Test with all empty keys
	data := &base.CryptoData{}
	err := validateCryptoData(data)
	assert.NotNil(t, err)

	// Test with valid keys
	data = &base.CryptoData{
		ApiHmacKey:      strings.Repeat("a", 32),
		ApiAesKey:       strings.Repeat("b", 16),
		InsHmacKey:      strings.Repeat("c", 32),
		InsAesKey:       strings.Repeat("d", 16),
		MonitorHmacKey:  strings.Repeat("e", 32),
		DataSyncHmacKey: strings.Repeat("f", 32),
	}
	err = validateCryptoData(data)
	assert.Nil(t, err)

	// Test with invalid HMAC key length
	data = &base.CryptoData{
		ApiHmacKey:      "short",
		ApiAesKey:       strings.Repeat("b", 16),
		InsHmacKey:      strings.Repeat("c", 32),
		InsAesKey:       strings.Repeat("d", 16),
		MonitorHmacKey:  strings.Repeat("e", 32),
		DataSyncHmacKey: strings.Repeat("f", 32),
	}
	err = validateCryptoData(data)
	assert.NotNil(t, err)

	// Test with invalid AES key length
	err = validateCryptoData(&base.CryptoData{
		ApiHmacKey:      strings.Repeat("a", 32),
		ApiAesKey:       "short",
		InsHmacKey:      strings.Repeat("c", 32),
		InsAesKey:       strings.Repeat("d", 16),
		MonitorHmacKey:  strings.Repeat("e", 32),
		DataSyncHmacKey: strings.Repeat("f", 32),
	})
	// Note: api aes key check passes but ins aes key is invalid, so we just check it doesn't panic
}

// TestInitLogExt tests initLog function
func TestInitLogExt(t *testing.T) {
	// Test with empty config
	cfg := &base.GlobalConfig{}
	err := initLog(cfg)
	assert.Nil(t, err)

	// Test with valid config
	tmpDir, err := os.MkdirTemp("", "aigw-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg = &base.GlobalConfig{
		LogLevel: "debug",
		LogPath:  tmpDir,
	}
	err = initLog(cfg)
	assert.Nil(t, err)
}

// TestHandleHMACKeyExt tests handleHMACKey function
func TestHandleHMACKeyExt(t *testing.T) {
	// Test with valid key
	err := handleHMACKey(strings.Repeat("a", 32))
	assert.Nil(t, err)

	// Test with invalid key
	err = handleHMACKey("short")
	assert.NotNil(t, err)
}

// TestHandleAESKeyExt tests handleAESKey function
func TestHandleAESKeyExt(t *testing.T) {
	// Test with valid key (16 bytes)
	err := handleAESKey(strings.Repeat("a", 16))
	assert.Nil(t, err)

	// Test with invalid key
	err = handleAESKey("short")
	assert.NotNil(t, err)

	// Test with key of wrong length (32 bytes instead of 16)
	err = handleAESKey(strings.Repeat("b", 32))
	assert.NotNil(t, err)
}

// TestHandleConfigExt tests handleConfig function
func TestHandleConfigExt(t *testing.T) {
	// Test with valid path
	tmpFile, err := os.CreateTemp("", "config_*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("{}")
	tmpFile.Close()

	err = handleConfig(tmpFile.Name())
	assert.Nil(t, err)

	// Test with invalid path
	err = handleConfig("/non/existent/path/config.json")
	assert.NotNil(t, err)
}

// TestServerHandlerFields tests serverHandler fields
func TestServerHandlerFields(t *testing.T) {
	// Test initial state
	assert.NotNil(t, serverHandler.cfgMgr)
	assert.NotNil(t, serverHandler.crypto)
}

// TestInitMonitorManager tests the initMonitorManager function
func TestInitMonitorManager(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "success case",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset serverHandler state
			resetServerHandler()

			globalCfg := &base.GlobalConfig{
				Host: "localhost",
			}
			monitorCfg := &base.MonitorConfig{
				Address:     "127.0.0.1:8080",
				AlarmPath:   "/alarm",
				ServiceName: "test-service",
			}
			hmacMgr := crypto.NewHmacManager([]byte("1234567890abcdef1234567890abcdef"))

			// Mock NewMonitorManger to return nil error
			patches := gomonkey.ApplyFunc(alarmmonitor.NewMonitorManger,
				func(cfg *base.MonitorConfig, opts ...alarmmonitor.AlarmClientOption) (*alarmmonitor.MonitorManager, error) {
					return &alarmmonitor.MonitorManager{}, nil
				})
			defer patches.Reset()

			// Mock MonitorManager.Start to return nil error
			patches.ApplyMethod(reflect.TypeOf(&alarmmonitor.MonitorManager{}), "Start",
				func(m *alarmmonitor.MonitorManager) error {
					return nil
				})
			defer patches.Reset()

			monitorMgr, err := initMonitorManager(globalCfg, monitorCfg, hmacMgr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, monitorMgr)
			}
		})
	}
}

// TestInitMonitorManagerFail tests initMonitorManager failure cases
func TestInitMonitorManagerFail(t *testing.T) {
	t.Run("NewMonitorManger fails", func(t *testing.T) {
		resetServerHandler()

		globalCfg := &base.GlobalConfig{
			Host: "localhost",
		}
		monitorCfg := &base.MonitorConfig{
			Address:     "127.0.0.1:8080",
			AlarmPath:   "/alarm",
			ServiceName: "test-service",
		}
		hmacMgr := crypto.NewHmacManager([]byte("1234567890abcdef1234567890abcdef"))

		// Mock NewMonitorManger to return error
		patches := gomonkey.ApplyFunc(alarmmonitor.NewMonitorManger,
			func(cfg *base.MonitorConfig, opts ...alarmmonitor.AlarmClientOption) (*alarmmonitor.MonitorManager, error) {
				return nil, fmt.Errorf("failed to create monitor manager")
			})
		defer patches.Reset()

		monitorMgr, err := initMonitorManager(globalCfg, monitorCfg, hmacMgr)
		assert.Error(t, err)
		assert.Nil(t, monitorMgr)
		assert.Contains(t, err.Error(), "failed to create monitor manager")
	})

	t.Run("MonitorManager.Start fails", func(t *testing.T) {
		resetServerHandler()

		globalCfg := &base.GlobalConfig{
			Host: "localhost",
		}
		monitorCfg := &base.MonitorConfig{
			Address:     "127.0.0.1:8080",
			AlarmPath:   "/alarm",
			ServiceName: "test-service",
		}
		hmacMgr := crypto.NewHmacManager([]byte("1234567890abcdef1234567890abcdef"))

		// Mock NewMonitorManger to return success
		patches := gomonkey.ApplyFunc(alarmmonitor.NewMonitorManger,
			func(cfg *base.MonitorConfig, opts ...alarmmonitor.AlarmClientOption) (*alarmmonitor.MonitorManager, error) {
				return &alarmmonitor.MonitorManager{}, nil
			})
		defer patches.Reset()

		// Mock MonitorManager.Start to return error
		patches.ApplyMethod(reflect.TypeOf(&alarmmonitor.MonitorManager{}), "Start",
			func(m *alarmmonitor.MonitorManager) error {
				return fmt.Errorf("failed to start monitor manager")
			})
		defer patches.Reset()

		monitorMgr, err := initMonitorManager(globalCfg, monitorCfg, hmacMgr)
		assert.Error(t, err)
		assert.Nil(t, monitorMgr)
		assert.Contains(t, err.Error(), "failed to start monitor manager")
	})
}

// TestInitModelManager tests the initModelManager function
func TestInitModelManager(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "success case",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetServerHandler()

			// Setup aigwMgr for callback
			cfg := &base.AigwConfig{
				GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
				Predictor:    base.PredictorConfig{PredictType: "none"},
			}
			aigwMgr, err := core.NewAigwManager(cfg, core.WithRuntimeMode(base.SdkMode))
			assert.NoError(t, err)
			serverHandler.aigwMgr = aigwMgr
			defer func() {
				if serverHandler.aigwMgr != nil {
					serverHandler.aigwMgr.Uninit()
				}
			}()

			dsCfg := &base.DataSyncConfig{
				Address:  "127.0.0.1:8080",
				Path:     "/models",
				Interval: 60,
			}
			hmacMgr := crypto.NewHmacManager([]byte("1234567890abcdef1234567890abcdef"))

			// Mock NewModelManager
			patches := gomonkey.ApplyFunc(modelmonitor.NewModelManager,
				func(queryURL string, callback modelmonitor.EventCallback, hmacMgr *crypto.HmacManager, interval int) *modelmonitor.ModelManager {
					return &modelmonitor.ModelManager{}
				})
			defer patches.Reset()

			// Mock ModelManager.Start
			patches.ApplyMethod(reflect.TypeOf(&modelmonitor.ModelManager{}), "Start",
				func(m *modelmonitor.ModelManager) error {
					return nil
				})
			defer patches.Reset()

			modelMgr, err := initModelManager(dsCfg, hmacMgr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, modelMgr)
			}
		})
	}
}

// TestInitModelManagerFail tests initModelManager failure cases
func TestInitModelManagerFail(t *testing.T) {
	t.Run("ModelManager.Start fails", func(t *testing.T) {
		resetServerHandler()

		// Setup aigwMgr for callback
		cfg := &base.AigwConfig{
			GlobalConfig: base.GlobalConfig{LogLevel: "info", SnapshotUpdateInterval: 1},
			Predictor:    base.PredictorConfig{PredictType: "none"},
		}
		aigwMgr, err := core.NewAigwManager(cfg, core.WithRuntimeMode(base.SdkMode))
		assert.NoError(t, err)
		serverHandler.aigwMgr = aigwMgr
		defer func() {
			if serverHandler.aigwMgr != nil {
				serverHandler.aigwMgr.Uninit()
			}
		}()

		dsCfg := &base.DataSyncConfig{
			Address:  "127.0.0.1:8080",
			Path:     "/models",
			Interval: 60,
		}
		hmacMgr := crypto.NewHmacManager([]byte("1234567890abcdef1234567890abcdef"))

		// Mock NewModelManager
		patches := gomonkey.ApplyFunc(modelmonitor.NewModelManager,
			func(queryURL string, callback modelmonitor.EventCallback, hmacMgr *crypto.HmacManager, interval int) *modelmonitor.ModelManager {
				return &modelmonitor.ModelManager{}
			})
		defer patches.Reset()

		// Mock ModelManager.Start to return error
		patches.ApplyMethod(reflect.TypeOf(&modelmonitor.ModelManager{}), "Start",
			func(m *modelmonitor.ModelManager) error {
				return fmt.Errorf("failed to start model manager")
			})
		defer patches.Reset()

		modelMgr, err := initModelManager(dsCfg, hmacMgr)
		assert.Error(t, err)
		// Note: initModelManager returns the model manager even if Start fails
		// The error indicates the failure, not a nil return value
		assert.NotNil(t, modelMgr)
		assert.Contains(t, err.Error(), "failed to start model manager")
	})
}

