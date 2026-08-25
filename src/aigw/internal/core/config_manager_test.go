/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: config manager test
 * Create: 2025-06-21
 */

// Package base contains the base definitions for AIGW.
package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"huawei.com/aigw/internal/base"
)

// TestNewAigwConfigManager tests the creation of a new AigwConfigManager.
func TestNewAigwConfigManager(t *testing.T) {
	manager := NewAigwConfigManager()
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.config)

	c := manager.GetAigwConfig()
	assert.NotNil(t, c)
	z := manager.GetZkConfig()
	assert.NotNil(t, z)
	mc := manager.GetMonitorConfig()
	assert.NotNil(t, mc)
}

// TestResetDefault tests the default
func TestResetDefault(t *testing.T) {
	c := &base.AigwConfig{}
	resetDefault(c)

	assert.Equal(t, defaultHost, c.GlobalConfig.Host)
	assert.Equal(t, defaultPort, c.GlobalConfig.Port)
	assert.Equal(t, defaultLogPath, c.GlobalConfig.LogPath)
	assert.Equal(t, defaultLogLevel, c.GlobalConfig.LogLevel)

	zcfg := &c.ZkConfig
	zcfg.Address = "invalid"
	resetDefault(c)
	assert.Equal(t, "default", zcfg.AclScheme)
	assert.Equal(t, defaultZkConnectTimeout, zcfg.ConnectTimeout)
	assert.Equal(t, defaultZkSessionTimeout, zcfg.SessionTimeout)
}

// TestLoadConfigInvalid tests the LoadConfig method.
func TestLoadConfigInvalid(t *testing.T) {
	manager := NewAigwConfigManager()
	assert.NotNil(t, manager)

	err := manager.LoadConfig("invalid")
	assert.Error(t, err)

	err = manager.LoadConfig("/usr/bin/ls")
	assert.Error(t, err)
}

// TestLoadConfig tests the LoadConfig method.
func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	config := base.AigwConfig{
		ZkConfig: base.ZookeeperConfig{
			Address:               "127.0.0.1:2181",
			AclScheme:             "default",
			ConnectTimeout:        defaultZkConnectTimeout,
			SessionTimeout:        defaultZkSessionTimeout,
			InferenceInstancePath: "/inference/instances",
			ScheduleServicePath:   "/schedule/services",
		},
		Predictor: base.PredictorConfig{
			PredictType: "none",
			Lightgbm: base.LightgbmConfig{
				ClassifierFile: "classifier.pkl",
				VectorizerFile: "vectorizer.pkl",
			},
		},
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model:                "model1",
				BlockSize:            64,
				DeployPolicy:         "mixed",
				MaxTimeToFirstToken:  100,
				MaxTimeBetweenTokens: 200,
				TokenizeModelName:    "DeepSeek-R1",
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:               "roundRobin",
					Prefill:             "true",
					Decode:              "false",
					BatchSize:           100,
					ReservedBlockNumber: 10,
					MinMatchedLength:    50,
				VirtualNodes:        160, // Default value set by validation
				FallbackNum:         3,   // Default value set by validation
				},
			},
		},
		GlobalConfig: base.GlobalConfig{
			Host:     defaultHost,
			Port:     defaultPort,
			LogPath:  defaultLogPath,
			LogLevel: defaultLogLevel,

			SnapshotUpdateInterval: 60,
			SecuritySchema:         "default",
			ReqTimeout:             600,
		},
		Limits: base.Limits{
			TotalInsNum:    2048,
			InsNumPerModel: 128,
			ModelNum:       128,
			Concurrency:    128,
			MaxPromptRunes: 1024,
		},
	}

	configJSON, err := json.Marshal(config)
	assert.NoError(t, err)

	tmpFile, err := os.CreateTemp("", "config-*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(configJSON)
	assert.NoError(t, err)
	tmpFile.Close()

	// Test loading the config
	manager := NewAigwConfigManager()
	err = manager.LoadConfig(tmpFile.Name())
	assert.NoError(t, err)

	// Verify the loaded config
	assert.Equal(t, config, manager.config)
}

// TestValidateConfig tests the ValidateConfig method.
func TestValidateConfig(t *testing.T) {
	manager := NewAigwConfigManager()

	// Valid config
	validConfig := base.AigwConfig{
		ZkConfig: base.ZookeeperConfig{
			Address:               "127.0.0.1:2181",
			ConnectTimeout:        defaultZkConnectTimeout,
			SessionTimeout:        defaultZkSessionTimeout,
			InferenceInstancePath: "/inference/instances",
			ScheduleServicePath:   "/schedule/services",
		},
		Predictor: base.PredictorConfig{
			PredictType: "ema",
			Lightgbm: base.LightgbmConfig{
				ClassifierFile: "classifier.pkl",
				VectorizerFile: "vectorizer.pkl",
			},
		},
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model:                "model1",
				BlockSize:            64,
				DeployPolicy:         "mixed",
				MaxTimeToFirstToken:  100,
				MaxTimeBetweenTokens: 200,
				TokenizeModelName:    "DeepSeek-R1",
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:               "roundRobin",
					Prefill:             "true",
					Decode:              "false",
					BatchSize:           100,
					ReservedBlockNumber: 10,
					MinMatchedLength:    50,
				},
			},
		},
		GlobalConfig: base.GlobalConfig{
			Host:     defaultHost,
			Port:     defaultPort,
			LogPath:  defaultLogPath,
			LogLevel: defaultLogLevel,

			SnapshotUpdateInterval: 60,
			SecuritySchema:         "default",
			ReqTimeout:             600,
		},
		Limits: base.Limits{
			TotalInsNum:    2048,
			InsNumPerModel: 128,
			ModelNum:       128,
			Concurrency:    128,
			MaxPromptRunes: 1024,
		},
	}

	err := manager.ValidateConfig(&validConfig)
	assert.NoError(t, err)

	// Invalid ZookeeperConfig
	invalidZkConfig := base.AigwConfig{
		ZkConfig: base.ZookeeperConfig{
			Address:               "invalid:address",
			InferenceInstancePath: "/inference/instances",
			ScheduleServicePath:   "/schedule/services",
		},
	}
	err = manager.ValidateConfig(&invalidZkConfig)
	assert.Error(t, err)

	// Invalid PredictorConfig
	invalidPredictorConfig := base.AigwConfig{
		Predictor: base.PredictorConfig{
			PredictType: "invalid",
		},
	}
	err = manager.ValidateConfig(&invalidPredictorConfig)
	assert.Error(t, err)

	// Invalid GlobalSchedulerConfig
	invalidGsConfig := base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{
			{
				Model:                "model1",
				BlockSize:            32, // Invalid block size
				DeployPolicy:         "mixed",
				MaxTimeToFirstToken:  100,
				MaxTimeBetweenTokens: 200,
				TokenizeModelName:    "DeepSeek-R1",
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:               "roundRobin",
					Prefill:             "true",
					Decode:              "false",
					BatchSize:           100,
					ReservedBlockNumber: 10,
					MinMatchedLength:    50,
				},
			},
		},
	}
	err = manager.ValidateConfig(&invalidGsConfig)
	assert.Error(t, err)

	// Invalid GlobalConfig
	invalidGlobalConfig := base.AigwConfig{
		GlobalConfig: base.GlobalConfig{
			SnapshotUpdateInterval: 0, // Invalid interval
		},
	}
	err = manager.ValidateConfig(&invalidGlobalConfig)
	assert.Error(t, err)
}

// TestPrintConfig tests the PrintConfig method.
func TestPrintConfig(t *testing.T) {
	manager := NewAigwConfigManager()
	config := base.AigwConfig{
		ZkConfig: base.ZookeeperConfig{
			Address:               "127.0.0.1:2181",
			InferenceInstancePath: "/inference/instances",
			ScheduleServicePath:   "/schedule/services",
		},
	}
	manager.config = config

	// Capture the log output
	logOutput := &strings.Builder{}
	log.SetOutput(logOutput)

	manager.PrintConfig()
}

// TestValidateZookeeperConfig tests the validateZookeeperConfig method.
func TestValidateZookeeperConfig(t *testing.T) {
	// Valid ZookeeperConfig
	validZkConfig := base.ZookeeperConfig{
		Address:               "127.0.0.1:2181",
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	err := validateZookeeperConfig(&validZkConfig)
	assert.NoError(t, err)

	// Invalid address
	invalidAddressZkConfig := base.ZookeeperConfig{
		Address:               "invalid:address",
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	err = validateZookeeperConfig(&invalidAddressZkConfig)
	assert.Error(t, err)

	// Invalid InferenceInstancePath
	invalidInferencePathZkConfig := base.ZookeeperConfig{
		Address:               "127.0.0.1:2181",
		InferenceInstancePath: "invalid",
		ScheduleServicePath:   "/schedule/services",
	}
	err = validateZookeeperConfig(&invalidInferencePathZkConfig)
	assert.Error(t, err)

	// Invalid ScheduleServicePath
	invalidSchedulePathZkConfig := base.ZookeeperConfig{
		Address:               "127.0.0.1:2181",
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "invalid",
	}
	err = validateZookeeperConfig(&invalidSchedulePathZkConfig)
	assert.Error(t, err)

	// invalid timeout
	invalidTimeout := base.ZookeeperConfig{
		Address:               "127.0.0.1:2181",
		AclScheme:             "default",
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
		ConnectTimeout:        -1,
		SessionTimeout:        -1,
	}
	err = validateZookeeperConfig(&invalidTimeout)
	assert.Error(t, err)

	invalidTimeout.ConnectTimeout = 1
	err = validateZookeeperConfig(&invalidTimeout)
	assert.Error(t, err)

	invalidTimeout.EnableTls = true
	err = validateZookeeperConfig(&invalidTimeout)
	assert.Error(t, err)

	invalidTimeout.CaFile = "/usr/bin/ls"
	invalidTimeout.CrtFile = "/usr/bin/ls"
	const s = 1024
	invalidTimeout.ServerName = strings.Repeat("1024", s)
	err = validateZookeeperConfig(&invalidTimeout)
	assert.Error(t, err)
}

// TestValidatePredictorConfig tests the validatePredictorConfig method.
func TestValidatePredictorConfig(t *testing.T) {
	// Valid PredictorConfig
	validPredictorConfig := base.PredictorConfig{
		PredictType: "none",
		Lightgbm: base.LightgbmConfig{
			ClassifierFile: "classifier.pkl",
			VectorizerFile: "vectorizer.pkl",
		},
	}
	err := validatePredictorConfig(&validPredictorConfig)
	assert.NoError(t, err)

	// Invalid predictType
	invalidPredictTypeConfig := base.PredictorConfig{
		PredictType: "invalid",
	}
	err = validatePredictorConfig(&invalidPredictTypeConfig)
	assert.Error(t, err)

	// Invalid ClassifierFile
	invalidClassifierFileConfig := base.PredictorConfig{
		PredictType: "lightgbm",
		Lightgbm: base.LightgbmConfig{
			ClassifierFile: "invalid_path",
			VectorizerFile: "/usr/bin/ls",
		},
	}
	err = validatePredictorConfig(&invalidClassifierFileConfig)
	assert.Error(t, err)

	// Invalid VectorizerFile
	invalidVectorizerFileConfig := base.PredictorConfig{
		PredictType: "lightgbm",
		Lightgbm: base.LightgbmConfig{
			ClassifierFile: "/usr/bin/ls",
			VectorizerFile: "invalid_path",
		},
	}
	err = validatePredictorConfig(&invalidVectorizerFileConfig)
	assert.Error(t, err)
}

// TestValidateGlobalSchedulersConfig tests the validateGlobalSchedulersConfig method.
func TestValidateGlobalSchedulersConfig(t *testing.T) {
	// Valid GlobalSchedulerConfig
	validGsConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err := validateGlobalSchedulersConfig(validGsConfig)
	assert.NoError(t, err)

	// Invalid block size
	invalidBlockSizeConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            -1, // Invalid block size
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidBlockSizeConfig)
	assert.Error(t, err)

	// Invalid deployPolicy
	invalidDeployPolicyConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "invalid",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidDeployPolicyConfig)
	assert.Error(t, err)

	// Invalid MaxTimeToFirstToken
	invalidMaxTimeToFirstTokenConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  0, // Invalid value
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidMaxTimeToFirstTokenConfig)
	assert.Error(t, err)

	// Invalid MaxTimeBetweenTokens
	invalidMaxTimeBetweenTokensConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 0, // Invalid value
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidMaxTimeBetweenTokensConfig)
	assert.Error(t, err)

	// Invalid loadBalancer mixed type
	invalidLoadBalancerMixedTypeConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "DeepSeek-R1",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "invalid",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidLoadBalancerMixedTypeConfig)
	assert.Error(t, err)

	// Invalid tokenizer config file
	invalidTokenizerCfgFileConfig := []base.GlobalSchedulerConfig{
		{
			Model:                "model1",
			BlockSize:            64,
			DeployPolicy:         "mixed",
			MaxTimeToFirstToken:  100,
			MaxTimeBetweenTokens: 200,
			TokenizeModelName:    "",
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "true",
				Decode:              "false",
				BatchSize:           100,
				ReservedBlockNumber: 10,
				MinMatchedLength:    50,
				VirtualNodes:        160, // Default value for consistent hash
				FallbackNum:         3,   // Default value for consistent hash
			},
		},
	}
	err = validateGlobalSchedulersConfig(invalidTokenizerCfgFileConfig)
	assert.Error(t, err)
}

// TestValidateGlobalConfig tests the validateGlobalConfig method.
func TestValidateGlobalConfig(t *testing.T) {
	// Valid GlobalConfig
	validGlobalConfig := base.GlobalConfig{
		Host:     defaultHost,
		Port:     defaultPort,
		LogPath:  defaultLogPath,
		LogLevel: defaultLogLevel,

		SnapshotUpdateInterval: 60,
		SecuritySchema:         "default",
		ReqTimeout:             600,
	}
	err := validateGlobalConfig(&validGlobalConfig)
	assert.NoError(t, err)

	// Invalid SnapshotUpdateInterval (too low)
	invalidIntervalLowConfig := base.GlobalConfig{
		SnapshotUpdateInterval: -1,
	}
	err = validateGlobalConfig(&invalidIntervalLowConfig)
	assert.Error(t, err)

	// invalid port
	bad := validGlobalConfig
	bad.Port = "1"
	err = validateGlobalConfig(&bad)
	assert.Error(t, err)
}

// TestValidateLoadBalancerInvalidMixedType tests the validateLoadBalancer function when the mixed
// load balancer type is invalid
func TestValidateLoadBalancerInvalidMixedType(t *testing.T) {
	gsCfg := &base.GlobalSchedulerConfig{
		DeployPolicy: "mixed",
		LoadBalancer: base.LoadBalancerConfig{
			Mixed: "invalidType",
		},
		Model: "someModel",
	}

	err := validateLoadBalancer(gsCfg)
	expectedErr := fmt.Errorf("invalid loadBalanceType %q for mixed deployPolicy, model %q",
		"invalidType", "someModel")
	assert.EqualError(t, err, expectedErr.Error())
}

// TestValidateLoadBalancerInvalidBatchSize tests the validateLoadBalancer function when the batch size is invalid
func TestValidateLoadBalancerInvalidBatchSize(t *testing.T) {
	gsCfg := &base.GlobalSchedulerConfig{
		DeployPolicy: "somePolicy",
		LoadBalancer: base.LoadBalancerConfig{
			BatchSize: -1,
		},
	}

	err := validateLoadBalancer(gsCfg)
	expectedErr := fmt.Errorf("invalid batch size value: %v, should > 0", -1)
	assert.EqualError(t, err, expectedErr.Error())
}

// TestValidateLoadBalancerInvalidReservedBlockNumber tests the validateLoadBalancer function when the reserved
// block number is invalid
func TestValidateLoadBalancerInvalidReservedBlockNumber(t *testing.T) {
	gsCfg := &base.GlobalSchedulerConfig{
		DeployPolicy: "roundRobin",
		LoadBalancer: base.LoadBalancerConfig{
			BatchSize:           1,
			ReservedBlockNumber: -1,
		},
	}

	err := validateLoadBalancer(gsCfg)
	expectedErr := fmt.Errorf("invalid ReservedBlockNumber value: %v, should > 0", -1)
	assert.EqualError(t, err, expectedErr.Error())
}

// TestValidateLoadBalancerInvalidMinMatchedLength tests the validateLoadBalancer function when the minimum matched
// length is invalid
func TestValidateLoadBalancerInvalidMinMatchedLength(t *testing.T) {
	gsCfg := &base.GlobalSchedulerConfig{
		DeployPolicy: "roundRobin",
		LoadBalancer: base.LoadBalancerConfig{
			BatchSize:           1,
			ReservedBlockNumber: 1,
			MinMatchedLength:    -1,
		},
	}

	err := validateLoadBalancer(gsCfg)
	expectedErr := fmt.Errorf("invalid MinMatchedLength value: %v, should > 0", -1)
	assert.EqualError(t, err, expectedErr.Error())
}

func TestValidateLimits(t *testing.T) {
	tests := []struct {
		name    string
		limits  base.Limits
		wantErr bool
	}{
		{
			name: "valid limits",
			limits: base.Limits{
				TotalInsNum:    4096,
				InsNumPerModel: 512,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: false,
		},
		{
			name: "TotalInsNum exceeds max",
			limits: base.Limits{
				TotalInsNum:    maxTotalInstanceNum + 1,
				InsNumPerModel: 512,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "TotalInsNum less than 1",
			limits: base.Limits{
				TotalInsNum:    0,
				InsNumPerModel: 512,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "InsNumPerModel exceeds max",
			limits: base.Limits{
				TotalInsNum:    4096,
				InsNumPerModel: maxInsPerModel + 1,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "ModelNum exceeds max",
			limits: base.Limits{
				TotalInsNum:    4096,
				InsNumPerModel: 512,
				ModelNum:       maxModelNum + 1,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "Concurrency exceeds max",
			limits: base.Limits{
				TotalInsNum:    4096,
				InsNumPerModel: 512,
				ModelNum:       512,
				Concurrency:    513,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "TotalInsNum less than InsNumPerModel",
			limits: base.Limits{
				TotalInsNum:    100,
				InsNumPerModel: 200,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: 1024,
			},
			wantErr: true,
		},
		{
			name: "MaxPromptRunes below minimum allowed value",
			limits: base.Limits{
				TotalInsNum:    100,
				InsNumPerModel: 200,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: minPromptRunes - 1,
			},
			wantErr: true,
		},
		{
			name: "MaxPromptRunes exceed maximum allowed value",
			limits: base.Limits{
				TotalInsNum:    100,
				InsNumPerModel: 200,
				ModelNum:       512,
				Concurrency:    512,
				MaxPromptRunes: maxPromptRunes + 1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLimits(&tt.limits)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLimits() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDataSyncConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     base.DataSyncConfig
		wantErr bool
	}{
		{
			name:    "empty address",
			cfg:     base.DataSyncConfig{Address: ""},
			wantErr: false,
		},
		{
			name: "valid address and interval",
			cfg: base.DataSyncConfig{
				Address:  "127.0.0.1:8080",
				Path:     "/valid/path",
				Interval: 300,
			},
			wantErr: false,
		},
		{
			name: "invalid address format",
			cfg: base.DataSyncConfig{
				Address: "invalid-address",
				Path:    "/valid/path",
			},
			wantErr: true,
		},
		{
			name: "interval too small",
			cfg: base.DataSyncConfig{
				Address:  "127.0.0.1:8080",
				Interval: 0,
			},
			wantErr: true,
		},
		{
			name: "interval too large",
			cfg: base.DataSyncConfig{
				Address:  "127.0.0.1:8080",
				Interval: 601,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDataSyncConfig(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDataSyncConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMonitorConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     base.MonitorConfig
		wantErr bool
	}{
		{
			name:    "empty address",
			cfg:     base.MonitorConfig{Address: ""},
			wantErr: false,
		},
		{
			name: "valid config",
			cfg: base.MonitorConfig{
				Address:     "127.0.0.1:8080",
				AlarmPath:   "/valid/alarm",
				ServiceName: "valid_service",
				Version:     "v1.0",
				BusinessId:  "12345",
			},
			wantErr: false,
		},
		{
			name: "invalid address",
			cfg: base.MonitorConfig{
				Address: "256.0.0.1:8080",
			},
			wantErr: true,
		},
		{
			name: "invalid alarm path",
			cfg: base.MonitorConfig{
				Address:   "127.0.0.1:8080",
				AlarmPath: "invalid path with spaces",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMonitorConfig(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMonitorConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenizerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	validConfigPath := tmpDir + "/config.json"
	os.WriteFile(validConfigPath, []byte("test"), 1024)

	tests := []struct {
		name    string
		cfg     base.TokenizerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: base.TokenizerConfig{
				TokenizeModelName: "valid-model",
				ConfigPath:        validConfigPath,
				TokenizerType:     "huggingfaceTokenizers",
			},
			wantErr: false,
		},
		{
			name: "invalid tokenizer type",
			cfg: base.TokenizerConfig{
				TokenizeModelName: "valid-model",
				ConfigPath:        validConfigPath,
				TokenizerType:     "invalid-type",
			},
			wantErr: true,
		},
		{
			name: "non-existent config path",
			cfg: base.TokenizerConfig{
				ConfigPath: "/non/existent/path",
			},
			wantErr: true,
		},
		{
			name: "empty model name",
			cfg: base.TokenizerConfig{
				TokenizeModelName: "",
				ConfigPath:        validConfigPath,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenizerConfig(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTokenizerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
