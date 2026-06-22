/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aigw type test
 * Create: 2026-03-27
 */

package base

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAigwConfigString(t *testing.T) {
	config := AigwConfig{
		MonitorConfig: MonitorConfig{
			Address:     "localhost:9090",
			AlarmPath:   "/alarms",
			ServiceName: "aigw",
			Version:     "v1",
			BusinessId:  "biz123",
		},
		ZkConfig: ZookeeperConfig{
			Address:               "localhost:2181",
			AclScheme:             "digest",
			ConnectTimeout:        10,
			SessionTimeout:        30,
			InferenceInstancePath: "/aigw/instances",
			ScheduleServicePath:   "/aigw/schedule",
			EnableTls:             false,
		},
		DataSyncConfig: DataSyncConfig{
			Address:  "localhost:6379",
			Path:     "/data",
			Interval: 60,
		},
		Predictor: PredictorConfig{
			PredictType: "lightgbm",
			Lightgbm: LightgbmConfig{
				ClassifierFile: "/path/to/model.txt",
				VectorizerFile: "/path/to/vectorizer.bin",
			},
		},
		GsConfigs: []GlobalSchedulerConfig{
			{
				Model:                "gpt-3.5-turbo",
				BlockSize:            128,
				DeployPolicy:         "balanced",
				MaxTimeToFirstToken:  2.0,
				MaxTimeBetweenTokens: 0.1,
				TokenizeModelName:    "bert-base",
				LoadBalancer: LoadBalancerConfig{
					Mixed:               "leastconn",
					Prefill:             "token",
					Decode:              "rr",
					BatchSize:           10,
					ReservedBlockNumber: 2,
					MinMatchedLength:    512,
					PowerOfTwo:          true,
					PretrainTTFTPath:    "/path/ttft.bin",
				},
				InsConnectType:       "sse",
				CacheRefreshIntervalMs: 100,
				TokenizationRatio:      1.3,
			},
		},
		Tokenizers: []TokenizerConfig{
			{
				TokenizeModelName: "bert-base",
				ConfigPath:        "/path/to/bert.json",
				TokenizerType:     "bert",
			},
		},
		GlobalConfig: GlobalConfig{
			Host:                  "0.0.0.0",
			Port:                  "8080",
			LogPath:               "/var/log/aigw",
			LogLevel:              "info",
			CryptoSock:            "/var/run/aigw.sock",
			SnapshotUpdateInterval: 100,
			SecuritySchema:        "hmac",
			ReqTimeout:            30,
		},
		Limits: Limits{
			TotalInsNum:    100,
			InsNumPerModel: 50,
			ModelNum:       10,
			Concurrency:    1000,
			MaxPromptRunes: 10000,
		},
	}

	str := config.String()
	if str == "" {
		t.Error("AigwConfig.String() should not return empty string")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(str), &parsed); err != nil {
		t.Errorf("AigwConfig.String() returned invalid JSON: %v", err)
	}
}

func TestAigwConfigStringEmpty(t *testing.T) {
	// Test with minimal config
	config := AigwConfig{}
	str := config.String()
	if str == "" {
		t.Error("AigwConfig.String() should not return empty string even with zero values")
	}
}

func TestRuntimeMode(t *testing.T) {
	if ServiceMode != 0 {
		t.Errorf("ServiceMode should be 0, got %d", ServiceMode)
	}
	if SdkMode != 1 {
		t.Errorf("SdkMode should be 1, got %d", SdkMode)
	}
}

func TestGlobalSchedulerConfig_ProviderModeUnmarshal(t *testing.T) {
	data := `{
		"model": "gpt-4o-mini",
		"mode": "provider",
		"providerPool": {
			"strategy": "adaptive",
			"cooldown": {"failureThreshold": 3, "durationSec": 60, "rateLimitDurationSec": 90, "auth401FloorSec": 300},
			"retry": {"maxFailoverEndpoints": 3, "maxRetriesPerEndpoint": 2},
			"deployments": [
				{"id": "a", "provider": "openai", "apiBase": "https://api.openai.com", "apiKey": "sk-x", "tpm": 60000, "rpm": 500}
			]
		}
	}`
	var cfg GlobalSchedulerConfig
	assert.NoError(t, json.Unmarshal([]byte(data), &cfg))
	assert.Equal(t, "provider", cfg.Mode)
	assert.NotNil(t, cfg.ProviderPool)
	assert.Equal(t, "adaptive", cfg.ProviderPool.Strategy)
	assert.Len(t, cfg.ProviderPool.Deployments, 1)
	assert.Equal(t, 60000, cfg.ProviderPool.Deployments[0].TPM)
	assert.Equal(t, 300, cfg.ProviderPool.Cooldown.Auth401FloorSec)
}

func TestGlobalSchedulerConfig_ModeOptionalDefaultsEmpty(t *testing.T) {
	data := `{"model": "m", "blockSize": 128, "deployPolicy": "mixed"}`
	var cfg GlobalSchedulerConfig
	assert.NoError(t, json.Unmarshal([]byte(data), &cfg))
	assert.Equal(t, "", cfg.Mode, "missing mode unmarshals to empty; treated as instance downstream")
	assert.Nil(t, cfg.ProviderPool)
}