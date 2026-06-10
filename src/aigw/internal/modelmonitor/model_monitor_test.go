/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package modelmonitor provides the management of model for AIGW.
 * Create: 2025-08-14
 */

// Package modelmonitor provides the management of models for AIGW.
package modelmonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
)

const (
	testTimeout      = 1 * time.Second
	expectRetryTimes = 1
	sleepTime        = 50 * time.Millisecond
)

type mockCallbacks struct {
	registerCalled   map[string]bool
	unregisterCalled map[string]bool
	lock             sync.Mutex
}

func newMockCallbacks() *mockCallbacks {
	return &mockCallbacks{
		registerCalled:   make(map[string]bool),
		unregisterCalled: make(map[string]bool),
	}
}

func (m *mockCallbacks) RegisterModel(config *base.GlobalSchedulerConfig) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.registerCalled[config.Model] = true
	return nil
}

func (m *mockCallbacks) UnregisterModel(model string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.unregisterCalled[model] = true
	return nil
}

// 测试辅助函数
func createTestServer(responseCode int, responseBody interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(responseCode)
		if responseBody != nil {
			json.NewEncoder(w).Encode(responseBody)
		}
	}))
}

func TestNewModelManager(t *testing.T) {
	hmacMgr := crypto.NewHmacManager([]byte("test-key"))
	cb := EventCallback{
		RegisterModelCb:   func(*base.GlobalSchedulerConfig) error { return nil },
		UnregisterModelCb: func(string) error { return nil },
	}

	manager := NewModelManager("http://test-url", cb, hmacMgr, 1)

	if manager.queryURL != "http://test-url" {
		t.Errorf("Expected queryURL to be 'http://test-url', got '%s'", manager.queryURL)
	}

	if manager.interval != 1*time.Second {
		t.Errorf("Expected interval 1s, got %v", manager.interval)
	}
}

func TestFetchOnceSuccess(t *testing.T) {
	expectedModels := []ModelData{
		{Model: "model1", BlockSize: 128},
	}
	ts := createTestServer(http.StatusOK, DataSyncInfo{ModelList: expectedModels})
	defer ts.Close()

	mockCB := newMockCallbacks()
	manager := NewModelManager(ts.URL, EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, crypto.NewHmacManager(nil), 1)

	models, err := manager.fetchOnce()
	if err != nil {
		t.Fatalf("fetchOnce failed: %v", err)
	}

	if len(models) != 1 || models[0].Model != "model1" {
		t.Errorf("Expected 1 model, got %+v", models)
	}
}

func TestFetchOnceWithHMAC(t *testing.T) {
	var receivedHeader http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(DataSyncInfo{})
		if err != nil {
			t.Error("encode err")
		}
	}))
	defer ts.Close()

	hmacMgr := crypto.NewHmacManager([]byte("test-key"))
	manager := NewModelManager(ts.URL, EventCallback{}, hmacMgr, 1)

	manager.fetchOnce()

	if receivedHeader.Get("X-Timestamp") == "" || receivedHeader.Get("X-Signature") == "" {
		t.Error("HMAC headers not set")
	}
}

func TestDiffModels(t *testing.T) {
	manager := NewModelManager("", EventCallback{}, nil, 1)
	manager.gsTable = map[string]bool{
		"model1": true,
		"model2": true,
	}

	remoteList := []ModelData{
		{Model: "model2"},
		{Model: "model3"},
	}

	toAdd, toDel := manager.diff(remoteList)

	if len(toAdd) != 1 || toAdd[0].Model != "model3" {
		t.Errorf("Expected 1 to add (model3), got %v", toAdd)
	}

	if len(toDel) != 1 || toDel[0] != "model1" {
		t.Errorf("Expected 1 to del (model1), got %v", toDel)
	}
}

func TestAddAndDeleteModel(t *testing.T) {
	mockCB := newMockCallbacks()
	manager := NewModelManager("", EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, nil, 1)

	testModel := ModelData{
		Model:                "test-model",
		BlockSize:            128,
		DeployPolicy:         "Mix",
		MaxTimeToFirstToken:  "test",
		MaxTimeBetweenTokens: "0.5",
		TokenizeModelName:    "tokenizer",
	}
	manager.addGs(testModel)
	if manager.gsTable["test-model"] {
		t.Error("Model added to gsTable with error data")
	}

	testModel = ModelData{
		Model:                "test-model",
		BlockSize:            128,
		DeployPolicy:         "Mix",
		MaxTimeToFirstToken:  "0.5",
		MaxTimeBetweenTokens: "test",
		TokenizeModelName:    "tokenizer",
	}
	manager.addGs(testModel)
	if manager.gsTable["test-model"] {
		t.Error("Model added to gsTable with error data")
	}

	testModel = ModelData{
		Model:                "test-model",
		BlockSize:            128,
		DeployPolicy:         "test",
		MaxTimeToFirstToken:  "25",
		MaxTimeBetweenTokens: "0.5",
		TokenizeModelName:    "tokenizer",
	}
	manager.addGs(testModel)
	if manager.gsTable["test-model"] {
		t.Error("Model added to gsTable with error data")
	}

	testModel = ModelData{
		Model:                "test-model",
		BlockSize:            128,
		DeployPolicy:         "Mix",
		MaxTimeToFirstToken:  "1.5",
		MaxTimeBetweenTokens: "0.5",
		TokenizeModelName:    "tokenizer",
	}
	manager.addGs(testModel)

	if !mockCB.registerCalled["test-model"] {
		t.Error("Register callback not called")
	}
	if !manager.gsTable["test-model"] {
		t.Error("Model not added to gsTable")
	}

	manager.delGs("test-model")
	if !mockCB.unregisterCalled["test-model"] {
		t.Error("Unregister callback not called")
	}
	if manager.gsTable["test-model"] {
		t.Error("Model not removed from gsTable")
	}
}

func TestMainLoop(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	ts := createTestServer(http.StatusOK, DataSyncInfo{
		ModelList: []ModelData{{Model: "loop-model", TokenizeModelName: "DeepSeek-R1",
			MaxTimeToFirstToken: "100", MaxTimeBetweenTokens: "50", BlockSize: 128, DeployPolicy: "Mix"}},
	})
	defer ts.Close()

	mockCB := newMockCallbacks()
	manager := NewModelManager(ts.URL, EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, crypto.NewHmacManager(nil), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	manager.ctx = ctx

	go func() {
		defer wg.Done()
		manager.wg.Add(1)
		manager.loop()
	}()

	wg.Wait()

	manager.mux.RLock()
	defer manager.mux.RUnlock()
	if _, ok := manager.gsTable["loop-model"]; !ok {
		t.Error("Model not added during loop")
	}
}

func TestStartStop(t *testing.T) {
	ts := createTestServer(http.StatusOK, DataSyncInfo{})
	defer ts.Close()

	manager := NewModelManager(ts.URL, EventCallback{}, crypto.NewHmacManager(nil), 1)
	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(testTimeout)

	manager.Stop()
}

func TestValidateModelData(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ModelData
		wantErr bool
	}{
		{
			name: "TestValidateModelData_InvalidModelName",
			cfg: ModelData{
				Model:                "",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_InvalidTokenizeModelName",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_InvalidDeployPolicy",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Single",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_BlockSizeZero",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            0,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_BlockSizeNegative",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            -1,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_InvalidMaxTimeToFirstToken",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "abc",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_MaxTimeToFirstTokenZero",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_InvalidMaxTimeBetweenTokens",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "def",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_MaxTimeBetweenTokensZero",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "0",
			},
			wantErr: true,
		},
		{
			name: "TestValidateModelData_ValidAllFields",
			cfg: ModelData{
				Model:                "model",
				TokenizeModelName:    "tokenizer",
				DeployPolicy:         "Mix",
				BlockSize:            128,
				MaxTimeToFirstToken:  "1.0",
				MaxTimeBetweenTokens: "1.0",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateModelData(&tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("validateModelData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateModelAddScenario(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(DataSyncInfo{
			ModelList: []ModelData{
				{
					Model:                "new-model",
					BlockSize:            128,
					DeployPolicy:         "Mix",
					MaxTimeToFirstToken:  "1.5",
					MaxTimeBetweenTokens: "0.5",
					TokenizeModelName:    "tokenizer",
				},
			},
		})
		if err != nil {
			t.Error("encode err")
		}
	}))
	defer ts.Close()

	mockCB := newMockCallbacks()
	manager := NewModelManager(ts.URL, EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, crypto.NewHmacManager(nil), 1)

	manager.updateModel()

	manager.mux.RLock()
	defer manager.mux.RUnlock()

	if !manager.gsTable["new-model"] {
		t.Error("New model not added to gsTable")
	}

	mockCB.lock.Lock()
	defer mockCB.lock.Unlock()
	if !mockCB.registerCalled["new-model"] {
		t.Error("Register callback not called for new model")
	}
}

func TestUpdateModelDeleteScenario(t *testing.T) {
	mockCB := newMockCallbacks()
	manager := NewModelManager("", EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, crypto.NewHmacManager(nil), 1)
	manager.gsTable["old-model"] = true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(DataSyncInfo{ModelList: []ModelData{}})
		if err != nil {
			t.Error("encode err")
		}
	}))
	defer ts.Close()
	manager.queryURL = ts.URL

	manager.updateModel()

	manager.mux.RLock()
	defer manager.mux.RUnlock()

	if manager.gsTable["old-model"] {
		t.Error("Old model not removed from gsTable")
	}

	mockCB.lock.Lock()
	defer mockCB.lock.Unlock()
	if !mockCB.unregisterCalled["old-model"] {
		t.Error("Unregister callback not called for deleted model")
	}
}

func TestUpdateModelInvalidData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(DataSyncInfo{
			ModelList: []ModelData{
				{
					Model:        "invalid-model",
					DeployPolicy: "InvalidPolicy",
				},
			},
		})
		if err != nil {
			t.Error("encode err")
		}
	}))
	defer ts.Close()

	mockCB := newMockCallbacks()
	manager := NewModelManager(ts.URL, EventCallback{
		RegisterModelCb:   mockCB.RegisterModel,
		UnregisterModelCb: mockCB.UnregisterModel,
	}, crypto.NewHmacManager(nil), 1)

	manager.updateModel()

	manager.mux.RLock()
	defer manager.mux.RUnlock()

	if manager.gsTable["invalid-model"] {
		t.Error("Invalid model should not be added")
	}
}

func TestUpdateModelWithFetchError(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	manager := NewModelManager(ts.URL, EventCallback{}, crypto.NewHmacManager(nil), 1)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	manager.ctx = ctx

	manager.gsTable["existing-model"] = true

	manager.updateModel()

	t.Run("State unchanged", func(t *testing.T) {
		manager.mux.RLock()
		defer manager.mux.RUnlock()
		if !manager.gsTable["existing-model"] {
			t.Error("Existing model should remain unchanged")
		}
	})

	t.Run("Retry attempts", func(t *testing.T) {
		if callCount != expectRetryTimes {
			t.Errorf("Expected at least 2 retry attempts, got %d", callCount)
		}
	})
}
