/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: HttpServer test
 * Create: 2025-06-18
 */

// Package server provides north interfaces for AIGW.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
)

const (
	httpServerTestWaitTime = 800 * time.Millisecond
)

type mockAigwManager struct {
	registerInstanceCalled   bool
	unregisterInstanceCalled bool
	getSuggestionCalled      bool
	statsCalled              bool
}

func TestHttpServer(t *testing.T) {
	manager := &mockAigwManager{}
	aigwManager := &core.AigwManager{}
	serverHandler.cfgMgr = core.NewAigwConfigManager()
	err := serverHandler.cfgMgr.LoadConfig(validConfigPath)
	if err != nil {
		t.Fatalf("Failed to LoadConfig: %v", err)
	}
	patchReg := gomonkey.ApplyMethod(reflect.TypeOf(aigwManager), "RegisterInstance",
		func(aigwManager *core.AigwManager, req *base.RegisterInstanceIn) error {
			manager.registerInstanceCalled = true
			t.Logf("register instance %v", req)
			return nil
		})
	defer patchReg.Reset()
	patchUnreg := gomonkey.ApplyMethod(reflect.TypeOf(aigwManager), "UnregisterInstance",
		func(aigwManager *core.AigwManager, req *base.UnregisterInstanceIn) error {
			manager.unregisterInstanceCalled = true
			t.Logf("unregister instance %v", req)
			return nil
		})
	defer patchUnreg.Reset()
	patchGetSuggestion := gomonkey.ApplyMethod(reflect.TypeOf(aigwManager), "GetSuggestion",
		func(aigwManager *core.AigwManager, in *core.GetSuggestionIn) (*base.GetSuggestionOut, error) {
			manager.getSuggestionCalled = true
			t.Logf("get suggestion %v", in)
			return &base.GetSuggestionOut{
				TargetPrefillUrl: "test-instance",
				TargetDecodeUrl:  "test-endpoint",
			}, nil
		})
	defer patchGetSuggestion.Reset()

	patchStats := gomonkey.ApplyMethod(reflect.TypeOf(aigwManager), "GetAllStats",
		func(aigwManager *core.AigwManager) *base.AigwAllStats {
			manager.statsCalled = true
			t.Logf("get stats")
			return &base.AigwAllStats{
				StatsSlice: []*base.StatsEntry{
					{
						ModelName: "DeepSeek-V3",
						Counts: map[string]uint64{
							"ScheduleSuccess":        1,
							"ScheduleFailure":        2,
							"TokenizerEncodeError":   3,
							"LightGbmVectorizeError": 4,
							"LightGbmPredictError":   5,
							"LbNoCandidateIns":       6,
						},
					},
					{
						ModelName: "DeepSeek-R1",
						Counts: map[string]uint64{
							"ScheduleSuccess":        6,
							"ScheduleFailure":        5,
							"TokenizerEncodeError":   4,
							"LightGbmVectorizeError": 3,
							"LightGbmPredictError":   2,
							"LbNoCandidateIns":       1,
						},
					},
				},
			}
		})
	defer patchStats.Reset()

	server := NewHttpServer(aigwManager, "localhost", "9999", nil)

	server.Start()

	// wait server to start
	time.Sleep(httpServerTestWaitTime)

	testHealth(t, server)

	testRegisterInstance(t, server, manager)

	testUnregisterInstance(t, server, manager)

	testScheduleForOpenAi(t, server, manager)

	testStats(t, server, manager)

	server.Stop()
}

func testHealth(t *testing.T, server *HttpServer) {
	resp, err := http.Get(fmt.Sprintf("http://%s:%s/aigw/v1/health", server.host, server.port))
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func testRegisterInstance(t *testing.T, server *HttpServer, manager *mockAigwManager) {
	url := fmt.Sprintf("http://%s:%s/aigw/v1/register-instance", server.host, server.port)
	reqBody := &base.RegisterInstanceIn{
		Name:  "test-instance",
		Model: "test-model",
		Role:  "test-role",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to call register-instance endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if !manager.registerInstanceCalled {
		t.Error("RegisterInstance method was not called")
	}
}

func testUnregisterInstance(t *testing.T, server *HttpServer, manager *mockAigwManager) {
	url := fmt.Sprintf("http://%s:%s/aigw/v1/unregister-instance", server.host, server.port)
	reqBody := &base.UnregisterInstanceIn{
		Model: "test-model",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to call unregister-instance endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if !manager.unregisterInstanceCalled {
		t.Error("UnregisterInstance method was not called")
	}
}

func testScheduleForOpenAi(t *testing.T, server *HttpServer, manager *mockAigwManager) {
	url := fmt.Sprintf("http://%s:%s/aigw/v1/openai/get-suggestion", server.host, server.port)
	m1 := base.OpenAiMessage{
		Role:    "system",
		Content: "you are AI.",
	}
	m2 := base.OpenAiMessage{
		Role:    "user",
		Content: "hello, who are you?",
	}
	reqBody := struct {
		UUID     string               `json:"uuid"`
		Model    string               `json:"model"`
		Messages []base.OpenAiMessage `json:"messages"`
	}{
		UUID:     "test-uuid",
		Model:    "test-model",
		Messages: []base.OpenAiMessage{m1, m2},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to call get-suggestion endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if !manager.getSuggestionCalled {
		t.Error("GetSuggestion method was not called")
	}

	// read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var out base.GetSuggestionOut
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if out.TargetPrefillUrl != "test-instance" || out.TargetDecodeUrl != "test-endpoint" {
		t.Errorf("Expected instance ID %s and endpoint %s, got %s and %s", "test-instance", "test-endpoint",
			out.TargetPrefillUrl, out.TargetDecodeUrl)
	}
}

func testStats(t *testing.T, server *HttpServer, manager *mockAigwManager) {
	url := fmt.Sprintf("http://%s:%s/aigw/v1/stats", server.host, server.port)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("Failed to call stats endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d , got %d", http.StatusOK, resp.StatusCode)
	}
	if !manager.statsCalled {
		t.Error("stats method was not called")
	}

	//read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var actual base.AigwAllStats
	if err := json.Unmarshal(body, &actual); err != nil {
		t.Errorf("Failed to decode response body: %v", err)
	}
	expected := base.AigwAllStats{
		StatsSlice: []*base.StatsEntry{
			{
				ModelName: "DeepSeek-V3",
				Counts: map[string]uint64{
					"ScheduleSuccess":        1,
					"ScheduleFailure":        2,
					"TokenizerEncodeError":   3,
					"LightGbmVectorizeError": 4,
					"LightGbmPredictError":   5,
					"LbNoCandidateIns":       6,
				},
			},
			{
				ModelName: "DeepSeek-R1",
				Counts: map[string]uint64{
					"ScheduleSuccess":        6,
					"ScheduleFailure":        5,
					"TokenizerEncodeError":   4,
					"LightGbmVectorizeError": 3,
					"LightGbmPredictError":   2,
					"LbNoCandidateIns":       1,
				},
			},
		},
	}

	assert.Equal(t, expected, actual)
}

// TestNewHttpServer test an empty instance
func TestNewHttpServer(t *testing.T) {
	manager := &core.AigwManager{}
	server := NewHttpServer(manager, "localhost", "9999", nil)
	if server.manager != manager {
		t.Error("Expected manager to be set correctly")
	}
	if server.host != "localhost" {
		t.Error("Expected host to be set correctly")
	}
	if server.port != "9999" {
		t.Error("Expected port to be set correctly")
	}
}

// TestHttpServerLifecycle
func TestHttpServerLifecycle(t *testing.T) {
	manager := &core.AigwManager{}
	server := NewHttpServer(manager, "localhost", "9999", nil)

	server.Start()

	time.Sleep(httpServerTestWaitTime)

	server.Stop()

	server.server = nil
	server.Stop()
}

// TestHttpServer_ErrorHandling
func TestHttpServer_ErrorHandling(t *testing.T) {
	aigwManager := &core.AigwManager{}
	server := NewHttpServer(aigwManager, "localhost", "9999", nil)
	server.Start()

	time.Sleep(httpServerTestWaitTime)

	resp, err := http.Post(fmt.Sprintf("http://%s:%s/aigw/v1/health", server.host, server.port), "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to call health endpoint with POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
	}

	server.Stop()
}

// TestRegisterInstance_Error
func TestRegisterInstance_Error(t *testing.T) {
	aigwManager := &core.AigwManager{}
	server := NewHttpServer(aigwManager, "localhost", "9999", nil)
	server.Start()

	time.Sleep(httpServerTestWaitTime)

	url := fmt.Sprintf("http://%s:%s/aigw/v1/register-instance", server.host, server.port)

	// testing GET
	resp1, e1 := http.Get(url)
	if e1 != nil {
		t.Fatalf("Failed to call register-instance endpoint with POST: %v", e1)
	}
	if resp1.StatusCode != http.StatusMethodNotAllowed {
		fmt.Printf("ytt :%v", resp1.StatusCode)
		t.Errorf("Get should be not allowed")
	}

	// testing invalid json body
	resp, err := http.Post(url, "application/json", bytes.NewBuffer([]byte("invalid json")))
	if err != nil {
		t.Fatalf("Failed to call register-instance endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	server.Stop()
}

// TestUnregisterInstance_Error
func TestUnregisterInstance_Error(t *testing.T) {
	aigwManager := &core.AigwManager{}
	server := NewHttpServer(aigwManager, "localhost", "9999", nil)
	server.Start()

	time.Sleep(httpServerTestWaitTime)

	url := fmt.Sprintf("http://%s:%s/aigw/v1/unregister-instance", server.host, server.port)

	resp1, e1 := http.Get(url)
	if e1 != nil {
		t.Fatalf("Failed to call unregister-instance endpoint with POST: %v", e1)
	}
	if resp1.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Get should be not allowed")
	}

	// testing invalid json body
	resp, err := http.Post(url, "application/json", bytes.NewBuffer([]byte("invalid json")))
	if err != nil {
		t.Fatalf("Failed to call unregister-instance endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	server.Stop()
}

// TestScheduleForOpenAi_Error tests schedule with error
func TestScheduleForOpenAi_Error(t *testing.T) {
	aigwManager := &core.AigwManager{}
	server := NewHttpServer(aigwManager, "localhost", "9999", nil)
	server.Start()

	time.Sleep(httpServerTestWaitTime)

	url := fmt.Sprintf("http://%s:%s/aigw/v1/openai/get-suggestion", server.host, server.port)

	resp1, e1 := http.Get(url)
	if e1 != nil {
		t.Fatalf("Failed to call get-suggestion endpoint: %v", e1)
	}
	if resp1.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Get should be not allowed")
	}

	// test with an empty prompt
	reqBody := struct {
		UUID   string `json:"uuid"`
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}{
		UUID:  "test-uuid",
		Model: "test-model",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to call getsuggestion endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	server.Stop()
}

// TestProcessMessages tests processMessages function
func TestProcessMessages(t *testing.T) {
	tests := []struct {
		name     string
		messages []base.OpenAiMessage
		expected string
	}{
		{
			name: "single message",
			messages: []base.OpenAiMessage{
				{Role: "user", Content: "hello"},
			},
			expected: "user:hello ",
		},
		{
			name: "multiple messages",
			messages: []base.OpenAiMessage{
				{Role: "system", Content: "You are a helpful assistant."},
				{Role: "user", Content: "hello"},
			},
			expected: "system:You are a helpful assistant. user:hello ",
		},
		{
			name:     "empty messages",
			messages: []base.OpenAiMessage{},
			expected: "",
		},
		{
			name: "message with special characters",
			messages: []base.OpenAiMessage{
				{Role: "user", Content: "Hello\nWorld\t!"},
			},
			expected: "user:Hello\nWorld\t! ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processMessages(tt.messages)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHttpServerSetReady tests setReady and isServerReady
func TestHttpServerSetReady(t *testing.T) {
	server := NewHttpServer(nil, "localhost", "8080", nil)

	// Initially not ready
	assert.False(t, server.isServerReady())

	// Set ready
	server.setReady()
	assert.True(t, server.isServerReady())
}

// TestHttpServerStopNilServer tests stopping when server is nil
func TestHttpServerStopNilServer(t *testing.T) {
	server := NewHttpServer(nil, "localhost", "8080", nil)
	// Should not panic
	server.Stop()
}
